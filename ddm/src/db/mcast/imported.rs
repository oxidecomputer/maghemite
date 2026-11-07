// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The imported multicast set, made mutable through an [`ImportedMcastEdit`]
//! guard that wakes the multicast sweep when membership gets updated.

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;

use ddm_api_types::db::MulticastRoute;
use ddm_api_types::net::MulticastOrigin;
use ddm_protocol::RouterId;
use tokio::sync::watch;

#[derive(Debug, Clone)]
struct ImportedEntry {
    route: MulticastRoute,
    ifname: String,
    seq: u64,
}

/// A type wrapper over the set of imported multicast routes, keyed by origin
/// and then by nexthop and the interface that its peer was discovered on.
///
/// A lookup per origin produces the path snapshot for an update. Each
/// origin's routes are sorted by nexthop and then by interface, with the
/// lowest-nexthop route first.
///
/// Per-peer work (e.g., stale-route scans, expiry) visits each origin just
/// once.
// Note: We use a sorted `Vec` here over a `BTreeMap` because an origin rarely
// has more than a few nexthops.
#[derive(Debug, Default, Clone)]
pub struct ImportedMcast(HashMap<MulticastOrigin, Vec<ImportedEntry>>);

fn find_link(
    nexthops: &[ImportedEntry],
    nexthop: Ipv6Addr,
    ifname: &str,
) -> Result<usize, usize> {
    nexthops.binary_search_by(|entry| {
        (entry.route.nexthop, entry.ifname.as_str()).cmp(&(nexthop, ifname))
    })
}

impl ImportedMcast {
    /// Begin an edit operation.
    ///
    /// Dropping the returned guard wakes `wake`'s watched subscribers if the
    /// edit added or removed an `(origin, nexthop, ifname)` entry.
    pub(in crate::db) fn edit<'a>(
        &'a mut self,
        wake: &'a watch::Sender<u64>,
    ) -> ImportedMcastEdit<'a> {
        ImportedMcastEdit {
            imported: self,
            wake,
            changed: false,
        }
    }

    /// Each imported route paired with the interface its peer was discovered
    /// on.
    pub(in crate::db) fn links(
        &self,
    ) -> impl Iterator<Item = (&MulticastRoute, &str)> {
        self.0
            .values()
            .flatten()
            .map(|entry| (&entry.route, entry.ifname.as_str()))
    }

    pub(in crate::db) fn shortest_path_routes<'a>(
        &'a self,
        peer_router_id: &'a RouterId,
    ) -> impl Iterator<Item = &'a MulticastRoute> {
        self.0.keys().filter_map(move |origin| {
            self.shortest_path(origin, peer_router_id)
        })
    }

    /// Pick the route with the shortest path, breaking ties by the lowest
    /// origin metric (first), then by the lowest nexthop address (e.g.,
    /// `fe80::1` < `fe80::2`), and finally by the interface name.
    ///
    /// Routes whose path contains `peer_router_id` (the peer an update gets
    /// sent to) are omitted. That peer would discard such a path as a loop
    /// and drop its route through us.
    pub(in crate::db) fn shortest_path(
        &self,
        origin: &MulticastOrigin,
        peer_router_id: &RouterId,
    ) -> Option<&MulticastRoute> {
        let key = |entry: &ImportedEntry| {
            (
                entry.route.path.len(),
                entry.route.origin.metric(),
                entry.route.nexthop,
            )
        };
        self.0
            .get(origin)?
            .iter()
            .filter(|entry| {
                !entry
                    .route
                    .path
                    .iter()
                    .any(|hop| &hop.router_id == peer_router_id)
            })
            .min_by(|a, b| {
                key(a).cmp(&key(b)).then_with(|| a.ifname.cmp(&b.ifname))
            })
            .map(|entry| &entry.route)
    }

    /// Return origins imported via `nexthop` on `ifname` before a `seq`
    /// that are not contained in `announced`.
    pub(in crate::db) fn stale(
        &self,
        nexthop: Ipv6Addr,
        ifname: &str,
        seq: u64,
        announced: &HashSet<MulticastOrigin>,
    ) -> Vec<MulticastOrigin> {
        self.0
            .values()
            .filter_map(|nexthops| {
                find_link(nexthops, nexthop, ifname)
                    .ok()
                    .map(|i| &nexthops[i])
            })
            .filter(|entry| {
                entry.seq < seq && !announced.contains(&entry.route.origin)
            })
            .map(|entry| entry.route.origin.clone())
            .collect()
    }
}

/// The effect of [`ImportedMcastEdit::insert`] on the imported set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::db) enum Inserted {
    /// A new `(origin, nexthop, ifname)` entry.
    New,
    /// An existing entry whose path or metric changed.
    Changed,
    /// An existing entry refreshed without change.
    Unchanged,
}

/// An edit guard for [`ImportedMcast`].
///
/// Mutations record whether or not they added or removed an entry. If an
/// update occurred, then dropping the guard wakes the multicast sweep process.
pub(in crate::db) struct ImportedMcastEdit<'a> {
    imported: &'a mut ImportedMcast,
    wake: &'a watch::Sender<u64>,
    changed: bool,
}

impl ImportedMcastEdit<'_> {
    /// Insert or refresh a `route` at `seq` number, reporting whether it added
    /// a new `(origin, nexthop, ifname)` entry, changed an existing entry's
    /// path or metric, or left it unchanged.
    ///
    /// Only a new entry wakes the sweep, because multicast membership depends
    /// only on which `(nexthop, ifname)` links import a group.
    pub(in crate::db) fn insert(
        &mut self,
        route: &MulticastRoute,
        ifname: &str,
        seq: u64,
    ) -> Inserted {
        let nexthops = self.imported.0.entry(route.origin.clone()).or_default();
        let inserted = match find_link(nexthops, route.nexthop, ifname) {
            Ok(idx) => {
                let entry = &mut nexthops[idx];
                entry.seq = seq;
                if entry.route.path != route.path
                    || entry.route.origin.metric() != route.origin.metric()
                {
                    entry.route = route.clone();
                    Inserted::Changed
                } else {
                    Inserted::Unchanged
                }
            }
            Err(idx) => {
                // Grow one slot at a time.
                nexthops.reserve_exact(1);
                nexthops.insert(
                    idx,
                    ImportedEntry {
                        route: route.clone(),
                        ifname: ifname.to_string(),
                        seq,
                    },
                );
                Inserted::New
            }
        };
        self.changed |= inserted == Inserted::New;
        inserted
    }

    pub(in crate::db) fn remove(
        &mut self,
        route: &MulticastRoute,
        ifname: &str,
        imported_before: Option<u64>,
    ) -> Option<MulticastRoute> {
        let nexthops = self.imported.0.get_mut(&route.origin)?;
        let idx = find_link(nexthops, route.nexthop, ifname).ok()?;
        if imported_before.is_some_and(|seq| nexthops[idx].seq >= seq) {
            return None;
        }
        let entry = nexthops.remove(idx);
        if nexthops.is_empty() {
            self.imported.0.remove(&route.origin);
        }
        self.changed = true;
        Some(entry.route)
    }

    pub(in crate::db) fn extract_link(
        &mut self,
        nexthop: Ipv6Addr,
        ifname: &str,
    ) -> HashSet<MulticastRoute> {
        let mut extracted = HashSet::new();
        self.imported.0.retain(|_, nexthops| {
            if let Ok(idx) = find_link(nexthops, nexthop, ifname) {
                extracted.insert(nexthops.remove(idx).route);
            }
            !nexthops.is_empty()
        });
        self.changed |= !extracted.is_empty();
        extracted
    }
}

impl Drop for ImportedMcastEdit<'_> {
    fn drop(&mut self) {
        if self.changed {
            self.wake.send_modify(|generation| {
                *generation = generation.wrapping_add(1);
            });
        }
    }
}
