// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Imported multicast routes and sequence numbers, persisted local origins,
//! and path snapshots used for update reconciliation.

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;

use ddm_api_types::db::MulticastRoute;
use ddm_api_types::net::MulticastOrigin;
use ddm_protocol::RouterId;
use mg_common::lock;
use slog::error;

use super::{Db, Error, RemovedNexthopRoutes};

/// Persistent tree for locally originated multicast groups.
const MCAST_ORIGINATE: &str = "mcast_originate";

impl Db {
    pub fn imported_mcast(&self) -> HashSet<MulticastRoute> {
        lock!(self.data).imported_mcast.routes().cloned().collect()
    }

    pub fn shortest_path_mcast(
        &self,
        peer_router_id: &RouterId,
    ) -> Vec<MulticastRoute> {
        lock!(self.data)
            .imported_mcast
            .shortest_path_routes(peer_router_id)
            .cloned()
            .collect()
    }

    /// Sequence cutoff for routes imported before a pull occurs.
    pub fn next_mcast_seq(&self) -> u64 {
        lock!(self.data).mcast_seq + 1
    }

    /// Apply multicast imports and removals under a held data lock, returning
    /// the routes that were actually removed.
    pub fn update_imported_mcast(
        &self,
        update: MulticastRibChange<'_>,
    ) -> HashSet<MulticastRoute> {
        let mut guard = lock!(self.data);
        let data = &mut *guard;

        // Path and metric live outside of route identity and may change on
        // re-import.
        for x in update.import {
            data.mcast_seq += 1;
            data.imported_mcast.insert(x, data.mcast_seq);
        }

        update
            .remove
            .iter()
            .filter_map(|x| {
                data.imported_mcast.remove(x, update.imported_before)
            })
            .collect()
    }

    /// Persist multicast origins to advertise to peers.
    pub fn originate_mcast(
        &self,
        origins: &HashSet<MulticastOrigin>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(MCAST_ORIGINATE)?;
        for origin in origins {
            // Keep metric in the value; re-origination can update it.
            tree.insert(
                mcast_origin_key(origin)?.as_str(),
                serde_json::to_string(origin)?.as_str(),
            )?;
        }
        tree.flush()?;
        Ok(())
    }

    /// Read the locally originated multicast origins.
    ///
    /// Bypassing an unreadable entry could cause a false withdrawal during
    /// reconciliation, so we fail the entire read to avoid this situation.
    ///
    /// # Errors
    ///
    /// Returns an error if the tree cannot be opened or if any entry fails to
    /// read or parse.
    pub fn originated_mcast(&self) -> Result<HashSet<MulticastOrigin>, Error> {
        let tree = self.persistent_data.open_tree(MCAST_ORIGINATE)?;
        tree.iter()
            .map(|item| {
                let (_key, value) = item?;
                Ok(serde_json::from_slice(&value)?)
            })
            .collect()
    }

    /// Remove persisted multicast origins.
    pub fn withdraw_mcast(
        &self,
        origins: &HashSet<MulticastOrigin>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(MCAST_ORIGINATE)?;
        for origin in origins {
            // Withdraw by identity, regardless of the supplied metric.
            tree.remove(mcast_origin_key(origin)?.as_str())?;
        }
        tree.flush()?;
        Ok(())
    }

    /// Snapshot multicast paths through local origins and imported routes.
    pub fn snapshot_mcast_paths<'a>(
        &self,
        origins: impl IntoIterator<Item = &'a MulticastOrigin>,
        peer_router_id: &RouterId,
    ) -> McastPathSnapshot {
        let origins: Vec<_> = origins.into_iter().collect();
        let imported = {
            let data = lock!(self.data);
            origins
                .iter()
                .filter_map(|origin| {
                    data.imported_mcast.shortest_path(origin, peer_router_id)
                })
                .map(|route| (route.origin.clone(), route.clone()))
                .collect()
        };
        self.path_snapshot(&origins, imported)
    }

    /// Snapshot multicast paths through local origins only.
    pub fn snapshot_local_mcast_paths<'a>(
        &self,
        origins: impl IntoIterator<Item = &'a MulticastOrigin>,
    ) -> McastPathSnapshot {
        let origins: Vec<_> = origins.into_iter().collect();
        self.path_snapshot(&origins, HashMap::new())
    }

    /// Remove multicast routes via `nexthop` on a downgrade below V4.
    ///
    /// Underlay and tunnel routes remain intact.
    pub fn remove_nexthop_mcast_routes(
        &self,
        nexthop: Ipv6Addr,
    ) -> RemovedNexthopRoutes {
        let removed = lock!(self.data).imported_mcast.extract_nexthop(nexthop);

        RemovedNexthopRoutes {
            underlay: HashSet::new(),
            tunnel: HashSet::new(),
            multicast: removed,
        }
    }

    /// Origins imported via `nexthop` before `seq` that are not in
    /// `announced`.
    pub fn stale_mcast_by_nexthop(
        &self,
        nexthop: Ipv6Addr,
        seq: u64,
        announced: &HashSet<MulticastOrigin>,
    ) -> Vec<MulticastOrigin> {
        lock!(self.data)
            .imported_mcast
            .stale(nexthop, seq, announced)
    }

    /// Read local origins to complete the snapshot of `imported`.
    ///
    /// NOTE: Callers must not hold the data lock because local origins are read
    /// from the persistent store without it. This makes the snapshot
    /// non-atomic: `imported` was read under the lock, and the two halves
    /// could diverge.
    ///
    /// A failed origin read leaves `originated` as `None`.
    fn path_snapshot(
        &self,
        origins: &[&MulticastOrigin],
        imported: HashMap<MulticastOrigin, MulticastRoute>,
    ) -> McastPathSnapshot {
        let originated = self
            .lookup_originated_mcast(origins)
            .inspect_err(|e| {
                error!(self.log, "lookup originated multicast origins: {e}");
            })
            .ok();
        McastPathSnapshot {
            imported,
            originated,
        }
    }

    fn lookup_originated_mcast(
        &self,
        origins: &[&MulticastOrigin],
    ) -> Result<HashSet<MulticastOrigin>, Error> {
        let tree = self.persistent_data.open_tree(MCAST_ORIGINATE)?;
        let mut originated = HashSet::new();
        for origin in origins {
            if let Some(value) = tree.get(mcast_origin_key(origin)?.as_str())? {
                originated.insert(serde_json::from_slice(&value)?);
            }
        }
        Ok(originated)
    }
}

#[derive(Debug, Clone)]
struct ImportedEntry {
    route: MulticastRoute,
    seq: u64,
}

/// A type wrapper over the set of imported multicast routes, keyed by origin
/// and then by nexthop.
///
/// A path snapshot for an update's origins is a lookup per origin. Each
/// origin's routes are sorted by nexthop, with the lowest-nexthop route
/// coming first. Per-peer work (e.g., stale-route scans, expiry) visits each
/// origin once.
// Note: We use a sorted `Vec` here over a `BTreeMap` because an origin rarely
// has more than a few nexthops.
#[derive(Debug, Default, Clone)]
pub struct ImportedMcast(HashMap<MulticastOrigin, Vec<ImportedEntry>>);

fn find_nexthop(
    nexthops: &[ImportedEntry],
    nexthop: Ipv6Addr,
) -> Result<usize, usize> {
    nexthops.binary_search_by_key(&nexthop, |entry| entry.route.nexthop)
}

impl ImportedMcast {
    fn routes(&self) -> impl Iterator<Item = &MulticastRoute> {
        self.0.values().flatten().map(|entry| &entry.route)
    }

    fn shortest_path_routes<'a>(
        &'a self,
        peer_router_id: &'a RouterId,
    ) -> impl Iterator<Item = &'a MulticastRoute> {
        self.0.keys().filter_map(move |origin| {
            self.shortest_path(origin, peer_router_id)
        })
    }

    fn insert(&mut self, route: &MulticastRoute, seq: u64) {
        let nexthops = self.0.entry(route.origin.clone()).or_default();
        match find_nexthop(nexthops, route.nexthop) {
            Ok(idx) => {
                let entry = &mut nexthops[idx];
                if entry.route.path != route.path
                    || entry.route.origin.metric() != route.origin.metric()
                {
                    entry.route = route.clone();
                }
                entry.seq = seq;
            }
            Err(idx) => {
                // Grow one slot at a time.
                nexthops.reserve_exact(1);
                nexthops.insert(
                    idx,
                    ImportedEntry {
                        route: route.clone(),
                        seq,
                    },
                );
            }
        }
    }

    fn remove(
        &mut self,
        route: &MulticastRoute,
        imported_before: Option<u64>,
    ) -> Option<MulticastRoute> {
        let nexthops = self.0.get_mut(&route.origin)?;
        let idx = find_nexthop(nexthops, route.nexthop).ok()?;
        if imported_before.is_some_and(|seq| nexthops[idx].seq >= seq) {
            return None;
        }
        let entry = nexthops.remove(idx);
        if nexthops.is_empty() {
            self.0.remove(&route.origin);
        }
        Some(entry.route)
    }

    pub(super) fn extract_nexthop(
        &mut self,
        nexthop: Ipv6Addr,
    ) -> HashSet<MulticastRoute> {
        let mut extracted = HashSet::new();
        self.0.retain(|_, nexthops| {
            if let Ok(idx) = find_nexthop(nexthops, nexthop) {
                extracted.insert(nexthops.remove(idx).route);
            }
            !nexthops.is_empty()
        });
        extracted
    }

    /// Pick the route with the shortest path, breaking ties by the lowest
    /// origin metric (first) and then by the lowest nexthop address (e.g.,
    /// `fe80::1` < `fe80::2`).
    ///
    /// Routes whose path contains `peer_router_id` (the peer an update gets
    /// sent to) are omitted. That peer would discard such a path as a loop
    /// and drop its route through us.
    fn shortest_path(
        &self,
        origin: &MulticastOrigin,
        peer_router_id: &RouterId,
    ) -> Option<&MulticastRoute> {
        self.0
            .get(origin)?
            .iter()
            .map(|entry| &entry.route)
            .filter(|route| {
                !route
                    .path
                    .iter()
                    .any(|hop| &hop.router_id == peer_router_id)
            })
            .min_by_key(|route| {
                (route.path.len(), route.origin.metric(), route.nexthop)
            })
    }

    fn stale(
        &self,
        nexthop: Ipv6Addr,
        seq: u64,
        announced: &HashSet<MulticastOrigin>,
    ) -> Vec<MulticastOrigin> {
        self.0
            .values()
            .filter_map(|nexthops| {
                find_nexthop(nexthops, nexthop).ok().map(|i| &nexthops[i])
            })
            .filter(|entry| {
                entry.seq < seq && !announced.contains(&entry.route.origin)
            })
            .map(|entry| entry.route.origin.clone())
            .collect()
    }
}

/// Persistent origin key, excluding metric as in `PartialEq` and `Hash`.
fn mcast_origin_key(origin: &MulticastOrigin) -> Result<String, Error> {
    Ok(serde_json::to_string(&(
        origin.overlay_group(),
        origin.underlay_group(),
        origin.vni(),
        origin.source(),
    ))?)
}

/// A batch of multicast imports and removals.
#[derive(Debug, Clone, Copy)]
pub struct MulticastRibChange<'a> {
    pub import: &'a HashSet<MulticastRoute>,
    pub remove: &'a HashSet<MulticastRoute>,
    /// Remove only routes imported before this sequence number.
    /// Pull reconciliation uses this cutoff to preserve concurrent pushes.
    pub imported_before: Option<u64>,
}

impl<'a> MulticastRibChange<'a> {
    /// A change without a sequence cutoff, as used for push withdrawals.
    pub fn new(
        import: &'a HashSet<MulticastRoute>,
        remove: &'a HashSet<MulticastRoute>,
    ) -> Self {
        Self {
            import,
            remove,
            imported_before: None,
        }
    }
}

/// Imported routes and local origins used for multicast update
/// reconciliation.
#[derive(Debug, Clone)]
pub struct McastPathSnapshot {
    imported: HashMap<MulticastOrigin, MulticastRoute>,
    originated: Option<HashSet<MulticastOrigin>>,
}

impl McastPathSnapshot {
    pub fn imported(
        &self,
        origin: &MulticastOrigin,
    ) -> Option<&MulticastRoute> {
        self.imported.get(origin)
    }

    /// Local origins, or `None` on a failed read.
    /// An unreadable origin set cannot establish a final withdrawal.
    pub fn originated(&self) -> Option<&HashSet<MulticastOrigin>> {
        self.originated.as_ref()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use camino_tempfile::Utf8TempDir;
    use ddm_api_types::db::TunnelRoute;
    use ddm_api_types::net::{
        OverlayMulticast, TunnelOrigin, UnderlayMulticastIpv6, Vni,
    };
    use ddm_protocol::v4::MulticastPathHop;
    use pretty_assertions::assert_eq;
    use slog::Logger;

    use super::*;

    const NO_PEER: RouterId = RouterId::new(String::new());

    fn test_db() -> (Utf8TempDir, Db) {
        let dir = Utf8TempDir::new().unwrap();
        let log = Logger::root(slog::Discard, slog::o!());
        let db = Db::new(dir.path().as_str(), log).unwrap();
        (dir, db)
    }

    fn mcast_origin(overlay: &str, underlay: &str) -> MulticastOrigin {
        MulticastOrigin::new(
            OverlayMulticast::new(overlay.parse().unwrap()).unwrap(),
            UnderlayMulticastIpv6::new(underlay.parse().unwrap()).unwrap(),
            Vni::new(77).unwrap(),
            None,
        )
        .unwrap()
    }

    fn route(origin: MulticastOrigin, nexthop: &str) -> MulticastRoute {
        MulticastRoute {
            origin,
            nexthop: nexthop.parse().unwrap(),
            path: vec![MulticastPathHop::new(
                "remote".into(),
                "fe80::2".parse().unwrap(),
            )],
        }
    }

    fn import(db: &Db, routes: &HashSet<MulticastRoute>) {
        db.update_imported_mcast(MulticastRibChange::new(
            routes,
            &HashSet::new(),
        ));
    }

    pub(crate) fn corrupt_mcast_origin_store(
        db: &Db,
        origin: &MulticastOrigin,
    ) {
        let tree = db.persistent_data.open_tree(MCAST_ORIGINATE).unwrap();
        tree.insert(
            mcast_origin_key(origin).unwrap().as_str(),
            "not-an-origin",
        )
        .unwrap();
        tree.flush().unwrap();
    }

    /// A corrupt origin entry fails on reads that touch it, while other origins
    /// and imported routes remain available to read.
    #[test]
    fn corrupt_origin_store_fails_closed() {
        let (_dir, db) = test_db();
        let good = mcast_origin("233.252.0.1", "ff04::1");
        let bad = mcast_origin("233.252.0.2", "ff04::2");
        let route = MulticastRoute {
            origin: bad.clone(),
            nexthop: "fe80::a".parse().unwrap(),
            path: Vec::new(),
        };
        db.originate_mcast(&HashSet::from([good.clone()])).unwrap();
        db.update_imported_mcast(MulticastRibChange::new(
            &HashSet::from([route.clone()]),
            &HashSet::new(),
        ));
        assert_eq!(db.originated_mcast().unwrap().len(), 1);

        corrupt_mcast_origin_store(&db, &bad);

        assert!(db.originated_mcast().is_err());

        let paths = db.snapshot_mcast_paths([&bad], &NO_PEER);
        assert!(paths.originated().is_none());
        assert_eq!(paths.imported(&bad), Some(&route));

        assert_eq!(
            db.snapshot_mcast_paths([&good], &NO_PEER).originated(),
            Some(&HashSet::from([good])),
        );
    }

    /// A path snapshot includes persisted local origins and current imports.
    #[test]
    fn snapshot_mcast_paths_reads_both_sources() {
        let (_dir, db) = test_db();

        // Distinct overlay/underlay groups so identity-based equality on
        // `MulticastOrigin` keeps the persisted and imported origins apart.
        let local_origin =
            mcast_origin("233.252.0.1", "ff04::1").with_metric(10);
        let imported_origin =
            mcast_origin("233.252.0.2", "ff04::2").with_metric(20);
        let route = route(imported_origin, "fe80::2");

        db.originate_mcast(&HashSet::from([local_origin.clone()]))
            .unwrap();
        db.update_imported_mcast(MulticastRibChange::new(
            &HashSet::from([route.clone()]),
            &HashSet::new(),
        ));

        let paths =
            db.snapshot_mcast_paths([&local_origin, &route.origin], &NO_PEER);
        let imported = paths.imported(&route.origin).unwrap();
        assert_eq!(imported, &route);
        assert_eq!(imported.origin.metric(), 20);
        assert_eq!(imported.path, route.path);
        let originated = paths.originated().unwrap();
        assert_eq!(originated.get(&local_origin).unwrap().metric(), 10);
        assert_eq!(originated, &HashSet::from([local_origin]));
    }

    /// The origin store keys on identity, meaning that metric can
    /// never split an entry.
    #[test]
    fn origin_store_keys_on_identity_not_metric() {
        let (_dir, db) = test_db();

        // Re-originating with a changed metric overwrites the stored entry.
        db.originate_mcast(&HashSet::from([mcast_origin(
            "233.252.0.1",
            "ff04::1",
        )
        .with_metric(10)]))
            .unwrap();
        db.originate_mcast(&HashSet::from([mcast_origin(
            "233.252.0.1",
            "ff04::1",
        )
        .with_metric(20)]))
            .unwrap();

        let stored = db.originated_mcast().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored.iter().next().unwrap().metric(), 20);

        // A withdraw with the default metric still matches.
        db.withdraw_mcast(&HashSet::from([mcast_origin(
            "233.252.0.1",
            "ff04::1",
        )]))
        .unwrap();
        assert!(db.originated_mcast().unwrap().is_empty());
    }

    /// Only the multicast routes via the given nexthop are removed.
    #[test]
    fn remove_nexthop_mcast_routes_is_scoped_to_the_peer() {
        let (_dir, db) = test_db();

        // `a` and `a2` go via the removed nexthop. `b` is another peer's and
        // stays.
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let b = route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::b");
        let a2 = route(mcast_origin("233.252.0.3", "ff04::3"), "fe80::a");
        import(&db, &HashSet::from([a.clone(), b.clone(), a2.clone()]));

        // Underlay and tunnel routes via the same nexthop also stay.
        db.import(&HashSet::from([crate::db::Route {
            destination: "fd00::/64".parse().unwrap(),
            nexthop: "fe80::a".parse().unwrap(),
            ifname: "test0".into(),
            path: vec!["remote".into()],
        }]));

        let tunnel = TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "203.0.113.0/24".parse().unwrap(),
                boundary_addr: "fd00:1701::a".parse().unwrap(),
                vni: 47,
                metric: 0,
            },
            nexthop: "fe80::a".parse().unwrap(),
        };
        db.import_tunnel(&HashSet::from([tunnel]));

        let removed =
            db.remove_nexthop_mcast_routes("fe80::a".parse().unwrap());

        // A snapshot taken after removal no longer views the removed routes.
        let paths = db
            .snapshot_mcast_paths([&a.origin, &b.origin, &a2.origin], &NO_PEER);
        assert!(paths.imported(&a.origin).is_none());
        assert!(paths.imported(&a2.origin).is_none());
        assert_eq!(paths.imported(&b.origin), Some(&b));
        assert_eq!(removed.multicast, HashSet::from([a, a2]));
        assert!(removed.underlay.is_empty());
        assert!(removed.tunnel.is_empty());
        assert_eq!(db.imported_mcast(), HashSet::from([b.clone()]));
        assert_eq!(db.imported_count(), 1);
        assert_eq!(db.imported_tunnel(), HashSet::from([tunnel]));
    }

    #[test]
    fn remove_nexthop_routes_removes_every_family_for_a_peer() {
        let (_dir, db) = test_db();

        let multicast_a =
            route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let multicast_b =
            route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::b");
        import(
            &db,
            &HashSet::from([multicast_a.clone(), multicast_b.clone()]),
        );

        let underlay = |nexthop: &str, dst: &str| crate::db::Route {
            destination: dst.parse().unwrap(),
            nexthop: nexthop.parse().unwrap(),
            ifname: "test0".into(),
            path: vec!["remote".into()],
        };
        let underlay_a = underlay("fe80::a", "fd00:a::/64");
        let underlay_b = underlay("fe80::b", "fd00:b::/64");
        db.import(&HashSet::from([underlay_a.clone(), underlay_b.clone()]));

        let tunnel = |nexthop: &str, boundary: &str| TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "203.0.113.0/24".parse().unwrap(),
                boundary_addr: boundary.parse().unwrap(),
                vni: 47,
                metric: 0,
            },
            nexthop: nexthop.parse().unwrap(),
        };
        let tunnel_a = tunnel("fe80::a", "fd00:1701::a");
        let tunnel_b = tunnel("fe80::b", "fd00:1701::b");
        db.import_tunnel(&HashSet::from([tunnel_a, tunnel_b]));

        let removed = db.remove_nexthop_routes("fe80::a".parse().unwrap());

        assert_eq!(removed.underlay, HashSet::from([underlay_a]));
        assert_eq!(removed.tunnel, HashSet::from([tunnel_a]));
        let paths = db.snapshot_mcast_paths(
            [&multicast_a.origin, &multicast_b.origin],
            &NO_PEER,
        );
        assert!(paths.imported(&multicast_a.origin).is_none());
        assert_eq!(paths.imported(&multicast_b.origin), Some(&multicast_b));
        assert_eq!(removed.multicast, HashSet::from([multicast_a]));
        assert_eq!(db.imported(), HashSet::from([underlay_b]));
        assert_eq!(db.imported_tunnel(), HashSet::from([tunnel_b]));
    }

    /// The stale set excludes other peers, announced origins, and later
    /// imports.
    #[test]
    fn stale_mcast_by_nexthop_filters() {
        let (_dir, db) = test_db();
        let peer: Ipv6Addr = "fe80::a".parse().unwrap();

        let announced =
            route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let unannounced =
            route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::a");
        let other_peer =
            route(mcast_origin("233.252.0.3", "ff04::3"), "fe80::b");
        import(
            &db,
            &HashSet::from([
                announced.clone(),
                unannounced.clone(),
                other_peer,
            ]),
        );

        let seq = db.next_mcast_seq();
        let late = route(mcast_origin("233.252.0.4", "ff04::4"), "fe80::a");
        import(&db, &HashSet::from([late]));

        let stale = db.stale_mcast_by_nexthop(
            peer,
            seq,
            &HashSet::from([announced.origin]),
        );
        assert_eq!(stale, vec![unannounced.origin]);
    }

    /// The cutoff removes an untouched route and preserves imports made
    /// after it.
    #[test]
    fn stale_removal_skips_routes_imported_after_the_cutoff() {
        let (_dir, db) = test_db();

        let prev = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let refreshed =
            route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::a");
        import(&db, &HashSet::from([prev.clone(), refreshed.clone()]));

        let started_at = db.next_mcast_seq();

        // A concurrent push re-announces `refreshed` and adds a `new` route
        // while the pull is reading a snapshot that contains neither of these.
        let new = route(mcast_origin("233.252.0.3", "ff04::3"), "fe80::a");
        import(&db, &HashSet::from([refreshed.clone(), new.clone()]));

        // Even if the reader's candidate set was computed before the push was
        // applied, the bounded removal skips anything (re)imported since.
        let candidates = HashSet::from([
            prev.clone(),
            MulticastRoute {
                path: Vec::new(),
                ..refreshed.clone()
            },
            MulticastRoute {
                path: Vec::new(),
                ..new.clone()
            },
        ]);
        let removed = db.update_imported_mcast(MulticastRibChange {
            import: &HashSet::new(),
            remove: &candidates,
            imported_before: Some(started_at),
        });

        assert_eq!(removed, HashSet::from([prev]));
        assert_eq!(db.imported_mcast(), HashSet::from([refreshed, new]));
    }

    #[test]
    fn shortest_path_falls_back_after_removal_and_expiry() {
        let (_dir, db) = test_db();
        let origin = mcast_origin("233.252.0.1", "ff04::1");
        let other = mcast_origin("233.252.0.2", "ff04::2");
        let low = route(origin.clone(), "fe80::1");
        let high = route(origin.clone(), "fe80::2");
        let other_low = route(other.clone(), "fe80::1");
        import(&db, &HashSet::from([low.clone(), high.clone(), other_low]));

        let shortest = |db: &Db, origin: &MulticastOrigin| {
            db.snapshot_mcast_paths([origin], &NO_PEER)
                .imported(origin)
                .map(|route| (route.nexthop, route.path.clone()))
        };
        assert_eq!(
            shortest(&db, &origin),
            Some((low.nexthop, low.path.clone()))
        );

        db.update_imported_mcast(MulticastRibChange::new(
            &HashSet::new(),
            &HashSet::from([low.clone()]),
        ));
        assert_eq!(
            shortest(&db, &origin),
            Some((high.nexthop, high.path.clone()))
        );

        let refreshed = MulticastRoute {
            path: vec![MulticastPathHop::new(
                "refreshed".into(),
                "fe80::3".parse().unwrap(),
            )],
            ..high.clone()
        };
        import(&db, &HashSet::from([refreshed.clone()]));
        assert_eq!(
            shortest(&db, &origin),
            Some((high.nexthop, refreshed.path.clone()))
        );

        import(&db, &HashSet::from([low.clone()]));
        let removed = db.remove_nexthop_mcast_routes(low.nexthop);
        assert_eq!(removed.multicast.len(), 2);
        assert_eq!(
            shortest(&db, &origin),
            Some((high.nexthop, refreshed.path))
        );
        assert_eq!(shortest(&db, &other), None);

        db.remove_nexthop_mcast_routes(high.nexthop);
        assert_eq!(shortest(&db, &origin), None);
        assert!(db.imported_mcast().is_empty());
    }

    #[test]
    fn shortest_path_skips_the_peer_and_prefers_shorter_paths() {
        let mut imported = ImportedMcast::default();
        let origin = mcast_origin("233.252.0.1", "ff04::1");
        let hop = |id: &str| {
            MulticastPathHop::new(id.into(), "fe80::9".parse().unwrap())
        };
        let via = |nexthop: &str, path: &[&str]| MulticastRoute {
            origin: origin.clone(),
            nexthop: nexthop.parse().unwrap(),
            path: path.iter().map(|id| hop(id)).collect(),
        };

        let peer_in_path = via("fe80::1", &["peer", "x"]);
        let long = via("fe80::2", &["a", "b", "c"]);
        let short = via("fe80::3", &["d", "e"]);
        imported.insert(&peer_in_path, 1);
        imported.insert(&long, 2);
        imported.insert(&short, 3);

        let picked = imported.shortest_path(&origin, &"peer".into()).unwrap();
        assert_eq!(picked.nexthop, short.nexthop);

        let picked = imported.shortest_path(&origin, &"other".into()).unwrap();
        assert_eq!(picked.nexthop, peer_in_path.nexthop);
    }

    #[test]
    fn shortest_path_handles_length_ties_by_metric() {
        let mut imported = ImportedMcast::default();
        let origin = mcast_origin("233.252.0.1", "ff04::1");
        let hop = |id: &str| {
            MulticastPathHop::new(id.into(), "fe80::9".parse().unwrap())
        };
        let via = |nexthop: &str, metric: u64, path: &[&str]| MulticastRoute {
            origin: origin.clone().with_metric(metric),
            nexthop: nexthop.parse().unwrap(),
            path: path.iter().map(|id| hop(id)).collect(),
        };

        let low_nexthop = via("fe80::1", 20, &["a", "b"]);
        let low_metric = via("fe80::2", 10, &["c", "d"]);
        let shorter = via("fe80::3", 30, &["e"]);
        imported.insert(&low_nexthop, 1);
        imported.insert(&low_metric, 2);

        let picked = imported.shortest_path(&origin, &"peer".into()).unwrap();
        assert_eq!(picked.nexthop, low_metric.nexthop);

        imported.insert(&shorter, 3);
        let picked = imported.shortest_path(&origin, &"peer".into()).unwrap();
        assert_eq!(picked.nexthop, shorter.nexthop);
    }

    #[test]
    fn imported_mcast_drops_emptied_origins() {
        let mut imported = ImportedMcast::default();
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");

        imported.insert(&a, 1);
        assert_eq!(imported.remove(&a, None), Some(a.clone()));
        assert!(imported.0.is_empty());

        imported.insert(&a, 2);
        assert_eq!(imported.extract_nexthop(a.nexthop), HashSet::from([a]));
        assert!(imported.0.is_empty());
    }
}
