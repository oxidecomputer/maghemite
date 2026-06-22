// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_api_types::db::{MulticastRoute, TunnelRoute};
use ddm_api_types::net::{MulticastOrigin, TunnelOrigin};
use mg_common::lock;
use oxnet::{IpNet, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{Logger, error};
use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};

/// The handle used to open a persistent key-value tree for originated
/// prefixes.
const ORIGINATE: &str = "originate";

/// The handle used to open a persistent key-value tree for originated
/// tunnel endpoints.
const TUNNEL_ORIGINATE: &str = "tunnel_originate";

/// The handle used to open a persistent key-value tree for originated
/// multicast groups.
const MCAST_ORIGINATE: &str = "mcast_originate";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("datastore error {0}")]
    DataStore(#[from] sled::Error),

    #[error("db key error {0}")]
    DbKey(String),

    #[error("db value error {0}")]
    DbValue(String),

    #[error("serialization error {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct Db {
    data: Arc<Mutex<DbData>>,
    persistent_data: sled::Db,
    log: Logger,
}

/// The realized change to the imported multicast set after applying an update.
///
/// This holds the routes that actually became present or absent, computed as
/// the set difference between the pre- and post-update state rather than the
/// raw request. Downstream consumers reconcile only these groups, so an update
/// that re-imports an existing route or withdraws an absent one yields an empty
/// delta and triggers no work.
#[derive(Debug, Default, Clone)]
pub struct McastRibDelta {
    /// Routes newly present after the update.
    pub added: HashSet<MulticastRoute>,

    /// Routes no longer present after the update.
    pub removed: HashSet<MulticastRoute>,
}

#[derive(Default, Clone)]
pub struct DbData {
    pub imported: HashSet<Route>,
    pub imported_tunnel: HashSet<TunnelRoute>,
    pub imported_mcast: HashSet<MulticastRoute>,
}

unsafe impl Sync for Db {}
unsafe impl Send for Db {}

impl Db {
    pub fn new(db_path: &str, log: Logger) -> Result<Self, sled::Error> {
        Ok(Self {
            data: Arc::new(Mutex::new(DbData::default())),
            persistent_data: sled::open(db_path)?,
            log,
        })
    }

    pub fn dump(&self) -> DbData {
        lock!(self.data).clone()
    }

    pub fn imported(&self) -> HashSet<Route> {
        lock!(self.data).imported.clone()
    }

    pub fn imported_count(&self) -> usize {
        lock!(self.data).imported.len()
    }

    pub fn imported_tunnel(&self) -> HashSet<TunnelRoute> {
        lock!(self.data).imported_tunnel.clone()
    }

    pub fn imported_tunnel_count(&self) -> usize {
        lock!(self.data).imported_tunnel.len()
    }

    pub fn imported_mcast(&self) -> HashSet<MulticastRoute> {
        lock!(self.data).imported_mcast.clone()
    }

    pub fn imported_mcast_count(&self) -> usize {
        lock!(self.data).imported_mcast.len()
    }

    /// Underlay groups imported via `nexthop`, deduplicated.
    pub fn mcast_groups_for_nexthop(
        &self,
        nexthop: Ipv6Addr,
    ) -> HashSet<Ipv6Addr> {
        // Filter under the lock so the caller never clones the full imported
        // set just to keep one peer's routes. Non-destructive analog of the
        // next-hop filter in `remove_nexthop_routes`.
        lock!(self.data)
            .imported_mcast
            .iter()
            .filter(|route| route.nexthop == nexthop)
            .map(|route| route.origin.underlay_group.ip())
            .collect()
    }

    pub fn import(&self, r: &HashSet<Route>) {
        lock!(self.data).imported.extend(r.clone());
    }

    pub fn import_tunnel(&self, r: &HashSet<TunnelRoute>) {
        lock!(self.data).imported_tunnel.extend(r.clone());
    }

    pub fn delete_import(&self, r: &HashSet<Route>) {
        let imported = &mut lock!(self.data).imported;
        for x in r {
            imported.remove(x);
        }
    }

    pub fn delete_import_tunnel(&self, r: &HashSet<TunnelRoute>) {
        let imported = &mut lock!(self.data).imported_tunnel;
        for x in r {
            imported.remove(x);
        }
    }

    /// Atomically import and delete multicast routes under a single lock,
    /// returning the effective [`McastRibDelta`] against the state before
    /// any modification.
    ///
    /// The single lock avoids a TOCTOU race where concurrent modifications
    /// between separate lock acquisitions could produce an incorrect delta.
    /// Callers that redistribute the update also need post-modification
    /// reachability and use
    /// [`Db::update_imported_mcast_with_reachability`] instead.
    pub fn update_imported_mcast(
        &self,
        import: &HashSet<MulticastRoute>,
        remove: &HashSet<MulticastRoute>,
    ) -> McastRibDelta {
        Self::apply_imported_mcast(&mut lock!(self.data), import, remove)
    }

    /// [`Db::update_imported_mcast`] variant that also captures a
    /// [`MulticastReachability`] snapshot of post-modification reachability.
    ///
    /// The imported set is captured under the same lock as the modification,
    /// so downstream withdrawal reconciliation cannot observe imported state
    /// older than the modification that produced it. Callers that do not
    /// redistribute have no reconciliation to feed and skip this variant's
    /// imported-set clone and persistent origin read.
    pub fn update_imported_mcast_with_reachability(
        &self,
        import: &HashSet<MulticastRoute>,
        remove: &HashSet<MulticastRoute>,
    ) -> (McastRibDelta, MulticastReachability) {
        let (delta, imported) = {
            let mut data = lock!(self.data);
            let delta = Self::apply_imported_mcast(&mut data, import, remove);
            (delta, data.imported_mcast.clone())
        };

        // Persistent origins are not touched by this method, so reading them
        // outside the lock still yields a post-modification snapshot. The
        // added tree scan is acceptable, sled caches the tree and it stays
        // small.
        (delta, self.reachability_snapshot(imported))
    }

    /// Apply `import` and `remove` to the imported multicast set under the
    /// caller-held lock, returning the effective delta.
    fn apply_imported_mcast(
        data: &mut DbData,
        import: &HashSet<MulticastRoute>,
        remove: &HashSet<MulticastRoute>,
    ) -> McastRibDelta {
        let before = data.imported_mcast.clone();
        // Route identity excludes the path, so `insert` would keep a stale
        // path on re-import. `replace` lets the newest path win.
        for x in import {
            data.imported_mcast.replace(x.clone());
        }

        for x in remove {
            data.imported_mcast.remove(x);
        }

        let added = data.imported_mcast.difference(&before).cloned().collect();
        let removed =
            before.difference(&data.imported_mcast).cloned().collect();
        McastRibDelta { added, removed }
    }

    pub fn originate(&self, prefixes: &HashSet<Ipv6Net>) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(ORIGINATE)?;
        for p in prefixes {
            tree.insert(p.db_key(), "")?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn originate_tunnel(
        &self,
        origins: &HashSet<TunnelOrigin>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(TUNNEL_ORIGINATE)?;
        for o in origins {
            let entry = serde_json::to_string(o)?;
            tree.insert(entry.as_str(), "")?;
        }
        tree.flush()?;
        Ok(())
    }

    /// Persist multicast origins for advertisement to peers.
    pub fn originate_mcast(
        &self,
        origins: &HashSet<MulticastOrigin>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(MCAST_ORIGINATE)?;
        for o in origins {
            // Key by the metric-excluded identity, storing the full origin as
            // the value. `MulticastOrigin` equality ignores `metric`, so keying
            // by identity lets a re-origination with a changed metric overwrite
            // the stored entry instead of leaving a stale one under the old
            // metric.
            tree.insert(
                o.identity_key()?.as_str(),
                serde_json::to_string(o)?.as_str(),
            )?;
        }
        tree.flush()?;
        Ok(())
    }

    /// Scan a persistent origin tree with `parse`, skipping entries that
    /// fail to read or parse. `kind` names the entry kind for log context.
    fn scan_origin_tree<T>(
        &self,
        tree: &str,
        kind: &str,
        parse: impl Fn(&[u8], &[u8]) -> Result<T, Error>,
    ) -> Result<HashSet<T>, Error>
    where
        T: Eq + std::hash::Hash,
    {
        let tree = self.persistent_data.open_tree(tree)?;
        let result = tree
            .iter()
            .filter_map(|item| {
                let (key, value) = match item {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error fetching ddm {kind} entry: {e}"
                        );
                        return None;
                    }
                };
                match parse(key.as_ref(), value.as_ref()) {
                    Ok(item) => Some(item),
                    Err(e) => {
                        error!(self.log, "db: error parsing ddm {kind}: {e}");
                        None
                    }
                }
            })
            .collect();
        Ok(result)
    }

    pub fn originated(&self) -> Result<HashSet<Ipv6Net>, Error> {
        self.scan_origin_tree(ORIGINATE, "origin prefix", |key, _value| {
            Ipv6Net::from_db_key(key).map_err(|e| Error::DbKey(e.to_string()))
        })
    }

    pub fn originated_count(&self) -> Result<usize, Error> {
        Ok(self.originated()?.len())
    }

    pub fn originated_tunnel(&self) -> Result<HashSet<TunnelOrigin>, Error> {
        self.scan_origin_tree(TUNNEL_ORIGINATE, "tunnel origin", |key, _v| {
            Ok(serde_json::from_slice(key)?)
        })
    }

    pub fn originated_tunnel_count(&self) -> Result<usize, Error> {
        Ok(self.originated_tunnel()?.len())
    }

    /// Multicast origins originated locally.
    ///
    /// Each origin is keyed by its metric-excluded identity and stored as the
    /// value, so the current metric is read back from the value rather than the
    /// key.
    ///
    /// This iterates the tree directly rather than going through
    /// [`Db::scan_origin_tree`], which skips entries that fail to read or
    /// parse. Withdrawal reconciliation treats the result as the complete
    /// origin set, so a silently skipped entry could become a false final
    /// withdrawal. Here any per-entry failure fails the whole read. The
    /// caller surfaces that by degrading the snapshot's origin set, and
    /// reconciliation then drops the withdrawal rather than treating the
    /// missing origins as truly gone.
    ///
    /// # Errors
    ///
    /// Returns an error if the tree cannot be opened or any entry fails to
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

    pub fn originated_mcast_count(&self) -> Result<usize, Error> {
        Ok(self.originated_mcast()?.len())
    }

    pub fn withdraw(&self, prefixes: &HashSet<Ipv6Net>) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(ORIGINATE)?;
        for p in prefixes {
            tree.remove(p.db_key())?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn withdraw_tunnel(
        &self,
        origins: &HashSet<TunnelOrigin>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(TUNNEL_ORIGINATE)?;
        for o in origins {
            let entry = serde_json::to_string(o)?;
            tree.remove(entry.as_str())?;
        }
        tree.flush()?;
        Ok(())
    }

    /// Remove persisted multicast origins.
    ///
    /// State machines revalidate reachability at processing time via
    /// [`Db::multicast_reachability`] rather than from a snapshot captured
    /// here.
    ///
    /// The modification lands before any event is enqueued, so the
    /// processing-time snapshot is guaranteed to reflect this removal.
    pub fn withdraw_mcast(
        &self,
        origins: &HashSet<MulticastOrigin>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(MCAST_ORIGINATE)?;
        for o in origins {
            // Remove by identity so a withdraw matches regardless of the metric
            // the origin was advertised with (e.g. the CLI's default metric).
            tree.remove(o.identity_key()?.as_str())?;
        }
        tree.flush()?;
        Ok(())
    }

    /// Capture current multicast reachability for processing-time
    /// revalidation. An event is enqueued only after its modification completes,
    /// so a snapshot taken while processing that event is post-modification. It
    /// also observes any later modification, which lets a state machine avoid
    /// acting on reachability that has since been restored.
    pub fn multicast_reachability(&self) -> MulticastReachability {
        // Same lock-ordering discipline as `update_imported_mcast`: clone
        // `imported_mcast` under the data lock and read persistent origins
        // after dropping it, since the two sources are not co-modified.
        let imported = lock!(self.data).imported_mcast.clone();
        self.reachability_snapshot(imported)
    }

    pub fn remove_nexthop_routes(
        &self,
        nexthop: Ipv6Addr,
    ) -> RemovedNexthopRoutes {
        let (removed, tnl_removed, mcast_removed, imported_mcast) = {
            let mut data = lock!(self.data);
            let mut removed = HashSet::new();
            for x in &data.imported {
                if x.nexthop == nexthop {
                    removed.insert(x.clone());
                }
            }
            for x in &removed {
                data.imported.remove(x);
            }

            let mut tnl_removed = HashSet::new();
            for x in &data.imported_tunnel {
                if x.nexthop == nexthop {
                    tnl_removed.insert(*x);
                }
            }
            for x in &tnl_removed {
                data.imported_tunnel.remove(x);
            }

            let mut mcast_removed = HashSet::new();
            for x in &data.imported_mcast {
                if x.nexthop == nexthop {
                    mcast_removed.insert(x.clone());
                }
            }
            for x in &mcast_removed {
                data.imported_mcast.remove(x);
            }

            let imported_mcast = data.imported_mcast.clone();
            (removed, tnl_removed, mcast_removed, imported_mcast)
        };

        // Persistent origins are not touched by this method, so reading them
        // outside the lock still yields a post-modification snapshot.
        RemovedNexthopRoutes {
            underlay: removed,
            tunnel: tnl_removed,
            multicast: mcast_removed,
            mcast_reachability: self.reachability_snapshot(imported_mcast),
        }
    }

    /// Build a post-modification reachability snapshot around an imported
    /// set captured under the data lock, taking ownership so no further
    /// clone is needed. A persistent origin read failure degrades
    /// `originated` to the empty set and marks the snapshot, so consumers
    /// know the empty origin set is a read failure rather than a real
    /// absence.
    fn reachability_snapshot(
        &self,
        imported: HashSet<MulticastRoute>,
    ) -> MulticastReachability {
        match self.originated_mcast() {
            Ok(originated) => MulticastReachability {
                imported,
                originated,
                origins_degraded: false,
            },
            Err(e) => {
                error!(self.log, "read remaining multicast origins: {e}");
                MulticastReachability {
                    imported,
                    originated: HashSet::new(),
                    origins_degraded: true,
                }
            }
        }
    }

    pub fn routes_by_vector(
        &self,
        dst: Ipv6Net,
        nexthop: Ipv6Addr,
    ) -> Vec<Route> {
        let data = lock!(self.data);
        let mut result = Vec::new();
        for x in &data.imported {
            if x.destination == dst && x.nexthop == nexthop {
                result.push(x.clone());
            }
        }
        result
    }
}

/// Routes withdrawn for a next hop, grouped by route family.
pub struct RemovedNexthopRoutes {
    pub underlay: HashSet<Route>,
    pub tunnel: HashSet<TunnelRoute>,
    pub multicast: HashSet<MulticastRoute>,
    /// Post-modification multicast reachability snapshot captured under the same
    /// removal that produced `multicast`. Downstream reconciliation reads
    /// viable paths from here rather than reading the database again.
    pub mcast_reachability: MulticastReachability,
}

/// A snapshot of multicast reachability: imported routes and local origins.
///
/// Only `Db` methods construct this. A snapshot is either captured by the
/// modification that produced a set of withdrawals or read at processing time
/// via [`Db::multicast_reachability`]. In both cases, it describes state no
/// older than that modification, since the event that triggers a
/// processing-time read is enqueued only after the modification completes.
#[derive(Debug, Clone)]
pub struct MulticastReachability {
    imported: HashSet<MulticastRoute>,
    originated: HashSet<MulticastOrigin>,
    origins_degraded: bool,
}

impl MulticastReachability {
    pub fn imported(&self) -> &HashSet<MulticastRoute> {
        &self.imported
    }

    pub fn originated(&self) -> &HashSet<MulticastOrigin> {
        &self.originated
    }

    /// Whether the persistent origin read failed, degrading `originated` to
    /// the empty set. A degraded snapshot cannot distinguish a withdrawn
    /// origin from an unread one.
    pub fn origins_degraded(&self) -> bool {
        self.origins_degraded
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct Route {
    pub destination: Ipv6Net,
    pub nexthop: Ipv6Addr,
    pub ifname: String,
    pub path: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum EffectiveTunnelRouteSet {
    /// The routes in the contained set are active with priority greater than
    /// zero.
    Active(HashSet<TunnelRoute>),

    /// The routes in the contained set are inactive with a priority equal to
    /// zero.
    Inactive(HashSet<TunnelRoute>),
}

impl EffectiveTunnelRouteSet {
    fn values(&self) -> &HashSet<TunnelRoute> {
        match self {
            EffectiveTunnelRouteSet::Active(s) => s,
            EffectiveTunnelRouteSet::Inactive(s) => s,
        }
    }
}

//NOTE this is the same algorithm as rdb::Db::effective_route set but for
//     tunnel routes. We need to apply the same logic here, but because
//     the server routers get tunnel endpoint information from a disparate
//     set of transit routers that are not in cahoots, we need to calculate
//     the effective set for all the tunneled routes for all endpoints.
pub fn effective_route_set(
    full: &HashSet<TunnelRoute>,
) -> HashSet<TunnelRoute> {
    let mut sets = HashMap::<IpNet, EffectiveTunnelRouteSet>::new();
    for x in full.iter() {
        match sets.get_mut(&x.origin.overlay_prefix) {
            Some(set) => {
                if x.origin.metric > 0 {
                    match set {
                        EffectiveTunnelRouteSet::Active(s) => {
                            s.insert(*x);
                        }
                        EffectiveTunnelRouteSet::Inactive(_) => {
                            let mut value = HashSet::new();
                            value.insert(*x);
                            sets.insert(
                                x.origin.overlay_prefix,
                                EffectiveTunnelRouteSet::Active(value),
                            );
                        }
                    }
                } else {
                    match set {
                        EffectiveTunnelRouteSet::Active(_) => {
                            //Nothing to do here, the active set takes priority
                        }
                        EffectiveTunnelRouteSet::Inactive(s) => {
                            s.insert(*x);
                        }
                    }
                }
            }
            None => {
                let mut value = HashSet::new();
                value.insert(*x);
                if x.origin.metric > 0 {
                    sets.insert(
                        x.origin.overlay_prefix,
                        EffectiveTunnelRouteSet::Active(value),
                    );
                } else {
                    sets.insert(
                        x.origin.overlay_prefix,
                        EffectiveTunnelRouteSet::Inactive(value),
                    );
                }
            }
        }
    }
    let mut result = HashSet::new();
    for xs in sets.values() {
        for x in xs.values() {
            let mut v = *x;
            //NOTE the point of this function is to determine an effective set
            //     of routes based on the metric value to send to a data plane.
            //     So from the data plane's perspective all routes returned
            //     from this function are equally viable. Thus, we set the
            //     metric to zero so there are not hash function differences
            //     on subsequent operations involving the returned set.
            v.origin.metric = 0;
            result.insert(v);
        }
    }
    result
}

trait DbKey: Sized {
    fn db_key(&self) -> Vec<u8>;
    fn from_db_key(v: &[u8]) -> Result<Self, Error>;
}

impl DbKey for Ipv6Net {
    fn db_key(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = self.addr().octets().into();
        buf.push(self.width());
        buf
    }

    fn from_db_key(v: &[u8]) -> Result<Self, Error> {
        if v.len() < 17 {
            Err(Error::DbKey(format!(
                "buffer too short for prefix 6 key {} < 17",
                v.len()
            )))
        } else {
            Self::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&v[..16]).unwrap()),
                v[16],
            )
            .map_err(|e| Error::DbKey(e.to_string()))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    #[test]
    fn test_effective_tunnel_route_set() {
        let mut before = HashSet::<TunnelRoute>::new();
        before.insert(TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "0.0.0.0/0".parse().unwrap(),
                boundary_addr: "fd00:a::1".parse().unwrap(),
                vni: 99,
                metric: 0,
            },
            nexthop: "fe80:a::1".parse().unwrap(),
        });
        before.insert(TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "0.0.0.0/0".parse().unwrap(),
                boundary_addr: "fd00:b::1".parse().unwrap(),
                vni: 99,
                metric: 0,
            },
            nexthop: "fe80:b::1".parse().unwrap(),
        });
        let effective_before = effective_route_set(&before);

        let mut after = HashSet::<TunnelRoute>::new();
        after.insert(TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "0.0.0.0/0".parse().unwrap(),
                boundary_addr: "fd00:a::1".parse().unwrap(),
                vni: 99,
                metric: 0,
            },
            nexthop: "fe80:a::1".parse().unwrap(),
        });
        after.insert(TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "0.0.0.0/0".parse().unwrap(),
                boundary_addr: "fd00:b::1".parse().unwrap(),
                vni: 99,
                metric: 100,
            },
            nexthop: "fe80:b::1".parse().unwrap(),
        });
        let effective_after = effective_route_set(&after);

        let to_add: HashSet<TunnelRoute> = effective_after
            .difference(&effective_before)
            .copied()
            .collect();

        let expected_add = HashSet::<TunnelRoute>::new();
        assert_eq!(to_add, expected_add);

        let to_del: HashSet<TunnelRoute> = effective_before
            .difference(&effective_after)
            .copied()
            .collect();

        let mut expected_del = HashSet::<TunnelRoute>::new();
        expected_del.insert(TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "0.0.0.0/0".parse().unwrap(),
                boundary_addr: "fd00:a::1".parse().unwrap(),
                vni: 99,
                metric: 0,
            },
            nexthop: "fe80:a::1".parse().unwrap(),
        });
        assert_eq!(to_del, expected_del);
    }
}
