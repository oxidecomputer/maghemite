// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_api_types::net::TunnelOrigin;
use ddm_protocol::v3::{self, PathVector};
use mg_common::lock;
use oxnet::{IpNet, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{Logger, error};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};

/// The handle used to open a persistent key-value tree for originated
/// prefixes.
const ORIGINATE: &str = "originate";

/// The handle used to open a persistent key-value tree for originated
/// tunnel endpoints.
const TUNNEL_ORIGINATE: &str = "tunnel_originate";

/// The handle used to open a persistent key-value tree for the originated
/// rack prefix. It holds at most one prefix.
const RACK_PREFIX: &str = "rack_prefix";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("datastore error")]
    DataStore(#[from] sled::Error),

    #[error("db key error {0}")]
    DbKey(String),

    #[error("db value error {0}")]
    DbValue(String),

    #[error("serialization error")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct Db {
    data: Arc<Mutex<DbData>>,
    persistent_data: sled::Db,
    log: Logger,
}

#[derive(Default, Clone)]
pub struct DbData {
    pub imported: HashSet<Route>,
    pub imported_tunnel: HashSet<TunnelRoute>,
    pub external_peers: BTreeSet<String>,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Db>()
};

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

    /// Imported routes for which `filter` returns true.
    fn imported_matching(
        &self,
        filter: impl Fn(&Route) -> bool,
    ) -> HashSet<Route> {
        lock!(self.data)
            .imported
            .iter()
            .filter(|r| filter(r))
            .cloned()
            .collect()
    }

    /// Imported routes learned from the peer at `nexthop`.
    pub fn imported_from(&self, nexthop: Ipv6Addr) -> HashSet<Route> {
        self.imported_matching(|r| r.nexthop == nexthop)
    }

    pub fn imported_tunnel(&self) -> HashSet<TunnelRoute> {
        lock!(self.data).imported_tunnel.clone()
    }

    /// Imported tunnel routes learned from the peer at `nexthop`.
    pub fn imported_tunnel_from(
        &self,
        nexthop: Ipv6Addr,
    ) -> HashSet<TunnelRoute> {
        lock!(self.data)
            .imported_tunnel
            .iter()
            .filter(|r| r.nexthop == nexthop)
            .cloned()
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

    /// Persist `prefixes` as originated.
    pub fn originate(&self, prefixes: &HashSet<Ipv6Net>) -> Result<(), Error> {
        self.update_persisted(ORIGINATE, prefixes, [])
    }

    /// Persist `origins` as originated.
    pub fn originate_tunnel(
        &self,
        origins: &HashSet<TunnelOrigin>,
    ) -> Result<(), Error> {
        self.update_persisted(TUNNEL_ORIGINATE, origins, [])
    }

    pub fn originated(&self) -> Result<HashSet<Ipv6Net>, Error> {
        self.persisted(ORIGINATE)
    }

    pub fn originated_count(&self) -> Result<usize, Error> {
        Ok(self.originated()?.len())
    }

    pub fn originated_tunnel(&self) -> Result<HashSet<TunnelOrigin>, Error> {
        self.persisted(TUNNEL_ORIGINATE)
    }

    pub fn originated_tunnel_count(&self) -> Result<usize, Error> {
        Ok(self.originated_tunnel()?.len())
    }

    /// Stop persisting `prefixes` as originated.
    pub fn withdraw(&self, prefixes: &HashSet<Ipv6Net>) -> Result<(), Error> {
        self.update_persisted(ORIGINATE, [], prefixes)
    }

    /// Stop persisting `origins` as originated.
    pub fn withdraw_tunnel(
        &self,
        origins: &HashSet<TunnelOrigin>,
    ) -> Result<(), Error> {
        self.update_persisted(TUNNEL_ORIGINATE, [], origins)
    }

    /// The originated rack prefix, if one is set.
    pub fn rack_prefix(&self) -> Result<Option<Ipv6Net>, Error> {
        Ok(self.persisted(RACK_PREFIX)?.into_iter().next())
    }

    /// Set or clear the originated rack prefix, replacing any it holds.
    pub fn set_rack_prefix(
        &self,
        prefix: Option<Ipv6Net>,
    ) -> Result<(), Error> {
        let held: HashSet<Ipv6Net> = self.persisted(RACK_PREFIX)?;
        self.update_persisted(RACK_PREFIX, &prefix, &held)
    }

    /// The set of values persisted in `tree`. Entries that cannot be read
    /// are logged and skipped.
    fn persisted<K: DbKey>(&self, tree: &str) -> Result<HashSet<K>, Error> {
        let result = self
            .persistent_data
            .open_tree(tree)?
            .iter()
            .keys()
            .filter_map(|key| {
                match key.map_err(Error::from).and_then(|k| K::from_db_key(&k))
                {
                    Ok(value) => Some(value),
                    Err(e) => {
                        error!(self.log, "db: skipping {tree} entry: {e}");
                        None
                    }
                }
            })
            .collect();
        Ok(result)
    }

    /// Remove `remove` from and add `insert` to the set of values persisted
    /// in `tree`, in one atomic batch, and flush it to disk.
    fn update_persisted<'a, K: DbKey + 'a>(
        &self,
        tree: &str,
        insert: impl IntoIterator<Item = &'a K>,
        remove: impl IntoIterator<Item = &'a K>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(tree)?;
        let mut batch = sled::Batch::default();
        for k in remove {
            batch.remove(k.db_key()?);
        }
        for k in insert {
            batch.insert(k.db_key()?, "");
        }
        tree.apply_batch(batch)?;
        tree.flush()?;
        Ok(())
    }

    pub fn remove_nexthop_routes(
        &self,
        nexthop: Ipv6Addr,
    ) -> (HashSet<Route>, HashSet<TunnelRoute>) {
        let mut data = lock!(self.data);
        // Routes are generally held in sets to prevent duplication and provide
        // handy set-algebra operations.
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
                tnl_removed.insert(x.clone());
            }
        }
        for x in &tnl_removed {
            data.imported_tunnel.remove(x);
        }
        (removed, tnl_removed)
    }

    pub fn routes_by_vector(
        &self,
        dst: Ipv6Net,
        nexthop: Ipv6Addr,
    ) -> HashSet<Route> {
        self.imported_matching(|r| r.destination == dst && r.nexthop == nexthop)
    }

    pub fn get_external_peers(&self) -> BTreeSet<String> {
        lock!(self.data).external_peers.clone()
    }

    pub fn set_external_peers(&mut self, value: BTreeSet<String>) {
        lock!(self.data).external_peers = value;
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

impl From<Route> for PathVector {
    fn from(val: Route) -> Self {
        Self {
            destination: val.destination,
            path: val.path,
        }
    }
}

/// A tunnel route imported from a peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TunnelRoute {
    pub origin: TunnelOrigin,

    /// The routers the route was advertised through, starting with its
    /// originator and ending with the peer it was learned from.
    pub path: Vec<String>,

    // The nexthop is only used to associate the route with a peer allowing us
    // to remove the route if the peer expires. It does not influence what goes
    // into the underlaying underlay routing platform. Tunnel routes only
    // influence the state of the underlying encapsulation service.
    pub nexthop: Ipv6Addr,
}

impl TunnelRoute {
    /// The route `origin` as received from the peer at `nexthop`.
    pub fn received(origin: &v3::TunnelOrigin, nexthop: Ipv6Addr) -> Self {
        Self {
            origin: origin.into(),
            path: origin.path.clone(),
            nexthop,
        }
    }
}

/// An imported route as its peer advertised it.
impl From<TunnelRoute> for v3::TunnelOrigin {
    fn from(val: TunnelRoute) -> Self {
        val.origin.to_wire(val.path)
    }
}

impl From<TunnelRoute> for ddm_api_types::db::TunnelRoute {
    fn from(val: TunnelRoute) -> Self {
        let TunnelRoute {
            origin,
            path,
            nexthop,
        } = val;
        Self {
            origin,
            path,
            nexthop,
        }
    }
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
                            s.insert(x.clone());
                        }
                        EffectiveTunnelRouteSet::Inactive(_) => {
                            let mut value = HashSet::new();
                            value.insert(x.clone());
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
                            s.insert(x.clone());
                        }
                    }
                }
            }
            None => {
                let mut value = HashSet::new();
                value.insert(x.clone());
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
            let mut v = x.clone();
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

/// Tunnel forwarding entries to change after the imported tunnel table goes
/// from `before` to `after`.
pub struct TunnelForwardingChanges {
    pub add: HashSet<TunnelOrigin>,
    pub remove: HashSet<TunnelOrigin>,
}

/// Compare the effective tunnel routes of two imported tunnel tables by
/// origin. Tunnel forwarding entries carry no nexthop, so an origin that any
/// peer still provides must not be removed, and one that another peer already
/// provided need not be added.
pub fn tunnel_forwarding_changes(
    before: &HashSet<TunnelRoute>,
    after: &HashSet<TunnelRoute>,
) -> TunnelForwardingChanges {
    let before: HashSet<TunnelOrigin> = effective_route_set(before)
        .iter()
        .map(|r| r.origin)
        .collect();
    let after: HashSet<TunnelOrigin> = effective_route_set(after)
        .iter()
        .map(|r| r.origin)
        .collect();

    TunnelForwardingChanges {
        add: after.difference(&before).copied().collect(),
        remove: before.difference(&after).copied().collect(),
    }
}

/// A value stored as the key of an entry in a persistent tree, which holds a
/// set of such values.
trait DbKey: Sized + Eq + std::hash::Hash {
    fn db_key(&self) -> Result<Vec<u8>, Error>;
    fn from_db_key(v: &[u8]) -> Result<Self, Error>;
}

impl DbKey for Ipv6Net {
    fn db_key(&self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = self.addr().octets().into();
        buf.push(self.width());
        Ok(buf)
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

/// Tunnel origins are stored as their JSON text.
impl DbKey for TunnelOrigin {
    fn db_key(&self) -> Result<Vec<u8>, Error> {
        Ok(serde_json::to_vec(self)?)
    }

    fn from_db_key(v: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice(v)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    fn tunnel_route(boundary: &str, metric: u64, nexthop: &str) -> TunnelRoute {
        TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "0.0.0.0/0".parse().unwrap(),
                boundary_addr: boundary.parse().unwrap(),
                vni: 99,
                metric,
            },
            path: Vec::new(),
            nexthop: nexthop.parse().unwrap(),
        }
    }

    /// Check the boundary addresses added and removed when the imported
    /// tunnel table goes from `before` to `after`.
    fn assert_tunnel_changes(
        before: &[TunnelRoute],
        after: &[TunnelRoute],
        add: &[&str],
        remove: &[&str],
    ) {
        let addrs = |s: HashSet<TunnelOrigin>| -> BTreeSet<Ipv6Addr> {
            s.iter().map(|o| o.boundary_addr).collect()
        };
        let expected = |xs: &[&str]| -> BTreeSet<Ipv6Addr> {
            xs.iter().map(|x| x.parse().unwrap()).collect()
        };
        let c = tunnel_forwarding_changes(
            &before.iter().cloned().collect(),
            &after.iter().cloned().collect(),
        );
        assert_eq!(
            (addrs(c.add), addrs(c.remove)),
            (expected(add), expected(remove)),
        );
    }

    #[test]
    fn tunnel_forwarding_kept_while_another_peer_provides_origin() {
        let a = tunnel_route("fd00:a::1", 0, "fe80:a::1");
        let b = tunnel_route("fd00:a::1", 0, "fe80:b::1");
        assert_tunnel_changes(&[a, b.clone()], &[b], &[], &[]);
    }

    #[test]
    fn tunnel_forwarding_kept_while_another_path_provides_origin() {
        // One peer can advertise an origin along several paths.
        let mut a = tunnel_route("fd00:a::1", 0, "fe80:a::1");
        a.path = vec!["t0".to_string()];
        let mut b = a.clone();
        b.path = vec!["t1".to_string(), "t0".to_string()];
        assert_tunnel_changes(&[a, b.clone()], &[b], &[], &[]);
    }

    #[test]
    fn tunnel_forwarding_unchanged_when_another_peer_provides_installed_origin()
    {
        let a = tunnel_route("fd00:a::1", 0, "fe80:a::1");
        let b = tunnel_route("fd00:a::1", 0, "fe80:b::1");
        assert_tunnel_changes(
            std::slice::from_ref(&b),
            &[a, b.clone()],
            &[],
            &[],
        );
    }

    #[test]
    fn tunnel_forwarding_removed_with_last_peer_providing_origin() {
        let b = tunnel_route("fd00:a::1", 0, "fe80:b::1");
        let other = tunnel_route("fd00:b::1", 0, "fe80:b::1");
        assert_tunnel_changes(&[b.clone(), other], &[b], &[], &["fd00:b::1"]);
    }

    #[test]
    fn tunnel_forwarding_switches_to_inactive_origin_when_active_lost() {
        let active = tunnel_route("fd00:c::1", 100, "fe80:c::1");
        let inactive = tunnel_route("fd00:a::1", 0, "fe80:b::1");
        assert_tunnel_changes(
            &[active, inactive.clone()],
            &[inactive],
            &["fd00:a::1"],
            &["fd00:c::1"],
        );
    }

    #[test]
    fn tunnel_forwarding_unchanged_when_inactive_origin_withdrawn() {
        // The inactive origin was never installed, so nothing is removed.
        let active = tunnel_route("fd00:c::1", 100, "fe80:c::1");
        let inactive = tunnel_route("fd00:a::1", 0, "fe80:b::1");
        assert_tunnel_changes(&[active.clone(), inactive], &[active], &[], &[]);
    }

    #[test]
    fn tunnel_forwarding_ignores_differing_nonzero_metrics() {
        // Metrics only choose between active and inactive origins, so the
        // same TEP at different non-zero metrics is one forwarding entry.
        let a = tunnel_route("fd00:a::1", 100, "fe80:a::1");
        let b = tunnel_route("fd00:a::1", 5, "fe80:b::1");
        assert_tunnel_changes(&[a, b.clone()], &[b], &[], &[]);
    }

    #[test]
    fn tunnel_forwarding_unchanged_when_origin_becomes_active() {
        // The peer changes the origin's metric from 0 to non-zero. The OPTE
        // entry has no metric, so adding the new origin and removing the old
        // one would clear the entry that was just set.
        let inactive = tunnel_route("fd00:a::1", 0, "fe80:a::1");
        let active = tunnel_route("fd00:a::1", 100, "fe80:a::1");
        assert_tunnel_changes(&[inactive], &[active], &[], &[]);
    }

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
            path: Vec::new(),
            nexthop: "fe80:a::1".parse().unwrap(),
        });
        before.insert(TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "0.0.0.0/0".parse().unwrap(),
                boundary_addr: "fd00:b::1".parse().unwrap(),
                vni: 99,
                metric: 0,
            },
            path: Vec::new(),
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
            path: Vec::new(),
            nexthop: "fe80:a::1".parse().unwrap(),
        });
        after.insert(TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "0.0.0.0/0".parse().unwrap(),
                boundary_addr: "fd00:b::1".parse().unwrap(),
                vni: 99,
                metric: 100,
            },
            path: Vec::new(),
            nexthop: "fe80:b::1".parse().unwrap(),
        });
        let effective_after = effective_route_set(&after);

        let to_add: HashSet<TunnelRoute> = effective_after
            .difference(&effective_before)
            .cloned()
            .collect();

        let expected_add = HashSet::<TunnelRoute>::new();
        assert_eq!(to_add, expected_add);

        let to_del: HashSet<TunnelRoute> = effective_before
            .difference(&effective_after)
            .cloned()
            .collect();

        let mut expected_del = HashSet::<TunnelRoute>::new();
        expected_del.insert(TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "0.0.0.0/0".parse().unwrap(),
                boundary_addr: "fd00:a::1".parse().unwrap(),
                vni: 99,
                metric: 0,
            },
            path: Vec::new(),
            nexthop: "fe80:a::1".parse().unwrap(),
        });
        assert_eq!(to_del, expected_del);
    }

    // Originations persist across upgrades, so their keys must keep the
    // encoding earlier releases wrote: an Ipv6Net as its address octets and
    // width, a tunnel origin as its JSON text.
    #[test]
    fn originations_keep_their_on_disk_encoding() {
        let dir = std::env::temp_dir()
            .join(format!("ddm-originate-test-{}", std::process::id()));
        let db = Db::new(
            dir.to_str().unwrap(),
            Logger::root(slog::Discard, slog::o!()),
        )
        .unwrap();
        let prefix: Ipv6Net = "fd00:1::/64".parse().unwrap();
        let origin = TunnelOrigin {
            overlay_prefix: "203.0.113.0/24".parse().unwrap(),
            boundary_addr: "fd00:1701::1".parse().unwrap(),
            vni: 47,
            metric: 10,
        };
        let mut prefix_key = prefix.addr().octets().to_vec();
        prefix_key.push(64);
        let origin_key = serde_json::to_string(&origin).unwrap();

        // Read what an earlier release wrote.
        let underlay = db.persistent_data.open_tree(ORIGINATE).unwrap();
        let tunnel = db.persistent_data.open_tree(TUNNEL_ORIGINATE).unwrap();
        underlay.insert(&prefix_key, "").unwrap();
        tunnel.insert(origin_key.as_str(), "").unwrap();
        assert_eq!(db.originated().unwrap(), HashSet::from([prefix]));
        assert_eq!(db.originated_tunnel().unwrap(), HashSet::from([origin]));

        // Write it the same way.
        db.withdraw(&HashSet::from([prefix])).unwrap();
        db.withdraw_tunnel(&HashSet::from([origin])).unwrap();
        assert!(underlay.is_empty() && tunnel.is_empty());
        db.originate(&HashSet::from([prefix])).unwrap();
        db.originate_tunnel(&HashSet::from([origin])).unwrap();
        let keys = |t: &sled::Tree| -> Vec<Vec<u8>> {
            t.iter().keys().map(|k| k.unwrap().to_vec()).collect()
        };
        assert_eq!(keys(&underlay), vec![prefix_key]);
        assert_eq!(keys(&tunnel), vec![origin_key.into_bytes()]);

        drop(db);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rack_prefix_is_replaced_cleared_and_persisted() {
        let dir = std::env::temp_dir()
            .join(format!("ddm-rack-prefix-test-{}", std::process::id()));
        let path = dir.to_str().unwrap();
        let open =
            || Db::new(path, Logger::root(slog::Discard, slog::o!())).unwrap();
        let a: Ipv6Net = "fd00:a::/56".parse().unwrap();
        let b: Ipv6Net = "fd00:b::/48".parse().unwrap();

        let db = open();
        assert_eq!(db.rack_prefix().unwrap(), None);
        db.set_rack_prefix(Some(a)).unwrap();
        db.set_rack_prefix(Some(b)).unwrap();
        drop(db);

        // b replaced a rather than joining it.
        let db = open();
        assert_eq!(
            db.persisted::<Ipv6Net>(RACK_PREFIX).unwrap(),
            HashSet::from([b])
        );
        assert_eq!(db.rack_prefix().unwrap(), Some(b));
        db.set_rack_prefix(None).unwrap();
        assert_eq!(db.rack_prefix().unwrap(), None);
        drop(db);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
