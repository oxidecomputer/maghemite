// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_api_types::db::TunnelRoute;
use ddm_api_types::net::{RackPrefixInfo, TunnelOrigin};
use ddm_protocol::v3::{PathVector, RackPrefix};
use mg_common::lock;
use oxnet::{IpNet, Ipv6Net, SocketAddrV6Json};
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

/// The handle used to open a persistent key-value tree for originated
/// rack prefixes.
const RACK_ORIGINATE: &str = "rack_originate";

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

#[derive(Default, Clone)]
pub struct DbData {
    pub imported: HashSet<Route>,
    pub imported_tunnel: HashSet<TunnelRoute>,
    pub imported_rack: HashSet<RackRoute>,
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

    /// Routes in the imported table chosen by `table` for which `filter`
    /// returns true.
    fn imported_matching<T: Clone + Eq + std::hash::Hash>(
        &self,
        table: impl Fn(&DbData) -> &HashSet<T>,
        filter: impl Fn(&T) -> bool,
    ) -> HashSet<T> {
        table(&lock!(self.data))
            .iter()
            .filter(|r| filter(r))
            .cloned()
            .collect()
    }

    /// Imported routes learned from the peer at `nexthop`.
    pub fn imported_from(&self, nexthop: Ipv6Addr) -> HashSet<Route> {
        self.imported_matching(|d| &d.imported, |r| r.nexthop == nexthop)
    }

    pub fn imported_tunnel(&self) -> HashSet<TunnelRoute> {
        lock!(self.data).imported_tunnel.clone()
    }

    /// Imported tunnel routes learned from the peer at `nexthop`.
    pub fn imported_tunnel_from(
        &self,
        nexthop: Ipv6Addr,
    ) -> HashSet<TunnelRoute> {
        self.imported_matching(|d| &d.imported_tunnel, |r| r.nexthop == nexthop)
    }

    pub fn imported_rack(&self) -> HashSet<RackRoute> {
        lock!(self.data).imported_rack.clone()
    }

    /// Imported rack routes learned from the peer at `nexthop`.
    pub fn imported_rack_from(&self, nexthop: Ipv6Addr) -> HashSet<RackRoute> {
        self.imported_matching(
            |d| &d.imported_rack,
            |r| r.route.nexthop == nexthop,
        )
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

    pub fn import_rack(&self, r: &HashSet<RackRoute>) {
        lock!(self.data).imported_rack.extend(r.iter().cloned());
    }

    pub fn delete_import_rack(&self, r: &HashSet<RackRoute>) {
        let imported = &mut lock!(self.data).imported_rack;
        for x in r {
            imported.remove(x);
        }
    }

    /// Store `(prefix, value)` entries in `tree`, keyed by prefix. Returns
    /// the previous value of each entry whose value changed.
    fn originate_prefix<V: AsRef<[u8]>>(
        &self,
        entries: impl IntoIterator<Item = (Ipv6Net, V)>,
        tree: &str,
    ) -> Result<Vec<(Ipv6Net, sled::IVec)>, Error> {
        let tree = self.persistent_data.open_tree(tree)?;
        let mut replaced = Vec::new();
        for (p, v) in entries {
            if let Some(old) = tree.insert(p.db_key(), v.as_ref())?
                && old.as_ref() != v.as_ref()
            {
                replaced.push((p, old));
            }
        }
        tree.flush()?;
        Ok(replaced)
    }

    pub fn originate(&self, prefixes: &HashSet<Ipv6Net>) -> Result<(), Error> {
        self.originate_prefix(prefixes.iter().map(|p| (*p, "")), ORIGINATE)?;
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

    /// Originate rack prefixes. Entries are keyed by prefix, so originating a
    /// prefix again replaces its info. Returns the previous info of each
    /// prefix whose info changed.
    pub fn originate_rack_prefix(
        &self,
        prefixes: &HashMap<Ipv6Net, RackPrefixInfo>,
    ) -> Result<HashMap<Ipv6Net, RackPrefixInfo>, Error> {
        let entries = prefixes
            .iter()
            .map(|(prefix, info)| Ok((*prefix, serde_json::to_vec(info)?)))
            .collect::<Result<Vec<_>, Error>>()?;
        let replaced = self.originate_prefix(entries, RACK_ORIGINATE)?;
        Ok(self.decode_rack_prefix_info(replaced))
    }

    /// The `(prefix, value)` entries stored in `tree`. Entries that cannot be
    /// read are logged and skipped.
    fn originated_prefix(
        &self,
        tree_name: &str,
    ) -> Result<Vec<(Ipv6Net, sled::IVec)>, Error> {
        let tree = self.persistent_data.open_tree(tree_name)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, value) = match item {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error ddm {tree_name} prefix: {e}"
                        );
                        return None;
                    }
                };
                Some(match Ipv6Net::from_db_key(&key) {
                    Ok(item) => (item, value),
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error parsing ddm {tree_name} entry value: {e}"
                        );
                        return None;
                    }
                })
            })
            .collect();
        Ok(result)
    }

    pub fn originated(&self) -> Result<HashSet<Ipv6Net>, Error> {
        Ok(self
            .originated_prefix(ORIGINATE)?
            .into_iter()
            .map(|(p, _)| p)
            .collect())
    }

    pub fn originated_count(&self) -> Result<usize, Error> {
        Ok(self.originated()?.len())
    }

    pub fn originated_tunnel(&self) -> Result<HashSet<TunnelOrigin>, Error> {
        let tree = self.persistent_data.open_tree(TUNNEL_ORIGINATE)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, _value) = match item {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error fetching ddm tunnel origin entry: {e}"
                        );
                        return None;
                    }
                };
                let value = String::from_utf8_lossy(&key);
                let value: TunnelOrigin = match serde_json::from_str(&value) {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error parsing ddm tunnel origin: {e}"
                        );
                        return None;
                    }
                };
                Some(value)
            })
            .collect();
        Ok(result)
    }

    pub fn originated_tunnel_count(&self) -> Result<usize, Error> {
        Ok(self.originated_tunnel()?.len())
    }

    pub fn originated_rack_prefix(
        &self,
    ) -> Result<HashMap<Ipv6Net, RackPrefixInfo>, Error> {
        let entries = self.originated_prefix(RACK_ORIGINATE)?;
        Ok(self.decode_rack_prefix_info(entries))
    }

    /// Decode stored rack prefix info. Entries that cannot be decoded are
    /// logged and skipped.
    fn decode_rack_prefix_info(
        &self,
        entries: Vec<(Ipv6Net, sled::IVec)>,
    ) -> HashMap<Ipv6Net, RackPrefixInfo> {
        entries
            .into_iter()
            .filter_map(|(prefix, value)| match serde_json::from_slice(&value) {
                Ok(info) => Some((prefix, info)),
                Err(e) => {
                    error!(
                        self.log,
                        "db: error parsing info for rack prefix {prefix}: {e}"
                    );
                    None
                }
            })
            .collect()
    }

    pub fn originated_rack_prefix_count(&self) -> Result<usize, Error> {
        Ok(self.originated_rack_prefix()?.len())
    }

    /// Remove prefixes from `tree`. Returns the removed entries.
    fn withdraw_prefix(
        &self,
        prefixes: &HashSet<Ipv6Net>,
        tree: &str,
    ) -> Result<Vec<(Ipv6Net, sled::IVec)>, Error> {
        let tree = self.persistent_data.open_tree(tree)?;
        let mut removed = Vec::new();
        for p in prefixes {
            if let Some(old) = tree.remove(p.db_key())? {
                removed.push((*p, old));
            }
        }
        tree.flush()?;
        Ok(removed)
    }

    pub fn withdraw(&self, prefixes: &HashSet<Ipv6Net>) -> Result<(), Error> {
        self.withdraw_prefix(prefixes, ORIGINATE)?;
        Ok(())
    }

    /// Stop originating rack prefixes. Returns the info of each prefix that
    /// was originated.
    pub fn withdraw_rack_prefix(
        &self,
        prefixes: &HashSet<Ipv6Net>,
    ) -> Result<HashMap<Ipv6Net, RackPrefixInfo>, Error> {
        let removed = self.withdraw_prefix(prefixes, RACK_ORIGINATE)?;
        Ok(self.decode_rack_prefix_info(removed))
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

    pub fn remove_nexthop_routes(&self, nexthop: Ipv6Addr) -> RemovedRoutes {
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
                tnl_removed.insert(*x);
            }
        }
        for x in &tnl_removed {
            data.imported_tunnel.remove(x);
        }

        let rack_removed: HashSet<RackRoute> = data
            .imported_rack
            .iter()
            .filter(|x| x.route.nexthop == nexthop)
            .cloned()
            .collect();
        data.imported_rack.retain(|x| x.route.nexthop != nexthop);

        RemovedRoutes {
            underlay: removed,
            tunnel: tnl_removed,
            rack: rack_removed,
        }
    }

    /// Whether any underlay or rack route still uses the forwarding entry for
    /// `dst` via `nexthop`. Underlay and rack routes are separate in the RIB
    /// but install into the same underlay forwarding table, so the entry can
    /// only be removed once neither table has a route along that vector.
    pub fn vector_in_use(&self, dst: Ipv6Net, nexthop: Ipv6Addr) -> bool {
        let data = lock!(self.data);
        let on_vector =
            |r: &Route| r.destination == dst && r.nexthop == nexthop;
        data.imported.iter().any(on_vector)
            || data.imported_rack.iter().any(|r| on_vector(&r.route))
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

/// The rack prefix this router sends to peers for one of its originated rack
/// prefixes. Peers match rack routes by their full value, so announcements,
/// withdrawals and pull responses must all build it here.
pub fn announced_rack_prefix(
    destination: Ipv6Net,
    info: RackPrefixInfo,
    router_id: &str,
) -> RackPrefix {
    RackPrefix {
        path_vector: PathVector {
            destination,
            path: vec![router_id.to_string()],
        },
        multi_rack_join_addr: info.multi_rack_join_addr,
    }
}

/// The routes [`Db::remove_nexthop_routes`] removed, by RIB table.
#[derive(Debug, Default)]
pub struct RemovedRoutes {
    pub underlay: HashSet<Route>,
    pub tunnel: HashSet<TunnelRoute>,
    pub rack: HashSet<RackRoute>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct RackRoute {
    pub route: Route,
    pub multi_rack_join_addr: Option<SocketAddrV6Json>,
}

impl From<RackRoute> for RackPrefix {
    fn from(val: RackRoute) -> Self {
        // compilation barrier. if fields ever change, this destructure fails.
        let RackRoute {
            route,
            multi_rack_join_addr,
        } = val;

        Self {
            path_vector: route.into(),
            multi_rack_join_addr,
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

/// Tunnel forwarding entries to change after the imported tunnel table goes
/// from `before` to `after`.
pub struct TunnelForwardingChanges {
    pub add: HashSet<TunnelRoute>,
    pub remove: HashSet<TunnelRoute>,
}

/// Compare the effective tunnel routes of two imported tunnel tables by
/// origin. Tunnel forwarding entries carry no nexthop, so an origin that any
/// peer still provides must not be removed, and one that another peer already
/// provided need not be added.
pub fn tunnel_forwarding_changes(
    before: &HashSet<TunnelRoute>,
    after: &HashSet<TunnelRoute>,
) -> TunnelForwardingChanges {
    let by_origin = |s| -> HashMap<TunnelOrigin, TunnelRoute> {
        effective_route_set(s)
            .into_iter()
            .map(|r| (r.origin, r))
            .collect()
    };
    let (before, after) = (by_origin(before), by_origin(after));
    let missing_from =
        |a: &HashMap<TunnelOrigin, TunnelRoute>,
         b: &HashMap<TunnelOrigin, TunnelRoute>| {
            a.iter()
                .filter(|(o, _)| !b.contains_key(o))
                .map(|(_, r)| *r)
                .collect()
        };
    TunnelForwardingChanges {
        add: missing_from(&after, &before),
        remove: missing_from(&before, &after),
    }
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
    fn tunnel_forwarding_kept_while_another_peer_provides_origin() {
        let route = |boundary: &str, metric, nexthop: &str| TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "0.0.0.0/0".parse().unwrap(),
                boundary_addr: boundary.parse().unwrap(),
                vni: 99,
                metric,
            },
            nexthop: nexthop.parse().unwrap(),
        };
        let a = route("fd00:a::1", 0, "fe80:a::1");
        let b = route("fd00:a::1", 0, "fe80:b::1");
        let other = route("fd00:b::1", 0, "fe80:b::1");

        // Losing one of two peers providing an origin changes nothing, and
        // a second peer providing an installed origin adds nothing.
        let both: HashSet<_> = [a, b, other].into();
        let only_b: HashSet<_> = [b, other].into();
        let c = tunnel_forwarding_changes(&both, &only_b);
        assert_eq!(c.remove, HashSet::new());
        assert_eq!(c.add, HashSet::new());
        let c = tunnel_forwarding_changes(&only_b, &both);
        assert_eq!(c.add, HashSet::new());

        // Losing the last peer providing an origin removes it.
        let c = tunnel_forwarding_changes(&only_b, &[b].into());
        assert_eq!(
            c.remove
                .iter()
                .map(|r| r.origin.boundary_addr)
                .collect::<Vec<_>>(),
            vec!["fd00:b::1".parse::<Ipv6Addr>().unwrap()],
        );

        // An inactive origin becomes effective once the active one is gone.
        let active = route("fd00:c::1", 100, "fe80:c::1");
        let with_active: HashSet<_> = [active, b].into();
        let c = tunnel_forwarding_changes(&with_active, &[b].into());
        assert_eq!(
            c.add
                .iter()
                .map(|r| r.origin.boundary_addr)
                .collect::<Vec<_>>(),
            vec!["fd00:a::1".parse::<Ipv6Addr>().unwrap()],
        );
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

    #[test]
    fn test_rack_routes() {
        let path = std::env::temp_dir()
            .join(format!("ddm-test-rack-routes-{}", std::process::id()));
        // A failed earlier run may have left its database behind.
        let _ = std::fs::remove_dir_all(&path);
        let log = Logger::root(slog::Discard, slog::o!());
        let db = Db::new(path.to_str().unwrap(), log).unwrap();

        let rack: Ipv6Net = "fd00:1::/56".parse().unwrap();
        let addr_a: SocketAddrV6Json = "[fd00:1::a]:4444"
            .parse::<std::net::SocketAddrV6>()
            .unwrap()
            .into();
        let addr_b: SocketAddrV6Json = "[fd00:1::b]:4444"
            .parse::<std::net::SocketAddrV6>()
            .unwrap()
            .into();
        let route = |nexthop: &str, hop: &str| Route {
            destination: rack,
            nexthop: nexthop.parse().unwrap(),
            ifname: "tfportqsfp0_0".into(),
            path: vec![hop.into()],
        };
        let t1 = route("fe80::1", "t1");
        let t2 = route("fe80::2", "t2");
        let rr = |route: &Route, addr: Option<&SocketAddrV6Json>| RackRoute {
            route: route.clone(),
            multi_rack_join_addr: addr.cloned(),
        };

        // Rack routes stay out of the underlay RIB.
        db.import_rack(&[rr(&t1, Some(&addr_a)), rr(&t2, None)].into());
        assert!(db.imported().is_empty());

        // An underlay route along t1's vector shares its forwarding entry.
        // Withdrawing it leaves the entry in use by the rack route.
        let u1 = Route {
            path: vec!["s1".into()],
            ..t1.clone()
        };
        db.import(&[u1.clone()].into());
        db.delete_import(&[u1].into());
        assert!(db.vector_in_use(rack, t1.nexthop));

        // The same path with a second join address is a separate rack route.
        // Withdrawing one of them keeps the vector in use.
        db.import_rack(&[rr(&t1, Some(&addr_b))].into());
        db.delete_import_rack(&[rr(&t1, Some(&addr_a))].into());
        assert!(db.vector_in_use(rack, t1.nexthop));

        // Once neither table has a route along the vector, it is unused.
        db.delete_import_rack(&[rr(&t1, Some(&addr_b))].into());
        assert!(!db.vector_in_use(rack, t1.nexthop));

        // Expiring a peer removes its routes from both tables.
        let u2 = Route {
            path: vec!["s2".into()],
            ..t2.clone()
        };
        db.import(&[u2.clone()].into());
        let removed = db.remove_nexthop_routes(t2.nexthop);
        assert_eq!(removed.underlay, [u2].into());
        assert_eq!(removed.rack, [rr(&t2, None)].into());
        assert!(!db.vector_in_use(rack, t2.nexthop));
        assert!(db.imported_rack().is_empty());

        // Originating a prefix again replaces its join address and reports
        // the address it replaced, so the caller can withdraw it.
        let other: Ipv6Net = "fd00:2::/56".parse().unwrap();
        let origin = |prefix, addr: Option<&SocketAddrV6Json>| {
            (
                prefix,
                RackPrefixInfo {
                    multi_rack_join_addr: addr.cloned(),
                },
            )
        };
        let replaced = db
            .originate_rack_prefix(
                &[origin(rack, Some(&addr_a)), origin(other, None)].into(),
            )
            .unwrap();
        assert!(replaced.is_empty());
        let replaced = db
            .originate_rack_prefix(
                &[origin(rack, Some(&addr_b)), origin(other, None)].into(),
            )
            .unwrap();
        assert_eq!(replaced, [origin(rack, Some(&addr_a))].into());
        assert_eq!(
            db.originated_rack_prefix().unwrap(),
            [origin(rack, Some(&addr_b)), origin(other, None)].into()
        );

        // Withdrawing reports what was originated, and nothing for a prefix
        // that was not.
        let removed = db.withdraw_rack_prefix(&[rack].into()).unwrap();
        assert_eq!(removed, [origin(rack, Some(&addr_b))].into());
        assert!(db.withdraw_rack_prefix(&[rack].into()).unwrap().is_empty());
        assert_eq!(
            db.originated_rack_prefix().unwrap(),
            [origin(other, None)].into()
        );

        drop(db);
        std::fs::remove_dir_all(path).unwrap();
    }
}
