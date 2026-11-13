// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_api_types::net::TunnelOrigin;
use ddm_protocol::v3::{self, PathVector};
use mg_common::lock;
use oxnet::{IpNet, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct Db {
    data: Arc<Mutex<DbData>>,
}

// All state is held in memory only. Sled-agent's DDM reconciler re-advertises
// underlay prefixes, mg-lower re-advertises tunnel endpoints, and the scrimlet
// DDM reconciler re-applies the rack prefix.
#[derive(Default, Clone)]
pub struct DbData {
    pub imported: HashSet<Route>,
    pub imported_tunnel: HashSet<TunnelRoute>,
    pub external_peers: BTreeSet<String>,
    pub originated: HashSet<Ipv6Net>,
    pub originated_tunnel: HashSet<TunnelOrigin>,
    pub rack_prefix: Option<Ipv6Net>,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Db>()
};

impl Db {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(DbData::default())),
        }
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

    /// Mark `prefixes` as originated.
    pub fn originate(&self, prefixes: &HashSet<Ipv6Net>) {
        lock!(self.data).originated.extend(prefixes.iter().copied());
    }

    /// Mark `origins` as originated.
    pub fn originate_tunnel(&self, origins: &HashSet<TunnelOrigin>) {
        lock!(self.data)
            .originated_tunnel
            .extend(origins.iter().copied());
    }

    pub fn originated(&self) -> HashSet<Ipv6Net> {
        lock!(self.data).originated.clone()
    }

    pub fn originated_count(&self) -> usize {
        lock!(self.data).originated.len()
    }

    pub fn originated_tunnel(&self) -> HashSet<TunnelOrigin> {
        lock!(self.data).originated_tunnel.clone()
    }

    pub fn originated_tunnel_count(&self) -> usize {
        lock!(self.data).originated_tunnel.len()
    }

    /// Stop marking `prefixes` as originated.
    pub fn withdraw(&self, prefixes: &HashSet<Ipv6Net>) {
        let originated = &mut lock!(self.data).originated;
        for p in prefixes {
            originated.remove(p);
        }
    }

    /// Stop marking `origins` as originated.
    pub fn withdraw_tunnel(&self, origins: &HashSet<TunnelOrigin>) {
        let originated_tunnel = &mut lock!(self.data).originated_tunnel;
        for o in origins {
            originated_tunnel.remove(o);
        }
    }

    /// The originated rack prefix, if one is set.
    pub fn rack_prefix(&self) -> Option<Ipv6Net> {
        lock!(self.data).rack_prefix
    }

    /// Set or clear the originated rack prefix, replacing any it holds.
    pub fn set_rack_prefix(&self, prefix: Option<Ipv6Net>) {
        lock!(self.data).rack_prefix = prefix;
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

    #[test]
    fn rack_prefix_is_replaced_and_cleared() {
        let db = Db::new();
        let a: Ipv6Net = "fd00:a::/56".parse().unwrap();
        let b: Ipv6Net = "fd00:b::/48".parse().unwrap();

        assert_eq!(db.rack_prefix(), None);
        db.set_rack_prefix(Some(a));
        db.set_rack_prefix(Some(b));
        assert_eq!(db.rack_prefix(), Some(b));
        db.set_rack_prefix(None);
        assert_eq!(db.rack_prefix(), None);
    }
}
