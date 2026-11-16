// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_api_types::admin::{PrefixKind, UnderlayAddress};
use ddm_api_types::net::TunnelOrigin;
use ddm_protocol::v3::{self, PathVector};
use mg_common::lock;
use oxnet::{IpNet, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hash;
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct Db {
    data: Arc<Mutex<DbData>>,
}

// All state is held in memory only. Sled-agent's DDM reconciler re-advertises
// underlay prefixes, mg-lower re-advertises tunnel endpoints.
#[derive(Default, Clone)]
pub struct DbData {
    pub imported_underlay: HashSet<Route>,
    pub imported_bootstrap: HashSet<Route>,
    pub imported_tunnel: HashSet<TunnelRoute>,
    pub external_peers: BTreeSet<String>,
    pub originated_underlay: HashSet<Ipv6Net>,
    pub originated_bootstrap: HashSet<Ipv6Net>,
    pub originated_tunnel: HashSet<TunnelOrigin>,
    pub rack_prefix: Option<Ipv6Net>,
    pub underlay_addr: Option<UnderlayAddress>,
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

    /// The set of imported underlay routes.
    pub fn imported_underlay(&self) -> HashSet<Route> {
        lock!(self.data).imported_underlay.clone()
    }

    /// The set of imported bootstrap routes.
    pub fn imported_bootstrap(&self) -> HashSet<Route> {
        lock!(self.data).imported_bootstrap.clone()
    }

    /// The set of imported tunnel routes.
    pub fn imported_tunnel(&self) -> HashSet<TunnelRoute> {
        lock!(self.data).imported_tunnel.clone()
    }

    /// Imported routes for which `filter` returns true.
    fn imported_matching<ROUTE: Eq + Hash>(
        &self,
        candidate_routes: impl IntoIterator<Item = ROUTE>,
        filter: impl Fn(&ROUTE) -> bool,
    ) -> HashSet<ROUTE> {
        candidate_routes.into_iter().filter(|r| filter(r)).collect()
    }

    /// Imported underlay routes learned from the peer at `nexthop`.
    pub fn imported_underlay_from(&self, nexthop: Ipv6Addr) -> HashSet<Route> {
        self.imported_matching::<Route>(self.imported_underlay(), |r| {
            r.nexthop == nexthop
        })
    }

    /// Imported bootstrap routes learned from the peer at `nexthop`.
    pub fn imported_bootstrap_from(&self, nexthop: Ipv6Addr) -> HashSet<Route> {
        self.imported_matching::<Route>(self.imported_bootstrap(), |r| {
            r.nexthop == nexthop
        })
    }

    /// Imported tunnel routes learned from the peer at `nexthop`.
    pub fn imported_tunnel_from(
        &self,
        nexthop: Ipv6Addr,
    ) -> HashSet<TunnelRoute> {
        self.imported_matching::<TunnelRoute>(self.imported_tunnel(), |r| {
            r.nexthop == nexthop
        })
    }

    /// Import underlay routes into the local DB
    pub fn import_underlay(&self, r: &HashSet<Route>) {
        lock!(self.data).imported_underlay.extend(r.clone());
    }

    /// Import bootstrap routes into the local DB
    pub fn import_bootstrap(&self, r: &HashSet<Route>) {
        lock!(self.data).imported_bootstrap.extend(r.clone());
    }

    /// Import tunnel routes into the local DB
    pub fn import_tunnel(&self, r: &HashSet<TunnelRoute>) {
        lock!(self.data).imported_tunnel.extend(r.clone());
    }

    /// Delete imported routes of `kind` from the local DB, returning the
    /// (destination, nexthop) vectors of the deleted routes that no remaining
    /// route of that kind still uses.
    ///
    /// Routes are tracked by path, but the forwarding platform only knows
    /// vectors, so a vector may only be removed from it once its last path
    /// is gone.
    pub fn delete_import(
        &self,
        kind: PrefixKind,
        routes: &HashSet<Route>,
    ) -> HashSet<(Ipv6Net, Ipv6Addr)> {
        let mut data = lock!(self.data);
        let imported = match kind {
            PrefixKind::Underlay => &mut data.imported_underlay,
            PrefixKind::Bootstrap => &mut data.imported_bootstrap,
        };
        let mut unused = HashSet::new();
        for r in routes {
            imported.remove(r);
            unused.insert((r.destination, r.nexthop));
        }
        for r in imported.iter() {
            unused.remove(&(r.destination, r.nexthop));
        }
        unused
    }

    /// Delete tunnel routes from the local DB
    pub fn delete_import_tunnel(&self, r: &HashSet<TunnelRoute>) {
        let imported = &mut lock!(self.data).imported_tunnel;
        for x in r {
            imported.remove(x);
        }
    }

    /// Mark underlay `prefixes` as originated.
    pub fn originate_underlay(&self, prefixes: &HashSet<Ipv6Net>) {
        lock!(self.data)
            .originated_underlay
            .extend(prefixes.iter().copied());
    }

    /// Mark bootstrap `prefixes` as originated.
    pub fn originate_bootstrap(&self, prefixes: &HashSet<Ipv6Net>) {
        lock!(self.data)
            .originated_bootstrap
            .extend(prefixes.iter().copied());
    }

    /// Mark `origins` as originated.
    pub fn originate_tunnel(&self, origins: &HashSet<TunnelOrigin>) {
        lock!(self.data)
            .originated_tunnel
            .extend(origins.iter().copied());
    }

    /// The set of underlay routes being originated
    pub fn originated_underlay(&self) -> HashSet<Ipv6Net> {
        lock!(self.data).originated_underlay.clone()
    }

    /// The number of underlay routes being originated
    pub fn originated_underlay_count(&self) -> usize {
        lock!(self.data).originated_underlay.len()
    }

    /// The set of bootstrap routes being originated
    pub fn originated_bootstrap(&self) -> HashSet<Ipv6Net> {
        lock!(self.data).originated_bootstrap.clone()
    }

    /// The number of bootstrap routes being originated
    pub fn originated_bootstrap_count(&self) -> usize {
        lock!(self.data).originated_bootstrap.len()
    }

    /// The set of tunnel routes being originated
    pub fn originated_tunnel(&self) -> HashSet<TunnelOrigin> {
        lock!(self.data).originated_tunnel.clone()
    }

    /// The number of tunnel routes being originated
    pub fn originated_tunnel_count(&self) -> usize {
        lock!(self.data).originated_tunnel.len()
    }

    /// Remove `prefixes` from underlay origination set
    pub fn withdraw_underlay(&self, prefixes: &HashSet<Ipv6Net>) {
        let originated = &mut lock!(self.data).originated_underlay;
        for p in prefixes {
            originated.remove(p);
        }
    }

    /// Remove `prefixes` from bootstrap origination set
    pub fn withdraw_bootstrap(&self, prefixes: &HashSet<Ipv6Net>) {
        let originated = &mut lock!(self.data).originated_bootstrap;
        for p in prefixes {
            originated.remove(p);
        }
    }

    /// Remove `origins` from tunnel origination set
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

    /// The underlay address of this router, if one is set.
    pub fn underlay_addr(&self) -> Option<UnderlayAddress> {
        lock!(self.data).underlay_addr
    }

    /// Set or clear the underlay address of this router.
    pub fn set_underlay_addr(&self, addr: Option<UnderlayAddress>) {
        lock!(self.data).underlay_addr = addr;
    }

    /// Remove all routes imported from the peer at `nexthop`.
    pub fn remove_peer_routes(
        &self,
        nexthop: Ipv6Addr,
    ) -> (HashSet<Route>, HashSet<Route>, HashSet<TunnelRoute>) {
        let mut data = lock!(self.data);
        // Routes are generally held in sets to prevent duplication and provide
        // handy set-algebra operations.
        let mut underlay_removed = HashSet::new();
        for x in &data.imported_underlay {
            if x.nexthop == nexthop {
                underlay_removed.insert(x.clone());
            }
        }
        for x in &underlay_removed {
            data.imported_underlay.remove(x);
        }

        let mut bootstrap_removed = HashSet::new();
        for x in &data.imported_bootstrap {
            if x.nexthop == nexthop {
                bootstrap_removed.insert(x.clone());
            }
        }
        for x in &bootstrap_removed {
            data.imported_bootstrap.remove(x);
        }

        let mut tunnel_removed = HashSet::new();
        for x in &data.imported_tunnel {
            if x.nexthop == nexthop {
                tunnel_removed.insert(x.clone());
            }
        }
        for x in &tunnel_removed {
            data.imported_tunnel.remove(x);
        }
        (underlay_removed, bootstrap_removed, tunnel_removed)
    }

    /// Get all configured external peers.
    pub fn get_external_peers(&self) -> BTreeSet<String> {
        lock!(self.data).external_peers.clone()
    }

    /// Set configured external peers.
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
    /// The address object of the session the route was learned on.
    pub addrobj_name: String,
    pub path: Vec<String>,
    pub kind: PrefixKind,
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

impl From<Route> for ddm_api_types::admin::LearnedPrefix {
    fn from(val: Route) -> Self {
        let Route {
            destination,
            nexthop: _,
            addrobj_name: _,
            path,
            kind,
        } = val;
        Self {
            kind,
            prefix: destination,
            path,
        }
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

    fn route(
        kind: PrefixKind,
        destination: &str,
        nexthop: &str,
        path: &[&str],
    ) -> Route {
        Route {
            destination: destination.parse().unwrap(),
            nexthop: nexthop.parse().unwrap(),
            addrobj_name: "tfportrear0_0/ll".to_string(),
            path: path.iter().map(|x| x.to_string()).collect(),
            kind,
        }
    }

    // A vector leaves the forwarding platform only when its last path is
    // withdrawn, and only routes of the withdrawn kind count toward that.
    #[test]
    fn delete_import_returns_vectors_without_remaining_paths() {
        use PrefixKind::{Bootstrap, Underlay};
        let db = Db::new();
        // Two paths to fd00:1::/64 via a, one path to fd00:2::/64 via a.
        let x1 = route(Underlay, "fd00:1::/64", "fe80::a", &["p"]);
        let x2 = route(Underlay, "fd00:1::/64", "fe80::a", &["q", "p"]);
        let y = route(Underlay, "fd00:2::/64", "fe80::a", &["p"]);
        // The same destination via another nexthop.
        let y_b = route(Underlay, "fd00:2::/64", "fe80::b", &["p"]);
        // A bootstrap route on the vector whose only underlay path goes away.
        let z = route(Bootstrap, "fd00:2::/64", "fe80::a", &["p"]);
        db.import_underlay(&HashSet::from([
            x1.clone(),
            x2.clone(),
            y.clone(),
            y_b.clone(),
        ]));
        db.import_bootstrap(&HashSet::from([z.clone()]));

        let unused =
            db.delete_import(Underlay, &HashSet::from([x1, y.clone()]));

        let vector = |r: &Route| (r.destination, r.nexthop);
        assert_eq!(unused, HashSet::from([vector(&y)]));
        assert_eq!(db.imported_underlay(), HashSet::from([x2, y_b]));
        assert_eq!(db.imported_bootstrap(), HashSet::from([z.clone()]));

        // Withdrawing the bootstrap route frees its vector, independent of
        // underlay routes on other vectors.
        let unused = db.delete_import(Bootstrap, &HashSet::from([z.clone()]));
        assert_eq!(unused, HashSet::from([vector(&z)]));
        assert!(db.imported_bootstrap().is_empty());
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
}
