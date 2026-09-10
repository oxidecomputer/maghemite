// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The imported route table and the rules for turning peer updates into
//! forwarding-platform deltas.
//!
//! This is a pure core: [`Rib::apply`] takes an event and returns the routes
//! to add and remove plus, on a transit router, the update to redistribute.
//! Executing those deltas is the caller's job.

use ddm_api_types::db::{RouterKind, TunnelRoute};
use ddm_protocol::v3;
use oxnet::{IpNet, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;

// A route stored in the RIB
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

#[derive(Debug, Clone)]
pub enum RibEvent {
    /// An update arrived from `peer` over the interface named `ifname`.
    Update {
        peer: Ipv6Addr,
        ifname: String,
        update: Box<v3::Update>,
    },

    /// A peer expired. Every route learned through `nexthop` is dropped,
    /// regardless of which interface learned it.
    PeerExpired { nexthop: Ipv6Addr },
}

/// The forwarding-platform deltas produced by a [`RibEvent`], plus the update
/// to redistribute to other peers.
#[derive(Debug, Default, Clone)]
pub struct RibOutput {
    pub add_underlay: HashSet<Route>,
    pub del_underlay: HashSet<Route>,
    pub add_tunnel: HashSet<TunnelRoute>,
    pub del_tunnel: HashSet<TunnelRoute>,

    /// Present only on a transit router. `None` on a server router, which
    /// never redistributes.
    pub redistribute: Option<v3::Update>,
}

pub struct Rib {
    hostname: String,
    kind: RouterKind,
    imported: HashSet<Route>,
    imported_tunnel: HashSet<TunnelRoute>,
}

impl Rib {
    pub fn new(hostname: String, kind: RouterKind) -> Self {
        Self {
            hostname,
            kind,
            imported: HashSet::new(),
            imported_tunnel: HashSet::new(),
        }
    }

    pub fn imported(&self) -> &HashSet<Route> {
        &self.imported
    }

    pub fn imported_tunnel(&self) -> &HashSet<TunnelRoute> {
        &self.imported_tunnel
    }

    pub fn apply(&mut self, event: RibEvent) -> RibOutput {
        match event {
            RibEvent::Update {
                peer,
                ifname,
                update,
            } => self.apply_update(peer, &ifname, &update),
            RibEvent::PeerExpired { nexthop } => self.expire_nexthop(nexthop),
        }
    }

    fn apply_update(
        &mut self,
        peer: Ipv6Addr,
        ifname: &str,
        update: &v3::Update,
    ) -> RibOutput {
        let mut out = RibOutput::default();

        if let Some(underlay) = &update.underlay {
            self.apply_underlay(peer, ifname, underlay, &mut out);
        }

        if let Some(tunnel) = &update.tunnel {
            self.apply_tunnel(peer, tunnel, &mut out);
        }

        if self.kind == RouterKind::Transit {
            out.redistribute = Some(v3::Update {
                underlay: update
                    .underlay
                    .as_ref()
                    .map(|u| u.with_path_element(self.hostname.clone())),
                tunnel: update.tunnel.clone(),
            });
        }

        out
    }

    fn apply_underlay(
        &mut self,
        peer: Ipv6Addr,
        ifname: &str,
        update: &v3::UnderlayUpdate,
        out: &mut RibOutput,
    ) {
        for prefix in &update.announce {
            let route = Route {
                destination: prefix.destination,
                nexthop: peer,
                ifname: ifname.to_owned(),
                path: prefix.path.clone(),
            };
            out.add_underlay.insert(route.clone());
            self.imported.insert(route);
        }

        let withdraw: HashSet<Route> = update
            .withdraw
            .iter()
            .map(|prefix| Route {
                destination: prefix.destination,
                nexthop: peer,
                ifname: ifname.to_owned(),
                path: prefix.path.clone(),
            })
            .collect();

        for route in &withdraw {
            self.imported.remove(route);
        }

        // A withdrawn path is not necessarily a withdrawn route. We track
        // routes by path, but the forwarding platform only knows the
        // (destination, nexthop) vector, and many paths can share one vector.
        // Deleting on the first withdrawn path would leave the platform
        // without a route the RIB still believes in, so only delete once the
        // whole vector is gone.
        for w in &withdraw {
            if !self.has_vector(w.destination, w.nexthop) {
                out.del_underlay.insert(w.clone());
            }
        }
    }

    fn apply_tunnel(
        &mut self,
        peer: Ipv6Addr,
        update: &v3::TunnelUpdate,
        out: &mut RibOutput,
    ) {
        let before = effective_route_set(&self.imported_tunnel);

        for x in &update.announce {
            self.imported_tunnel.insert(TunnelRoute {
                origin: *x,
                nexthop: peer,
            });
        }

        for x in &update.withdraw {
            self.imported_tunnel.remove(&TunnelRoute {
                origin: *x,
                nexthop: peer,
            });
        }

        let after = effective_route_set(&self.imported_tunnel);

        out.add_tunnel = after.difference(&before).copied().collect();
        out.del_tunnel = before.difference(&after).copied().collect();
    }

    fn expire_nexthop(&mut self, nexthop: Ipv6Addr) -> RibOutput {
        let removed: HashSet<Route> = self
            .imported
            .iter()
            .filter(|x| x.nexthop == nexthop)
            .cloned()
            .collect();
        for x in &removed {
            self.imported.remove(x);
        }

        let removed_tunnel: HashSet<TunnelRoute> = self
            .imported_tunnel
            .iter()
            .filter(|x| x.nexthop == nexthop)
            .copied()
            .collect();
        for x in &removed_tunnel {
            self.imported_tunnel.remove(x);
        }

        let redistribute =
            (self.kind == RouterKind::Transit).then(|| v3::Update {
                underlay: (!removed.is_empty()).then(|| {
                    v3::UnderlayUpdate::withdraw(
                        removed
                            .iter()
                            .map(|x| v3::PathVector {
                                destination: x.destination,
                                path: {
                                    let mut path = x.path.clone();
                                    path.push(self.hostname.clone());
                                    path
                                },
                            })
                            .collect(),
                    )
                }),
                tunnel: (!removed_tunnel.is_empty()).then(|| {
                    v3::TunnelUpdate::withdraw(
                        removed_tunnel.iter().map(|x| x.origin).collect(),
                    )
                }),
            });

        RibOutput {
            del_underlay: removed,
            del_tunnel: removed_tunnel,
            redistribute,
            ..Default::default()
        }
    }

    fn has_vector(
        &self,
        destination: oxnet::Ipv6Net,
        nexthop: Ipv6Addr,
    ) -> bool {
        self.imported
            .iter()
            .any(|x| x.destination == destination && x.nexthop == nexthop)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ddm_protocol::v3::{PathVector, TunnelOrigin, UnderlayUpdate};
    use oxnet::Ipv6Net;
    use pretty_assertions::assert_eq;

    const IFNAME: &str = "cxgbe0";

    fn peer(n: u16) -> Ipv6Addr {
        format!("fe80::{n}").parse().unwrap()
    }

    fn net(n: u16) -> Ipv6Net {
        format!("fd00:{n}::/64").parse().unwrap()
    }

    fn pv(n: u16, path: &[&str]) -> PathVector {
        PathVector {
            destination: net(n),
            path: path.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn announce(from: Ipv6Addr, prefixes: Vec<PathVector>) -> RibEvent {
        RibEvent::Update {
            peer: from,
            ifname: IFNAME.to_owned(),
            update: Box::new(
                UnderlayUpdate::announce(prefixes.into_iter().collect()).into(),
            ),
        }
    }

    fn withdraw(from: Ipv6Addr, prefixes: Vec<PathVector>) -> RibEvent {
        RibEvent::Update {
            peer: from,
            ifname: IFNAME.to_owned(),
            update: Box::new(
                UnderlayUpdate::withdraw(prefixes.into_iter().collect()).into(),
            ),
        }
    }

    fn tunnel_announce(from: Ipv6Addr, n: u16, metric: u64) -> RibEvent {
        RibEvent::Update {
            peer: from,
            ifname: IFNAME.to_owned(),
            update: Box::new(
                v3::TunnelUpdate::announce([tunnel_origin(n, metric)].into())
                    .into(),
            ),
        }
    }

    fn tunnel_origin(n: u16, metric: u64) -> TunnelOrigin {
        TunnelOrigin {
            overlay_prefix: "0.0.0.0/0".parse().unwrap(),
            boundary_addr: format!("fd00:b{n}::1").parse().unwrap(),
            vni: 99,
            metric,
        }
    }

    fn server() -> Rib {
        Rib::new("s1".to_owned(), RouterKind::Server)
    }

    fn transit() -> Rib {
        Rib::new("t1".to_owned(), RouterKind::Transit)
    }

    fn vectors<'a>(
        out: impl IntoIterator<Item = &'a Route>,
    ) -> Vec<(Ipv6Net, Ipv6Addr)> {
        let mut v: Vec<_> = out
            .into_iter()
            .map(|r| (r.destination, r.nexthop))
            .collect();
        v.sort();
        v
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
    fn announce_adds_route_and_imports_it() {
        let mut rib = server();
        let out = rib.apply(announce(peer(1), vec![pv(1, &["a"])]));

        assert_eq!(vectors(&out.add_underlay), vec![(net(1), peer(1))]);
        assert!(out.del_underlay.is_empty());
        assert_eq!(rib.imported().len(), 1);
    }

    #[test]
    fn server_router_never_redistributes() {
        let mut rib = server();
        let out = rib.apply(announce(peer(1), vec![pv(1, &["a"])]));
        assert!(out.redistribute.is_none());
    }

    #[test]
    fn transit_router_appends_itself_to_the_path() {
        let mut rib = transit();
        let out = rib.apply(announce(peer(1), vec![pv(1, &["a"])]));

        let underlay = out.redistribute.unwrap().underlay.unwrap();
        let paths: Vec<Vec<String>> =
            underlay.announce.iter().map(|x| x.path.clone()).collect();
        assert_eq!(paths, vec![vec!["a".to_owned(), "t1".to_owned()]]);
    }

    /// The rule this whole core exists to make testable: many paths can share one
    /// (destination, nexthop) vector, and the forwarding platform only knows the
    /// vector. Withdrawing one path must not delete the route.
    #[test]
    fn withdraw_of_one_path_leaves_the_vector_programmed() {
        let mut rib = server();
        rib.apply(announce(peer(1), vec![pv(1, &["a"]), pv(1, &["b"])]));

        let out = rib.apply(withdraw(peer(1), vec![pv(1, &["a"])]));

        assert!(
            out.del_underlay.is_empty(),
            "route deleted while path b still carries the vector"
        );
        assert_eq!(rib.imported().len(), 1);
    }

    #[test]
    fn withdraw_of_the_last_path_deletes_the_vector() {
        let mut rib = server();
        rib.apply(announce(peer(1), vec![pv(1, &["a"]), pv(1, &["b"])]));
        rib.apply(withdraw(peer(1), vec![pv(1, &["a"])]));

        let out = rib.apply(withdraw(peer(1), vec![pv(1, &["b"])]));

        assert_eq!(vectors(&out.del_underlay), vec![(net(1), peer(1))]);
        assert!(rib.imported().is_empty());
    }

    /// The same destination via two different peers is two vectors. Losing one
    /// must not disturb the other.
    #[test]
    fn withdraw_is_scoped_to_the_nexthop() {
        let mut rib = server();
        rib.apply(announce(peer(1), vec![pv(1, &["a"])]));
        rib.apply(announce(peer(2), vec![pv(1, &["a"])]));

        let out = rib.apply(withdraw(peer(1), vec![pv(1, &["a"])]));

        assert_eq!(vectors(&out.del_underlay), vec![(net(1), peer(1))]);
        assert_eq!(rib.imported().len(), 1);
    }

    #[test]
    fn withdrawing_an_unknown_path_deletes_nothing() {
        let mut rib = server();
        rib.apply(announce(peer(1), vec![pv(1, &["a"])]));

        let out = rib.apply(withdraw(peer(1), vec![pv(2, &["z"])]));

        assert_eq!(vectors(&out.del_underlay), vec![(net(2), peer(1))]);
        assert_eq!(rib.imported().len(), 1);
    }

    #[test]
    fn expiry_drops_every_route_learned_through_the_peer() {
        let mut rib = server();
        rib.apply(announce(peer(1), vec![pv(1, &["a"]), pv(2, &["a"])]));
        rib.apply(announce(peer(2), vec![pv(3, &["a"])]));

        let out = rib.apply(RibEvent::PeerExpired { nexthop: peer(1) });

        assert_eq!(
            vectors(&out.del_underlay),
            vec![(net(1), peer(1)), (net(2), peer(1))]
        );
        assert_eq!(rib.imported().len(), 1);
    }

    #[test]
    fn transit_redistributes_withdraws_on_expiry() {
        let mut rib = transit();
        rib.apply(announce(peer(1), vec![pv(1, &["a"])]));

        let out = rib.apply(RibEvent::PeerExpired { nexthop: peer(1) });

        let underlay = out.redistribute.unwrap().underlay.unwrap();
        assert!(underlay.announce.is_empty());
        let paths: Vec<Vec<String>> =
            underlay.withdraw.iter().map(|x| x.path.clone()).collect();
        assert_eq!(paths, vec![vec!["a".to_owned(), "t1".to_owned()]]);
    }

    #[test]
    fn expiring_an_unknown_peer_is_a_no_op() {
        let mut rib = transit();
        rib.apply(announce(peer(1), vec![pv(1, &["a"])]));

        let out = rib.apply(RibEvent::PeerExpired { nexthop: peer(9) });

        assert!(out.del_underlay.is_empty());
        assert!(out.del_tunnel.is_empty());
        let redistribute = out.redistribute.unwrap();
        assert!(redistribute.underlay.is_none());
        assert!(redistribute.tunnel.is_none());
    }

    #[test]
    fn tunnel_announce_programs_the_endpoint() {
        let mut rib = server();
        let out = rib.apply(tunnel_announce(peer(1), 1, 0));

        assert_eq!(out.add_tunnel.len(), 1);
        assert!(out.del_tunnel.is_empty());
    }

    /// A nonzero metric makes the whole overlay prefix prefer the metric-bearing
    /// origins, so an announce can *delete* a previously programmed endpoint.
    #[test]
    fn a_higher_metric_evicts_the_zero_metric_endpoints() {
        let mut rib = server();
        rib.apply(tunnel_announce(peer(1), 1, 0));

        let out = rib.apply(tunnel_announce(peer(2), 2, 100));

        assert_eq!(out.add_tunnel.len(), 1);
        assert_eq!(out.del_tunnel.len(), 1);
        let deleted = out.del_tunnel.iter().next().unwrap();
        assert_eq!(deleted.nexthop, peer(1));
    }

    #[test]
    fn expiry_drops_tunnel_endpoints_too() {
        let mut rib = server();
        rib.apply(tunnel_announce(peer(1), 1, 0));

        let out = rib.apply(RibEvent::PeerExpired { nexthop: peer(1) });

        assert_eq!(out.del_tunnel.len(), 1);
        assert!(rib.imported_tunnel().is_empty());
    }
}
