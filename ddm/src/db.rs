// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_api_types::db::TunnelRoute;
use ddm_api_types::net::TunnelOrigin;
use ddm_protocol::v3::PathVector;
use oxnet::{IpNet, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::Ipv6Addr;
use tokio::sync::watch;

#[derive(Clone)]
pub struct Db {
    data: watch::Sender<DbData>,
}

// All state is held in memory only. Sled-agent's DDM reconciler re-advertises
// underlay prefixes, mg-lower re-advertises tunnel endpoints.
#[derive(Default, Clone)]
pub struct DbData {
    pub imported: HashSet<Route>,
    pub imported_tunnel: HashSet<TunnelRoute>,
    pub external_peers: BTreeSet<String>,
    pub originated: HashSet<Ipv6Net>,
    pub originated_tunnel: HashSet<TunnelOrigin>,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Db>()
};

impl Db {
    pub fn new() -> Self {
        Self {
            data: watch::Sender::new(DbData::default()),
        }
    }

    /// A receiver that is notified whenever the database changes.
    pub fn watch(&self) -> watch::Receiver<DbData> {
        self.data.subscribe()
    }

    pub fn imported(&self) -> HashSet<Route> {
        self.data.borrow().imported.clone()
    }

    pub fn imported_count(&self) -> usize {
        self.data.borrow().imported.len()
    }

    pub fn imported_tunnel(&self) -> HashSet<TunnelRoute> {
        self.data.borrow().imported_tunnel.clone()
    }

    pub fn imported_tunnel_count(&self) -> usize {
        self.data.borrow().imported_tunnel.len()
    }

    pub fn import(&self, r: &HashSet<Route>) {
        self.data.send_modify(|d| d.imported.extend(r.clone()));
    }

    pub fn import_tunnel(&self, r: &HashSet<TunnelRoute>) {
        self.data
            .send_modify(|d| d.imported_tunnel.extend(r.clone()));
    }

    pub fn delete_import(&self, r: &HashSet<Route>) {
        self.data.send_modify(|d| {
            for x in r {
                d.imported.remove(x);
            }
        });
    }

    pub fn delete_import_tunnel(&self, r: &HashSet<TunnelRoute>) {
        self.data.send_modify(|d| {
            for x in r {
                d.imported_tunnel.remove(x);
            }
        });
    }

    /// Mark `prefixes` as originated.
    pub fn originate(&self, prefixes: &HashSet<Ipv6Net>) {
        self.data
            .send_modify(|d| d.originated.extend(prefixes.iter().copied()));
    }

    /// Mark `origins` as originated.
    pub fn originate_tunnel(&self, origins: &HashSet<TunnelOrigin>) {
        self.data.send_modify(|d| {
            d.originated_tunnel.extend(origins.iter().copied())
        });
    }

    pub fn originated(&self) -> HashSet<Ipv6Net> {
        self.data.borrow().originated.clone()
    }

    pub fn originated_count(&self) -> usize {
        self.data.borrow().originated.len()
    }

    pub fn originated_tunnel(&self) -> HashSet<TunnelOrigin> {
        self.data.borrow().originated_tunnel.clone()
    }

    pub fn originated_tunnel_count(&self) -> usize {
        self.data.borrow().originated_tunnel.len()
    }

    /// Stop marking `prefixes` as originated.
    pub fn withdraw(&self, prefixes: &HashSet<Ipv6Net>) {
        self.data.send_modify(|d| {
            for p in prefixes {
                d.originated.remove(p);
            }
        });
    }

    /// Stop marking `origins` as originated.
    pub fn withdraw_tunnel(&self, origins: &HashSet<TunnelOrigin>) {
        self.data.send_modify(|d| {
            for o in origins {
                d.originated_tunnel.remove(o);
            }
        });
    }

    pub fn remove_nexthop_routes(
        &self,
        nexthop: Ipv6Addr,
    ) -> (HashSet<Route>, HashSet<TunnelRoute>) {
        // Routes are generally held in sets to prevent duplication and provide
        // handy set-algebra operations.
        let mut removed = HashSet::new();
        let mut tnl_removed = HashSet::new();
        self.data.send_modify(|d| {
            for x in &d.imported {
                if x.nexthop == nexthop {
                    removed.insert(x.clone());
                }
            }
            for x in &removed {
                d.imported.remove(x);
            }

            for x in &d.imported_tunnel {
                if x.nexthop == nexthop {
                    tnl_removed.insert(x.clone());
                }
            }
            for x in &tnl_removed {
                d.imported_tunnel.remove(x);
            }
        });
        (removed, tnl_removed)
    }

    pub fn get_external_peers(&self) -> BTreeSet<String> {
        self.data.borrow().external_peers.clone()
    }

    pub fn set_external_peers(&mut self, value: BTreeSet<String>) {
        self.data.send_modify(|d| d.external_peers = value);
    }
}

impl Default for Db {
    fn default() -> Self {
        Self::new()
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

#[derive(Debug, Clone)]
enum EffectiveTunnelRouteSet {
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
