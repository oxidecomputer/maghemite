// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The imported route table and the rules for turning peer updates into
//! forwarding-platform deltas.
//!
//! This is a pure core: [`Rib::apply`] takes an event and returns the routes
//! to add and remove plus, on a transit router, the update to redistribute.
//! Executing those deltas is the caller's job.

use crate::db::{Route, effective_route_set};
use ddm_api_types::db::{RouterKind, TunnelRoute};
use ddm_protocol_types::v3;
use std::collections::HashSet;
use std::net::Ipv6Addr;

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
    pub add_underlay: Vec<Route>,
    pub del_underlay: Vec<Route>,
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
            out.add_underlay.push(route.clone());
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
                out.del_underlay.push(w.clone());
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
        let removed: Vec<Route> = self
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
mod tests;
