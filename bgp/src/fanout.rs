// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::connection::BgpConnection;
use crate::session::{
    AdminEvent, FsmEvent, RouteUpdate, RouteUpdate4, RouteUpdate6,
};
use crate::{COMPONENT_BGP, MOD_NEIGHBOR};
use rdb::types::{Ipv4Marker, Ipv6Marker, Prefix4, Prefix6};
use slog::Logger;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::sync::mpsc::Sender;

const UNIT_FANOUT: &str = "fanout";

/// Type aliases for address-family-specific fanouts
pub type Fanout4<Cnx> = Fanout<Cnx, Ipv4Marker>;
pub type Fanout6<Cnx> = Fanout<Cnx, Ipv6Marker>;

/// Fanout for distributing routes to peers for a specific address family.
///
/// The type parameter `Af` ensures compile-time safety:
/// - Fanout4 (Fanout<_, Ipv4Marker>) only accepts Prefix4
/// - Fanout6 (Fanout<_, Ipv6Marker>) only accepts Prefix6
pub struct Fanout<Cnx: BgpConnection, Af> {
    /// Indexed neighbor address
    egress: BTreeMap<IpAddr, Egress<Cnx>>,
    /// Zero-sized marker for address family type enforcement
    _af: PhantomData<Af>,
}

//NOTE necessary as #derive is broken for generic types
impl<Cnx: BgpConnection, Af> Default for Fanout<Cnx, Af> {
    fn default() -> Self {
        Self {
            egress: BTreeMap::new(),
            _af: PhantomData,
        }
    }
}

pub struct Egress<Cnx: BgpConnection> {
    pub event_tx: Option<Sender<FsmEvent<Cnx>>>,
    pub log: Logger,
}

// IPv4-specific implementation
impl<Cnx: BgpConnection> Fanout<Cnx, Ipv4Marker> {
    /// Announce and/or withdraw IPv4 routes to all peers.
    pub fn send_all(&self, nlri: Vec<Prefix4>, withdrawn: Vec<Prefix4>) {
        for egress in self.egress.values() {
            if !nlri.is_empty() {
                let announce =
                    RouteUpdate::V4(RouteUpdate4::Announce(nlri.clone()));
                egress.send_route_update(announce);
            }
            if !withdrawn.is_empty() {
                let withdraw =
                    RouteUpdate::V4(RouteUpdate4::Withdraw(withdrawn.clone()));
                egress.send_route_update(withdraw);
            }
        }
    }

    /// Announce and/or withdraw IPv4 routes to all peers except the origin.
    pub fn send_except(
        &self,
        origin: IpAddr,
        nlri: Vec<Prefix4>,
        withdrawn: Vec<Prefix4>,
    ) {
        for (peer_addr, egress) in &self.egress {
            if *peer_addr == origin {
                continue;
            }
            if !nlri.is_empty() {
                let announce =
                    RouteUpdate::V4(RouteUpdate4::Announce(nlri.clone()));
                egress.send_route_update(announce);
            }
            if !withdrawn.is_empty() {
                let withdraw =
                    RouteUpdate::V4(RouteUpdate4::Withdraw(withdrawn.clone()));
                egress.send_route_update(withdraw);
            }
        }
    }
}

// IPv6-specific implementation
impl<Cnx: BgpConnection> Fanout<Cnx, Ipv6Marker> {
    /// Announce and/or withdraw IPv6 routes to all peers.
    pub fn send_all(&self, nlri: Vec<Prefix6>, withdrawn: Vec<Prefix6>) {
        for egress in self.egress.values() {
            if !nlri.is_empty() {
                let announce =
                    RouteUpdate::V6(RouteUpdate6::Announce(nlri.clone()));
                egress.send_route_update(announce);
            }
            if !withdrawn.is_empty() {
                let withdraw =
                    RouteUpdate::V6(RouteUpdate6::Withdraw(withdrawn.clone()));
                egress.send_route_update(withdraw);
            }
        }
    }

    /// Announce and/or withdraw IPv6 routes to all peers except the origin.
    pub fn send_except(
        &self,
        origin: IpAddr,
        nlri: Vec<Prefix6>,
        withdrawn: Vec<Prefix6>,
    ) {
        for (peer_addr, egress) in &self.egress {
            if *peer_addr == origin {
                continue;
            }
            if !nlri.is_empty() {
                let announce =
                    RouteUpdate::V6(RouteUpdate6::Announce(nlri.clone()));
                egress.send_route_update(announce);
            }
            if !withdrawn.is_empty() {
                let withdraw =
                    RouteUpdate::V6(RouteUpdate6::Withdraw(withdrawn.clone()));
                egress.send_route_update(withdraw);
            }
        }
    }
}

// Common methods available for all address families
impl<Cnx: BgpConnection, Af> Fanout<Cnx, Af> {
    pub fn add_egress(&mut self, peer: IpAddr, egress: Egress<Cnx>) {
        self.egress.insert(peer, egress);
    }

    pub fn remove_egress(&mut self, peer: IpAddr) {
        self.egress.remove(&peer);
    }

    pub fn is_empty(&self) -> bool {
        self.egress.is_empty()
    }
}

impl<Cnx: BgpConnection> Egress<Cnx> {
    fn send_route_update(&self, route_update: RouteUpdate) {
        let Some(tx) = self.event_tx.as_ref() else {
            return;
        };

        // Capture Display output before send() consumes route_update.
        let update_desc = format!("{route_update}");

        if let Err(e) =
            tx.send(FsmEvent::Admin(AdminEvent::Announce(route_update)))
        {
            slog::error!(
                self.log,
                "failed to send route update to egress: {e}";
                "component" => COMPONENT_BGP,
                "module" => MOD_NEIGHBOR,
                "unit" => UNIT_FANOUT,
                "route_update" => update_desc,
                "error" => format!("{e}"),
            );
        }
    }
}
