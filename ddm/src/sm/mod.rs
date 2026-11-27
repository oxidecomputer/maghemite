// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! State machine type definitions and the [`StateMachine`] handle. The
//! routing state machine implementation (discovery, solicit, exchange) lives
//! in the [`state`] submodule and is illumos-only, since it programs kernel
//! routes via [`crate::sys`] and reads interface addressing through `libnet`.

use crate::db::Db;
use crate::discovery::{self, Version};
use ddm_api_types::db::{PeerStats, PeerStatus, RouterKind};
use ddm_api_types::net::TunnelOrigin;
use iddqd::{IdOrdItem, id_upcast};
use oxnet::Ipv6Net;
use slog::Logger;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Display;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::watch;
use uuid::Uuid;

#[cfg(all(feature = "backend", target_os = "illumos"))]
pub(crate) mod state;

#[derive(Debug, Clone)]
pub enum AdminEvent {
    /// Announce a set of IPv6 prefixes
    Announce(PrefixSet),

    /// Withdraw a set of IPv6 prefixes
    Withdraw(PrefixSet),

    /// Expire the peer at the specified address
    Expire(Ipv6Addr),

    /// Synchronize with active peers by pulling their prefixes.
    Sync,

    /// A new external peer has been added to the router. Its state machine,
    /// identified by its address object name, can be reached using the
    /// provided sender.
    NewExternalPeer {
        addrobj_name: String,
        tx: Sender<Event>,
    },

    /// Shutdown on receipt of this event.
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum PrefixSet {
    Underlay(HashSet<Ipv6Net>),
    Bootstrap(HashSet<Ipv6Net>),
    Tunnel(HashSet<TunnelOrigin>),
    /// The rack prefix, advertised as an underlay route to the peers allowed
    /// to receive it.
    Rack(Ipv6Net),
}

#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// Upon reception of this event, a state machine is to push the update to
    /// its peer.
    Push(Box<ddm_protocol::v3::Update>),

    /// Upon reception of this event, a state machine is to redistribute the
    /// update to it's sibling routers through it's event channels. The state
    /// machine is responsible for maintaining the path vector and performing
    /// loop breaking.
    Redistribute(Box<ddm_protocol::v3::Update>),
}

#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// An event sent from the discovery subsystem to the state machine letting
    /// it know the identity of a newly discovered or changed peer.
    Advertise(PeerIdentity),

    /// An event sent from the discovery subsystem to the state machine letting
    /// it know that solicitation has failed.
    SolicitFail,

    /// An event sent from the discovery subsystem to the state machine letting
    /// it know that the peer has expired.
    Expire,
}

#[derive(Debug, Clone)]
pub enum Event {
    Discovery(DiscoveryEvent),
    Peer(PeerEvent),
    Admin(AdminEvent),
}

impl From<DiscoveryEvent> for Event {
    fn from(e: DiscoveryEvent) -> Self {
        Self::Discovery(e)
    }
}

impl From<PeerEvent> for Event {
    fn from(e: PeerEvent) -> Self {
        Self::Peer(e)
    }
}

impl From<AdminEvent> for Event {
    fn from(e: AdminEvent) -> Self {
        Self::Admin(e)
    }
}

#[derive(Debug)]
pub enum StateType {
    Solicit,
    Exchange,
}

#[derive(Debug)]
pub enum EventError {
    InvalidEvent(StateType),
}

#[derive(Debug)]
pub enum EventResponse {
    Success,
    Prefixes(Vec<Ipv6Net>),
}

#[derive(Error, Debug)]
pub enum SmError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("discovery error: {0}")]
    Discovery(#[from] discovery::DiscoveryError),
}

#[derive(Clone)]
pub struct Config {
    /// Interface this state machine is associated with.
    pub if_index: u32,

    /// Interface name this state machine is associated with.
    pub if_name: String,

    /// Address object name the state machine uses for peering. Must correspond
    /// to IPv6 link local address.
    pub addrobj_name: String,

    /// Link local Ipv6 address this state machine is associated with
    pub addr: Ipv6Addr,

    /// How long to wait between solicitations.
    pub solicit_interval: Duration,

    /// How often to check for link failure while waiting for discovery messges.
    pub discovery_read_timeout: Duration,

    /// How long to wait between attempts to get an IP address for a specified
    /// address object.
    pub ip_addr_wait: Duration,

    /// How long to wait without a solicitation response before expiring a peer
    pub expire_threshold: Duration,

    /// How long to wait for a response to exchange messages.
    pub exchange_timeout: Duration,

    /// The kind of router this is, server or transit.
    pub kind: RouterKind,

    /// TCP port to use for prefix exchange.
    pub exchange_port: u16,

    /// Dendrite dpd config
    pub dpd: Option<DpdConfig>,

    /// Rack ID
    pub rack_id: Option<Uuid>,

    /// Sled ID
    pub sled_id: Option<Uuid>,
}

#[derive(Clone)]
pub struct DpdConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub enum FsmState {
    Init,
    Solicit,
    Exchange(PeerIdentity),
}

impl FsmState {
    pub fn to_peer_status(&self, elapsed: Duration) -> PeerStatus {
        match self {
            FsmState::Init => PeerStatus::Init(elapsed),
            FsmState::Solicit => PeerStatus::Solicit(elapsed),
            FsmState::Exchange(_) => PeerStatus::Exchange(elapsed),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PeerIdentity {
    pub addr: Ipv6Addr,
    pub hostname: String,
    pub kind: RouterKind,
    pub version: Version,
}

impl Display for PeerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let PeerIdentity {
            addr,
            hostname,
            kind,
            version,
        } = self;
        write!(f, "{hostname}@{addr} ({kind}, version {})", *version as u8,)
    }
}

/// The route types that are allowed to be advertised to a DDM peer.
///
/// This is computed once when a DDM moves into Exchange state, using the local
/// and remote `RouterKind` to determine the set of route types that should be
/// propagated to the peer. If the peer expires, `RouteAdvertisementAllowances`
/// is dropped since the next peer may come up with a different `RouterKind`,
/// warranting a new `RouteAdvertisementAllowances`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteAdvertisementAllowances {
    /// Originated underlay prefixes.
    pub originated_underlay_routes: bool,
    /// Originated bootstrap prefixes.
    pub originated_bootstrap_routes: bool,
    /// Originated tunnel routes.
    pub originated_tunnel_routes: bool,
    /// The originated rack prefix.
    pub originated_rack_prefix: bool,
    /// Routes learned from other peers.
    pub redistributed_routes: bool,
}

impl RouteAdvertisementAllowances {
    /// What a router of kind `local` may send to a peer of kind `peer`.
    pub fn tx(local: RouterKind, peer: RouterKind) -> Self {
        use RouterKind::*;
        match (local, peer) {
            // Server routers originate just underlay/bootstrap routes.
            // All other route types are disallowed from being sent to peers.
            //
            // This upholds the valley-free routing invariant for Servers.
            // i.e.
            // Servers generate or terminate packets, but never transit them.
            // Transit -> Server -> Transit can never happen.
            (Server, _) => Self {
                originated_underlay_routes: true,
                originated_bootstrap_routes: true,
                originated_tunnel_routes: false,
                originated_rack_prefix: false,
                redistributed_routes: false,
            },

            // Transit routers originate Tunnel routes and a Rack prefix when
            // peering with another Transit router. This ensures other racks
            // learn about our rack address space via a single aggregate /56,
            // and that they know about our external connectivity in case they
            // do not have their own (either due to network design or failures).
            // Bootstrap routes must never leave the rack, and are not allowed.
            (Transit, Transit) => Self {
                originated_underlay_routes: false,
                originated_bootstrap_routes: false,
                originated_tunnel_routes: true,
                originated_rack_prefix: true,
                redistributed_routes: false,
            },

            // Transit routers are allowed to originate underlay and tunnel
            // routes to Server routers, but not rack prefixes. They may
            // redistribute any route they have received to a Server router.
            //
            // This ensures that:
            // 1) Underlay/Bootstrap routes from Servers are redistributed
            //    across a rack, so Server -> Transit -> Server flows work as
            //    expected.
            // 2) Tunnel routes learned from mgd are originated to Servers.
            //    This allows Servers to use our connection to the External net.
            // 3) Tunnel routes learned from other racks are redistributed to
            //    Servers. This allows them to use other racks' connections to
            //    the External network even if our rack has none (either due to
            //    failure conditions or network design).
            // 4) Rack prefixes may NOT be originated to Servers. This avoids
            //    situations where Server 1 loses a /64 route to Server 2 but
            //    continues to send traffic to Server 2 via a less specific /56.
            //    If the /64 has legitimately been withdrawn from the topology,
            //    then dropping earlier is better.
            // 5) Rack prefixes learned from other racks are redistributed to
            //    Servers. This allows Servers to learn routes to other racks.
            (Transit, Server) => Self {
                originated_underlay_routes: true,
                originated_bootstrap_routes: true,
                originated_tunnel_routes: true,
                originated_rack_prefix: false,
                redistributed_routes: true,
            },
        }
    }
}

/// A snapshot of an interface's state machine, published by the state machine
/// through [`Interface`] and read by the admin API and stats collection.
#[derive(Clone, Debug)]
pub struct InterfaceState {
    pub if_index: u32,
    pub if_name: String,
    pub external: bool,
    pub fsm_state: FsmState,
    pub last_fsm_state_change: Instant,
}

impl InterfaceState {
    pub fn external() -> Self {
        Self {
            external: true,
            ..Default::default()
        }
    }

    fn transition(&mut self, state: FsmState) {
        self.fsm_state = state;
        self.last_fsm_state_change = Instant::now();
    }

    /// The peer this interface is exchanging routes with, if any, and how
    /// long the interface has been in its current state.
    pub fn peer(&self) -> Option<(PeerStatus, PeerIdentity)> {
        let FsmState::Exchange(peer) = &self.fsm_state else {
            return None;
        };
        let elapsed = self.last_fsm_state_change.elapsed();
        Some((self.fsm_state.to_peer_status(elapsed), peer.clone()))
    }
}

impl Default for InterfaceState {
    fn default() -> Self {
        Self {
            if_index: 0,
            if_name: String::new(),
            external: false,
            fsm_state: FsmState::Init,
            last_fsm_state_change: Instant::now(),
        }
    }
}

/// Publishes an interface's [`InterfaceState`] from its state machine to
/// readers in other threads without them sharing a lock.
///
/// The `watch` sender is private so every update goes through `send_modify`
/// (`send` silently drops updates when there are no receivers), and readers
/// get a clone rather than a guard that would block the next update.
#[derive(Clone)]
pub struct Interface(watch::Sender<InterfaceState>);

impl Interface {
    pub fn new(state: InterfaceState) -> Self {
        Self(watch::Sender::new(state))
    }

    pub fn transition(&self, state: FsmState) {
        self.0.send_modify(|i| i.transition(state));
    }

    pub fn set_if_info(&self, index: u32, name: String) {
        self.0.send_modify(|i| {
            i.if_index = index;
            i.if_name = name;
        });
    }

    pub fn snapshot(&self) -> InterfaceState {
        self.0.borrow().clone()
    }
}

#[derive(Default)]
pub struct SessionStats {
    // Discovery
    pub solicitations_sent: AtomicU64,
    pub solicitations_received: AtomicU64,
    pub advertisements_sent: AtomicU64,
    pub advertisements_received: AtomicU64,
    pub peer_expirations: AtomicU64,
    pub peer_address_changes: AtomicU64,
    pub peer_established: AtomicU64,

    // Exchange
    pub updates_sent: AtomicU64,
    pub updates_received: AtomicU64,
    pub update_send_fail: AtomicU64,
}

#[derive(Clone)]
pub struct SmContext {
    pub config: Config,
    pub db: Db,
    pub tx: Sender<Event>,
    pub event_channels: BTreeMap<String, Sender<Event>>,
    pub rt: Arc<tokio::runtime::Handle>,
    pub router_id: String,
    pub bootstrap_addr: Ipv6Addr,
    pub iface: Interface,
    pub stats: Arc<SessionStats>,
    pub log: Logger,
    pub discovery_stop: Option<Arc<AtomicBool>>,
    pub first_run: bool,
}

impl SmContext {
    /// This session's statistics.
    pub fn peer_stats(&self) -> PeerStats {
        let SessionStats {
            solicitations_sent,
            solicitations_received,
            advertisements_sent,
            advertisements_received,
            peer_expirations,
            peer_address_changes,
            peer_established,
            updates_sent,
            updates_received,
            update_send_fail,
        } = self.stats.as_ref();
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let peer = self.iface.snapshot().peer().map(|(_, p)| p.addr);
        let imported = |count: fn(&Db, Ipv6Addr) -> usize| {
            peer.map_or(0, |addr| count(&self.db, addr) as u64)
        };
        PeerStats {
            solicitations_sent: get(solicitations_sent),
            solicitations_received: get(solicitations_received),
            advertisements_sent: get(advertisements_sent),
            advertisements_received: get(advertisements_received),
            peer_expirations: get(peer_expirations),
            peer_address_changes: get(peer_address_changes),
            peer_established: get(peer_established),
            updates_sent: get(updates_sent),
            updates_received: get(updates_received),
            update_send_fail: get(update_send_fail),
            imported_underlay_prefixes: imported(
                Db::imported_underlay_count_from,
            ),
            imported_bootstrap_prefixes: imported(
                Db::imported_bootstrap_count_from,
            ),
            imported_tunnel_endpoints: imported(Db::imported_tunnel_count_from),
        }
    }
}

impl IdOrdItem for SmContext {
    type Key<'a> = &'a str;

    fn key(&self) -> Self::Key<'_> {
        &self.config.addrobj_name
    }

    id_upcast!();
}

pub struct StateMachine {
    pub ctx: SmContext,
    pub rx: Option<Receiver<Event>>,
}

#[cfg(not(target_os = "illumos"))]
impl StateMachine {
    pub fn run(&mut self) -> Result<(), SmError> {
        Ok(())
    }
}

/// Send an event to all sibling channels, removing any channels that are dead.
#[cfg(target_os = "illumos")]
pub(crate) fn send(
    e: Event,
    event_channels: &mut BTreeMap<String, Sender<Event>>,
) {
    event_channels.retain(|_, tx| tx.send(e.clone()).is_ok());
}

#[cfg(test)]
mod test {
    use super::RouteAdvertisementAllowances as Allow;
    use ddm_api_types::db::RouterKind::{Server, Transit};

    #[test]
    fn tx_route_advertisement_allowances() {
        // Written out by hand rather than derived from Allow::tx.
        let expected = [
            (Server, Server, [true, true, false, false, false]),
            (Server, Transit, [true, true, false, false, false]),
            (Transit, Server, [true, true, true, false, true]),
            (Transit, Transit, [false, false, true, true, false]),
        ];
        for (local, peer, [underlay, bootstrap, tunnel, rack, redistributed]) in
            expected
        {
            assert_eq!(
                Allow::tx(local, peer),
                Allow {
                    originated_underlay_routes: underlay,
                    originated_bootstrap_routes: bootstrap,
                    originated_tunnel_routes: tunnel,
                    originated_rack_prefix: rack,
                    redistributed_routes: redistributed,
                },
                "{local} -> {peer}",
            );
        }
    }
}
