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
use ddm_protocol::v3::RackPrefix;
use mg_common::lock;
use oxnet::Ipv6Net;
use slog::Logger;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Display;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
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
        aobj_name: String,
        tx: Sender<Event>,
    },

    /// Shutdown on receipt of this event.
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum PrefixSet {
    Underlay(HashSet<Ipv6Net>),
    Tunnel(HashSet<TunnelOrigin>),
    Rack(HashSet<RackPrefix>),
}

#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// Upon reception of this event, a state machine is to push the update to
    /// its peer.
    Push(ddm_protocol::v3::Update),

    /// Upon reception of this event, a state machine is to redistribute the
    /// update to it's sibling routers through it's event channels. The state
    /// machine is responsible for maintaining the path vector and performing
    /// loop breaking.
    Redistribute(ddm_protocol::v3::Update),
}

#[derive(Debug, Clone)]
pub enum NeighborEvent {
    /// An event sent from the discovery subsystem to the state machine letting
    /// it know the identity of the peer.
    Advertise(PeerIdentity),

    /// An event sent from the discovery subsystem to the state machine letting
    /// it know that solicitation has failed.
    SolicitFail,

    /// An event sent from the discovery subsystem to the state machine letting
    /// it know that the peer has expired.
    Expire,
}

// Peer events carry a full `Update` by value. Events are moved through
// channels at a low rate, so the size difference is not worth boxing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Event {
    Neighbor(NeighborEvent),
    Peer(PeerEvent),
    Admin(AdminEvent),
}

impl From<NeighborEvent> for Event {
    fn from(e: NeighborEvent) -> Self {
        Self::Neighbor(e)
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
    pub aobj_name: String,

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
    Exchange,
}

impl FsmState {
    pub fn to_peer_status(&self, elapsed: Duration) -> PeerStatus {
        match self {
            FsmState::Init => PeerStatus::Init(elapsed),
            FsmState::Solicit => PeerStatus::Solicit(elapsed),
            FsmState::Exchange => PeerStatus::Exchange(elapsed),
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
        write!(
            f,
            "PeerIdentity {{ addr={}, hostname={}, kind={}, version={} }}",
            self.addr, self.hostname, self.kind, self.version as u8,
        )
    }
}

/// Route advertisement allowances.
///
/// Indicates which route types may be advertised to a peer (true = allowed).
/// Allowances are granted as a function of our RouterKind and that of the peer
/// we're considering sending advertisements to.
#[derive(Clone)]
pub struct RouteAdvertisementAllowances {
    underlay: bool,
    tunnel: bool,
    rack: bool,
    redistributed: bool,
}

impl RouteAdvertisementAllowances {
    /// Calculate and return RouteAdvertisementAllowances
    pub fn new(my_kind: RouterKind, peer_kind: RouterKind) -> Self {
        use RouterKind::*;

        match (my_kind, peer_kind) {
            // Server-to-*:
            // Originate underlay and tunnel prefixes. Redistribute nothing.
            // XXX: Should Servers be allowed to originate tunnel prefixes?
            (Server, Server | Transit) => Self {
                underlay: true,
                tunnel: true,
                rack: false,
                redistributed: false,
            },

            // Transit-to-Server:
            // Originate underlay and tunnel prefixes. Redistribute everything.
            (Transit, Server) => Self {
                underlay: true,
                tunnel: true,
                rack: false,
                redistributed: true,
            },

            // Transit-to-Transit:
            // Originate rack prefixes. Redistribute nothing.
            (Transit, Transit) => Self {
                underlay: false,
                tunnel: false,
                rack: true,
                redistributed: false,
            },
        }
    }

    pub fn underlay(&self) -> bool {
        self.underlay
    }

    pub fn tunnel(&self) -> bool {
        self.tunnel
    }

    pub fn rack(&self) -> bool {
        self.rack
    }

    pub fn redistributed(&self) -> bool {
        self.redistributed
    }
}

pub struct InterfaceState {
    pub if_index: Mutex<u32>,
    pub if_name: Mutex<String>,
    pub external: bool,
    pub fsm_state: Mutex<FsmState>,
    pub last_fsm_state_change: Mutex<Instant>,
    pub peer_identity: Mutex<Option<PeerIdentity>>,
}

impl InterfaceState {
    pub fn external() -> Self {
        Self {
            external: true,
            ..Default::default()
        }
    }

    pub fn transition(&self, state: FsmState) {
        *lock!(self.fsm_state) = state;
        *lock!(self.last_fsm_state_change) = Instant::now();
    }

    pub fn clear_peer(&self) {
        *lock!(self.peer_identity) = None;
    }

    pub fn set_if_info(&self, index: u32, name: String) {
        *lock!(self.if_index) = index;
        *lock!(self.if_name) = name;
    }

    pub fn peer_status(&self) -> PeerStatus {
        let elapsed = lock!(self.last_fsm_state_change).elapsed();
        lock!(self.fsm_state).to_peer_status(elapsed)
    }
}

impl Default for InterfaceState {
    fn default() -> Self {
        Self {
            if_index: Mutex::new(0),
            if_name: Mutex::new(String::new()),
            external: false,
            fsm_state: Mutex::new(FsmState::Init),
            last_fsm_state_change: Mutex::new(Instant::now()),
            peer_identity: Mutex::new(None),
        }
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
    pub imported_underlay_prefixes: AtomicU64,
    pub imported_tunnel_endpoints: AtomicU64,
    pub imported_rack_prefixes: AtomicU64,
    pub update_send_fail: AtomicU64,
}

impl SessionStats {
    /// The current value of every counter.
    pub fn snapshot(&self) -> PeerStats {
        // compilation barrier. a new counter must be reported here.
        let Self {
            solicitations_sent,
            solicitations_received,
            advertisements_sent,
            advertisements_received,
            peer_expirations,
            peer_address_changes,
            peer_established,
            updates_sent,
            updates_received,
            imported_underlay_prefixes,
            imported_tunnel_endpoints,
            imported_rack_prefixes,
            update_send_fail,
        } = self;
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
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
            imported_underlay_prefixes: get(imported_underlay_prefixes),
            imported_tunnel_endpoints: get(imported_tunnel_endpoints),
            imported_rack_prefixes: get(imported_rack_prefixes),
        }
    }

    /// Set the imported counts to the routes `db` holds from `peer`.
    pub fn update_imported(&self, db: &Db, peer: Ipv6Addr) {
        let set =
            |c: &AtomicU64, n: usize| c.store(n as u64, Ordering::Relaxed);
        set(
            &self.imported_underlay_prefixes,
            db.imported_from(peer).len(),
        );
        set(
            &self.imported_tunnel_endpoints,
            db.imported_tunnel_from(peer).len(),
        );
        set(
            &self.imported_rack_prefixes,
            db.imported_rack_from(peer).len(),
        );
    }
}

#[derive(Clone)]
pub struct SmContext {
    pub config: Config,
    pub db: Db,
    pub tx: Sender<Event>,
    pub event_channels: BTreeMap<String, Sender<Event>>,
    pub rt: Arc<tokio::runtime::Handle>,
    pub router_id: String,
    pub iface: Arc<InterfaceState>,
    pub stats: Arc<SessionStats>,
    pub log: Logger,
    pub discovery_stop: Option<Arc<AtomicBool>>,
    pub first_run: bool,
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
    use super::*;
    use RouterKind::*;

    /// (local kind, peer kind, [underlay, tunnel, rack, redistributed])
    type Row = (RouterKind, RouterKind, [bool; 4]);

    /// The policy matrix, written out by hand rather than derived from
    /// `RouteAdvertisementAllowances::new`.
    const EXPECTED_ROUTE_ALLOWANCES: [Row; 4] = [
        // Servers originate their own prefixes and never redistribute.
        (Server, Server, [true, true, false, false]),
        (Server, Transit, [true, true, false, false]),
        // Transits pass everything they know down to servers, except the
        // rack aggregate, which only matters between racks.
        (Transit, Server, [true, true, false, true]),
        // Transits exchange only rack aggregates with each other.
        (Transit, Transit, [false, false, true, false]),
    ];

    #[test]
    fn route_advertisement_allowances() {
        let kinds = [Server, Transit];
        for local in kinds {
            for peer in kinds {
                let rows: Vec<_> = EXPECTED_ROUTE_ALLOWANCES
                    .iter()
                    .filter(|(l, p, _)| *l == local && *p == peer)
                    .collect();
                assert_eq!(rows.len(), 1, "{local} -> {peer}: expected 1 row");
                let expected = rows[0].2;

                let a = RouteAdvertisementAllowances::new(local, peer);
                let actual =
                    [a.underlay(), a.tunnel(), a.rack(), a.redistributed()];
                assert_eq!(actual, expected, "{local} -> {peer}");
            }
        }
    }
}
