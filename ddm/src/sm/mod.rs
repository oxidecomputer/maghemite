// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! State machine type definitions and the [`StateMachine`] handle. The
//! routing state machine implementation (discovery, solicit, exchange) lives
//! in the `state` submodule and is illumos-only, since it programs kernel
//! routes via `crate::sys` and reads interface addressing through `libnet`.

use crate::db::Db;
use crate::discovery::{self, Version};
use ddm_api_types::db::{PeerStatus, RouterKind};
use ddm_api_types::net::{MulticastOrigin, TunnelOrigin};
use mg_common::lock;
use oxnet::Ipv6Net;
use slog::Logger;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

#[cfg(all(feature = "backend", target_os = "illumos"))]
mod state;

#[derive(Debug)]
pub enum AdminEvent {
    /// Announce a set of IPv6 prefixes
    Announce(PrefixSet),

    /// Withdraw a set of IPv6 prefixes
    Withdraw(PrefixSet),

    /// Announce a set of multicast origins to peers.
    AnnounceMulticast(HashSet<MulticastOrigin>),

    /// Withdraw a set of multicast origins. Each state machine revalidates
    /// remaining reachability against the database when it processes the
    /// event, rather than acting on a snapshot captured at request time.
    /// The modification lands before this event is enqueued, so the processing-
    /// time read is guaranteed to observe the withdrawal, and it also
    /// observes any later import that has since restored reachability.
    WithdrawMulticast(HashSet<MulticastOrigin>),

    /// Expire the peer at the specified address
    Expire(Ipv6Addr),

    /// Synchronize with active peers by pulling their prefixes.
    Sync,
}

#[derive(Debug)]
pub enum PrefixSet {
    Underlay(HashSet<Ipv6Net>),
    Tunnel(HashSet<TunnelOrigin>),
}

#[derive(Debug)]
pub enum PeerEvent {
    Push(Arc<ddm_protocol::v4::Update>),
}

#[derive(Debug)]
pub enum NeighborEvent {
    Advertise((Ipv6Addr, Version)),
    SolicitFail,
    Expire,
}

#[derive(Debug)]
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

    /// How long to wait between solicitations (milliseconds).
    pub solicit_interval: u64,

    /// How often to check for link failure while waiting for discovery messges.
    pub discovery_read_timeout: u64,

    /// How long to wait between attempts to get an IP address for a specified
    /// address object.
    pub ip_addr_wait: u64,

    /// How long to wait without a solicitation response before expiring a peer
    /// (milliseconds).
    pub expire_threshold: u64,

    /// How long to wait for a response to exchange messages.
    pub exchange_timeout: u64,

    /// The kind of router this is, server or transit.
    pub kind: RouterKind,

    /// TCP port to use for prefix exchange.
    pub exchange_port: u16,

    /// Dendrite dpd config
    pub dpd: Option<DpdConfig>,
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
}

pub struct InterfaceState {
    pub if_index: Mutex<u32>,
    pub if_name: Mutex<String>,
    pub fsm_state: Mutex<FsmState>,
    pub last_fsm_state_change: Mutex<Instant>,
    pub peer_identity: Mutex<Option<PeerIdentity>>,
    /// Orders route application with expiry and renumber cleanup for this
    /// interface. Discovery must not take this lock: route programming can
    /// perform network and kernel I/O, while discovery needs to keep updating
    /// peer liveness independently.
    pub route_update: Mutex<()>,
}

impl InterfaceState {
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
            fsm_state: Mutex::new(FsmState::Init),
            last_fsm_state_change: Mutex::new(Instant::now()),
            peer_identity: Mutex::new(None),
            route_update: Mutex::new(()),
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
    pub update_send_fail: AtomicU64,
}

#[derive(Clone)]
pub struct SmContext {
    pub config: Config,
    pub db: Db,
    pub tx: Sender<Event>,
    pub event_channels: Vec<Sender<Event>>,
    pub rt: Arc<tokio::runtime::Handle>,
    pub hostname: String,
    pub iface: Arc<InterfaceState>,
    pub stats: Arc<SessionStats>,
    /// Notifies the `crate::mcast` sweep that an underlay group's imported
    /// membership changed, by sending the group's address. The sweep wakes early
    /// to reconcile the group's DPD members, so the control plane never touches
    /// DPD directly.
    pub mcast_notify: tokio::sync::mpsc::Sender<Ipv6Addr>,
    pub log: Logger,
}

pub struct StateMachine {
    pub ctx: SmContext,
    pub rx: Option<Receiver<Event>>,
}
