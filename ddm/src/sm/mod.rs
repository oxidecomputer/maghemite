// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! State machine type definitions and the [`StateMachine`] handle. The
//! routing state machine implementation (discovery, solicit, exchange) lives
//! in the [`state`] submodule and is illumos-only, since it programs kernel
//! routes via [`crate::sys`] and reads interface addressing through `libnet`.

use crate::db::Db;
use crate::discovery::{self, Version};
use ddm_api_types::db::{PeerStatus, RouterKind};
use ddm_api_types::net::{MulticastOrigin, TunnelOrigin};
use ddm_protocol::RouterId;
use mg_common::lock;
use oxnet::Ipv6Net;
use slog::Logger;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard};
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

    /// Announce a set of multicast origins to peers.
    AnnounceMulticast(HashSet<MulticastOrigin>),

    /// Withdraw multicast origins already removed from the DB.
    ///
    /// The removal hits before this event gets enqueued, so a path snapshot
    /// taken at processing time observes it and any import in the meantime.
    WithdrawMulticast(HashSet<MulticastOrigin>),

    /// Expire the peer at the specified address
    Expire(Ipv6Addr),

    /// Synchronize with active peers by pulling their prefixes.
    Sync,

    /// A new external peer has been added to the router that can be reached
    /// using the provided sender.
    NewExternalPeer(Sender<Event>),

    /// Shutdown on receipt of this event.
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum PrefixSet {
    Underlay(HashSet<Ipv6Net>),
    Tunnel(HashSet<TunnelOrigin>),
}

#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// Upon reception of this event, a state machine is to push the update to
    /// its peer.
    Push(Arc<ddm_protocol::v4::Update>),

    /// Redistribute to sibling routers through the event channels.
    ///
    /// The state machine adds the underlay hop and checks for loops.
    /// Multicast announcements arrive with the local hop already appended.
    /// Sibling state machines reconcile the multicast update when dequeuing
    /// the push event.
    Redistribute {
        update: Arc<ddm_protocol::v4::Update>,
        session: Arc<ExchangeSession>,
        peer: Ipv6Addr,
    },

    /// Upon reception of this event, a state machine is to expire its peer,
    /// since a persistent HTTP status ended the pull's ability to retry, or
    /// the pull worker panicked. The event carries the session's stop flag
    /// and the peer address the pull targeted, so that a stale event cannot
    /// expire a later session or a renumbered peer.
    PullFailed {
        session: Arc<AtomicBool>,
        peer: Ipv6Addr,
    },
}

#[derive(Debug, Clone)]
pub enum NeighborEvent {
    /// An event sent from the discovery subsystem to the state machine letting
    /// it know the link local ipv6 address of the peer and it's version.
    Advertise((Ipv6Addr, Version)),

    /// An event sent from the discovery subsystem to the state machine letting
    /// it know that solicitation has failed.
    SolicitFail,

    /// An event sent from the discovery subsystem to the state machine letting
    /// it know that the peer has expired.
    Expire,
}

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
    pub router_id: RouterId,
    pub kind: RouterKind,
}

pub struct InterfaceState {
    pub if_index: Mutex<u32>,
    pub if_name: Mutex<String>,
    pub external: bool,
    pub fsm_state: Mutex<FsmState>,
    pub last_fsm_state_change: Mutex<Instant>,
    pub peer_identity: Mutex<Option<PeerIdentity>>,
    /// The current exchange session.
    ///
    /// Updates validate against the session and execute their DB changes while
    /// holding this lock, which serializes DB work for the interface.
    ///
    /// Expiry and version change replace the session under the same lock, and
    /// any subsequent update from the previous session is rejected.
    /// Expiry also drains in-flight updates. See [`ExchangeSession`] for how
    /// route programming is drained.
    ///
    /// NOTE: discovery must not take this lock.
    pub session: Mutex<Option<Arc<ExchangeSession>>>,
}

/// The negotiated version and cancellation flag for one exchange session
/// with a peer, from entering the exchange state until expiry or a version
/// change.
///
/// Two races motivate how updates are fenced against expiry and version
/// change:
///
/// 1. A push still running when the peer expires could import and install
///    routes after expiry has removed them, leaving forwarding state for a
///    peer that is gone. Pushes already running in `spawn_blocking` survive
///    an abort of the exchange server.
/// 2. Two updates on one interface (a push and a pull) could interleave
///    their DB changes. Tunnel programming diffs the route set before and
///    after its own import, and underlay programming chooses removals after
///    its own withdrawal. Either could program or remove the wrong routes.
///
/// ```text
///  update                   expiry
///  ------                   ------
///  session lock ───┐
///  validate        │
///  update guard ─┐ │
///  DB changes    │ │        cancel()
///  unlock ───────┼─┘
///  install routes│          session lock ─────┐
///  (stops once   │          drain_updates()   │
///   canceled)    │            ...waits...     │
///  enqueue       │                            │
///  release ──────┘                            │
///                           clear session     │
///                           remove DB routes  │
///                           unlock ───────────┘
///                           remove backend routes
/// ```
///
/// The session lock serializes DB changes, and route installation runs
/// outside it. Updates on one interface do not wait on each other's backend
/// calls.
///
/// Expiry cancels before draining: an in-flight update checks for
/// cancellation before installing each route. In-flight removals finish
/// their batches before the drain completes. Expiry's backend removal covers
/// any routes the update had installed before it stopped, since their DB
/// entries were written first.
///
/// A version change replaces the session without canceling or draining it.
/// The peer and its DB routes are unchanged. The exchange state retains the
/// replaced session, and expiry cancels and drains it alongside the current
/// one.
///
/// TODO: Route installation and redistribution from two in-flight updates
/// are not strictly ordered. When a push and a pull overlap on one
/// interface, or a previous-session update is still installing after a
/// version change, a subsequent update's removal can reach the backend or a
/// peer before an earlier update's add of the same route. The backend or
/// peer then disagrees with the DB until the next update or resync for that
/// route. Unicast has no periodic repair currently.
#[derive(Debug)]
pub struct ExchangeSession {
    pub version: Version,
    canceled: AtomicBool,
    updates: RwLock<()>,
}

impl ExchangeSession {
    pub fn new(version: Version) -> Self {
        Self {
            version,
            canceled: AtomicBool::new(false),
            updates: RwLock::new(()),
        }
    }

    pub fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
    }

    pub fn is_canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }

    pub fn canceled(&self) -> &AtomicBool {
        &self.canceled
    }

    /// Mark a single update as in flight until the guard is dropped.
    ///
    /// Updates take the guard under the session lock and hold onto it through
    /// route programming and redistribution.
    pub fn update_guard(&self) -> RwLockReadGuard<'_, ()> {
        self.updates.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Wait for in-flight updates to finish.
    ///
    /// Callers hold this session lock, and while this drains, new updates
    /// cannot pass validation.
    pub fn drain_updates(&self) {
        drop(self.updates.write().unwrap_or_else(|e| e.into_inner()));
    }
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

    /// Take the session lock, recovering it if a pull worker panicked while
    /// holding onto it.
    ///
    /// Updates never write to the session itself, which means that a poisoned
    /// guard still contains a valid value, and expiry must be able to proceed
    /// after the panic it's cleaning up.
    pub fn session(&self) -> MutexGuard<'_, Option<Arc<ExchangeSession>>> {
        self.session.lock().unwrap_or_else(|e| e.into_inner())
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
            session: Mutex::new(None),
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
    pub router_id: RouterId,
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

#[cfg(not(all(feature = "backend", target_os = "illumos")))]
impl StateMachine {
    pub fn run(&mut self) -> Result<(), SmError> {
        Ok(())
    }
}

/// Send an event to all channels in the list, removing any channels from the
/// list that are dead.
#[cfg(all(feature = "backend", target_os = "illumos"))]
pub(crate) fn send(e: Event, event_channels: &mut Vec<Sender<Event>>) {
    event_channels.retain(|c| c.send(e.clone()).is_ok());
}

#[cfg(test)]
mod tests {
    use super::InterfaceState;

    #[test]
    fn session_lock_recovers_from_a_panic_while_held() {
        let iface = InterfaceState::default();
        let res =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = iface.session();
                panic!("pull worker died mid-import");
            }));
        assert!(res.is_err());
        assert!(iface.session.is_poisoned());

        let _recovered = iface.session();
    }
}
