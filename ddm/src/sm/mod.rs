// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! State machine type definitions and the [`StateMachine`] handle. The
//! routing state machine implementation (discovery, solicit, exchange) lives
//! in the [`state`] submodule and is illumos-only, since it programs kernel
//! routes via [`crate::sys`] and reads interface addressing through `libnet`.

use crate::db::Db;
use crate::discovery::Version;
use ddm_api_types::db::{
    InterfaceInfo, InterfaceStats, PeerIdentity, PeerStatus, RouterKind,
};
use ddm_api_types::net::TunnelOrigin;
use iddqd::{IdOrdItem, id_upcast};
use mg_common::{lock, read_lock};
use oxnet::Ipv6Net;
use slog::Logger;
use std::collections::{BTreeMap, HashSet};
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

pub mod overseer;
#[cfg(all(feature = "backend", target_os = "illumos"))]
mod state;
pub use overseer::Overseer;

#[derive(Debug)]
pub enum AdminEvent {
    /// Announce a set of IPv6 prefixes
    Announce(PrefixSet),

    /// Withdraw a set of IPv6 prefixes
    Withdraw(PrefixSet),

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
    Push(ddm_protocol::v3::Update),
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
    /// Tear this state machine down and exit its thread.
    Shutdown,
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

#[derive(Clone)]
pub struct Config {
    /// Interface this state machine is associated with.
    pub if_index: u32,

    /// Interface name this state machine is associated with. The interface
    /// must carry an IPv6 link-local address, which is resolved in `Init`.
    pub if_name: String,

    /// Link local Ipv6 address this state machine is associated with
    pub addr: Ipv6Addr,

    /// How long to wait between solicitations (milliseconds).
    pub solicit_interval: u64,

    /// How often to check for link failure while waiting for discovery messges.
    pub discovery_read_timeout: u64,

    /// How long to wait between attempts to find a link-local IPv6 address
    /// on the interface.
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

pub struct InterfaceState {
    pub if_index: Mutex<u32>,
    pub if_name: Mutex<String>,
    pub addr: Mutex<Ipv6Addr>,
    pub fsm_state: Mutex<FsmState>,
    pub last_fsm_state_change: Mutex<Instant>,
    pub peer_identity: Mutex<Option<PeerIdentity>>,
}

impl InterfaceState {
    pub fn transition(&self, state: FsmState) {
        *lock!(self.fsm_state) = state;
        *lock!(self.last_fsm_state_change) = Instant::now();
    }

    pub fn clear_peer(&self) {
        *lock!(self.peer_identity) = None;
    }

    pub fn set_if_info(&self, index: u32, name: String, addr: Ipv6Addr) {
        *lock!(self.if_index) = index;
        *lock!(self.if_name) = name;
        *lock!(self.addr) = addr;
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
            addr: Mutex::new(Ipv6Addr::UNSPECIFIED),
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
    pub update_send_fail: AtomicU64,
}

impl SessionStats {
    fn snapshot(&self) -> InterfaceStats {
        InterfaceStats {
            solicitations_sent: self.solicitations_sent.load(Ordering::Relaxed),
            solicitations_received: self
                .solicitations_received
                .load(Ordering::Relaxed),
            advertisements_sent: self
                .advertisements_sent
                .load(Ordering::Relaxed),
            advertisements_received: self
                .advertisements_received
                .load(Ordering::Relaxed),
            peer_expirations: self.peer_expirations.load(Ordering::Relaxed),
            peer_address_changes: self
                .peer_address_changes
                .load(Ordering::Relaxed),
            peer_established: self.peer_established.load(Ordering::Relaxed),
            updates_sent: self.updates_sent.load(Ordering::Relaxed),
            updates_received: self.updates_received.load(Ordering::Relaxed),
            imported_underlay_prefixes: self
                .imported_underlay_prefixes
                .load(Ordering::Relaxed),
            imported_tunnel_endpoints: self
                .imported_tunnel_endpoints
                .load(Ordering::Relaxed),
            update_send_fail: self.update_send_fail.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone)]
pub struct SmContext {
    pub config: Config,
    pub db: Db,
    pub tx: Sender<Event>,
    pub event_channels: Arc<RwLock<BTreeMap<String, Sender<Event>>>>,
    pub rt: tokio::runtime::Handle,
    pub hostname: String,
    pub iface: Arc<InterfaceState>,
    pub stats: Arc<SessionStats>,
    pub log: Logger,
}

impl SmContext {
    /// Snapshot the event senders for every other state machine.
    pub fn peer_channels(&self) -> Vec<(String, Sender<Event>)> {
        read_lock!(self.event_channels)
            .iter()
            .filter(|(name, _)| name.as_str() != self.config.if_name)
            .map(|(name, tx)| (name.clone(), tx.clone()))
            .collect()
    }

    pub fn interface_info(&self) -> InterfaceInfo {
        let status = self.iface.peer_status();
        let peer = lock!(self.iface.peer_identity).clone();
        InterfaceInfo {
            name: lock!(self.iface.if_name).clone(),
            addr: *lock!(self.iface.addr),
            status,
            peer,
            stats: self.stats.snapshot(),
        }
    }
}

pub struct StateMachine {
    pub ctx: SmContext,
    #[cfg_attr(
        not(all(feature = "backend", target_os = "illumos")),
        allow(dead_code)
    )]
    thread: Option<std::thread::JoinHandle<()>>,
    #[cfg_attr(
        not(all(feature = "backend", target_os = "illumos")),
        allow(dead_code)
    )]
    stop: Stop,
}

impl IdOrdItem for StateMachine {
    type Key<'a> = &'a str;

    fn key(&self) -> Self::Key<'_> {
        &self.ctx.config.if_name
    }

    id_upcast!();
}

/// A cancellation flag that wakes sleeping threads when set.
#[derive(Clone, Default)]
pub struct Stop(Arc<(Mutex<bool>, Condvar)>);

impl Stop {
    pub fn set(&self) {
        *lock!(self.0.0) = true;
        self.0.1.notify_all();
    }

    pub fn is_set(&self) -> bool {
        *lock!(self.0.0)
    }

    /// Wait for up to `duration`, returning whether the flag was set.
    pub fn wait(&self, duration: Duration) -> bool {
        let guard = lock!(self.0.0);
        let (guard, _) = self
            .0
            .1
            .wait_timeout_while(guard, duration, |stopped| !*stopped)
            .expect("stop condvar");
        *guard
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ddm_api_types::db::RouterKind;
    use mg_common::{read_lock, write_lock};
    use std::net::Ipv6Addr;
    use std::sync::OnceLock;
    use std::sync::mpsc;

    // A single shared runtime lives for the duration of the test binary.
    // SmContext holds a Handle; without a live runtime the handle would
    // be invalid, but our tests never drive any async work through it.
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

    fn rt_handle() -> tokio::runtime::Handle {
        let rt = RT.get_or_init(|| tokio::runtime::Runtime::new().unwrap());
        rt.handle().clone()
    }

    fn make_ctx(if_name: &str) -> SmContext {
        let (tx, _rx) = mpsc::channel();
        SmContext {
            config: Config {
                if_name: if_name.to_string(),
                if_index: 0,
                addr: Ipv6Addr::UNSPECIFIED,
                solicit_interval: 0,
                discovery_read_timeout: 0,
                ip_addr_wait: 0,
                expire_threshold: 0,
                exchange_timeout: 0,
                exchange_port: 0,
                kind: RouterKind::Server,
                dpd: None,
            },
            db: crate::db::Db::new_for_test(),
            tx,
            event_channels: Arc::new(RwLock::new(BTreeMap::new())),
            rt: rt_handle(),
            hostname: String::new(),
            iface: Arc::new(InterfaceState::default()),
            stats: Arc::new(SessionStats::default()),
            log: slog::Logger::root(slog::Discard, slog::o!()),
        }
    }

    #[test]
    fn interface_info_uses_shared_initialized_address() {
        let ctx = make_ctx("eth0");
        let addr = "fe80::1234".parse().unwrap();
        ctx.iface.set_if_info(7, "net0".to_string(), addr);

        let info = ctx.interface_info();
        assert_eq!(info.name, "net0");
        assert_eq!(info.addr, addr);
    }

    // event_channels is Arc<RwLock<...>>, so all clones of an SmContext see
    // updates to the shared sender mesh.

    #[test]
    fn event_channels_shared_across_clones() {
        let ctx = make_ctx("eth0");
        let clone = ctx.clone();

        let (tx, _rx) = mpsc::channel::<Event>();
        write_lock!(ctx.event_channels).insert("eth1".to_string(), tx);

        assert_eq!(read_lock!(clone.event_channels).len(), 1);
    }

    #[test]
    fn peer_channels_excludes_self() {
        let mut a = make_ctx("eth0");
        let mut b = make_ctx("eth1");
        let mesh = Arc::new(RwLock::new(BTreeMap::new()));
        a.event_channels = mesh.clone();
        b.event_channels = mesh.clone();
        write_lock!(mesh).insert("eth0".to_string(), a.tx.clone());
        write_lock!(mesh).insert("eth1".to_string(), b.tx.clone());

        assert_eq!(a.peer_channels()[0].0, "eth1");
        assert_eq!(b.peer_channels()[0].0, "eth0");
    }

    #[test]
    fn stop_wait_wakes_when_set() {
        let stop = Stop::default();
        let waiter = stop.clone();
        let thread =
            std::thread::spawn(move || waiter.wait(Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(10));
        stop.set();

        assert!(thread.join().unwrap());
    }

    #[test]
    fn stop_wait_times_out_when_unset() {
        assert!(!Stop::default().wait(Duration::from_millis(1)));
    }
}
