// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::clock::Clock;
use crate::config::PeerConfig;
use crate::connection::{BgpConnection, MAX_MD5SIG_KEYLEN};
use crate::error::{Error, ExpectationMismatch};
use crate::fanout::Fanout;
use crate::messages::{
    AddPathElement, Afi, Capability, Community, ErrorCode, ErrorSubcode,
    Message, NotificationMessage, OpenMessage, OptionalParameter,
    PathAttributeValue, RouteRefreshMessage, Safi, UpdateMessage,
};
use crate::policy::{CheckerResult, ShaperResult};
use crate::router::Router;
use crate::{dbg, err, inf, to_canonical, trc, wrn};
use mg_common::{lock, read_lock, write_lock};
pub use rdb::DEFAULT_ROUTE_PRIORITY;
use rdb::{Asn, BgpPathProperties, Db, ImportExportPolicy, Prefix, Prefix4};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::collections::{BTreeSet, VecDeque};
use std::fmt::{self, Display, Formatter};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct PeerConnection<Cnx: BgpConnection> {
    conn: Cnx,
    id: u32,
}

/// The states a BGP finite state machine may be at any given time. Many
/// of these states carry a connection by value. This is the same connection
/// that moves from state to state as transitions are made. Transitions from
/// states with a connection to states without a connection drop the
/// connection.
#[derive(Debug)]
pub enum FsmState<Cnx: BgpConnection> {
    /// Initial state. Refuse all incomming BGP connections. No resources
    /// allocated to peer.
    ///
    /// Basic Transitions:
    /// - ManualStart | AutomaticStart -> Connect
    /// - PassiveManualStart | PassiveAutomaticStart -> Active
    Idle,

    /// Waiting for the TCP connection to be completed.
    ///
    /// Basic Transitions:
    /// - ManualStop -> Idle
    /// - ConnectRetryTimerExpire -> Connect
    /// - DelayOpenTimerExpire -> OpenSent
    /// - TcpConnectionConfirmed -> OpenSent (unless delay_open = true)
    /// - BgpOpen -> OpenConfirm (only during delay_open interval)
    Connect,

    /// Trying to acquire peer by listening for and accepting a TCP connection.
    Active(Cnx),

    /// Waiting for open message from peer.
    OpenSent(Cnx),

    /// Waiting for keepaliave or notification from peer.
    OpenConfirm(PeerConnection<Cnx>),

    /// Sync up with peers.
    SessionSetup(PeerConnection<Cnx>),

    /// Able to exchange update, notification and keepliave messages with peers.
    Established(PeerConnection<Cnx>),
}

impl<Cnx: BgpConnection> FsmState<Cnx> {
    fn kind(&self) -> FsmStateKind {
        FsmStateKind::from(self)
    }
}

impl<Cnx: BgpConnection> Display for FsmState<Cnx> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.kind())
    }
}

/// Simplified representation of a BGP state without having to carry a
/// connection.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema,
)]
pub enum FsmStateKind {
    /// Initial state. Refuse all incomming BGP connections. No resources
    /// allocated to peer.
    Idle,

    /// Waiting for the TCP connection to be completed.
    Connect,

    /// Trying to acquire peer by listening for and accepting a TCP connection.
    Active,

    /// Waiting for open message from peer.
    OpenSent,

    /// Waiting for keepaliave or notification from peer.
    OpenConfirm,

    /// Sync up with peers.
    SessionSetup,

    /// Able to exchange update, notification and keepliave messages with peers.
    Established,
}

impl Display for FsmStateKind {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            FsmStateKind::Idle => write!(f, "idle"),
            FsmStateKind::Connect => write!(f, "connect"),
            FsmStateKind::Active => write!(f, "active"),
            FsmStateKind::OpenSent => write!(f, "open sent"),
            FsmStateKind::OpenConfirm => write!(f, "open confirm"),
            FsmStateKind::SessionSetup => write!(f, "session setup"),
            FsmStateKind::Established => write!(f, "established"),
        }
    }
}

impl<Cnx: BgpConnection> From<&FsmState<Cnx>> for FsmStateKind {
    fn from(s: &FsmState<Cnx>) -> FsmStateKind {
        match s {
            FsmState::Idle => FsmStateKind::Idle,
            FsmState::Connect => FsmStateKind::Connect,
            FsmState::Active(_) => FsmStateKind::Active,
            FsmState::OpenSent(_) => FsmStateKind::OpenSent,
            FsmState::OpenConfirm(_) => FsmStateKind::OpenConfirm,
            FsmState::SessionSetup(_) => FsmStateKind::SessionSetup,
            FsmState::Established(_) => FsmStateKind::Established,
        }
    }
}

/// These are the events that drive state transitions in the BGP peer state
/// machine.
#[derive(Clone)]
pub enum FsmEvent<Cnx: BgpConnection> {
    /// A new message from the peer has been received.
    Message(Message),

    /// A connection to the peer has been made.
    Connected(Cnx),

    // Instructs peer to announce the update
    Announce(UpdateMessage),

    // The shaper for the router has changed. Event contains previous checker.
    // Current shaper is available in the router policy object.
    ShaperChanged(Option<rhai::AST>),

    /// Fires when export policy has changed.
    ExportPolicyChanged(ImportExportPolicy),

    // The checker for the router has changed. Event contains previous checker.
    // Current checker is available in the router policy object.
    CheckerChanged(Option<rhai::AST>),

    // Indicates the peer session should be reset.
    Reset,

    /// Local system administrator manually starts the peer connection.
    ManualStart,

    /// Local system administrator manually stops the peer connection
    ManualStop,

    /// Local system automatically starts the BGP connection
    AutomaticStart,

    /// Local system administrator manually starts the peer connection, but has
    /// [`Session::passive_tcp_establishment`] enabled which indicates that the
    /// peer wil listen prior to establishing the connection.
    PassiveManualStart,

    /// Local system automatically starts the BGP connection with the
    /// [`Session::passive_tcp_establishment`] enable which indicates that the
    /// peer will listen prior to establishing a connection.
    PassiveAutomaticStart,

    /// Local system automatically starts the BGP peer connection with peer
    /// oscillation damping enabled.
    DampedAutomaticStart,

    /// Local system automatically starts the BGP peer connection with peer
    /// oscillation and damping enabled and passive tcp establishment enabled.
    PassiveDampedAutomaticStart,

    /// Local system automatically stops connection.
    AutomaticStop,

    /// Fires when the [`Session::connect_retry_timer`] expires.
    ConnectRetryTimerExpires,

    /// Fires when the [`Session::hold_timer`] expires.
    HoldTimerExpires,

    /// Fires when the [`Session::keepalive_timer`] expires.
    KeepaliveTimerExpires,

    /// Fires when the [`Session::delay_open_timer`] expires.
    DelayOpenTimerExpires,

    /// Fires when the [`Session::idle_hold_timer`] expires.
    IdleHoldTimerExpires,

    /// Fires when the local system gets a TCP connection request with a valid
    /// source/destination IP address/port.
    TcpConnectionValid,

    /// Fires when the local syste gets a TCP connection request with an invalid
    /// source/destination IP address/port.
    TcpConnectionInvalid,

    /// Fires when the local systems tcp-syn recieved a syn-ack from the remote
    /// peer and the local system has sent an ack.
    TcpConnectionAcked,

    /// Fires when the local system as recieved the final ack in establishing a
    /// TCP connection with the peer.
    TcpConnectionConfirmed,

    /// Fires when the remote peer sends a TCP fin or the local connection times
    /// out.
    TcpConnectionFails,

    /// Fires when a valid BGP open message has been received.
    BgpOpen,

    /// Fires when a valid BGP open message has been received when
    /// [`Session::delay_open`] is set.
    DelayedBgpOpen,

    /// Fires when an invalid BGP header has been received.
    BgpHeaderErr,

    /// Fires when a BGP open message has been recieved with errors.
    BgpOpenMsgErr,

    /// Fires when a connection has been detected while processing an open
    /// message.
    OpenCollissionDump,

    /// Fires when a notification with a version error is received.
    NotifyMsgVerErr,

    /// Fires when a notify message is received.
    NotifyMsg,

    /// Fires when a keepalive message is received.
    KeepAliveMsg,

    /// Fires when an update message is received.
    UpdateMsg,

    /// Fires when an invalid update message is received.
    UpdateMsgErr,

    /// Fires when we need to ask the peer for a route refresh.
    RouteRefreshNeeded,

    /// Fires when path attributes have changed.
    PathAttributesChanged,
}

impl<Cnx: BgpConnection> fmt::Debug for FsmEvent<Cnx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => write!(f, "message {message:?}"),
            Self::Connected(_) => write!(f, "connected"),
            Self::Announce(update) => write!(f, "update {update:?}"),
            Self::ShaperChanged(_) => write!(f, "shaper changed"),
            Self::CheckerChanged(_) => write!(f, "checker changed"),
            Self::ExportPolicyChanged(_) => write!(f, "export policy changed"),
            Self::Reset => write!(f, "reset"),
            Self::ManualStart => write!(f, "manual start"),
            Self::ManualStop => write!(f, "manual stop"),
            Self::AutomaticStart => write!(f, "automatic start"),
            Self::PassiveManualStart => write!(f, "passive manual start"),
            Self::PassiveAutomaticStart => write!(f, "passive automatic start"),
            Self::DampedAutomaticStart => write!(f, "damped automatic start"),
            Self::PassiveDampedAutomaticStart => {
                write!(f, "passive admped automatic start")
            }
            Self::AutomaticStop => write!(f, "automatic stop"),
            Self::ConnectRetryTimerExpires => {
                write!(f, "connect retry time expires")
            }
            Self::HoldTimerExpires => write!(f, "hold timer expires"),
            Self::KeepaliveTimerExpires => write!(f, "keepalive timer expires"),
            Self::DelayOpenTimerExpires => {
                write!(f, "delay open timer expires")
            }
            Self::IdleHoldTimerExpires => write!(f, "idle hold timer expires"),
            Self::TcpConnectionValid => write!(f, "tcp connection valid"),
            Self::TcpConnectionInvalid => write!(f, "tcp connection invalid"),
            Self::TcpConnectionAcked => write!(f, "tcp connection acked"),
            Self::TcpConnectionConfirmed => {
                write!(f, "tcp connection confirmed")
            }
            Self::TcpConnectionFails => write!(f, "tcp connection fails"),
            Self::BgpOpen => write!(f, "bgp open"),
            Self::DelayedBgpOpen => write!(f, "delay bgp open"),
            Self::BgpHeaderErr => write!(f, "bgp header err"),
            Self::BgpOpenMsgErr => write!(f, "bgp open message error"),
            Self::OpenCollissionDump => write!(f, "open collission dump"),
            Self::NotifyMsgVerErr => write!(f, "notify msg ver error"),
            Self::NotifyMsg => write!(f, "notify message"),
            Self::KeepAliveMsg => write!(f, "keepalive message"),
            Self::UpdateMsg => write!(f, "update message"),
            Self::UpdateMsgErr => write!(f, "update message error"),
            Self::RouteRefreshNeeded => write!(f, "route refresh needed"),
            Self::PathAttributesChanged => write!(f, "path attributes changed"),
        }
    }
}

// TODO break up into config/state objects.
/// Information about a session.
#[derive(Default, Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct SessionInfo {
    /// Track how many times a connection has been attempted.
    pub connect_retry_counter: u64,

    /// Passively wait for the remote BGP peer to establish a TCP connection.
    pub passive_tcp_establishment: bool,

    /// The ASN of the remote peer.
    pub remote_asn: Option<u32>,

    /// The ASN of the remote peer.
    pub remote_id: Option<u32>,

    /// Minimum acceptable TTL value for incomming BGP packets.
    pub min_ttl: Option<u8>,

    /// Md5 peer authentication key
    pub md5_auth_key: Option<String>,

    /// Multi-exit discriminator. This an optional attribute that is intended to
    /// be used on external eBGP sessions to discriminate among multiple exit or
    /// entry points to the same neighboring AS. The value of this attribute is
    /// a four-octet unsigned number, called a metric. All other factors being
    /// equal, the exit point with the lower metric should be preferred.
    pub multi_exit_discriminator: Option<u32>,

    /// Communities to be attached to updates sent over this session.
    pub communities: BTreeSet<u32>,

    /// Local preference attribute added to updates if this is an iBGP session
    pub local_pref: Option<u32>,

    /// Capabilities received from the peer.
    pub capabilities_received: BTreeSet<Capability>,

    /// Capabilities sent to the peer.
    pub capabilities_sent: BTreeSet<Capability>,

    /// Ensure that routes received from eBGP peers have the peer's ASN as the
    /// first element in the AS path.
    pub enforce_first_as: bool,

    /// Policy governing imported routes.
    pub allow_import: ImportExportPolicy,

    /// Policy governing exported routes.
    pub allow_export: ImportExportPolicy,

    /// Vlan tag to assign to data plane routes created by this session.
    pub vlan_id: Option<u16>,
}

impl SessionInfo {
    pub fn new() -> Arc<Mutex<SessionInfo>> {
        Arc::new(Mutex::new(SessionInfo::default()))
    }
}

/// Information about a neighbor (peer).
#[derive(Debug, Clone)]
pub struct NeighborInfo {
    pub name: Arc<Mutex<String>>,
    pub host: SocketAddr,
}

pub const MAX_MESSAGE_HISTORY: usize = 1024;

/// A message history entry is a BGP message with an associated timestamp
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistoryEntry {
    timestamp: chrono::DateTime<chrono::Utc>,
    message: Message,
}

/// Message history for a BGP session
#[derive(Default, Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistory {
    pub received: VecDeque<MessageHistoryEntry>,
    pub sent: VecDeque<MessageHistoryEntry>,
}

impl MessageHistory {
    fn receive(&mut self, msg: Message) {
        if self.received.len() >= MAX_MESSAGE_HISTORY {
            self.received.pop_back();
        }
        self.received.push_front(MessageHistoryEntry {
            message: msg,
            timestamp: chrono::Utc::now(),
        });
    }

    fn send(&mut self, msg: Message) {
        if self.sent.len() >= MAX_MESSAGE_HISTORY {
            self.sent.pop_back();
        }
        self.sent.push_front(MessageHistoryEntry {
            message: msg,
            timestamp: chrono::Utc::now(),
        });
    }
}

#[derive(Default)]
pub struct SessionCounters {
    pub keepalives_sent: AtomicU64,
    pub keepalives_received: AtomicU64,
    pub route_refresh_sent: AtomicU64,
    pub route_refresh_received: AtomicU64,
    pub opens_sent: AtomicU64,
    pub opens_received: AtomicU64,
    pub notifications_sent: AtomicU64,
    pub notifications_received: AtomicU64,
    pub updates_sent: AtomicU64,
    pub updates_received: AtomicU64,
    pub prefixes_advertised: AtomicU64,
    pub prefixes_imported: AtomicU64,
    pub idle_hold_timer_expirations: AtomicU64,
    pub hold_timer_expirations: AtomicU64,
    pub unexpected_update_message: AtomicU64,
    pub unexpected_keepalive_message: AtomicU64,
    pub unexpected_open_message: AtomicU64,
    pub update_nexhop_missing: AtomicU64,
    pub active_connections_accepted: AtomicU64,
    pub passive_connections_accepted: AtomicU64,
    pub connection_retries: AtomicU64,
    pub open_handle_failures: AtomicU64,
    pub transitions_to_idle: AtomicU64,
    pub transitions_to_connect: AtomicU64,
    pub transitions_to_active: AtomicU64,
    pub transitions_to_open_sent: AtomicU64,
    pub transitions_to_open_confirm: AtomicU64,
    pub transitions_to_session_setup: AtomicU64,
    pub transitions_to_established: AtomicU64,
    pub notification_send_failure: AtomicU64,
    pub open_send_failure: AtomicU64,
    pub keepalive_send_failure: AtomicU64,
    pub route_refresh_send_failure: AtomicU64,
    pub update_send_failure: AtomicU64,
}

pub enum ShaperApplication {
    Current,
    Difference(Option<rhai::AST>),
}

/// This is the top level object that tracks a BGP session with a peer.
pub struct SessionRunner<Cnx: BgpConnection> {
    /// A sender that can be used to send FSM events to this session. When a
    /// new connection is established, a copy of this sender is sent to the
    /// underlying BGP connection manager to send messages to the session
    /// runner as they are received.
    pub event_tx: Sender<FsmEvent<Cnx>>,

    /// Information about the neighbor this session is to peer with.
    pub neighbor: NeighborInfo,

    /// A log of the last `MAX_MESSAGE_HISTORY` messages. Keepalives are not
    /// included in message history.
    pub message_history: Arc<Mutex<MessageHistory>>,

    /// Counters for message types sent and received, state transitions, etc.
    pub counters: Arc<SessionCounters>,

    /// Clock that drives the state machine for this session.
    pub clock: Clock,

    pub session: Arc<Mutex<SessionInfo>>,
    event_rx: Receiver<FsmEvent<Cnx>>,
    state: Arc<Mutex<FsmStateKind>>,
    last_state_change: Mutex<Instant>,
    asn: Asn,
    id: u32,
    bind_addr: Option<SocketAddr>,
    shutdown: AtomicBool,
    running: AtomicBool,
    db: Db,
    fanout: Arc<RwLock<Fanout<Cnx>>>,
    router: Arc<Router<Cnx>>,

    log: Logger,
}

unsafe impl<Cnx: BgpConnection> Send for SessionRunner<Cnx> {}
unsafe impl<Cnx: BgpConnection> Sync for SessionRunner<Cnx> {}

impl<Cnx: BgpConnection + 'static> SessionRunner<Cnx> {
    /// Create a new BGP session runner. Only creates the session runner
    /// object. Must call `start` to begin the peering state machine.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connect_retry_time: Duration,
        keepalive_time: Duration,
        hold_time: Duration,
        idle_hold_time: Duration,
        delay_open_time: Duration,
        session: Arc<Mutex<SessionInfo>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
        event_tx: Sender<FsmEvent<Cnx>>,
        neighbor: NeighborInfo,
        asn: Asn,
        id: u32,
        resolution: Duration,
        bind_addr: Option<SocketAddr>,
        db: Db,
        fanout: Arc<RwLock<Fanout<Cnx>>>,
        router: Arc<Router<Cnx>>,
        log: Logger,
    ) -> SessionRunner<Cnx> {
        SessionRunner {
            session,
            event_rx,
            event_tx: event_tx.clone(),
            asn,
            id,
            neighbor,
            state: Arc::new(Mutex::new(FsmStateKind::Idle)),
            last_state_change: Mutex::new(Instant::now()),
            clock: Clock::new(
                resolution,
                connect_retry_time,
                keepalive_time,
                hold_time,
                idle_hold_time,
                delay_open_time,
                event_tx.clone(),
                log.clone(),
            ),
            bind_addr,
            log,
            shutdown: AtomicBool::new(false),
            running: AtomicBool::new(false),
            fanout,
            router,
            message_history: Arc::new(Mutex::new(MessageHistory::default())),
            counters: Arc::new(SessionCounters::default()),
            db,
        }
    }

    /// Request a peer session shutdown. Does not shut down the session right
    /// away. Simply sets a flag that the session is to be shut down which will
    /// be acted upon in the state machine loop.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// This is the BGP peer state machine entry point. This function only
    /// returns if a shutdown is requested.
    pub fn start(&self) {
        // Check if this session is already running.
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return;
        };

        self.initialize_capabilities();

        // Run the BGP peer state machine.
        dbg!(self; "starting peer state machine");
        let mut current = FsmState::<Cnx>::Idle;
        loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                self.on_shutdown();
                return;
            }

            // Check what state we are in and call the corresponding handler
            // function. All handler functions return the next state as their
            // return value, stash that in the `next_state` variable.
            //let current_state: FsmStateKind = (&current).into();
            let previous = current.kind();
            current = match current {
                FsmState::Idle => self.idle(),
                FsmState::Connect => self.on_connect(),
                FsmState::Active(conn) => self.on_active(conn),
                FsmState::OpenSent(conn) => self.on_open_sent(conn),
                FsmState::OpenConfirm(conn) => self.on_open_confirm(conn),
                FsmState::SessionSetup(conn) => self.session_setup(conn),
                FsmState::Established(conn) => self.on_established(conn),
            };

            // If we have made a state transition log that and update the
            // appropriate state variables.
            if current.kind() != previous {
                inf!(self; "{} -> {}", previous, current.kind());
                match current.kind() {
                    FsmStateKind::Idle => {
                        self.counters
                            .transitions_to_idle
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    FsmStateKind::Connect => {
                        self.counters
                            .transitions_to_connect
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    FsmStateKind::Active => {
                        self.counters
                            .transitions_to_active
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    FsmStateKind::OpenSent => {
                        self.counters
                            .transitions_to_open_sent
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    FsmStateKind::OpenConfirm => {
                        self.counters
                            .transitions_to_open_confirm
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    FsmStateKind::SessionSetup => {
                        self.counters
                            .transitions_to_session_setup
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    FsmStateKind::Established => {
                        self.counters
                            .transitions_to_established
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                *(lock!(self.state)) = current.kind();
                *(lock!(self.last_state_change)) = Instant::now();
            }
        }
    }

    fn initialize_capabilities(&self) {
        let mut session = lock!(self.session);
        session.capabilities_sent = BTreeSet::from([
            //Capability::RouteRefresh{},
            //Capability::EnhancedRouteRefresh{},
            Capability::MultiprotocolExtensions {
                afi: 1,  //IP
                safi: 1, //NLRI for unicast
            },
            //Capability::GracefulRestart{},
            Capability::AddPath {
                elements: BTreeSet::from([AddPathElement {
                    afi: 1,          //IP
                    safi: 1,         //NLRI for unicast
                    send_receive: 1, //receive
                }]),
            },
            Capability::RouteRefresh {},
        ]);
    }

    /// Initial state. Refuse all incomming BGP connections. No resources
    /// allocated to peer.
    fn idle(&self) -> FsmState<Cnx> {
        if lock!(self.clock.timers.idle_hold_timer).interval.is_zero() {
            return FsmState::Connect;
        } else {
            lock!(self.clock.timers.idle_hold_timer).enable();
        }

        let event = match self.event_rx.recv() {
            Ok(event) => event,
            Err(e) => {
                err!(self; "idle: event rx {e}");
                return FsmState::Idle;
            }
        };

        match event {
            FsmEvent::ManualStart => {
                if lock!(self.session).passive_tcp_establishment {
                    let conn = Cnx::new(
                        self.bind_addr,
                        self.neighbor.host,
                        self.log.clone(),
                    );
                    lock!(self.clock.timers.idle_hold_timer).disable();
                    FsmState::Active(conn)
                } else {
                    lock!(self.clock.timers.idle_hold_timer).disable();
                    FsmState::Connect
                }
            }
            FsmEvent::IdleHoldTimerExpires => {
                inf!(self; "idle hold time expire, attempting connect");
                self.counters
                    .idle_hold_timer_expirations
                    .fetch_add(1, Ordering::Relaxed);
                lock!(self.clock.timers.idle_hold_timer).disable();
                FsmState::Connect
            }
            FsmEvent::Message(Message::KeepAlive) => {
                self.counters
                    .unexpected_keepalive_message
                    .fetch_add(1, Ordering::Relaxed);
                wrn!(self; "unexpected keepalive message in idle");
                FsmState::Idle
            }
            FsmEvent::Message(Message::Open(_)) => {
                self.counters
                    .unexpected_open_message
                    .fetch_add(1, Ordering::Relaxed);
                wrn!(self; "unexpected open message in idle");
                FsmState::Idle
            }
            FsmEvent::Message(Message::Update(_)) => {
                self.counters
                    .unexpected_update_message
                    .fetch_add(1, Ordering::Relaxed);
                wrn!(self; "unexpected update message in idle");
                FsmState::Idle
            }
            x => {
                wrn!(self; "event {:?} not allowed in idle", x);
                FsmState::Idle
            }
        }
    }

    /// Waiting for the TCP connection to be completed.
    fn on_connect(&self) -> FsmState<Cnx> {
        lock!(self.session).connect_retry_counter = 0;
        lock!(self.clock.timers.connect_retry_timer).enable();

        let min_ttl = lock!(self.session).min_ttl;
        let md5_auth_key = lock!(self.session).md5_auth_key.clone();

        // Start with an initial connection attempt
        let conn =
            Cnx::new(self.bind_addr, self.neighbor.host, self.log.clone());
        if let Err(e) = conn.connect(
            self.event_tx.clone(),
            self.clock.resolution,
            min_ttl,
            md5_auth_key.clone(),
        ) {
            wrn!(self; "initial connect attempt failed: {e}");
        }
        loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                break FsmState::Idle;
            }
            let event = match self.event_rx.recv() {
                Ok(event) => event,
                Err(e) => {
                    err!(self; "on connect event rx: {e}");
                    continue;
                }
            };
            match event {
                FsmEvent::Reset => {
                    inf!(self; "exit connect due to reset");
                    lock!(self.session).connect_retry_counter = 0;
                    lock!(self.clock.timers.connect_retry_timer).disable();
                    return FsmState::Idle;
                }
                // If the connect retry timer fires, try to connect again.
                FsmEvent::ConnectRetryTimerExpires => {
                    self.counters
                        .connection_retries
                        .fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = conn.connect(
                        self.event_tx.clone(),
                        self.clock.resolution,
                        min_ttl,
                        md5_auth_key.clone(),
                    ) {
                        wrn!(self; "connect attempt failed: {e}");
                    }
                    lock!(self.session).connect_retry_counter += 1;
                }

                FsmEvent::Message(Message::Open(om)) => {
                    self.message_history
                        .lock()
                        .unwrap()
                        .receive(om.clone().into());
                    self.counters
                        .opens_received
                        .fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = self.handle_open(&conn, &om) {
                        wrn!(self; "failed to handle open message: {e}");
                        //TODO send a notification to the peer letting them know we are
                        //     rejecting the open message?
                        return FsmState::Active(conn);
                    }

                    // ACK the open with a reciprocal open and a keepalive and transition
                    // to open confirm.
                    if let Err(e) = self.send_open(&conn) {
                        err!(self; "send open failed {e}");
                        return FsmState::Idle;
                    }
                    self.send_keepalive(&conn);
                    return FsmState::OpenConfirm(PeerConnection {
                        conn,
                        id: om.id,
                    });
                }

                // The underlying connection has accepted a TCP connection
                // initiated by the peer.
                FsmEvent::Connected(accepted) => {
                    lock!(self.session).connect_retry_counter = 0;
                    lock!(self.clock.timers.connect_retry_timer).disable();
                    if let Err(e) = self.ensure_connection_policy(&accepted) {
                        err!(self; "{e}");
                        return FsmState::Idle;
                    }
                    inf!(self; "accepted connection from {}", accepted.peer());
                    if let Err(e) = self.send_open(&accepted) {
                        err!(self; "send open failed {e}");
                        return FsmState::Idle;
                    }
                    {
                        let ht = self.clock.timers.hold_timer.lock().unwrap();
                        ht.reset();
                        ht.enable();
                    }
                    self.counters
                        .passive_connections_accepted
                        .fetch_add(1, Ordering::Relaxed);
                    return FsmState::OpenSent(accepted);
                }

                // The the peer has accepted the TCP connection we have
                // initiated.
                FsmEvent::TcpConnectionConfirmed => {
                    lock!(self.session).connect_retry_counter = 0;
                    lock!(self.clock.timers.connect_retry_timer).disable();
                    if let Err(e) = self.ensure_connection_policy(&conn) {
                        err!(self; "{e}");
                        return FsmState::Idle;
                    }
                    inf!(self; "connected to {}", conn.peer());
                    if let Err(e) = self.send_open(&conn) {
                        err!(self; "send open failed {e}");
                        return FsmState::Idle;
                    }
                    {
                        let ht = self.clock.timers.hold_timer.lock().unwrap();
                        ht.reset();
                        ht.enable();
                    }
                    self.counters
                        .active_connections_accepted
                        .fetch_add(1, Ordering::Relaxed);
                    return FsmState::OpenSent(conn);
                }
                FsmEvent::Message(Message::KeepAlive) => {
                    self.counters
                        .unexpected_keepalive_message
                        .fetch_add(1, Ordering::Relaxed);
                    wrn!(self; "unexpected keep alive message in connect");
                }
                FsmEvent::Message(Message::Update(_)) => {
                    self.counters
                        .unexpected_update_message
                        .fetch_add(1, Ordering::Relaxed);
                    wrn!(self; "unexpected update message in connect");
                }
                // Some other event we don't care about fired, log it and carry
                // on.
                x => {
                    wrn!(self; "event {:?} not allowed in connect", x);
                    continue;
                }
            }
        }
    }

    /// Trying to acquire peer by listening for and accepting a TCP connection.
    fn on_active(&self, conn: Cnx) -> FsmState<Cnx> {
        let event = match self.event_rx.recv() {
            Ok(event) => event,
            Err(e) => {
                err!(self; "on active event rx: {e}");
                return FsmState::Active(conn);
            }
        };

        // The only thing we really care about in the active state is receiving
        // an open message from the peer.
        let om = match event {
            FsmEvent::Reset => {
                inf!(self; "exit active due to reset");
                return FsmState::Idle;
            }
            FsmEvent::Message(Message::Open(om)) => {
                self.message_history
                    .lock()
                    .unwrap()
                    .receive(om.clone().into());
                self.counters.opens_received.fetch_add(1, Ordering::Relaxed);
                om
            }
            FsmEvent::ConnectRetryTimerExpires => {
                inf!(self; "active: connect retry timer expired");
                self.counters
                    .connection_retries
                    .fetch_add(1, Ordering::Relaxed);
                return FsmState::Idle;
            }
            // The underlying connection has accepted a TCP connection
            // initiated by the peer.
            FsmEvent::Connected(accepted) => {
                if let Err(e) = self.ensure_connection_policy(&accepted) {
                    err!(self; "{e}");
                    return FsmState::Idle;
                }
                inf!(self; "active: accepted connection from {}", accepted.peer());
                if let Err(e) = self.send_open(&accepted) {
                    err!(self; "active: send open failed {e}");
                    return FsmState::Idle;
                }
                lock!(self.clock.timers.connect_retry_timer).disable();
                {
                    let ht = self.clock.timers.hold_timer.lock().unwrap();
                    ht.reset();
                    ht.enable();
                }
                lock!(self.session).connect_retry_counter = 0;
                lock!(self.clock.timers.connect_retry_timer).disable();
                self.counters
                    .passive_connections_accepted
                    .fetch_add(1, Ordering::Relaxed);
                return FsmState::OpenSent(accepted);
            }
            FsmEvent::IdleHoldTimerExpires => {
                self.counters
                    .idle_hold_timer_expirations
                    .fetch_add(1, Ordering::Relaxed);
                return FsmState::Active(conn);
            }
            FsmEvent::Message(Message::KeepAlive) => {
                self.counters
                    .unexpected_keepalive_message
                    .fetch_add(1, Ordering::Relaxed);
                wrn!(self; "unexpected keepalive message in active");
                return FsmState::Active(conn);
            }
            FsmEvent::Message(Message::Update(_)) => {
                self.counters
                    .unexpected_update_message
                    .fetch_add(1, Ordering::Relaxed);
                wrn!(self; "unexpected update message in active");
                return FsmState::Active(conn);
            }
            other => {
                wrn!(self;
                    "active: expected open message, received {:#?}, ignoring",
                    other);
                return FsmState::Active(conn);
            }
        };
        if let Err(e) = self.handle_open(&conn, &om) {
            wrn!(self; "failed to handle open message: {e}");
            //TODO send a notification to the peer letting them know we are
            //     rejecting the open message?
            return FsmState::Active(conn);
        }

        // ACK the open with a reciprocal open and a keepalive and transition
        // to open confirm.
        if let Err(e) = self.send_open(&conn) {
            err!(self; "send open failed {e}");
            return FsmState::Idle;
        }
        self.send_keepalive(&conn);
        FsmState::OpenConfirm(PeerConnection { conn, id: om.id })
    }

    /// Waiting for open message from peer.
    fn on_open_sent(&self, conn: Cnx) -> FsmState<Cnx> {
        let event = match self.event_rx.recv() {
            Ok(event) => event,
            Err(e) => {
                err!(self; "on open sent event rx: {e}");
                return FsmState::OpenSent(conn);
            }
        };

        // The only thing we really care about in the open sent state is
        // receiving a reciprocal open message from the peer.
        let om = match event {
            FsmEvent::Reset => {
                inf!(self; "exit open sent due to reset");
                return FsmState::Idle;
            }
            FsmEvent::Message(Message::Open(om)) => {
                self.message_history
                    .lock()
                    .unwrap()
                    .receive(om.clone().into());
                self.counters.opens_received.fetch_add(1, Ordering::Relaxed);
                om
            }
            FsmEvent::HoldTimerExpires => {
                wrn!(self; "open sent: hold timer expired");
                self.counters
                    .hold_timer_expirations
                    .fetch_add(1, Ordering::Relaxed);
                self.send_hold_timer_expired_notification(&conn);
                return FsmState::Idle;
            }
            FsmEvent::Message(Message::KeepAlive) => {
                self.counters
                    .unexpected_keepalive_message
                    .fetch_add(1, Ordering::Relaxed);
                wrn!(self; "unexpected keepalive message in open sent");
                return FsmState::Active(conn);
            }
            FsmEvent::Message(Message::Update(_)) => {
                self.counters
                    .unexpected_update_message
                    .fetch_add(1, Ordering::Relaxed);
                wrn!(self; "unexpected update message in open sent");
                return FsmState::Active(conn);
            }
            FsmEvent::Connected(accepted) => {
                // collision detection RFC 4271 6.8
                if lock!(self.session).remote_id.unwrap_or(0) > self.id {
                    lock!(self.session).connect_retry_counter = 0;
                    lock!(self.clock.timers.connect_retry_timer).disable();
                    if let Err(e) = self.ensure_connection_policy(&accepted) {
                        err!(self; "{e}");
                        return FsmState::Idle;
                    }
                    inf!(self; "accepted connection from {}", accepted.peer());
                    if let Err(e) = self.send_open(&accepted) {
                        err!(self; "send open failed {e}");
                        return FsmState::Idle;
                    }
                    {
                        let ht = self.clock.timers.hold_timer.lock().unwrap();
                        ht.reset();
                        ht.enable();
                    }
                    self.counters
                        .passive_connections_accepted
                        .fetch_add(1, Ordering::Relaxed);
                    return FsmState::OpenSent(accepted);
                } else {
                    return FsmState::Active(conn);
                }
            }
            other => {
                wrn!(
                    self;
                    "open sent: expected open, received {:#?}, ignoring", other
                );
                lock!(self.clock.timers.connect_retry_timer).enable();
                return FsmState::Active(conn);
            }
        };
        if let Err(e) = self.handle_open(&conn, &om) {
            match e {
                Error::PolicyCheckFailed => {
                    inf!(self; "{}", e)
                }
                e => {
                    wrn!(self; "failed to handle open message: {e}");
                    //TODO send a notification to the peer letting them know we are
                    //     rejecting the open message?
                    lock!(self.clock.timers.connect_retry_timer).enable();
                    self.counters
                        .open_handle_failures
                        .fetch_add(1, Ordering::Relaxed);
                    return FsmState::Active(conn);
                }
            }
        }

        // ACK the open with a keepalive and transition to open confirm.
        self.send_keepalive(&conn);
        FsmState::OpenConfirm(PeerConnection { conn, id: om.id })
    }

    /// Waiting for keepaliave or notification from peer.
    fn on_open_confirm(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        let event = match self.event_rx.recv() {
            Ok(event) => event,
            Err(e) => {
                err!(self; "on open confirm: event rx {e}");
                return FsmState::OpenConfirm(pc);
            }
        };
        match event {
            FsmEvent::Reset => {
                inf!(self; "exit open confirm due to reset");
                FsmState::Idle
            }
            // The peer has ACK'd our open message with a keepalive. Start the
            // session timers and enter session setup.
            FsmEvent::Message(Message::KeepAlive) => {
                {
                    let ht = self.clock.timers.hold_timer.lock().unwrap();
                    ht.reset();
                    ht.enable();
                }
                {
                    let kt = self.clock.timers.keepalive_timer.lock().unwrap();
                    kt.reset();
                    kt.enable();
                }
                self.counters
                    .keepalives_received
                    .fetch_add(1, Ordering::Relaxed);
                FsmState::SessionSetup(pc)
            }

            // Our open message has been rejected with a notifiction. Fail back
            // to the connect state, dropping the TCP connection.
            FsmEvent::Message(Message::Notification(m)) => {
                self.message_history
                    .lock()
                    .unwrap()
                    .receive(m.clone().into());
                wrn!(self; "notification received: {:#?}", m);
                lock!(self.session).connect_retry_counter += 1;
                self.clock.timers.hold_timer.lock().unwrap().disable();
                self.clock.timers.keepalive_timer.lock().unwrap().disable();
                self.counters
                    .notifications_received
                    .fetch_add(1, Ordering::Relaxed);
                FsmState::Idle
            }
            FsmEvent::HoldTimerExpires => {
                wrn!(self; "open sent: hold timer expired");
                self.clock.timers.hold_timer.lock().unwrap().disable();
                self.send_hold_timer_expired_notification(&pc.conn);
                self.counters
                    .hold_timer_expirations
                    .fetch_add(1, Ordering::Relaxed);
                FsmState::Idle
            }
            FsmEvent::Message(Message::Open(_)) => {
                self.counters
                    .unexpected_open_message
                    .fetch_add(1, Ordering::Relaxed);
                wrn!(self; "unexpected open message in open confirm");
                FsmState::Idle
            }
            FsmEvent::Message(Message::Update(_)) => {
                self.counters
                    .unexpected_update_message
                    .fetch_add(1, Ordering::Relaxed);
                wrn!(self; "unexpected update message in open confirm");
                FsmState::Idle
            }
            FsmEvent::Connected(accepted) => {
                // collision detection RFC 4271 6.8
                if lock!(self.session).remote_id.unwrap_or(0) > self.id {
                    lock!(self.session).connect_retry_counter = 0;
                    lock!(self.clock.timers.connect_retry_timer).disable();
                    if let Err(e) = self.ensure_connection_policy(&accepted) {
                        err!(self; "{e}");
                        return FsmState::Idle;
                    }
                    inf!(self; "accepted connection from {}", accepted.peer());
                    if let Err(e) = self.send_open(&accepted) {
                        err!(self; "send open failed {e}");
                        return FsmState::Idle;
                    }
                    {
                        let ht = self.clock.timers.hold_timer.lock().unwrap();
                        ht.reset();
                        ht.enable();
                    }
                    self.counters
                        .passive_connections_accepted
                        .fetch_add(1, Ordering::Relaxed);
                    FsmState::OpenSent(accepted)
                } else {
                    FsmState::OpenConfirm(pc)
                }
            }
            // An event we are not expecting, log it and re-enter this state.
            other => {
                wrn!(
                    self;
                    "event {:?} not expected in open confirm, ignoring", other
                );
                FsmState::OpenConfirm(pc)
            }
        }
    }

    /// Sync up with peers.
    fn session_setup(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        // Collect the prefixes this router is originating.
        let originated = match self.db.get_origin4() {
            Ok(value) => value,
            Err(e) => {
                //TODO possible death loop. Should we just panic here?
                err!(self; "failed to get originated from db: {e}");
                return FsmState::SessionSetup(pc);
            }
        };

        // Ensure the router has a fanout entry for this peer.
        let mut fanout = write_lock!(self.fanout);
        fanout.add_egress(
            self.neighbor.host.ip(),
            crate::fanout::Egress {
                event_tx: Some(self.event_tx.clone()),
                log: self.log.clone(),
            },
        );
        drop(fanout);

        self.send_keepalive(&pc.conn);

        // Send an update to our peer with the prefixes this router is
        // originating.
        if !originated.is_empty() {
            let mut update = UpdateMessage {
                path_attributes: self.router.base_attributes(),
                ..Default::default()
            };
            for p in originated {
                update.nlri.push(p.into());
            }
            read_lock!(self.fanout).send_all(&update);
            if let Err(e) =
                self.send_update(update, &pc.conn, ShaperApplication::Current)
            {
                err!(self; "sending update to peer failed {e}");
                return self.exit_established(pc);
            }
        }

        // Transition to the established state.
        FsmState::Established(pc)
    }

    fn originate_update(
        &self,
        pc: &PeerConnection<Cnx>,
        sa: ShaperApplication,
    ) -> anyhow::Result<()> {
        let originated = match self.db.get_origin4() {
            Ok(value) => value,
            Err(e) => {
                //TODO possible death loop. Should we just panic here?
                anyhow::bail!("failed to get originated from db: {e}");
            }
        };
        let mut update = UpdateMessage {
            path_attributes: self.router.base_attributes(),
            ..Default::default()
        };
        for p in originated {
            update.nlri.push(p.into());
        }
        if let Err(e) = self.send_update(update, &pc.conn, sa) {
            anyhow::bail!("shaper changed: sending update to peer failed {e}");
        }
        Ok(())
    }

    /// Able to exchange update, notification and keepliave messages with peers.
    fn on_established(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        let event = match self.event_rx.recv() {
            Ok(event) => event,
            Err(e) => {
                //TODO possible death loop. Should we just panic here? Is it
                // even possible to recover from an error here as it likely
                // means the channel is toast.
                err!(self; "on established: event rx {e}");
                return FsmState::Established(pc);
            }
        };
        match event {
            FsmEvent::Reset => {
                inf!(self; "exit established due to reset");
                self.exit_established(pc)
            }
            // When the keepliave timer fires, send a keepliave to the peer.
            FsmEvent::KeepaliveTimerExpires => {
                self.send_keepalive(&pc.conn);
                FsmState::Established(pc)
            }

            // If the hold timer fires, it means we've not received a keepalive
            // from the peer within the hold time - so exit the established
            // state and restart the peer FSM from the connect state.
            FsmEvent::HoldTimerExpires => {
                wrn!(self; "hold timer expired");
                self.counters
                    .hold_timer_expirations
                    .fetch_add(1, Ordering::Relaxed);
                self.send_hold_timer_expired_notification(&pc.conn);
                self.exit_established(pc)
            }

            // We've received an update message from the peer. Reset the hold
            // timer and apply the update to the RIB.
            FsmEvent::Message(Message::Update(m)) => {
                self.clock.timers.hold_timer.lock().unwrap().reset();
                inf!(self; "update received: {m:#?}");
                let peer_as = lock!(self.session).remote_asn.unwrap_or(0);
                self.apply_update(m.clone(), pc.id, peer_as);
                self.message_history.lock().unwrap().receive(m.into());
                self.counters
                    .updates_received
                    .fetch_add(1, Ordering::Relaxed);
                FsmState::Established(pc)
            }

            FsmEvent::Message(Message::RouteRefresh(m)) => {
                self.clock.timers.hold_timer.lock().unwrap().reset();
                inf!(self; "route refresh received: {m:#?}");
                self.message_history
                    .lock()
                    .unwrap()
                    .receive(m.clone().into());
                self.counters
                    .route_refresh_received
                    .fetch_add(1, Ordering::Relaxed);
                if let Err(e) = self.handle_refresh(m, &pc) {
                    err!(self; "handle refresh: {e:}");
                    self.exit_established(pc)
                } else {
                    FsmState::Established(pc)
                }
            }

            // We've received a notification from the peer. They are displeased
            // with us. Exit established and restart from the connect state.
            FsmEvent::Message(Message::Notification(m)) => {
                wrn!(self; "notification received: {m:#?}");
                self.message_history.lock().unwrap().receive(m.into());
                self.counters
                    .notifications_received
                    .fetch_add(1, Ordering::Relaxed);
                self.exit_established(pc)
            }

            // We've received a keepliave from the peer, reset the hold timer
            // and re-enter the established state.
            FsmEvent::Message(Message::KeepAlive) => {
                trc!(self; "keepalive received");
                self.counters
                    .keepalives_received
                    .fetch_add(1, Ordering::Relaxed);
                self.clock.timers.hold_timer.lock().unwrap().reset();
                FsmState::Established(pc)
            }

            // An announce request has come from the administrative API or
            // another peer session (redistribution). Send the update to our
            // peer.
            FsmEvent::Announce(update) => {
                if let Err(e) = self.send_update(
                    update,
                    &pc.conn,
                    ShaperApplication::Current,
                ) {
                    err!(self; "sending update to peer failed {e}");
                    return self.exit_established(pc);
                }
                FsmState::Established(pc)
            }

            FsmEvent::IdleHoldTimerExpires => FsmState::Established(pc),

            // On an unexpected message, log a warning and re-enter the
            // established state.
            FsmEvent::Message(Message::Open(_)) => {
                self.counters
                    .unexpected_open_message
                    .fetch_add(1, Ordering::Relaxed);
                wrn!(self; "unexpected open message in open established");
                FsmState::Established(pc)
            }

            FsmEvent::ShaperChanged(previous) => {
                match self.originate_update(
                    &pc,
                    ShaperApplication::Difference(previous),
                ) {
                    Err(e) => {
                        err!(self; "originate failed: {e}");
                        self.exit_established(pc)
                    }
                    Ok(()) => FsmState::Established(pc),
                }
            }

            FsmEvent::ExportPolicyChanged(previous) => {
                let originated = match self.db.get_origin4() {
                    Ok(value) => value,
                    Err(e) => {
                        //TODO possible death loop. Should we just panic here?
                        err!(self; "failed to get originated from db: {e}");
                        return FsmState::SessionSetup(pc);
                    }
                };
                let originated_before: BTreeSet<Prefix4> = match previous {
                    ImportExportPolicy::NoFiltering => {
                        originated.iter().cloned().collect()
                    }
                    ImportExportPolicy::Allow(list) => originated
                        .clone()
                        .into_iter()
                        .filter(|x| list.contains(&Prefix::from(*x)))
                        .collect(),
                };
                let session = lock!(self.session);
                let current = &session.allow_export;
                let originated_after: BTreeSet<Prefix4> = match current {
                    ImportExportPolicy::NoFiltering => {
                        originated.iter().cloned().collect()
                    }
                    ImportExportPolicy::Allow(list) => originated
                        .clone()
                        .into_iter()
                        .filter(|x| list.contains(&Prefix::from(*x)))
                        .collect(),
                };
                drop(session);

                let to_withdraw: BTreeSet<&Prefix4> =
                    originated_before.difference(&originated_after).collect();

                let to_announce: BTreeSet<&Prefix4> =
                    originated_after.difference(&originated_before).collect();

                if to_withdraw.is_empty() && to_announce.is_empty() {
                    return FsmState::Established(pc);
                }

                let update = UpdateMessage {
                    path_attributes: self.router.base_attributes(),
                    withdrawn: to_withdraw
                        .into_iter()
                        .map(|x| crate::messages::Prefix::from(*x))
                        .collect(),
                    nlri: to_announce
                        .into_iter()
                        .map(|x| crate::messages::Prefix::from(*x))
                        .collect(),
                };

                if let Err(e) = self.send_update(
                    update,
                    &pc.conn,
                    ShaperApplication::Current,
                ) {
                    err!(self; "sending update to peer failed {e}");
                    return self.exit_established(pc);
                }

                FsmState::Established(pc)
            }

            FsmEvent::PathAttributesChanged => {
                match self.originate_update(&pc, ShaperApplication::Current) {
                    Err(e) => {
                        err!(self; "originate failed: {e}");
                        self.exit_established(pc)
                    }
                    Ok(()) => FsmState::Established(pc),
                }
            }

            FsmEvent::RouteRefreshNeeded => {
                if let Some(remote_id) = lock!(self.session).remote_id {
                    self.db.mark_bgp_id_stale(remote_id);
                    self.send_route_refresh(&pc.conn);
                }
                FsmState::Established(pc)
            }

            FsmEvent::CheckerChanged(_previous) => {
                //TODO
                FsmState::Established(pc)
            }

            // Some unexpeted event, log and re-enter established.
            e => {
                wrn!(self; "unhandled event: {e:?}");
                FsmState::Established(pc)
            }
        }
    }

    // Housekeeping items to do when a session shutdown is requested.
    pub fn on_shutdown(&self) {
        inf!(self; "shutting down");

        // Go back to the beginning of the state machine.
        *(lock!(self.state)) = FsmStateKind::Idle;

        // Reset the shutdown signal and running flag.
        self.shutdown.store(false, Ordering::Release);
        self.running.store(false, Ordering::Release);

        inf!(self; "shutdown complete");
    }

    /// Send an event to the state machine driving this peer session.
    pub fn send_event(&self, e: FsmEvent<Cnx>) -> Result<(), Error> {
        self.event_tx
            .send(e)
            .map_err(|e| Error::ChannelSend(e.to_string()))
    }

    /// Handle an open message
    fn handle_open(&self, conn: &Cnx, om: &OpenMessage) -> Result<(), Error> {
        let mut remote_asn = om.asn as u32;
        let remote_id = om.id;
        for p in &om.parameters {
            if let OptionalParameter::Capabilities(caps) = p {
                for c in caps {
                    if let Capability::FourOctetAs { asn } = c {
                        remote_asn = *asn;
                    }
                }
            }
        }
        if let Some(expected_remote_asn) = lock!(self.session).remote_asn {
            if remote_asn != expected_remote_asn {
                self.send_notification(
                    conn,
                    ErrorCode::Open,
                    ErrorSubcode::Open(
                        crate::messages::OpenErrorSubcode::BadPeerAS,
                    ),
                );
                return Err(Error::UnexpectedAsn(ExpectationMismatch {
                    expected: expected_remote_asn,
                    got: remote_asn,
                }));
            }
        }
        if let Some(checker) =
            self.router.policy.checker.read().unwrap().as_ref()
        {
            match crate::policy::check_incoming_open(
                om.clone(),
                checker,
                remote_asn,
                self.neighbor.host.ip(),
                self.log.clone(),
            ) {
                Ok(result) => match result {
                    CheckerResult::Accept => {}
                    CheckerResult::Drop => {
                        return Err(Error::PolicyCheckFailed)
                    }
                },
                Err(e) => {
                    err!(self; "open checker exec: {e}");
                }
            }
        }
        {
            let mut session = lock!(self.session);
            session.remote_asn = Some(remote_asn);
            session.remote_id = Some(remote_id);
            session.capabilities_received = om.get_capabilities();
        }

        {
            let mut ht = self.clock.timers.hold_timer.lock().unwrap();
            let mut kt = self.clock.timers.keepalive_timer.lock().unwrap();
            let mut theirs = false;
            let requested = u64::from(om.hold_time);
            if requested > 0 {
                if requested < 3 {
                    self.send_notification(conn, ErrorCode::Open, ErrorSubcode::Open(
                        crate::messages::OpenErrorSubcode::UnacceptableHoldTime,
                    ));
                    return Err(Error::HoldTimeTooSmall);
                }
                if requested < ht.interval.as_secs() {
                    theirs = true;
                    ht.interval = Duration::from_secs(requested);
                    ht.reset();
                    // per BGP RFC section 10
                    kt.interval = Duration::from_secs(requested / 3);
                    kt.reset();
                }
            }
            if !theirs {
                ht.interval =
                    *lock!(self.clock.timers.hold_configured_interval);
                ht.reset();
                kt.interval =
                    *lock!(self.clock.timers.keepalive_configured_interval);
                kt.reset();
            }
        }
        Ok(())
    }

    /// Send a keepalive message to the session peer.
    fn send_keepalive(&self, conn: &Cnx) {
        trc!(self; "sending keepalive");
        if let Err(e) = conn.send(Message::KeepAlive) {
            err!(self; "failed to send keepalive {e}");
            self.counters
                .keepalive_send_failure
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters
                .keepalives_sent
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn send_route_refresh(&self, conn: &Cnx) {
        trc!(self; "sending route refresh");
        if let Err(e) = conn.send(Message::RouteRefresh(RouteRefreshMessage {
            afi: Afi::Ipv4 as u16,
            safi: Safi::NlriUnicast as u8,
        })) {
            err!(self; "failed to send route refresh {e}");
            self.counters
                .keepalive_send_failure
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters
                .keepalives_sent
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn send_hold_timer_expired_notification(&self, conn: &Cnx) {
        self.send_notification(
            conn,
            ErrorCode::HoldTimerExpired,
            ErrorSubcode::HoldTime(0),
        )
    }

    fn send_notification(
        &self,
        conn: &Cnx,
        error_code: ErrorCode,
        error_subcode: ErrorSubcode,
    ) {
        inf!(self; "sending notification {error_code:?}/{error_subcode:?}");
        let msg = Message::Notification(NotificationMessage {
            error_code,
            error_subcode,
            data: Vec::new(),
        });
        self.message_history.lock().unwrap().send(msg.clone());

        if let Err(e) = conn.send(msg) {
            err!(self; "failed to send notification {e}");
            self.counters
                .notification_send_failure
                .fetch_add(1, Ordering::Relaxed);
        }
        self.counters
            .notifications_sent
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Send an open message to the session peer.
    fn send_open(&self, conn: &Cnx) -> Result<(), Error> {
        let capabilities = lock!(self.session).capabilities_sent.clone();
        let mut msg = match self.asn {
            Asn::FourOctet(asn) => OpenMessage::new4(
                asn,
                self.clock
                    .timers
                    .hold_configured_interval
                    .lock()
                    .unwrap()
                    .as_secs() as u16,
                self.id,
            ),
            Asn::TwoOctet(asn) => OpenMessage::new2(
                asn,
                self.clock
                    .timers
                    .hold_configured_interval
                    .lock()
                    .unwrap()
                    .as_secs() as u16,
                self.id,
            ),
        };
        msg.add_capabilities(&capabilities);

        let mut out = Message::from(msg.clone());
        if let Some(shaper) = self.router.policy.shaper.read().unwrap().as_ref()
        {
            let peer_as = lock!(self.session).remote_asn.unwrap_or(0);
            match crate::policy::shape_outgoing_open(
                msg.clone(),
                shaper,
                peer_as,
                self.neighbor.host.ip(),
                self.log.clone(),
            ) {
                Ok(result) => match result {
                    ShaperResult::Emit(msg) => {
                        out = msg;
                    }
                    ShaperResult::Drop => {
                        return Ok(());
                    }
                },
                Err(e) => {
                    err!(self; "open shaper exec: {e}");
                }
            }
        }
        drop(msg);
        self.message_history.lock().unwrap().send(out.clone());

        self.counters.opens_sent.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = conn.send(out) {
            err!(self; "failed to send open {e}");
            self.counters
                .open_send_failure
                .fetch_add(1, Ordering::Relaxed);
            Err(e)
        } else {
            Ok(())
        }
    }

    fn is_ebgp(&self) -> bool {
        if let Some(remote) = self.session.lock().unwrap().remote_asn {
            if remote != self.asn.as_u32() {
                return true;
            }
        }
        false
    }

    fn is_ibgp(&self) -> bool {
        !self.is_ebgp()
    }

    fn shape_update(
        &self,
        update: UpdateMessage,
        shaper_application: ShaperApplication,
    ) -> Result<ShaperResult, Error> {
        match shaper_application {
            ShaperApplication::Current => self.shape_update_basic(update),
            ShaperApplication::Difference(previous) => {
                self.shape_update_differential(update, previous)
            }
        }
    }

    fn shape_update_basic(
        &self,
        update: UpdateMessage,
    ) -> Result<ShaperResult, Error> {
        if let Some(shaper) = self.router.policy.shaper.read().unwrap().as_ref()
        {
            let peer_as = lock!(self.session).remote_asn.unwrap_or(0);
            Ok(crate::policy::shape_outgoing_update(
                update.clone(),
                shaper,
                peer_as,
                self.neighbor.host.ip(),
                self.log.clone(),
            )?)
        } else {
            Ok(ShaperResult::Emit(update.into()))
        }
    }

    fn shape_update_differential(
        &self,
        update: UpdateMessage,
        previous: Option<rhai::AST>,
    ) -> Result<ShaperResult, Error> {
        let peer_as = lock!(self.session).remote_asn.unwrap_or(0);

        let former = match previous {
            Some(shaper) => crate::policy::shape_outgoing_update(
                update.clone(),
                &shaper,
                peer_as,
                self.neighbor.host.ip(),
                self.log.clone(),
            )?,
            None => ShaperResult::Emit(update.clone().into()),
        };

        let current = self.shape_update_basic(update)?;

        Ok(former.difference(&current))
    }

    /// Send an update message to the session peer.
    fn send_update(
        &self,
        mut update: UpdateMessage,
        conn: &Cnx,
        shaper_application: ShaperApplication,
    ) -> Result<(), Error> {
        let nexthop = to_canonical(match conn.local() {
            Some(sockaddr) => sockaddr.ip(),
            None => {
                wrn!(self; "connection has no local address");
                return Err(Error::Disconnected);
            }
        });

        update
            .path_attributes
            .push(PathAttributeValue::NextHop(nexthop).into());

        if let Some(med) = self.session.lock().unwrap().multi_exit_discriminator
        {
            update
                .path_attributes
                .push(PathAttributeValue::MultiExitDisc(med).into());
        }

        if self.is_ibgp() {
            update.path_attributes.push(
                PathAttributeValue::LocalPref(
                    self.session.lock().unwrap().local_pref.unwrap_or(0),
                )
                .into(),
            );
        }

        let cs: Vec<Community> = self
            .session
            .lock()
            .unwrap()
            .communities
            .clone()
            .into_iter()
            .map(Community::from)
            .collect();

        if !cs.is_empty() {
            update
                .path_attributes
                .push(PathAttributeValue::Communities(cs).into())
        }

        if let ImportExportPolicy::Allow(ref policy) =
            lock!(self.session).allow_export
        {
            let message_policy = policy
                .iter()
                .filter_map(|x| match x {
                    rdb::Prefix::V4(x) => Some(x),
                    _ => None,
                })
                .map(|x| crate::messages::Prefix::from(*x))
                .collect::<BTreeSet<crate::messages::Prefix>>();

            update.nlri.retain(|x| message_policy.contains(x));
            update.withdrawn.retain(|x| message_policy.contains(x));
        };

        let out = match self.shape_update(update, shaper_application)? {
            ShaperResult::Emit(msg) => msg,
            ShaperResult::Drop => return Ok(()),
        };

        self.message_history.lock().unwrap().send(out.clone());

        self.counters.updates_sent.fetch_add(1, Ordering::Relaxed);

        if let Err(e) = conn.send(out) {
            err!(self; "failed to send update {e}");
            self.counters
                .update_send_failure
                .fetch_add(1, Ordering::Relaxed);
            Err(e)
        } else {
            Ok(())
        }
    }

    /// Exit the established state. Remove prefixes received from the session
    /// peer from our RIB. Issue a withdraw to the peer and transition to back
    /// to the connect state.
    fn exit_established(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        lock!(self.session).connect_retry_counter += 1;
        self.clock.timers.hold_timer.lock().unwrap().disable();
        self.clock.timers.keepalive_timer.lock().unwrap().disable();

        write_lock!(self.fanout).remove_egress(self.neighbor.host.ip());

        // remove peer prefixes from db
        self.db.remove_peer_prefixes(pc.id);

        FsmState::Idle
    }

    /// Apply an update by adding it to our RIB.
    fn apply_update(&self, mut update: UpdateMessage, id: u32, peer_as: u32) {
        if let Err(e) = self.check_update(&update) {
            wrn!(
                self;
                "Update check failed for {:#?}: {e}. Ignoring",
                update,
            );
            return;
        }
        self.apply_static_update_policy(&mut update);

        if let Some(checker) =
            self.router.policy.checker.read().unwrap().as_ref()
        {
            match crate::policy::check_incoming_update(
                update.clone(),
                checker,
                peer_as,
                self.neighbor.host.ip(),
                self.log.clone(),
            ) {
                Ok(result) => match result {
                    CheckerResult::Accept => {}
                    CheckerResult::Drop => {
                        return;
                    }
                },
                Err(e) => {
                    err!(self; "update checker exec: {e}");
                }
            }
        }

        if let ImportExportPolicy::Allow(ref policy) =
            lock!(self.session).allow_import
        {
            let message_policy = policy
                .iter()
                .filter_map(|x| match x {
                    rdb::Prefix::V4(x) => Some(x),
                    _ => None,
                })
                .map(|x| crate::messages::Prefix::from(*x))
                .collect::<BTreeSet<crate::messages::Prefix>>();

            update.nlri.retain(|x| message_policy.contains(x));
            update.withdrawn.retain(|x| message_policy.contains(x));
        };

        self.update_rib(&update, id, peer_as);

        // NOTE: for now we are only acting as an edge router. This means we
        //       do not redistribute announcements. If this changes, uncomment
        //       the following to enable redistribution.
        //
        //    self.fanout_update(&update);
    }

    fn handle_refresh(
        &self,
        msg: RouteRefreshMessage,
        pc: &PeerConnection<Cnx>,
    ) -> Result<(), Error> {
        if msg.afi != Afi::Ipv4 as u16 {
            return Ok(());
        }
        let originated = match self.db.get_origin4() {
            Ok(value) => value,
            Err(e) => {
                err!(self; "failed to get originated from db: {e}");
                // This is not a protocol level issue
                return Ok(());
            }
        };
        if !originated.is_empty() {
            let mut update = UpdateMessage {
                path_attributes: self.router.base_attributes(),
                ..Default::default()
            };
            for p in originated {
                update.nlri.push(p.into());
            }
            read_lock!(self.fanout).send_all(&update);
            self.send_update(update, &pc.conn, ShaperApplication::Current)?;
        }
        Ok(())
    }

    /// Update this router's RIB based on an update message from a peer.
    fn update_rib(&self, update: &UpdateMessage, id: u32, peer_as: u32) {
        for w in &update.withdrawn {
            self.db.remove_peer_prefix(id, w.as_prefix4().into());
        }

        let originated = match self.db.get_origin4() {
            Ok(value) => value,
            Err(e) => {
                err!(self; "failed to get originated from db: {e}");
                Vec::new()
            }
        };

        if !update.nlri.is_empty() {
            let nexthop = match update.nexthop4() {
                Some(nh) => nh,
                None => {
                    wrn!(
                        self;
                        "update with nlri entries and no nexthop recieved {update:#?}"
                    );
                    self.counters
                        .update_nexhop_missing
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };

            for n in &update.nlri {
                let prefix = n.as_prefix4();
                // ignore prefixes we originate
                if originated.contains(&prefix) {
                    continue;
                }

                let mut as_path = Vec::new();
                if let Some(segments_list) = update.as_path() {
                    for segments in &segments_list {
                        as_path.extend(segments.value.iter());
                    }
                }

                let path = rdb::Path {
                    nexthop: nexthop.into(),
                    shutdown: update.graceful_shutdown(),
                    local_pref: update.local_pref(),
                    bgp: Some(BgpPathProperties {
                        origin_as: peer_as,
                        med: update.multi_exit_discriminator(),
                        stale: None,
                        id,
                        as_path,
                    }),
                    vlan_id: lock!(self.session).vlan_id,
                };

                if let Err(e) =
                    self.db.add_prefix_path(prefix.into(), path.clone(), false)
                {
                    err!(self; "failed to add path {:?} -> {:?}: {e}", prefix, path);
                }
            }
        }

        //TODO(IPv6) iterate through MpReachNlri attributes for IPv6
    }

    /// Perform a set of checks on an update to see if we can accept it.
    fn check_update(&self, update: &UpdateMessage) -> Result<(), Error> {
        self.check_for_self_in_path(update)?;
        self.check_v4_prefixes(update)?;
        self.check_nexthop_self(update)?;
        let info = lock!(self.session);
        if info.enforce_first_as {
            if let Some(peer_as) = info.remote_asn {
                self.enforce_first_as(update, peer_as)?;
            }
        }
        Ok(())
    }

    fn apply_static_update_policy(&self, update: &mut UpdateMessage) {
        if self.is_ebgp() {
            update.clear_local_pref()
        }
        if let Some(pref) = lock!(self.session).local_pref {
            update.set_local_pref(pref);
        }
    }

    /// Do not accept routes that have our ASN in the AS_PATH e.g., do
    /// path-vector routing not distance-vector routing.
    fn check_for_self_in_path(
        &self,
        update: &UpdateMessage,
    ) -> Result<(), Error> {
        let asn = match self.asn {
            Asn::TwoOctet(asn) => asn as u32,
            Asn::FourOctet(asn) => asn,
        };
        for pa in &update.path_attributes {
            let path = match &pa.value {
                PathAttributeValue::AsPath(segments) => segments,
                PathAttributeValue::As4Path(segments) => segments,
                _ => continue,
            };
            for segment in path {
                if segment.value.contains(&asn) {
                    wrn!(self; "self in AS path: {:?}", update);
                    return Err(Error::SelfLoopDetected);
                }
            }
        }
        Ok(())
    }

    //TODO similar check needed for v6 once we get full v6 support
    fn check_v4_prefixes(&self, update: &UpdateMessage) -> Result<(), Error> {
        for prefix in &update.nlri {
            if prefix.length == 0 {
                continue;
            }
            let first = prefix.value[0];
            // check 127.0.0.0/8, 224.0.0.0/4
            if (first == 127) || (first & 0xf0 == 224) {
                return Err(Error::InvalidNlriPrefix(prefix.as_prefix4()));
            }
        }
        Ok(())
    }

    fn check_nexthop_self(&self, update: &UpdateMessage) -> Result<(), Error> {
        // nothing to check when no prefixes presnt, and nexthop not required
        // for pure withdraw
        if update.nlri.is_empty() {
            return Ok(());
        }
        let nexthop = match update.nexthop4() {
            Some(nh) => nh,
            None => return Err(Error::MissingNexthop),
        };
        for prefix in &update.nlri {
            let prefix = prefix.as_prefix4();
            if prefix.length == 32 && prefix.value == nexthop {
                return Err(Error::NexthopSelf(prefix.value.into()));
            }
        }
        Ok(())
    }

    fn enforce_first_as(
        &self,
        update: &UpdateMessage,
        peer_as: u32,
    ) -> Result<(), Error> {
        let path = match update.as_path() {
            Some(path) => path,
            None => return Err(Error::MissingAsPath),
        };
        let path: Vec<u32> = path.into_iter().flat_map(|x| x.value).collect();
        if path.is_empty() {
            return Err(Error::EmptyAsPath);
        }

        if path[0] != peer_as {
            return Err(Error::EnforceAsFirst(peer_as, path));
        }

        Ok(())
    }

    // NOTE: for now we are only acting as an edge router. This means we
    //       do not redistribute announcements. So for now this function
    //       is unused. However, this may change in the future.
    #[allow(dead_code)]
    fn fanout_update(&self, update: &UpdateMessage) {
        let fanout = read_lock!(self.fanout);
        fanout.send(self.neighbor.host.ip(), update);
    }

    /// Return the current BGP peer state of this session runner.
    pub fn state(&self) -> FsmStateKind {
        *lock!(self.state)
    }

    /// Return the learned remote ASN of the peer (if any).
    pub fn remote_asn(&self) -> Option<u32> {
        lock!(self.session).remote_asn
    }

    /// Return how long the BGP peer state machine has been in the current
    /// state.
    pub fn current_state_duration(&self) -> Duration {
        lock!(self.last_state_change).elapsed()
    }

    pub fn ensure_connection_policy(&self, conn: &Cnx) -> anyhow::Result<()> {
        if let Some(md5_key) = lock!(self.session).md5_auth_key.clone() {
            let mut key = [0u8; MAX_MD5SIG_KEYLEN];
            let len = md5_key.len();
            if len > MAX_MD5SIG_KEYLEN {
                return Err(anyhow::anyhow!(
                    "md5 key too long, max size is {}",
                    MAX_MD5SIG_KEYLEN
                ));
            }
            key[..len].copy_from_slice(md5_key.as_bytes());
            if let Err(e) = conn.set_md5_sig(len as u16, key) {
                return Err(anyhow::anyhow!("failed to set md5 key: {e}"));
            }
        }
        if let Some(ttl) = lock!(self.session).min_ttl {
            if let Err(e) = conn.set_min_ttl(ttl) {
                return Err(anyhow::anyhow!("failed to set min ttl: {e}"));
            }
        }

        Ok(())
    }

    pub fn update_session_parameters(
        &self,
        cfg: PeerConfig,
        info: SessionInfo,
    ) -> Result<(), Error> {
        let mut reset_needed = self.update_session_config(cfg)?;
        reset_needed |= self.update_session_info(info)?;

        if reset_needed {
            self.event_tx
                .send(FsmEvent::Reset)
                .map_err(|e| Error::EventSend(e.to_string()))?;
        }

        Ok(())
    }

    pub fn update_session_config(
        &self,
        cfg: PeerConfig,
    ) -> Result<bool, Error> {
        *lock!(self.neighbor.name) = cfg.name;
        let mut reset_needed = false;

        if self.neighbor.host != cfg.host {
            return Err(Error::PeerAddressUpdate);
        }

        if cfg.keepalive >= cfg.hold_time {
            return Err(Error::KeepaliveLargerThanHoldTime);
        }

        let mut hold_time = lock!(self.clock.timers.hold_configured_interval);
        if hold_time.as_secs() != cfg.hold_time {
            *hold_time = Duration::from_secs(cfg.hold_time);
            reset_needed = true;
        }

        let mut keepalive =
            lock!(self.clock.timers.keepalive_configured_interval);
        if keepalive.as_secs() != cfg.keepalive {
            *keepalive = Duration::from_secs(cfg.keepalive);
            reset_needed = true;
        }

        lock!(self.clock.timers.idle_hold_timer).interval =
            Duration::from_secs(cfg.idle_hold_time);

        lock!(self.clock.timers.delay_open_timer).interval =
            Duration::from_secs(cfg.delay_open);

        lock!(self.clock.timers.connect_retry_timer).interval =
            Duration::from_secs(cfg.connect_retry);

        Ok(reset_needed)
    }

    pub fn update_session_info(
        &self,
        info: SessionInfo,
    ) -> Result<bool, Error> {
        let mut reset_needed = false;
        let mut path_attributes_changed = false;
        let mut refresh_needed = false;
        let mut current = lock!(self.session);

        current.connect_retry_counter = info.connect_retry_counter;
        current.passive_tcp_establishment = info.passive_tcp_establishment;

        if current.remote_asn != info.remote_asn {
            current.remote_asn = info.remote_asn;
            reset_needed = true;
        }

        if current.min_ttl != info.min_ttl {
            current.min_ttl = info.min_ttl;
            reset_needed = true;
        }

        if current.md5_auth_key != info.md5_auth_key {
            current.md5_auth_key = info.md5_auth_key;
            reset_needed = true;
        }

        if current.multi_exit_discriminator != info.multi_exit_discriminator {
            current.multi_exit_discriminator = info.multi_exit_discriminator;
            path_attributes_changed = true;
        }

        if current.communities != info.communities {
            current.communities.clone_from(&info.communities);
            path_attributes_changed = true;
        }

        if current.local_pref != info.local_pref {
            current.local_pref = info.local_pref;
            refresh_needed = true;
        }

        if current.enforce_first_as != info.enforce_first_as {
            current.enforce_first_as = info.enforce_first_as;
            reset_needed = true;
        }

        if current.allow_import != info.allow_import {
            current.allow_import = info.allow_import;
            refresh_needed = true;
        }

        if current.allow_export != info.allow_export {
            let previous = current.allow_export.clone();
            current.allow_export = info.allow_export;
            drop(current);
            self.event_tx
                .send(FsmEvent::ExportPolicyChanged(previous))
                .map_err(|e| Error::EventSend(e.to_string()))?;
        } else {
            drop(current);
        }

        if path_attributes_changed {
            self.event_tx
                .send(FsmEvent::PathAttributesChanged)
                .map_err(|e| Error::EventSend(e.to_string()))?;
        }

        if refresh_needed {
            self.event_tx
                .send(FsmEvent::RouteRefreshNeeded)
                .map_err(|e| Error::EventSend(e.to_string()))?;
        }

        Ok(reset_needed)
    }
}
