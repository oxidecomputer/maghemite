// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::clock::SessionClock;
use crate::config::PeerConfig;
use crate::connection::{
    BgpConnection, BgpConnector, ConnectionCreator, ConnectionId,
};
use crate::error::{Error, ExpectationMismatch};
use crate::fanout::Fanout;
use crate::log::{collision_log, session_log, session_log_lite};
use crate::messages::{
    AddPathElement, Afi, Capability, CeaseErrorSubcode, Community, ErrorCode,
    ErrorSubcode, Message, NotificationMessage, OpenMessage, OptionalParameter,
    PathAttributeValue, RouteRefreshMessage, Safi, UpdateMessage,
};
use crate::policy::{CheckerResult, ShaperResult};
use crate::router::Router;
use crossbeam_channel::{Receiver, Select, Sender};
use mg_common::{lock, read_lock, write_lock};
use rdb::{Asn, BgpPathProperties, Db, ImportExportPolicy, Prefix, Prefix4};
pub use rdb::{DEFAULT_RIB_PRIORITY_BGP, DEFAULT_ROUTE_PRIORITY};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Display, Formatter};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

const UNIT_SESSION_RUNNER: &str = "session_runner";

#[derive(Debug)]
pub struct PeerConnection<Cnx: BgpConnection> {
    conn: Cnx,
    id: u32,
}

pub enum CollisionPair<Cnx: BgpConnection> {
    OpenConfirm(PeerConnection<Cnx>, Cnx),
    OpenSent(Cnx, Cnx),
}

/// The states a BGP finite state machine may be at any given time. Many
/// of these states carry a connection by value. This is the same connection
/// that moves from state to state as transitions are made. Transitions from
/// states with a connection to states without a connection drop the
/// connection.
pub enum FsmState<Cnx: BgpConnection> {
    /// Initial state. Refuse all incoming BGP connections. No resources
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
    Active,

    /// Waiting for open message from peer.
    OpenSent(Cnx),

    /// Waiting for keepaliave or notification from peer.
    OpenConfirm(PeerConnection<Cnx>),

    /// Waiting for Open from incoming connection to perform Collision Resolution.
    CollisionDetection(CollisionPair<Cnx>),

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

    /// Handler for Connection Collisions (RFC 4271 6.8)
    CollisionDetection,

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
            FsmStateKind::CollisionDetection => {
                write!(f, "collision detection")
            }
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
            FsmState::Active => FsmStateKind::Active,
            FsmState::OpenSent(_) => FsmStateKind::OpenSent,
            FsmState::OpenConfirm(_) => FsmStateKind::OpenConfirm,
            FsmState::CollisionDetection(_) => FsmStateKind::CollisionDetection,
            FsmState::SessionSetup(_) => FsmStateKind::SessionSetup,
            FsmState::Established(_) => FsmStateKind::Established,
        }
    }
}

#[derive(Clone)]
pub enum AdminEvent {
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
    // XXX: We have handlers for this, but no senders. This is likely how we'll
    // want to implement `neighbor shutdown`.
    ManualStop,

    /// Fires when we need to ask the peer for a route refresh.
    SendRouteRefresh,

    /// Fires when we need to re-send our routes to the peer.
    ReAdvertiseRoutes,

    /// Fires when path attributes have changed.
    PathAttributesChanged,
}

impl fmt::Debug for AdminEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminEvent::Announce(update) => {
                write!(f, "announce {update:?}")
            }
            AdminEvent::ShaperChanged(_) => write!(f, "shaper changed"),
            AdminEvent::CheckerChanged(_) => write!(f, "checker changed"),
            AdminEvent::ExportPolicyChanged(_) => {
                write!(f, "export policy changed")
            }
            AdminEvent::Reset => write!(f, "reset"),
            AdminEvent::ManualStart => write!(f, "manual start"),
            AdminEvent::ManualStop => write!(f, "manual stop"),
            AdminEvent::SendRouteRefresh => {
                write!(f, "route refresh needed")
            }
            AdminEvent::ReAdvertiseRoutes => {
                write!(f, "re-advertise routes")
            }
            AdminEvent::PathAttributesChanged => {
                write!(f, "path attributes changed")
            }
        }
    }
}

impl AdminEvent {
    fn title(&self) -> &'static str {
        match self {
            AdminEvent::Announce(_) => "update",
            AdminEvent::ShaperChanged(_) => "shaper changed",
            AdminEvent::CheckerChanged(_) => "checker changed",
            AdminEvent::ExportPolicyChanged(_) => "export policy changed",
            AdminEvent::Reset => "reset",
            AdminEvent::ManualStart => "manual start",
            AdminEvent::ManualStop => "manual stop",
            AdminEvent::SendRouteRefresh => "route refresh needed",
            AdminEvent::ReAdvertiseRoutes => "re-advertise routes",
            AdminEvent::PathAttributesChanged => "path attributes changed",
        }
    }
}

/// FsmEvents pertaining to a specific Connection
pub enum ConnectionEvent {
    /// A new message from the peer has been received.
    Message { msg: Message, conn_id: ConnectionId },

    /// Fires when the connection's hold timer expires.
    HoldTimerExpires(ConnectionId),

    /// Fires when the connection's keepalive timer expires.
    KeepaliveTimerExpires(ConnectionId),

    /// Fires when the connection's delay open timer expires.
    DelayOpenTimerExpires(ConnectionId),
}

impl fmt::Debug for ConnectionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionEvent::Message { msg, conn_id } => {
                write!(f, "message {msg:?} from {}", conn_id.short())
            }
            ConnectionEvent::HoldTimerExpires(conn_id) => {
                write!(f, "hold timer expires for {}", conn_id.short())
            }
            ConnectionEvent::KeepaliveTimerExpires(conn_id) => {
                write!(f, "keepalive timer expires for {}", conn_id.short())
            }
            ConnectionEvent::DelayOpenTimerExpires(conn_id) => {
                write!(f, "delay open timer expires for {}", conn_id.short())
            }
        }
    }
}

impl ConnectionEvent {
    fn title(&self) -> &'static str {
        match self {
            ConnectionEvent::Message { .. } => "message",
            ConnectionEvent::HoldTimerExpires(_) => "hold timer expires",
            ConnectionEvent::KeepaliveTimerExpires(_) => {
                "keepalive timer expires"
            }
            ConnectionEvent::DelayOpenTimerExpires(_) => {
                "delay open timer expires"
            }
        }
    }
}

/// Session-level events that persist across connections
pub enum SessionEvent<Cnx: BgpConnection> {
    /// Fires when the session's connect retry timer expires.
    ConnectRetryTimerExpires,

    /// Fires when the session's idle hold timer expires.
    IdleHoldTimerExpires,

    /// A connection to the peer has been made. We use this event to indicate
    /// an inbound connection has completed.
    Connected(Cnx),

    /// Fires when the local system has received the final ack in establishing
    /// a TCP connection with the peer. We use this event to indicate an
    /// outbound connection has completed.
    TcpConnectionConfirmed(Cnx),
}

impl<Cnx: BgpConnection> fmt::Debug for SessionEvent<Cnx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionEvent::ConnectRetryTimerExpires => {
                write!(f, "connect retry timer expires")
            }
            SessionEvent::IdleHoldTimerExpires => {
                write!(f, "idle hold timer expires")
            }
            SessionEvent::Connected(_) => write!(f, "connected"),
            SessionEvent::TcpConnectionConfirmed(_) => {
                write!(f, "tcp connection confirmed")
            }
        }
    }
}

impl<Cnx: BgpConnection> SessionEvent<Cnx> {
    fn title(&self) -> &'static str {
        match self {
            SessionEvent::ConnectRetryTimerExpires => {
                "connect retry timer expires"
            }
            SessionEvent::IdleHoldTimerExpires => "idle hold timer expires",
            SessionEvent::Connected(_) => "connected",
            SessionEvent::TcpConnectionConfirmed(_) => {
                "tcp connection confirmed"
            }
        }
    }
}

/// These are the events that drive state transitions in the BGP peer state
/// machine. They are subdivided into event categories
pub enum FsmEvent<Cnx: BgpConnection> {
    /// Events triggered by an Administrative action
    Admin(AdminEvent),

    /// Events specific to a single Connection.
    Connection(ConnectionEvent),

    /// Session-level events that persist across connections
    Session(SessionEvent<Cnx>),
}

impl<Cnx: BgpConnection> fmt::Debug for FsmEvent<Cnx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admin(admin_event) => write!(f, "{admin_event:?}"),
            Self::Connection(connection_event) => {
                write!(f, "{connection_event:?}")
            }
            Self::Session(session_event) => write!(f, "{session_event:?}"),
        }
    }
}

impl<Cnx: BgpConnection> FsmEvent<Cnx> {
    pub fn title(&self) -> &str {
        match self {
            Self::Admin(admin_event) => admin_event.title(),
            Self::Connection(connection_event) => connection_event.title(),
            Self::Session(session_event) => session_event.title(),
        }
    }
}

/// FSM Events specified in RFC 4271 which we either don't implement or whose
/// implementations are carried out through other means.
#[allow(dead_code)]
pub enum UnusedEvent {
    /// Local system administrator manually starts the peer connection, but has
    /// [`Session::passive_tcp_establishment`] enabled which indicates that the
    /// peer wil listen prior to establishing the connection. Functionality is
    /// implemented via ManualStart when passive_tcp_establishment is enabled
    PassiveManualStart,

    /// Local system automatically starts the BGP connection
    AutomaticStart,

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

    /// Fires when the [`Session::delay_open_timer`] expires.
    DelayOpenTimerExpires,

    /// Fires when a valid BGP open message has been received.
    /// Implemented via Message::Open
    BgpOpen,

    /// Fires when a valid BGP open message has been received when
    /// [`Session::delay_open`] is set.
    DelayedBgpOpen,

    /// Fires when an invalid BGP header has been received.
    /// Implemented via error handling in BgpConnection::recv()
    BgpHeaderErr,

    /// Fires when a BGP open message has been recieved with errors.
    /// Implemented via error handling in handle_open()
    BgpOpenMsgErr,

    /// Fires when a notification with a version error is received.
    /// Implemented via error handling of Message::Notification
    NotifyMsgVerErr,

    /// Fires when a notify message is received.
    /// Implemented via Message::Notification
    NotifyMsg,

    /// Fires when a keepalive message is received.
    /// Implemented via Message::KeepAlive
    KeepAliveMsg,

    /// Fires when an update message is received.
    /// Implemented via Message::UpdateMessage
    UpdateMsg,

    /// Fires when an invalid update message is received.
    /// Implemented via error handling of Message::UpdateMessage
    UpdateMsgErr,

    /// Fires when the local system gets a TCP connection request with a valid
    /// source/destination IP address/port.
    TcpConnectionValid,

    /// Fires when the local syste gets a TCP connection request with an invalid
    /// source/destination IP address/port.
    TcpConnectionInvalid,

    /// Fires when the local systems tcp-syn recieved a syn-ack from the remote
    /// peer and the local system has sent an ack.
    TcpConnectionAcked,

    /// Fires when the remote peer sends a TCP fin or the local connection times
    /// out.
    TcpConnectionFails,

    /// Fires when a connection has been detected while processing an open
    /// message. We implement Collision handling in FsmState::CollisionDetection
    OpenCollisionDump,
}

impl fmt::Debug for UnusedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AutomaticStart => write!(f, "automatic start"),
            Self::PassiveManualStart => write!(f, "passive manual start"),
            Self::PassiveAutomaticStart => write!(f, "passive automatic start"),
            Self::DampedAutomaticStart => write!(f, "damped automatic start"),
            Self::PassiveDampedAutomaticStart => {
                write!(f, "passive damped automatic start")
            }
            Self::AutomaticStop => write!(f, "automatic stop"),
            Self::DelayOpenTimerExpires => {
                write!(f, "delay open timer expires")
            }
            Self::TcpConnectionValid => write!(f, "tcp connection valid"),
            Self::TcpConnectionInvalid => write!(f, "tcp connection invalid"),
            Self::TcpConnectionAcked => write!(f, "tcp connection acked"),
            Self::TcpConnectionFails => write!(f, "tcp connection fails"),
            Self::BgpOpen => write!(f, "bgp open"),
            Self::DelayedBgpOpen => write!(f, "delay bgp open"),
            Self::BgpHeaderErr => write!(f, "bgp header err"),
            Self::BgpOpenMsgErr => write!(f, "bgp open message error"),
            Self::OpenCollisionDump => write!(f, "open collission dump"),
            Self::NotifyMsgVerErr => write!(f, "notify msg ver error"),
            Self::NotifyMsg => write!(f, "notify message"),
            Self::KeepAliveMsg => write!(f, "keepalive message"),
            Self::UpdateMsg => write!(f, "update message"),
            Self::UpdateMsgErr => write!(f, "update message error"),
        }
    }
}

impl UnusedEvent {
    pub fn title(&self) -> &'static str {
        match self {
            Self::AutomaticStart => "automatic start",
            Self::PassiveManualStart => "passive manual start",
            Self::PassiveAutomaticStart => "passive automatic start",
            Self::DampedAutomaticStart => "damped automatic start",
            Self::PassiveDampedAutomaticStart => {
                "passive admped automatic start"
            }
            Self::AutomaticStop => "automatic stop",
            Self::DelayOpenTimerExpires => "delay open timer expires",
            Self::TcpConnectionValid => "tcp connection valid",
            Self::TcpConnectionInvalid => "tcp connection invalid",
            Self::TcpConnectionAcked => "tcp connection acked",
            Self::TcpConnectionFails => "tcp connection fails",
            Self::BgpOpen => "bgp open",
            Self::DelayedBgpOpen => "delay bgp open",
            Self::BgpHeaderErr => "bgp header err",
            Self::BgpOpenMsgErr => "bgp open message error",
            Self::OpenCollisionDump => "open collission dump",
            Self::NotifyMsgVerErr => "notify msg ver error",
            Self::NotifyMsg => "notify message",
            Self::KeepAliveMsg => "keepalive message",
            Self::UpdateMsg => "update message",
            Self::UpdateMsgErr => "update message error",
        }
    }
}

/// Information about a session.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct SessionInfo {
    /// Passively wait for the remote BGP peer to establish a TCP connection.
    pub passive_tcp_establishment: bool,
    /// Expected ASN of the remote peer (for validation). None means any remote
    /// ASN is acceptable.
    pub remote_asn: Option<u32>,
    /// Expected Router-ID of the remote peer (for validation)  . None means any
    /// remote BGP-ID is acceptable.
    pub remote_id: Option<u32>,
    /// Optional Source IP used for connection. None means the Source IP is
    /// derived by the system.
    pub bind_addr: Option<SocketAddr>,
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
    /// Ensure that routes received from eBGP peers have the peer's ASN as the
    /// first element in the AS path.
    pub enforce_first_as: bool,
    /// Policy governing imported routes.
    pub allow_import: ImportExportPolicy,
    /// Policy governing exported routes.
    pub allow_export: ImportExportPolicy,
    /// Vlan tag to assign to data plane routes created by this session.
    pub vlan_id: Option<u16>,
    /// Timer intervals for session and connection management
    /// How long to wait between connection attempts.
    pub connect_retry_time: Duration,
    /// Time between sending keepalive messages.
    pub keepalive_time: Duration,
    /// How long to keep a session alive between keepalive, update and/or notification messages.
    pub hold_time: Duration,
    /// Amount of time that a peer is held in the idle state.
    pub idle_hold_time: Duration,
    /// Interval to wait before sending out an open message.
    pub delay_open_time: Duration,
    /// Timer resolution for clocks (how often timers tick)
    pub resolution: Duration,
}

impl Default for SessionInfo {
    fn default() -> Self {
        Self {
            passive_tcp_establishment: false,
            remote_asn: None,
            remote_id: None,
            bind_addr: None,
            min_ttl: None,
            md5_auth_key: None,
            multi_exit_discriminator: None,
            communities: BTreeSet::new(),
            local_pref: None,
            enforce_first_as: false,
            allow_import: ImportExportPolicy::default(),
            allow_export: ImportExportPolicy::default(),
            vlan_id: None,
            // Default timer values based on BGP standards
            connect_retry_time: Duration::from_secs(120),
            keepalive_time: Duration::from_secs(60),
            hold_time: Duration::from_secs(180),
            idle_hold_time: Duration::from_secs(0), // No dampening by default
            delay_open_time: Duration::from_secs(5),
            resolution: Duration::from_millis(100), // 100ms timer resolution
        }
    }
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

/// Session endpoint that combines the event sender with session configuration.
/// This is used in addr_to_session map to provide both communication channel
/// and policy information for each peer.
#[derive(Clone)]
pub struct SessionEndpoint<Cnx: BgpConnection> {
    /// Event sender for FSM events to this session
    pub event_tx: Sender<FsmEvent<Cnx>>,

    /// Session configuration including policy settings
    pub config: Arc<Mutex<SessionInfo>>,
}

pub const MAX_MESSAGE_HISTORY: usize = 1024;

/// A message history entry is a BGP message with an associated timestamp
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistoryEntry {
    timestamp: chrono::DateTime<chrono::Utc>,
    message: Message,
    connection_id: Option<ConnectionId>,
}

/// Message history for a BGP session
#[derive(Default, Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistory {
    pub received: VecDeque<MessageHistoryEntry>,
    pub sent: VecDeque<MessageHistoryEntry>,
}

impl MessageHistory {
    fn receive(&mut self, msg: Message, connection_id: Option<ConnectionId>) {
        if self.received.len() >= MAX_MESSAGE_HISTORY {
            self.received.pop_back();
        }
        self.received.push_front(MessageHistoryEntry {
            message: msg,
            timestamp: chrono::Utc::now(),
            connection_id,
        });
    }

    fn send(&mut self, msg: Message, connection_id: Option<ConnectionId>) {
        if self.sent.len() >= MAX_MESSAGE_HISTORY {
            self.sent.pop_back();
        }
        self.sent.push_front(MessageHistoryEntry {
            message: msg,
            timestamp: chrono::Utc::now(),
            connection_id,
        });
    }
}

/// Session-level counters that persist across connection changes
/// These serve as aggregate counters across all connections for the session
#[derive(Default)]
pub struct SessionCounters {
    // FSM Counters
    pub connect_retry_counter: AtomicU64, // increments/zeroes with FSM per RFC
    pub connection_retries: AtomicU64,    // total number of retries
    pub active_connections_accepted: AtomicU64,
    pub passive_connections_accepted: AtomicU64,
    pub transitions_to_idle: AtomicU64,
    pub transitions_to_connect: AtomicU64,
    pub transitions_to_active: AtomicU64,
    pub transitions_to_open_sent: AtomicU64,
    pub transitions_to_open_confirm: AtomicU64,
    pub transitions_to_collision_detection: AtomicU64,
    pub transitions_to_session_setup: AtomicU64,
    pub transitions_to_established: AtomicU64,
    pub hold_timer_expirations: AtomicU64,
    pub idle_hold_timer_expirations: AtomicU64,

    // NLRI counters
    pub prefixes_advertised: AtomicU64,
    pub prefixes_imported: AtomicU64,

    // Message counters
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

    // Message error counters
    pub unexpected_update_message: AtomicU64,
    pub unexpected_keepalive_message: AtomicU64,
    pub unexpected_open_message: AtomicU64,
    pub unexpected_route_refresh_message: AtomicU64,
    pub unexpected_notification_message: AtomicU64,
    pub update_nexhop_missing: AtomicU64,
    pub open_handle_failures: AtomicU64,

    // Send failure counters
    pub notification_send_failure: AtomicU64,
    pub open_send_failure: AtomicU64,
    pub keepalive_send_failure: AtomicU64,
    pub route_refresh_send_failure: AtomicU64,
    pub update_send_failure: AtomicU64,

    // Connection failure counters
    pub tcp_connection_failure: AtomicU64,
    pub md5_auth_failures: AtomicU64,
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
    pub event_tx: RwLock<Sender<FsmEvent<Cnx>>>,

    /// Information about the neighbor this session is to peer with.
    pub neighbor: NeighborInfo,

    /// A log of the last `MAX_MESSAGE_HISTORY` messages. Keepalives are not
    /// included in message history.
    pub message_history: Arc<Mutex<MessageHistory>>,

    /// Counters for message types sent and received, state transitions, etc.
    pub counters: Arc<SessionCounters>,

    /// Session-level clock for timers that persist across connections
    pub clock: Arc<SessionClock>,

    /// Configuration for this BGP Session
    pub session: Arc<Mutex<SessionInfo>>,

    /// Track how many times a connection has been attempted.
    pub connect_retry_counter: AtomicU64,

    event_rx: RwLock<Receiver<FsmEvent<Cnx>>>,
    state: Arc<Mutex<FsmStateKind>>,
    last_state_change: Mutex<Instant>,
    asn: Asn,
    id: u32,

    /// The actual ASN learned from the remote peer (runtime state)
    remote_asn: Arc<Mutex<Option<u32>>>,

    /// The actual Router-ID learned from the remote peer (runtime state)
    remote_id: Arc<Mutex<Option<u32>>>,

    /// Capabilities received from the peer (runtime state)
    capabilities_received: Arc<Mutex<BTreeSet<Capability>>>,

    /// Capabilities sent to the peer (runtime state)
    capabilities_sent: Arc<Mutex<BTreeSet<Capability>>>,

    shutdown: AtomicBool,
    running: AtomicBool,
    db: Db,
    fanout: Arc<RwLock<Fanout<Cnx>>>,
    router: Arc<Router<Cnx>>,

    /// Registry of active connections indexed by ConnectionId
    connections: Arc<Mutex<BTreeMap<ConnectionId, Cnx>>>,

    /// The ConnectionId of the primary connection for the SessionRunner. Mainly
    /// used as a simple anchor point for pulling out Connection state.
    primary_connection: Arc<Mutex<Option<ConnectionId>>>,

    log: Logger,
}

unsafe impl<Cnx: BgpConnection> Send for SessionRunner<Cnx> {}
unsafe impl<Cnx: BgpConnection> Sync for SessionRunner<Cnx> {}

impl<Cnx: BgpConnection + 'static> SessionRunner<Cnx> {
    /// Create a new BGP session runner. Only creates the session runner
    /// object. Must call `start` to begin the peering state machine.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session: Arc<Mutex<SessionInfo>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
        event_tx: Sender<FsmEvent<Cnx>>,
        neighbor: NeighborInfo,
        asn: Asn,
        id: u32,
        db: Db,
        fanout: Arc<RwLock<Fanout<Cnx>>>,
        router: Arc<Router<Cnx>>,
        log: Logger,
    ) -> SessionRunner<Cnx> {
        let session_info = lock!(session);
        let runner = SessionRunner {
            session: session.clone(),
            connect_retry_counter: AtomicU64::new(0),
            event_rx: RwLock::new(event_rx),
            event_tx: RwLock::new(event_tx.clone()),
            asn,
            id,
            neighbor,
            state: Arc::new(Mutex::new(FsmStateKind::Idle)),
            last_state_change: Mutex::new(Instant::now()),
            clock: Arc::new(SessionClock::new(
                session_info.resolution,
                session_info.connect_retry_time,
                session_info.idle_hold_time,
                event_tx.clone(),
                log.clone(),
            )),
            log,
            shutdown: AtomicBool::new(false),
            running: AtomicBool::new(false),
            fanout,
            router,
            message_history: Arc::new(Mutex::new(MessageHistory::default())),
            counters: Arc::new(SessionCounters::default()),
            db,
            remote_asn: Arc::new(Mutex::new(None)),
            remote_id: Arc::new(Mutex::new(None)),
            capabilities_received: Arc::new(Mutex::new(BTreeSet::new())),
            capabilities_sent: Arc::new(Mutex::new(BTreeSet::new())),
            connections: Arc::new(Mutex::new(BTreeMap::new())),
            primary_connection: Arc::new(Mutex::new(None)),
        };
        drop(session_info);
        runner
    }

    /// Request a peer session shutdown. Does not shut down the session right
    /// away. Simply sets a flag that the session is to be shut down which will
    /// be acted upon in the state machine loop.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Get a specific connection by ID
    pub fn get_conn(&self, conn_id: &ConnectionId) -> Option<Cnx> {
        lock!(self.connections).get(conn_id).cloned()
    }

    /// Promote a connection to be the primary for this BGP session
    fn set_primary_conn(&self, conn_id: Option<ConnectionId>) {
        *lock!(self.primary_connection) = conn_id;
    }

    /// Get the primary connection
    pub fn get_primary_conn(&self) -> Option<Cnx> {
        let primary_id = lock!(self.primary_connection).clone()?;
        lock!(self.connections).get(&primary_id).cloned()
    }

    /// Add a connection to the registry. Newly registered connection is
    /// promoted to primary only if there isn't already a primary.
    pub fn register_conn(&self, conn: Cnx) {
        let conn_id = conn.id().clone();
        lock!(self.connections).insert(conn_id.clone(), conn);

        if self.get_primary_conn().is_none() {
            self.set_primary_conn(Some(conn_id));
        }
    }

    /// Remove a connection from the registry
    pub fn unregister_conn(&self, conn_id: &ConnectionId) {
        if let Some(conn) = lock!(self.connections).remove(conn_id) {
            // Stop all running clocks to reduce unnecessary noise
            conn.clock().disable_all();
        }

        // If this was the primary connection, either promote another connection
        // or reset it to None
        let mut primary = lock!(self.primary_connection);
        if primary.as_ref() == Some(conn_id) {
            *primary = lock!(self.connections).keys().next().cloned();
        }
    }

    /// Clean up connections when transitioning to Idle state
    fn cleanup_connections(&self) {
        let mut connections = lock!(self.connections);
        connections.clear();
        *lock!(self.primary_connection) = None;
    }

    /// This is the BGP peer state machine entry point. This function only
    /// returns if a shutdown is requested.
    pub fn start(self: &Arc<Self>) {
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
        session_log_lite!(self, info, "starting peer state machine";
            "params" => format!("{:?}", lock!(self.session))
        );
        let mut current = FsmState::<Cnx>::Idle;

        loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                self.on_shutdown();
                return;
            }

            let previous = current.kind();

            // Check what state we are in and call the corresponding handler
            // function. All handler functions return the next state as their
            // return value, stash that in the `current` variable.
            current = match current {
                FsmState::Idle => self.idle(),
                FsmState::Connect => self.on_connect(),
                FsmState::Active => self.on_active(),
                FsmState::OpenSent(conn) => self.on_open_sent(conn),
                FsmState::OpenConfirm(conn) => self.on_open_confirm(conn),
                FsmState::CollisionDetection(cpair) => {
                    self.collision_detection(cpair)
                }
                FsmState::SessionSetup(conn) => self.session_setup(conn),
                FsmState::Established(conn) => self.on_established(conn),
            };

            // If we have made a state transition log that and update the
            // appropriate state variables.
            if current.kind() != previous {
                session_log_lite!(
                    self,
                    info,
                    "fsm transition {} -> {}",
                    previous,
                    current.kind()
                );
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
                    FsmStateKind::CollisionDetection => {
                        self.counters
                            .transitions_to_collision_detection
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
        *lock!(self.capabilities_sent) = BTreeSet::from([
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

    /// Initial state. Refuse all incoming BGP connections. No resources
    /// allocated to peer.
    fn idle(&self) -> FsmState<Cnx> {
        {
            let ihl = lock!(self.clock.timers.idle_hold_timer);
            if !ihl.interval.is_zero() {
                ihl.restart();
            }
        }

        // Clean up connection registry
        self.cleanup_connections();

        let event = match read_lock!(self.event_rx).recv() {
            Ok(event) => {
                session_log_lite!(self, debug, "received fsm event {}",
                    event.title();
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "event" => event.title()
                );
                event
            }
            Err(e) => {
                session_log_lite!(self, error, "event rx error: {e}";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "error" => format!("{e}")
                );
                return FsmState::Idle;
            }
        };

        match event {
            FsmEvent::Admin(admin_event) => match admin_event {
                AdminEvent::ManualStart => {
                    lock!(self.clock.timers.idle_hold_timer).disable();

                    // RFC 4271:
                    // ```
                    // Each BGP peer paired in a potential connection will
                    // attempt to connect to the other, unless configured to
                    // remain in the idle state, or configured to remain passive.
                    // ```
                    // While the RFC does state that we should start the
                    // ConnectRetryTimer upon a manual/automatic start with
                    // passive tcp establishment, that is directly contradictory
                    // to the premise of passive connections not attempting to
                    // connect to peers. So instead we stop ConnectRetryTimer.
                    if lock!(self.session).passive_tcp_establishment {
                        lock!(self.clock.timers.connect_retry_timer).stop();
                        return FsmState::Active;
                    }

                    lock!(self.clock.timers.connect_retry_timer).restart();
                    FsmState::Connect
                }
                other => {
                    session_log_lite!(self, warn,
                        "unexpected admin fsm event, ignoring";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "event" => other.title()
                    );
                    FsmState::Idle
                }
            },

            // IdleHoldTimer is the mechanism by which maghemite implements
            // DampPeerOscillation. This holds the peer in Idle until the timer
            // has popped, preventing the connection from flapping. The interval
            // is supplied via PeerConfig as an unsigned int, and is always set
            // to something valid. DampPeerOscillation is disabled if the
            // interval is 0.
            FsmEvent::Session(SessionEvent::IdleHoldTimerExpires) => {
                self.counters
                    .idle_hold_timer_expirations
                    .fetch_add(1, Ordering::Relaxed);
                lock!(self.clock.timers.idle_hold_timer).disable();

                if lock!(self.session).passive_tcp_establishment {
                    return FsmState::Active;
                }
                FsmState::Connect
            }

            // Any other event (Events 9-12, 15-28) received in the Idle state
            // does not cause change in the state of the local system.

            // The only reason we handle messages separately is for counters
            FsmEvent::Connection(ConnectionEvent::Message { msg, conn_id }) => {
                session_log_lite!(self, warn, "unexpected message";
                    "fsm_state" => format!("{}", self.state()),
                    "message" => msg.title()
                );

                match msg {
                    // Event 19
                    Message::Open(_) => {
                        self.counters
                            .unexpected_open_message
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    // Event 25
                    Message::Notification(_) => {
                        self.counters
                            .notifications_received
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    // Event 26
                    Message::KeepAlive => {
                        self.counters
                            .unexpected_keepalive_message
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    // Event 27
                    Message::Update(_) => {
                        self.counters
                            .unexpected_update_message
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Message::RouteRefresh(_) => {
                        self.counters
                            .unexpected_route_refresh_message
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }

                FsmState::Idle
            }

            _ => {
                session_log_lite!(self, warn,
                    "{} event not allowed in this state", event.title();
                    "fsm_state" => format!("{}", self.state()).as_str()
                );
                FsmState::Idle
            }
        }
    }

    /// Waiting for a TCP connection to be completed (inbound or outbound).
    /// Connect is the only state where we initiate outbound connections.
    /// Passive peers should never enter the Connect state, since they never
    /// initiate outbound connections.
    fn on_connect(&self) -> FsmState<Cnx> {
        let min_ttl = lock!(self.session).min_ttl;
        let md5_auth_key = lock!(self.session).md5_auth_key.clone();

        // Start with an initial connection attempt using BgpConnector
        session_log_lite!(self,
            debug,
            "starting initial connect attempt";
            "fsm_state" => format!("{}", self.state()).as_str()
        );
        let session_info = lock!(self.session);
        match Cnx::Connector::connect(
            self.neighbor.host,
            self.clock.resolution,
            min_ttl,
            md5_auth_key.clone(),
            self.log.clone(),
            read_lock!(self.event_tx).clone(),
            &session_info,
        ) {
            Err(e) => {
                session_log_lite!(self,
                    warn,
                    "initial connect attempt failed";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "error" => format!("{e}")
                )
            }
            Ok(conn) => {
                session_log!(self, debug, conn,
                    "initial connect attempt succeeded";
                    "fsm_state" => format!("{}", self.state()).as_str()
                );
                if let Err(e) =
                    read_lock!(self.event_tx).send(FsmEvent::Session(
                        SessionEvent::TcpConnectionConfirmed(conn),
                    ))
                {
                    session_log_lite!(self,
                        error,
                        "failed to send TcpConnectionConfirmed event: {e}";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
                }
            }
        }

        loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                break FsmState::Idle;
            }

            let event = match read_lock!(self.event_rx).recv() {
                Ok(event) => {
                    session_log_lite!(self,
                        debug,
                        "received fsm event {}", event.title();
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "event" => event.title()
                    );
                    event
                }
                Err(e) => {
                    session_log_lite!(self,
                        error,
                        "event rx error: {e}";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
                    continue;
                }
            };

            match event {
                FsmEvent::Admin(admin_event) => match admin_event {
                    AdminEvent::ManualStop | AdminEvent::Reset => {
                        session_log_lite!(self,
                            info,
                            "rx {}, fsm transition to idle", admin_event.title();
                            "fsm_state" => format!("{}", self.state()).as_str()
                        );
                        self.connect_retry_counter.store(0, Ordering::Relaxed);
                        lock!(self.clock.timers.connect_retry_timer).stop();
                        return FsmState::Idle;
                    }
                    other => {
                        session_log_lite!(self, warn,
                            "unexpected admin fsm event, ignoring";
                            "fsm_state" => format!("{}", self.state()).as_str(),
                            "event" => other.title()
                        );
                        return FsmState::Idle;
                    }
                },

                FsmEvent::Session(session_event) => match session_event {
                    // In response to the ConnectRetryTimer_Expires event (Event 9), the
                    // local system:
                    //
                    //   - drops the TCP connection,
                    //
                    //   - restarts the ConnectRetryTimer,
                    //
                    //   - stops the DelayOpenTimer and resets the timer to zero,
                    //
                    //   - initiates a TCP connection to the other BGP peer,
                    //
                    //   - continues to listen for a connection that may be initiated by
                    //     the remote BGP peer, and
                    //
                    //   - stays in the Connect state.
                    SessionEvent::ConnectRetryTimerExpires => {
                        self.counters
                            .connection_retries
                            .fetch_add(1, Ordering::Relaxed);

                        // Attempt to establish a new connection using BgpConnector
                        let session_info = lock!(self.session);
                        match Cnx::Connector::connect(
                            self.neighbor.host,
                            Duration::from_millis(100),
                            min_ttl,
                            md5_auth_key.clone(),
                            self.log.clone(),
                            read_lock!(self.event_tx).clone(),
                            &session_info,
                        ) {
                            Err(e) => {
                                session_log_lite!(self,
                                    warn,
                                    "connect attempt failed";
                                    "fsm_state" => format!("{}", self.state()).as_str(),
                                    "error" => format!("{e}")
                                );
                            }
                            Ok(conn) => {
                                if let Err(e) =
                                    read_lock!(self.event_tx)
                                        .send(FsmEvent::Session(
                                        SessionEvent::TcpConnectionConfirmed(
                                            conn,
                                        ),
                                    ))
                                {
                                    session_log_lite!(self,
                                        error,
                                        "failed to send TcpConnectionConfirmed event: {e}";
                                        "fsm_state" => format!("{}", self.state()).as_str(),
                                        "error" => format!("{e}")
                                    );
                                }
                            }
                        }
                        lock!(self.clock.timers.connect_retry_timer).restart();
                    }

                    // If the TCP connection succeeds (Event 16 or Event 17), the local
                    // system checks the DelayOpen attribute prior to processing.  If the
                    // DelayOpen attribute is set to TRUE, the local system:
                    //
                    //   - stops the ConnectRetryTimer (if running) and sets the
                    //     ConnectRetryTimer to zero,
                    //
                    //   - sets the DelayOpenTimer to the initial value, and
                    //
                    //   - stays in the Connect state.
                    //
                    // If the DelayOpen attribute is set to FALSE, the local system:
                    //
                    //   - stops the ConnectRetryTimer (if running) and sets the
                    //     ConnectRetryTimer to zero,
                    //
                    //   - completes BGP initialization
                    //
                    //   - sends an OPEN message to its peer,
                    //
                    //   - sets the HoldTimer to a large value, and
                    //
                    //   - changes its state to OpenSent.
                    //
                    // A HoldTimer value of 4 minutes is suggested.
                    SessionEvent::Connected(accepted)
                    | SessionEvent::TcpConnectionConfirmed(accepted) => {
                        match accepted.creator() {
                            ConnectionCreator::Dispatcher => {
                                session_log!(self, info, accepted,
                                    "accepted inbound connection from {}", accepted.peer();
                                    "fsm_state" => format!("{}", self.state()).as_str()
                                )
                            }
                            ConnectionCreator::Connector => {
                                session_log!(self, info, accepted,
                                    "outbound connection to {} accepted", accepted.peer();
                                    "fsm_state" => format!("{}", self.state()).as_str()
                                )
                            }
                        }

                        self.register_conn(accepted.clone());

                        // DelayOpen can be configured for a peer, but its functionality
                        // is not implemented.  Follow DelayOpen == false instructions.

                        self.connect_retry_counter.store(0, Ordering::Relaxed);
                        lock!(self.clock.timers.connect_retry_timer).stop();

                        if let Err(e) = self.send_open(&accepted) {
                            session_log!(self, error, accepted,
                                "failed to send open, fsm transition to idle";
                                "fsm_state" => format!("{}", self.state()).as_str(),
                                "error" => format!("{e}")
                            );
                            return FsmState::Idle;
                        }

                        lock!(accepted.clock().timers.hold_timer).restart();
                        self.counters
                            .passive_connections_accepted
                            .fetch_add(1, Ordering::Relaxed);

                        return FsmState::OpenSent(accepted);
                    }

                    // Event 13
                    SessionEvent::IdleHoldTimerExpires => {
                        lock!(self.clock.timers.connect_retry_timer).stop();
                        self.connect_retry_counter
                            .fetch_add(1, Ordering::Relaxed);

                        session_log_lite!(self,
                            warn,
                            "{} event not allowed in this state, fsm transition to idle",
                            session_event.title();
                            "fsm_state" => format!("{}", self.state()).as_str()
                        );

                        return FsmState::Idle;
                    }
                },

                // In response to any other events (Events 8, 10-11, 13, 19, 23,
                // 25-28), the local system:
                //
                //   - if the ConnectRetryTimer is running, stops and resets the
                //     ConnectRetryTimer (sets to zero),
                //
                //   - if the DelayOpenTimer is running, stops and resets the
                //     DelayOpenTimer (sets to zero),
                //
                //   - releases all BGP resources,
                //
                //   - drops the TCP connection,
                //
                //   - increments the ConnectRetryCounter by 1,
                //
                //   - performs peer oscillation damping if the DampPeerOscillations
                //     attribute is set to True, and
                //
                //   - changes its state to Idle.
                FsmEvent::Connection(connection_event) => {
                    let title = connection_event.title();
                    match connection_event {
                        ConnectionEvent::Message { msg, conn_id } => {
                            session_log_lite!(self,
                                warn,
                                "rx unexpected {} message (conn_id {}), fsm transition to idle",
                                msg.title(), conn_id.short();
                                "fsm_state" => format!("{}", self.state()).as_str(),
                                "message" => msg.title(),
                                "message_contents" => format!("{msg}")
                            );

                            lock!(self.clock.timers.connect_retry_timer).stop();
                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);

                            match msg {
                                // Event 19
                                Message::Open(_) => {
                                    self.counters
                                        .unexpected_open_message
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                // Event 27
                                Message::Update(_) => {
                                    self.counters
                                        .unexpected_update_message
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                // Event 25
                                Message::Notification(_) => {
                                    self.counters
                                        .notifications_received
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                // Event 26
                                Message::KeepAlive => {
                                    self.counters
                                        .unexpected_keepalive_message
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                Message::RouteRefresh(_) => {
                                    self.counters
                                        .unexpected_route_refresh_message
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }

                            return FsmState::Idle;
                        }

                        // Events 8 (AutomaticStop, unused), 10-11, 13
                        ConnectionEvent::HoldTimerExpires(conn_id)
                        | ConnectionEvent::KeepaliveTimerExpires(conn_id)
                        | ConnectionEvent::DelayOpenTimerExpires(conn_id) => {
                            lock!(self.clock.timers.connect_retry_timer).stop();
                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);

                            session_log_lite!(self, warn,
                                "connection fsm event {title} (conn_id {}) not allowed in this state, fsm transition to idle",
                                conn_id.short();
                                "fsm_state" => format!("{}", self.state()).as_str()
                            );

                            return FsmState::Idle;
                        }
                    }
                }
            }
        }
    }

    /// Trying to acquire peer by listening for and accepting a TCP connection.
    /// We do not initiate connections from Active -- that happens in Connect.
    /// Passive peers only ever live in Active while waiting for connections to
    /// complete; they should never transition to Connect.
    fn on_active(&self) -> FsmState<Cnx> {
        loop {
            let event = match read_lock!(self.event_rx).recv() {
                Ok(event) => {
                    session_log_lite!(self, debug, "received fsm event";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "event" => event.title()
                    );
                    event
                }
                Err(e) => {
                    session_log_lite!(self, error, "event rx error: {e}";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
                    // TODO: Possible death loop. Should we just panic here?
                    return FsmState::Active;
                }
            };

            // The Dispatcher thread is running independently and will hand off
            // any inbound connections via a Connected event. So pretty much all
            // we need to do is sit and wait for that event or for timers to pop
            match event {
                FsmEvent::Admin(admin_event) => match admin_event {
                    // In response to a ManualStop event (Event 2), the local system:
                    //
                    //   - If the DelayOpenTimer is running and the
                    //     SendNOTIFICATIONwithoutOPEN session attribute is set, the
                    //     local system sends a NOTIFICATION with a Cease,
                    //
                    //   - releases all BGP resources including stopping the
                    //     DelayOpenTimer
                    //
                    //   - drops the TCP connection,
                    //
                    //   - sets ConnectRetryCounter to zero,
                    //
                    //   - stops the ConnectRetryTimer and sets the ConnectRetryTimer to
                    //     zero, and
                    //
                    //   - changes its state to Idle.
                    AdminEvent::ManualStop | AdminEvent::Reset => {
                        session_log_lite!(self, info,
                            "rx {}, fsm transition to idle", admin_event.title();
                            "fsm_state" => format!("{}", self.state()).as_str()
                        );

                        self.connect_retry_counter.store(0, Ordering::Relaxed);
                        lock!(self.clock.timers.connect_retry_timer).stop();

                        return FsmState::Idle;
                    }

                    other => {
                        session_log_lite!(self, warn,
                            "unexpected admin fsm event, ignoring";
                            "fsm_state" => format!("{}", self.state()).as_str(),
                            "event" => other.title()
                        );
                        continue;
                    }
                },

                FsmEvent::Connection(connection_event) => {
                    match connection_event {
                        // In response to any other event (Events 8, 10-11, 13, 19, 23,
                        // 25-28), the local system:
                        //
                        //   - sets the ConnectRetryTimer to zero,
                        //
                        //   - releases all BGP resources,
                        //
                        //   - drops the TCP connection,
                        //
                        //   - increments the ConnectRetryCounter by one,
                        //
                        //   - (optionally) performs peer oscillation damping if the
                        //     DampPeerOscillations attribute is set to TRUE, and
                        //
                        //   - changes its state to Idle.
                        ConnectionEvent::Message { msg, conn_id } => {
                            session_log_lite!(self, warn,
                                "rx unexpected {} message (conn_id: {}), fsm transition to idle",
                                msg.title(), conn_id.short();
                                "fsm_state" => format!("{}", self.state()).as_str(),
                                "message" => msg.title()
                            );

                            lock!(self.clock.timers.connect_retry_timer).stop();
                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);

                            match msg {
                                // Event 19
                                Message::Open(om) => {
                                    self.counters
                                        .opens_received
                                        .fetch_add(1, Ordering::Relaxed);

                                    // If BGP message header checking (Event 21) or OPEN message checking
                                    // detects an error (Event 22) (see Section 6.2), the local system:
                                    //
                                    //   - (optionally) sends a NOTIFICATION message with the appropriate
                                    //     error code if the SendNOTIFICATIONwithoutOPEN attribute is set
                                    //     to TRUE,
                                    //
                                    //   - sets the ConnectRetryTimer to zero,
                                    //
                                    //   - releases all BGP resources,
                                    //
                                    //   - drops the TCP connection,
                                    //
                                    //   - increments the ConnectRetryCounter by 1,
                                    //
                                    //   - (optionally) performs peer oscillation damping if the
                                    //     DampPeerOscillations attribute is set to TRUE, and
                                    //
                                    //   - changes its state to Idle.
                                    lock!(self.message_history).receive(
                                        om.clone().into(),
                                        Some(conn_id.clone()),
                                    );

                                    // check if connection is registered/known
                                    let conn = match self.get_conn(&conn_id) {
                                        Some(connection) => connection,
                                        None => {
                                            session_log_lite!(self, warn,
                                                "rx open message from peer {} for unknown connection (conn_id: {}), ignoring",
                                                conn_id.remote().ip(), conn_id.short();
                                                "fsm_state" => format!("{}", self.state()).as_str()
                                            );
                                            continue;
                                        }
                                    };

                                    if let Err(e) = self.handle_open(&conn, &om)
                                    {
                                        session_log!(self, warn, conn,
                                            "failed to handle open message, fsm transition to idle";
                                            "fsm_state" => format!("{}", self.state()).as_str(),
                                            "error" => format!("{e}")
                                        );
                                        // notification sent by handle_open(), nothing to do here
                                        self.connect_retry_counter
                                            .fetch_add(1, Ordering::Relaxed);
                                        self.connect_retry_counter
                                            .fetch_add(1, Ordering::Relaxed);
                                        // peer oscillation damping happens in idle, nothing to do here
                                        return FsmState::Idle;
                                    }

                                    // ACK the open with a reciprocal open and a keepalive and transition
                                    // to open confirm.
                                    if let Err(e) = self.send_open(&conn) {
                                        session_log!(self, error, conn,
                                            "failed to send open, fsm transition to idle";
                                            "fsm_state" => format!("{}", self.state()).as_str(),
                                            "error" => format!("{e}")
                                        );
                                        return FsmState::Idle;
                                    }

                                    self.send_keepalive(&conn);
                                    lock!(conn.clock().timers.keepalive_timer)
                                        .restart();

                                    return FsmState::OpenConfirm(
                                        PeerConnection { conn, id: om.id },
                                    );
                                }
                                // Event 27
                                Message::Update(_) => {
                                    self.counters
                                        .unexpected_update_message
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                // Event 25
                                Message::Notification(_) => {
                                    self.counters
                                        .notifications_received
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                // Event 26
                                Message::KeepAlive => {
                                    self.counters
                                        .unexpected_keepalive_message
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                Message::RouteRefresh(_) => {
                                    self.counters
                                        .unexpected_route_refresh_message
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }

                            return FsmState::Idle;
                        }

                        // Events 8 (Automatic Stop), 10-11, 13
                        ConnectionEvent::HoldTimerExpires(ref conn_id)
                        | ConnectionEvent::KeepaliveTimerExpires(ref conn_id) =>
                        {
                            lock!(self.clock.timers.connect_retry_timer).stop();
                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);

                            session_log_lite!(self, warn,
                                "connection fsm event {} not allowed in this state, fsm transition to idle",
                                connection_event.title();
                                "fsm_state" => format!("{}", self.state()).as_str()
                            );

                            return FsmState::Idle;
                        }

                        ConnectionEvent::DelayOpenTimerExpires(_) => {
                            session_log_lite!(self, warn,
                                "connection fsm event {} not allowed in this state, ignoring",
                                connection_event.title();
                                "fsm_state" => format!("{}", self.state()).as_str()
                            );

                            continue;
                        }
                    }
                }

                FsmEvent::Session(session_event) => match session_event {
                    // In response to a ConnectRetryTimer_Expires event (Event 9), the
                    // local system:
                    //
                    //   - restarts the ConnectRetryTimer (with initial value),
                    //
                    //   - initiates a TCP connection to the other BGP peer,
                    //
                    //   - continues to listen for a TCP connection that may be initiated
                    //     by a remote BGP peer, and
                    //
                    //   - changes its state to Connect.
                    SessionEvent::ConnectRetryTimerExpires => {
                        // RFC 4271 says that in Idle the FSM should restart the
                        // ConnectRetryTimer "In response to a
                        // ManualStart_with_PassiveTcpEstablishment event" even
                        // though it also says that in Active the FSM should
                        // react to a ConnectRetryTimerExpires event by
                        // transitioning to Connect and attempting a new
                        // outbound TCP session, which is exactly the opposite of
                        // what you want to do for a passive peer. ...So we stop
                        // the timer and stay in Active when passive.
                        if lock!(self.session).passive_tcp_establishment {
                            lock!(self.clock.timers.connect_retry_timer).stop();
                            session_log_lite!(self, info,
                                "rx {} but peer is configured as passive, ignoring",
                                session_event.title();
                                "fsm_state" => format!("{}", self.state()).as_str()
                            );
                            continue;
                        }

                        session_log_lite!(self, info,
                            "rx {}, fsm transition to connect",
                            session_event.title();
                            "fsm_state" => format!("{}", self.state()).as_str()
                        );

                        lock!(self.clock.timers.connect_retry_timer).restart();
                        self.counters
                            .connection_retries
                            .fetch_add(1, Ordering::Relaxed);

                        return FsmState::Connect;
                    }

                    // The underlying connection has accepted a TCP connection
                    // initiated by the peer.
                    SessionEvent::Connected(accepted) => {
                        session_log!(self, info, accepted,
                            "accepted inbound connection from {}", accepted.peer();
                            "fsm_state" => format!("{}", self.state()).as_str()
                        );

                        self.register_conn(accepted.clone());

                        if let Err(e) = self.send_open(&accepted) {
                            session_log!(self, error, accepted,
                                "failed to send open, fsm transition to idle";
                                "fsm_state" => format!("{}", self.state()).as_str(),
                                "error" => format!("{e}")
                            );
                            lock!(self.clock.timers.connect_retry_timer)
                                .restart();
                            return FsmState::Idle;
                        }

                        lock!(accepted.clock().timers.hold_timer).restart();
                        lock!(self.clock.timers.connect_retry_timer).zero();
                        self.counters
                            .passive_connections_accepted
                            .fetch_add(1, Ordering::Relaxed);

                        // XXX: DelayOpenTimer
                        /*
                        // Stay in Active, transmit Open when DelayOpenTimerExpires pops
                        if lock!(accepted.connection_clock().timers.delay_open_timer).expired() {
                            continue;
                        }
                        */

                        return FsmState::OpenSent(accepted);
                    }

                    // An outbound connection we initiated has been accepted by
                    // the peer. Outbound connections aren't allowed in Active
                    // state, so this shouldn't happen. However, if it does then
                    // it's likely a timing thing as a result of improper
                    // Connector handling (not dropping the TcpStream).
                    SessionEvent::TcpConnectionConfirmed(confirmed) => {
                        session_log!(self, info, confirmed,
                            "outbound connection to peer {} (conn_id: {}) accepted, but not allowed. ignoring",
                            confirmed.peer(), confirmed.id().short();
                            "fsm_state" => format!("{}", self.state()).as_str()
                        );

                        continue;
                    }

                    SessionEvent::IdleHoldTimerExpires => {
                        session_log_lite!(self, warn,
                            "{} event not allowed in this state, ignoring",
                            session_event.title();
                            "fsm_state" => format!("{}", self.state()).as_str()
                        );

                        continue;
                    }
                },
            };
        }
    }

    /// Waiting for open message from peer.
    fn on_open_sent(&self, conn: Cnx) -> FsmState<Cnx> {
        let om = loop {
            let event = match read_lock!(self.event_rx).recv() {
                Ok(event) => {
                    session_log!(self, debug, conn, "received fsm event";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "event" => event.title()
                    );
                    event
                }
                Err(e) => {
                    session_log!(self, error, conn,
                        "event rx error: {e}";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
                    return FsmState::OpenSent(conn);
                }
            };

            // The main thing we really care about in the open sent state is
            // receiving a reciprocal open message from the peer.
            match event {
                // XXX: continue breaking this down hierarchically
                FsmEvent::Connection(ConnectionEvent::Message { msg: Message::Open(om), conn_id }) => {
                    lock!(self.message_history).receive(om.clone().into(), Some(conn_id.clone()));
                    if let Some(_conn) = self.get_conn(&conn_id) {
                        self.counters.opens_received.fetch_add(1, Ordering::Relaxed);
                    }
                    break om;
                }

                // If a ManualStop event (Event 2) is issued in the OpenSent state,
                // the local system:
                //
                //   - sends the NOTIFICATION with a Cease,
                //
                //   - sets the ConnectRetryTimer to zero,
                //
                //   - releases all BGP resources,
                //
                //   - drops the TCP connection,
                //
                //   - sets the ConnectRetryCounter to zero, and
                //
                //   - changes its state to Idle.
                FsmEvent::Admin(AdminEvent::ManualStop) => {
                    session_log!(self, info, conn,
                        "rx {}, fsm transition to idle", event.title();
                        "fsm_state" => format!("{}", self.state()).as_str()
                    );

                    self.send_notification(
                        &conn,
                        ErrorCode::Cease,
                        ErrorSubcode::Cease(
                            CeaseErrorSubcode::AdministrativeShutdown,
                        ),
                    );

                    self.connect_retry_counter.store(0, Ordering::Relaxed);
                    lock!(self.clock.timers.connect_retry_timer).restart();

                    return FsmState::Idle;
                }

                // Follow ManualStop logic, but with the appropriate ErrorSubcode
                FsmEvent::Admin(AdminEvent::Reset) => {
                    session_log!(self, info, conn,
                        "rx {}, fsm transition to idle", event.title();
                        "fsm_state" => format!("{}", self.state()).as_str()
                    );

                    self.send_notification(
                        &conn,
                        ErrorCode::Cease,
                        ErrorSubcode::Cease(CeaseErrorSubcode::AdministrativeReset),
                    );

                    self.connect_retry_counter.store(0, Ordering::Relaxed);
                    lock!(self.clock.timers.connect_retry_timer).restart();

                    return FsmState::Idle;
                }

                // If the HoldTimer_Expires (Event 10), the local system:
                //
                //   - sends a NOTIFICATION message with the error code Hold Timer
                //     Expired,
                //
                //   - sets the ConnectRetryTimer to zero,
                //
                //   - releases all BGP resources,
                //
                //   - drops the TCP connection,
                //
                //   - increments the ConnectRetryCounter,
                //
                //   - (optionally) performs peer oscillation damping if the
                //     DampPeerOscillations attribute is set to TRUE, and
                //
                //   - changes its state to Idle.
                FsmEvent::Connection(ConnectionEvent::HoldTimerExpires(conn_id)) => {
                    session_log!(self, warn, conn,
                        "hold timer expired, fsm transition to idle";
                        "fsm_state" => format!("{}", self.state()).as_str()
                    );

                    self.counters
                        .hold_timer_expirations
                        .fetch_add(1, Ordering::Relaxed);

                    self.send_hold_timer_expired_notification(&conn);
                    lock!(self.clock.timers.connect_retry_timer)
                        .zero();
                    self.connect_retry_counter.fetch_add(1, Ordering::Relaxed);

                    return FsmState::Idle;
                }

                // Inbound connection has been accepted by the dispatcher.
                // No messages have been exchanged on this connection yet.
                FsmEvent::Session(SessionEvent::Connected(accepted)) => {
                    return FsmState::CollisionDetection(
                        CollisionPair::OpenSent(conn, accepted)
                    );
                }

                // Outbound connection has been accepted by the peer.
                // No messages have been exchanged on this connection yet.
                FsmEvent::Session(SessionEvent::TcpConnectionConfirmed(confirmed)) => {
                    return FsmState::CollisionDetection(
                        CollisionPair::OpenSent(conn, confirmed)
                    );
                }

                // In response to any other event (Events 9, 11-13, 20, 25-28), the
                // local system:
                //
                //   - sends the NOTIFICATION with the Error Code Finite State
                //     Machine Error,
                //
                //   - sets the ConnectRetryTimer to zero,
                //
                //   - releases all BGP resources,
                //
                //   - drops the TCP connection,
                //
                //   - increments the ConnectRetryCounter by 1,
                //
                //   - (optionally) performs peer oscillation damping if the
                //     DampPeerOscillations attribute is set to TRUE, and
                //
                //   - changes its state to Idle.

                // Events 9, 11-13
                FsmEvent::Session(SessionEvent::ConnectRetryTimerExpires)
                | FsmEvent::Connection(ConnectionEvent::KeepaliveTimerExpires(ref conn_id))
                // | FsmEvent::DelayOpenTimerExpires // Event 12
                | FsmEvent::Session(SessionEvent::IdleHoldTimerExpires) => {
                    session_log!(self, warn, conn,
                        "{} event not allowed in this state, fsm transition to idle",
                        event.title();
                        "fsm_state" => format!("{}", self.state()).as_str()
                    );

                    self.send_fsm_notification(&conn);

                    lock!(self.clock.timers.connect_retry_timer).stop();
                    self.connect_retry_counter.fetch_add(1, Ordering::Relaxed);

                    return FsmState::Idle;
                }

                // Events 20, 25-28
                FsmEvent::Connection(ConnectionEvent::Message { msg, conn_id }) => {
                    session_log!(self, warn, conn,
                        "rx unexpected {} message, fsm transition to idle",
                        msg.title();
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "message" => msg.title()
                    );

                    self.send_fsm_notification(&conn);

                    lock!(self.clock.timers.connect_retry_timer).stop();
                    self.connect_retry_counter.fetch_add(1, Ordering::Relaxed);

                    match msg {
                        // Event 19, 20
                        Message::Open(_) => {
                            // XXX: this invariant of Message is handled earlier,
                            //      so this should be unreachable
                            session_log!(self, warn, conn,
                                "fsm error: {} should have been handled already",
                                msg.title();
                                "fsm_state" => format!("{}", self.state()).as_str(),
                                "message" => msg.title()
                            );
                            self.counters
                                .unexpected_open_message
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        // Event 27, 28
                        Message::Update(_) => {
                            self.counters
                                .unexpected_update_message
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        // Event 25
                        Message::Notification(_) => {
                            self.counters
                                .notifications_received
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        // Event 26
                        Message::KeepAlive => {
                            self.counters
                                .unexpected_keepalive_message
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Message::RouteRefresh(_) => {
                            self.counters
                                .unexpected_route_refresh_message
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    return FsmState::Idle;
                }

                // We need to ignore other events here. Something like a change
                // to policy config shouldn't cause us to change states.
                other => {
                    session_log!(self, warn, conn,
                        "unexpected fsm event, ignoring";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "event" => other.title()
                    );
                }
            }
        };

        // If the BGP message header checking (Event 21) or OPEN message
        // checking detects an error (Event 22)(see Section 6.2), the local
        // system:
        //
        // - sends a NOTIFICATION message with the appropriate error code,
        //
        // - sets the ConnectRetryTimer to zero,
        //
        // - releases all BGP resources,
        //
        // - drops the TCP connection,
        //
        // - increments the ConnectRetryCounter by 1,
        //
        // - (optionally) performs peer oscillation damping if the
        //   DampPeerOscillations attribute is TRUE, and
        //
        // - changes its state to Idle.
        if let Err(e) = self.handle_open(&conn, &om) {
            match e {
                Error::PolicyCheckFailed => {
                    session_log!(self, info, conn,
                        "policy check failed";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
                }
                e => {
                    session_log!(self, warn, conn,
                        "failed to handle open message, fsm transition to idle";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
                    self.counters
                        .open_handle_failures
                        .fetch_add(1, Ordering::Relaxed);
                    // Notification sent by handle_open for all Errors except
                    // PolicyCheckFailed, which is handled in other match arm.
                    return FsmState::Idle;
                }
            }
        }

        // When an OPEN message is received, all fields are checked for
        // correctness.  If there are no errors in the OPEN message (Event
        // 19), the local system:
        //
        //   - resets the DelayOpenTimer to zero,
        //
        //   - sets the BGP ConnectRetryTimer to zero,
        //
        //   - sends a KEEPALIVE message, and
        //
        //   - sets a KeepaliveTimer (via the text below)
        //
        //   - sets the HoldTimer according to the negotiated value (see
        //     Section 4.2),
        //
        //   - changes its state to OpenConfirm.

        // ACK the open with a keepalive and transition to open confirm.
        self.send_keepalive(&conn);

        lock!(self.clock.timers.connect_retry_timer).zero();
        lock!(conn.clock().timers.keepalive_timer).restart();
        // hold_timer set in handle_open(), enable it here
        lock!(conn.clock().timers.hold_timer).enable();

        FsmState::OpenConfirm(PeerConnection { conn, id: om.id })
    }

    /// Waiting for keepalive or notification from peer.
    fn on_open_confirm(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        let event = match read_lock!(self.event_rx).recv() {
            Ok(event) => {
                session_log!(self, debug, pc.conn,
                     "received fsm event";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "event" => event.title()
                );
                event
            }
            Err(e) => {
                session_log!(self, error,  pc.conn,
                    "event rx error: {e}";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "error" => format!("{e}")
                );
                return FsmState::OpenConfirm(pc);
            }
        };

        match event {
            // In response to a ManualStop event (Event 2) initiated by the
            // operator, the local system:
            //
            //   - sends the NOTIFICATION message with a Cease,
            //
            //   - releases all BGP resources,
            //
            //   - drops the TCP connection,
            //
            //   - sets the ConnectRetryCounter to zero,
            //
            //   - sets the ConnectRetryTimer to zero, and
            //
            //   - changes its state to Idle.
            FsmEvent::Admin(AdminEvent::ManualStop) => {
                session_log!(self, info,  pc.conn,
                    "rx {}, fsm transition to idle",
                    event.title();
                    "fsm_state" => format!("{}", self.state()).as_str()
                );

                self.send_notification(
                    &pc.conn,
                    ErrorCode::Cease,
                    ErrorSubcode::Cease(
                        CeaseErrorSubcode::AdministrativeShutdown,
                    ),
                );

                self.connect_retry_counter.store(0, Ordering::Relaxed);
                lock!(self.clock.timers.connect_retry_timer).zero();

                FsmState::Idle
            }

            // Follow ManualStop logic, but with the appropriate ErrorSubcode
            FsmEvent::Admin(AdminEvent::Reset) => {
                session_log!(self, info,  pc.conn,
                    "rx {}, fsm transition to idle",
                    event.title();
                    "fsm_state" => format!("{}", self.state()).as_str()
                );

                self.send_notification(
                    &pc.conn,
                    ErrorCode::Cease,
                    ErrorSubcode::Cease(CeaseErrorSubcode::AdministrativeReset),
                );

                self.connect_retry_counter.store(0, Ordering::Relaxed);
                lock!(self.clock.timers.connect_retry_timer).zero();

                FsmState::Idle
            }

            // If the HoldTimer_Expires event (Event 10) occurs before a
            // KEEPALIVE message is received, the local system:
            //
            //   - sends the NOTIFICATION message with the Error Code Hold Timer
            //     Expired,
            //
            //   - sets the ConnectRetryTimer to zero,
            //
            //   - releases all BGP resources,
            //
            //   - drops the TCP connection,
            //
            //   - increments the ConnectRetryCounter by 1,
            //
            //   - (optionally) performs peer oscillation damping if the
            //     DampPeerOscillations attribute is set to TRUE, and
            //
            //   - changes its state to Idle.
            FsmEvent::Connection(ConnectionEvent::HoldTimerExpires(
                conn_id,
            )) => {
                session_log!(self, warn, pc.conn,
                    "hold timer expired, fsm transition to idle";
                    "fsm_state" => format!("{}", self.state()).as_str()
                );

                self.send_hold_timer_expired_notification(&pc.conn);
                self.counters
                    .hold_timer_expirations
                    .fetch_add(1, Ordering::Relaxed);

                lock!(pc.conn.clock().timers.hold_timer).disable();

                self.connect_retry_counter.fetch_add(1, Ordering::Relaxed);
                lock!(self.clock.timers.connect_retry_timer).restart();

                FsmState::Idle
            }

            // If the local system receives a KeepaliveTimer_Expires event (Event
            // 11), the local system:
            //
            //   - sends a KEEPALIVE message,
            //
            //   - restarts the KeepaliveTimer, and
            //
            //   - remains in the OpenConfirmed state.
            FsmEvent::Connection(ConnectionEvent::KeepaliveTimerExpires(
                conn_id,
            )) => {
                session_log!(self, warn, pc.conn,
                    "keepalive timer expired, generate keepalive";
                    "fsm_state" => format!("{}", self.state()).as_str()
                );
                self.send_keepalive(&pc.conn);
                lock!(pc.conn.clock().timers.keepalive_timer).restart();
                FsmState::OpenConfirm(pc)
            }

            // The peer has ACK'd our open message with a keepalive. Start the
            // session timers and enter session setup.
            FsmEvent::Connection(ConnectionEvent::Message {
                msg: Message::KeepAlive,
                conn_id,
            }) => {
                lock!(pc.conn.clock().timers.hold_timer).restart();
                lock!(pc.conn.clock().timers.keepalive_timer).restart();
                self.counters
                    .keepalives_received
                    .fetch_add(1, Ordering::Relaxed);
                FsmState::SessionSetup(pc)
            }

            // If the local system receives a TcpConnectionFails event (Event 18)
            // from the underlying TCP or a NOTIFICATION message (Event 25), the
            // local system:
            //
            //   - sets the ConnectRetryTimer to zero,
            //
            //   - releases all BGP resources,
            //
            //   - drops the TCP connection,
            //
            //   - increments the ConnectRetryCounter by 1,
            //
            //   - (optionally) performs peer oscillation damping if the
            //     DampPeerOscillations attribute is set to TRUE, and
            //
            //   - changes its state to Idle.
            FsmEvent::Connection(ConnectionEvent::Message {
                msg: Message::Notification(m),
                conn_id,
            }) => {
                session_log!(self, warn, pc.conn,
                    "notification received, fsm transition to idle";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "message" => "notification",
                    "message_contents" => format!("{m}")
                );

                lock!(self.message_history).receive(m.clone().into(), None);

                lock!(self.clock.timers.connect_retry_timer).restart();
                self.connect_retry_counter.fetch_add(1, Ordering::Relaxed);
                lock!(pc.conn.clock().timers.hold_timer).disable();
                lock!(pc.conn.clock().timers.keepalive_timer).disable();

                self.counters
                    .notifications_received
                    .fetch_add(1, Ordering::Relaxed);

                FsmState::Idle
            }

            FsmEvent::Connection(ConnectionEvent::Message {
                msg: Message::Open(om),
                conn_id,
            }) => {
                self.counters
                    .unexpected_open_message
                    .fetch_add(1, Ordering::Relaxed);
                self.connect_retry_counter.fetch_add(1, Ordering::Relaxed);
                lock!(self.clock.timers.connect_retry_timer).restart();
                session_log!(self, warn, pc.conn,
                    "unexpected message, fsm transition to idle";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "message" => "open",
                    "message_contents" => format!("{om}").as_str()
                );
                FsmState::Idle
            }

            FsmEvent::Connection(ConnectionEvent::Message {
                msg: Message::Update(um),
                conn_id,
            }) => {
                self.counters
                    .unexpected_update_message
                    .fetch_add(1, Ordering::Relaxed);
                session_log!(self, warn, pc.conn,
                    "unexpected message, fsm transition to idle";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "message" => "update",
                    "message_contents" => format!("{um}").as_str()
                );
                FsmState::Idle
            }

            // Inbound connection has been accepted by the dispatcher.
            // No messages have been exchanged on this connection yet.
            FsmEvent::Session(SessionEvent::Connected(accepted)) => {
                FsmState::CollisionDetection(CollisionPair::OpenConfirm(
                    pc, accepted,
                ))
            }

            // Outbound connection has been accepted by the peer.
            // No messages have been exchanged on this connection yet.
            FsmEvent::Session(SessionEvent::TcpConnectionConfirmed(
                confirmed,
            )) => FsmState::CollisionDetection(CollisionPair::OpenConfirm(
                pc, confirmed,
            )),

            FsmEvent::Session(SessionEvent::IdleHoldTimerExpires) => {
                session_log!(self, info, pc.conn,
                    "idle hold timer expired, ignoring";
                    "fsm_state" => format!("{}", self.state()).as_str()
                );
                self.counters
                    .idle_hold_timer_expirations
                    .fetch_add(1, Ordering::Relaxed);
                lock!(self.clock.timers.idle_hold_timer).disable();
                FsmState::OpenConfirm(pc)
            }

            // An event we are not expecting, log it and re-enter this state.
            other => {
                session_log!(self, warn, pc.conn,
                    "unexpected fsm event, ignoring";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "event" => other.title()
                );
                FsmState::OpenConfirm(pc)
            }
        }
    }

    /// Handler for Connection Collisions (RFC 4271 6.8)
    /// Solicits Open from peer to learn their BGP-ID, then performs
    /// collision resolution.
    //
    // ```
    // 1) The BGP Identifier of the local system is compared to the BGP
    //    Identifier of the remote system (as specified in the OPEN
    //    message).  Comparing BGP Identifiers is done by converting them
    //    to host byte order and treating them as 4-octet unsigned
    //    integers.
    //
    // 2) If the value of the local BGP Identifier is less than the
    //    remote one, the local system closes the BGP connection that
    //    already exists (the one that is already in the OpenConfirm
    //    state), and accepts the BGP connection initiated by the remote
    //    system.
    //
    // 3) Otherwise, the local system closes the newly created BGP
    //    connection (the one associated with the newly received OPEN
    //    message), and continues to use the existing one (the one that
    //    is already in the OpenConfirm state).
    //
    //    Unless allowed via configuration, a connection collision with an
    //    existing BGP connection that is in the Established state causes
    //    closing of the newly created connection.
    //
    //    Note that a connection collision cannot be detected with connections
    //    that are in Idle, Connect, or Active states.
    //
    //    Closing the BGP connection (that results from the collision
    //    resolution procedure) is accomplished by sending the NOTIFICATION
    //    message with the Error Code Cease.
    // ```
    //
    // The following steps are defined in the RFC for handling of a connection
    // that will be dropped as a result of collision resolution, and are
    // applicable for connections in either OpenSent or OpenConfirm states.
    //
    // ```
    //   - sends a NOTIFICATION with a Cease,
    //
    //   - sets the ConnectRetryTimer to zero,
    //
    //   - releases all BGP resources,
    //
    //   - drops the TCP connection,
    //
    //   - increments the ConnectRetryCounter by 1,
    //
    //   - (optionally) performs peer oscillation damping if the
    //     DampPeerOscillations attribute is set to TRUE, and
    //
    //   - changes its state to Idle.
    // ```
    fn collision_detection(
        self: &Arc<Self>,
        conn_pair: CollisionPair<Cnx>,
    ) -> FsmState<Cnx> {
        match conn_pair {
            CollisionPair::OpenConfirm(exist, new) => {
                self.register_conn(new.clone());
                collision_log!(self, info, new, exist.conn,
                    "collision detected: new connection [{:?}, conn_id: {}], existing connection [{:?}, conn_id: {}]",
                    new.conn(), new.id().short(),
                    exist.conn.conn(), exist.conn.id().short();
                );
                self.collision_detection_open_confirm(exist, new)
            }
            CollisionPair::OpenSent(exist, new) => {
                self.register_conn(new.clone());
                collision_log!(self, info, new, exist,
                    "collision detected: new connection [{:?}, conn_id: {}], existing connection [{:?}, conn_id: {}]",
                    new.conn(), new.id().short(),
                    exist.conn(), exist.id().short();
                );
                self.collision_detection_open_sent(exist, new)
            }
        }
    }

    // XXX: Fix collision_detection functions
    // XXX: Actually use conn_id in FSM event handlers
    // XXX: Refactor FSM event match statements to use event types

    // Handler for collisions when existing connection was in OpenConfirm state
    fn collision_detection_open_confirm(
        self: &Arc<Self>,
        exist: PeerConnection<Cnx>,
        new: Cnx,
    ) -> FsmState<Cnx> {
        if let Err(e) = self.send_open(&new) {
            collision_log!(self, error, new, exist.conn,
                "error sending open to new conn, fsm transition existing conn to open confirm: {e}";
                "error" => format!("{e}")
            );
            return FsmState::OpenConfirm(exist);
        }

        lock!(new.clock().timers.hold_timer).restart();
        self.counters
            .passive_connections_accepted
            .fetch_add(1, Ordering::Relaxed);

        // We just sent an Open to `new`, so treat it like it's in OpenSent.

        let om = loop {
            let event = match read_lock!(self.event_rx).recv() {
                Ok(event) => {
                    collision_log!(self, debug, new, exist.conn,
                        "new conn received fsm event {}", event.title();
                        "event" => event.title()
                    );
                    event
                }
                Err(e) => {
                    collision_log!(self, error, new, exist.conn,
                        "event rx error for new conn ({e}), fsm transition existing conn back to open confirm";
                        "error" => format!("{e}")
                    );
                    return FsmState::OpenConfirm(exist);
                }
            };

            match event {
                FsmEvent::Connection(ConnectionEvent::Message {
                    msg: Message::Open(om),
                    conn_id,
                }) => {
                    lock!(self.message_history)
                        .receive(om.clone().into(), None);
                    self.counters
                        .opens_received
                        .fetch_add(1, Ordering::Relaxed);
                    // Note: session counter increment would happen in SessionRunner context
                    break om;
                }

                FsmEvent::Admin(AdminEvent::ManualStop) => {
                    collision_log!(self, info, new, exist.conn,
                        "rx manual stop, fsm transition to idle";
                    );

                    self.send_notification(
                        &new,
                        ErrorCode::Cease,
                        ErrorSubcode::Cease(
                            CeaseErrorSubcode::AdministrativeShutdown,
                        ),
                    );

                    self.send_notification(
                        &exist.conn,
                        ErrorCode::Cease,
                        ErrorSubcode::Cease(
                            CeaseErrorSubcode::AdministrativeShutdown,
                        ),
                    );

                    self.connect_retry_counter.store(0, Ordering::Relaxed);
                    lock!(self.clock.timers.connect_retry_timer).restart();

                    return FsmState::Idle;
                }

                FsmEvent::Admin(AdminEvent::Reset) => {
                    collision_log!(self, info, new, exist.conn,
                        "rx fsm reset, fsm transition to idle";
                    );

                    self.send_notification(
                        &new,
                        ErrorCode::Cease,
                        ErrorSubcode::Cease(
                            CeaseErrorSubcode::AdministrativeReset,
                        ),
                    );

                    self.send_notification(
                        &exist.conn,
                        ErrorCode::Cease,
                        ErrorSubcode::Cease(
                            CeaseErrorSubcode::AdministrativeReset,
                        ),
                    );

                    self.connect_retry_counter.store(0, Ordering::Relaxed);
                    lock!(self.clock.timers.connect_retry_timer).restart();

                    return FsmState::Idle;
                }

                FsmEvent::Connection(ConnectionEvent::HoldTimerExpires(
                    conn_id,
                )) => {
                    collision_log!(self, warn, new, exist.conn,
                        "hold timer expired, fsm transition existing conn back to open confirm";
                    );

                    self.send_hold_timer_expired_notification(&new);

                    return FsmState::OpenConfirm(exist);
                }

                FsmEvent::Connection(ConnectionEvent::Message {
                    msg,
                    conn_id,
                }) => {
                    collision_log!(self, warn, new, exist.conn,
                        "rx unexpected {} message, drop new conn", msg.title();
                        "message" => msg.title()
                    );

                    self.send_fsm_notification(&new);

                    collision_log!(self, info, new, exist.conn,
                        "fsm transition existing conn back to open confirm";
                    );

                    return FsmState::OpenConfirm(exist);
                }

                FsmEvent::Session(SessionEvent::ConnectRetryTimerExpires)
                | FsmEvent::Connection(
                    ConnectionEvent::KeepaliveTimerExpires(ref conn_id),
                )
                | FsmEvent::Session(SessionEvent::IdleHoldTimerExpires) => {
                    collision_log!(self, warn, new, exist.conn,
                        "{} event not allowed in this state, drop new conn", event.title();
                    );

                    self.send_fsm_notification(&new);

                    collision_log!(self, info, new, exist.conn,
                        "fsm transition existing conn back to open confirm";
                    );

                    return FsmState::OpenConfirm(exist);
                }

                other => {
                    collision_log!(self, warn, new, exist.conn,
                        "unexpected {} event received, ignoring..", other.title();
                    );

                    continue;
                }
            }
        };

        let my_id = self.id;
        let exist_id = exist.id;
        let new_id = om.id;
        collision_log!(self, info, new, exist.conn,
            "collision detected: local id {my_id}, remote id {new_id}";
        );

        if new_id != exist_id {
            // XXX: Is this the right thing to do here?
            //      It seems pretty unlikely that we'd organically encounter
            //      RIDs differing across parallel connections to the same
            //      peer IP, but what would the alternative be, just take the RID
            //      of one connection and assume both match?
            collision_log!(self, error, new, exist.conn,
                "collision error: rx BGP-ID mismatch, {new_id} (new conn) != {exist_id} (existing conn)";
            );
            collision_log!(self, info, new, exist.conn,
                "fsm transition to idle";
            );

            return FsmState::Idle;
        }

        if my_id > new_id {
            collision_log!(self, info, new, exist.conn,
                "collision resolution: existing conn wins with higher BGP-ID ({my_id} > {new_id})";
            );

            // Our RID is higher, we win. Kill `new`. Kill it to death.
            self.send_collision_resolution_notification(&new);

            lock!(exist.conn.clock().timers.hold_timer).restart();
            lock!(exist.conn.clock().timers.keepalive_timer).restart();

            return FsmState::SessionSetup(exist);
        }

        // Our RID is lower, we lose. Barring any errors, setup
        // new conn and leave `existing` for dead.
        collision_log!(self, info, new, exist.conn,
            "collision resolution: new conn wins ({new_id} >= {my_id})";
        );

        self.send_collision_resolution_notification(&exist.conn);

        self.connect_retry_counter.store(0, Ordering::Relaxed);
        self.counters
            .connection_retries
            .fetch_add(1, Ordering::Relaxed);

        if let Err(e) = self.handle_open(&new, &om) {
            collision_log!(self, warn, new, exist.conn,
                "new conn failed to handle open message: {e}";
                "error" => format!("{e}")
            );
            collision_log!(self, info, new, exist.conn,
                "fsm transition existing conn to idle";
            );

            return FsmState::Idle;
        }

        lock!(new.clock().timers.hold_timer).restart();
        lock!(new.clock().timers.keepalive_timer).restart();

        FsmState::SessionSetup(PeerConnection {
            conn: new,
            id: new_id,
        })
    }

    // Handler for collisions when existing connection was in OpenSent state
    fn collision_detection_open_sent(
        self: &Arc<Self>,
        exist: Cnx,
        new: Cnx,
    ) -> FsmState<Cnx> {
        if let Err(e) = self.send_open(&new) {
            collision_log!(self, error, new, exist,
                "error sending open to new conn: {e}";
                "error" => format!("{e}")
            );
            collision_log!(self, info, new, exist,
                "fsm transition existing conn to open confirm";
                "error" => format!("{e}")
            );
            return FsmState::OpenSent(exist);
        }

        lock!(new.clock().timers.hold_timer).restart();
        self.counters
            .passive_connections_accepted
            .fetch_add(1, Ordering::Relaxed);

        // We just sent an Open to `new`, so treat it like it's in OpenSent.
        // Now both `new` and `exist` are OpenSent and we need to care for them
        // until they both get Open messages and we can do collision resolution.

        let mut select = Select::new();
        let op_new = select.recv(&new.event_rx);
        let exist_event_rx = read_lock!(self.event_rx);
        let op_exist = select.recv(&exist_event_rx);
        let mut opens = (None, None);

        let (om_new, om_exist) = loop {
            // We don't need ready_timeout() or ready_deadline() because the
            // hold timer is running for both connections. In the worst case
            // (from a delay standpoint), we will return when the timer pops
            // for HoldTimerExpires.
            let (event, is_new, _conn, mh) = match select.ready() {
                i if i == op_new => match new.event_rx.recv() {
                    Ok(event) => {
                        collision_log!(self, debug, new, exist,
                            "new conn received fsm event {}", event.title();
                            "event" => event.title()
                        );
                        (event, true, &new, new.message_history.clone())
                    }
                    Err(e) => {
                        collision_log!(self, error, new, exist,
                            "new conn event rx error: {e}";
                            "error" => format!("{e}")
                        );
                        drop(exist_event_rx); // Drop the read lock before returning
                        return FsmState::OpenSent(exist);
                    }
                },
                i if i == op_exist => match exist_event_rx.recv() {
                    Ok(event) => {
                        collision_log!(self, debug, new, exist,
                            "existing conn received fsm event {}", event.title();
                            "event" => event.title()
                        );
                        (event, false, &exist, self.message_history.clone())
                    }
                    Err(e) => {
                        collision_log!(self, error, new, exist,
                            "existing conn event rx error: {e}";
                            "error" => format!("{e}")
                        );
                        drop(exist_event_rx); // Drop the read lock before calling commandeer
                        self.commandeer(
                            new.event_rx,
                            new.event_tx.clone(),
                            lock!(new.message_history).clone(),
                            new.clock,
                        );

                        return FsmState::OpenSent(new);
                    }
                },
                i => {
                    collision_log!(self, info, new, exist,
                        "select returned invalid index {i}, fsm transition to idle";
                    );
                    drop(exist_event_rx); // Drop the read lock before returning
                    return FsmState::Idle;
                }
            };

            match event {
                FsmEvent::Connection(ConnectionEvent::Message {
                    msg,
                    conn_id,
                }) => {
                    match msg {
                        Message::Open(om) => {
                            lock!(mh).receive(
                                om.clone().into(),
                                Some(conn_id.clone()),
                            );
                            self.counters
                                .opens_received
                                .fetch_add(1, Ordering::Relaxed);
                            if is_new {
                                opens.0 = Some(om);
                            } else {
                                opens.1 = Some(om);
                            }
                        }

                        // Because we are maintaining two connections in
                        // parallel, we must handle Keepalives here.
                        // e.g.
                        // It is valid if we receive and process an Open and a
                        // Keepalive via one connection before receiving and
                        // processing an Open via the other connection. In this
                        // case, we shouldn't bail out to Idle.
                        //
                        // To stay on the conservative side, we will only accept
                        // Keepalives from a connection if it has already
                        // received an Open.
                        Message::KeepAlive => {
                            self.counters
                                .keepalives_received
                                .fetch_add(1, Ordering::Relaxed);
                            if is_new && opens.0.is_some() {
                                lock!(new.clock().timers.hold_timer).restart();
                                lock!(new.clock().timers.keepalive_timer)
                                    .restart();
                            } else if !is_new && opens.1.is_some() {
                                lock!(exist.clock().timers.hold_timer)
                                    .restart();
                                lock!(exist.clock().timers.keepalive_timer)
                                    .restart();
                            } else {
                                collision_log!(self, warn, new, exist,
                                    "existing conn rx unexpected {} message", msg.title();
                                    "message" => msg.title()
                                );

                                self.send_fsm_notification(&exist);

                                collision_log!(self, info, new, exist,
                                    "fsm transition new conn to open sent";
                                );

                                return FsmState::OpenSent(new);
                            }
                        }

                        _ => {
                            if is_new {
                                collision_log!(self, warn, new, exist,
                                    "new conn rx unexpected {} message", msg.title();
                                    "message" => msg.title()
                                );

                                self.send_fsm_notification(&new);

                                collision_log!(self, info, new, exist,
                                    "fsm transition existing conn to open sent";
                                );

                                return FsmState::OpenSent(exist);
                            } else {
                                collision_log!(self, warn, new, exist,
                                    "existing conn rx unexpected {} message", msg.title();
                                    "message" => msg.title()
                                );

                                self.send_fsm_notification(&exist);

                                collision_log!(self, info, new, exist,
                                    "fsm transition new conn to open sent";
                                );

                                return FsmState::OpenSent(new);
                            }
                        }
                    }
                }

                FsmEvent::Admin(AdminEvent::ManualStop) => {
                    if is_new {
                        collision_log!(self, info, new, exist,
                            "new conn rx manual stop, fsm transition to idle";
                        );
                    } else {
                        collision_log!(self, info, new, exist,
                            "existing conn rx manual stop, fsm transition to idle";
                        );
                    }

                    self.send_notification(
                        &new,
                        ErrorCode::Cease,
                        ErrorSubcode::Cease(
                            CeaseErrorSubcode::AdministrativeShutdown,
                        ),
                    );

                    self.send_notification(
                        &exist,
                        ErrorCode::Cease,
                        ErrorSubcode::Cease(
                            CeaseErrorSubcode::AdministrativeShutdown,
                        ),
                    );

                    self.connect_retry_counter.store(0, Ordering::Relaxed);
                    {
                        let guard = &self.clock;
                        lock!(guard.timers.connect_retry_timer)
                    }
                    .restart();

                    drop(exist_event_rx); // Drop the read lock before returning
                    return FsmState::Idle;
                }

                FsmEvent::Admin(AdminEvent::Reset) => {
                    if is_new {
                        collision_log!(self, info, new, exist,
                            "new conn rx fsm reset, fsm transition to idle";
                        );
                    } else {
                        collision_log!(self, info, new, exist,
                            "existing conn rx fsm reset, fsm transition to idle";
                        );
                    }

                    self.send_notification(
                        &new,
                        ErrorCode::Cease,
                        ErrorSubcode::Cease(
                            CeaseErrorSubcode::AdministrativeReset,
                        ),
                    );

                    self.send_notification(
                        &exist,
                        ErrorCode::Cease,
                        ErrorSubcode::Cease(
                            CeaseErrorSubcode::AdministrativeReset,
                        ),
                    );

                    self.connect_retry_counter.store(0, Ordering::Relaxed);
                    {
                        let guard = &self.clock;
                        lock!(guard.timers.connect_retry_timer)
                    }
                    .restart();

                    drop(exist_event_rx); // Drop the read lock before returning
                    return FsmState::Idle;
                }

                FsmEvent::Connection(ConnectionEvent::HoldTimerExpires(
                    conn_id,
                )) => {
                    if is_new {
                        collision_log!(self, warn, new, exist,
                            "hold timer expired for new conn";
                        );

                        self.send_hold_timer_expired_notification(&new);
                        drop(exist_event_rx); // Drop the read lock before calling commandeer

                        self.commandeer(
                            new.event_rx,
                            new.event_tx.clone(),
                            lock!(new.message_history).clone(),
                            new.clock,
                        );

                        collision_log!(self, info, new, exist,
                            "fsm transition existing conn to open sent";
                        );

                        return FsmState::OpenSent(exist);
                    } else {
                        collision_log!(self, warn, new, exist,
                            "hold timer expired for existing conn";
                        );

                        self.send_hold_timer_expired_notification(&exist);
                        drop(exist_event_rx); // Drop the read lock before calling commandeer

                        self.commandeer(
                            new.event_rx,
                            new.event_tx.clone(),
                            lock!(new.message_history).clone(),
                            new.clock,
                        );

                        collision_log!(self, info, new, exist,
                            "fsm transition new conn to open sent";
                        );

                        return FsmState::OpenSent(new);
                    }
                }

                FsmEvent::Session(SessionEvent::ConnectRetryTimerExpires)
                | FsmEvent::Connection(
                    ConnectionEvent::KeepaliveTimerExpires(conn_id),
                )
                | FsmEvent::Session(SessionEvent::IdleHoldTimerExpires) => {
                    if is_new {
                        collision_log!(self, warn, new, exist,
                            "{} event not allowed in this state, drop new conn", event.title();
                        );

                        self.send_fsm_notification(&new);

                        collision_log!(self, info, new, exist,
                            "fsm transition existing conn to open sent";
                        );

                        return FsmState::OpenSent(exist);
                    } else {
                        collision_log!(self, warn, new, exist,
                            "{} event not allowed in this state, drop existing conn", event.title();
                        );

                        self.send_fsm_notification(&exist);
                        drop(exist_event_rx); // Drop the read lock before calling commandeer

                        self.commandeer(
                            new.event_rx,
                            new.event_tx.clone(),
                            lock!(new.message_history).clone(),
                            new.clock,
                        );

                        collision_log!(self, info, new, exist,
                            "fsm transition new conn to open sent";
                        );

                        return FsmState::OpenSent(new);
                    }
                }

                other => {
                    if is_new {
                        collision_log!(self, warn, new, exist,
                            "unexpected {} event received by new conn, ignoring..", other.title();
                        );
                    } else {
                        collision_log!(self, warn, new, exist,
                            "unexpected {} event received by existing conn, ignoring..", other.title();
                        );
                    }

                    continue;
                }
            };

            match opens {
                (Some(new), Some(exist)) => break (new, exist),
                _ => continue,
            }
        };

        // Drop the read lock now that we're done with the loop and before any potential commandeer() calls
        drop(exist_event_rx);

        let my_id = self.id;
        let new_id = om_new.id;
        let exist_id = om_exist.id;
        if new_id != exist_id {
            // XXX: Is this the right thing to do here?
            //      RIDs differing across parallel connections to the same
            //      peer IP seems pretty unlikely to occur organically, but
            //      what would the alternative be? just take the RID of one
            //      connection and assume both match?
            collision_log!(self, error, new, exist,
                "collision error: rx BGP-ID mismatch, {new_id} (new conn) != {exist_id} (existing conn)";
            );
            collision_log!(self, info, new, exist,
                "fsm transition to idle";
            );

            return FsmState::Idle;
        }

        collision_log!(self, info, new, exist,
            "collision detected: local id {my_id}, remote id {new_id}";
        );

        if my_id > new_id {
            collision_log!(self, info, new, exist,
                "collision resolution: existing conn wins with higher RID ({my_id} > {new_id})";
            );

            // Our RID is higher, we win. Kill `new`. Kill it to death.
            self.send_collision_resolution_notification(&new);

            if let Err(e) = self.handle_open(&exist, &om_exist) {
                collision_log!(self, warn, new, exist,
                    "existing conn won, but failed to handle open message: ({e}), fsm transition to idle";
                    "error" => format!("{e}")
                );

                return FsmState::Idle;
            }

            lock!(exist.clock().timers.hold_timer).restart();
            lock!(exist.clock().timers.keepalive_timer).restart();

            return FsmState::SessionSetup(PeerConnection {
                conn: exist,
                id: new_id,
            });
        }

        // Our RID is lower, we lose. Barring any errors, setup
        // new conn and leave `existing` for dead.
        collision_log!(self, info, new, exist,
            "collision resolution: new conn wins ({new_id} >= {my_id})";
        );

        self.send_collision_resolution_notification(&exist);

        lock!(self.clock.timers.connect_retry_timer).zero();
        self.counters
            .connection_retries
            .fetch_add(1, Ordering::Relaxed);

        if let Err(e) = self.handle_open(&new, &om_new) {
            collision_log!(self, warn, new, exist,
                "new conn won but failed to handle open message: {e}, fsm transition to idle";
                "error" => format!("{e}")
            );

            return FsmState::Idle;
        }

        self.counters
            .passive_connections_accepted
            .fetch_add(1, Ordering::Relaxed);

        lock!(new.clock().timers.hold_timer).restart();
        lock!(new.clock().timers.keepalive_timer).restart();

        FsmState::SessionSetup(PeerConnection {
            conn: new,
            id: new_id,
        })
    }

    /// Sync up with peers.
    fn session_setup(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        // Collect the prefixes this router is originating.
        let originated = match self.db.get_origin4() {
            Ok(value) => value,
            Err(e) => {
                //TODO possible death loop. Should we just panic here?
                session_log!(self, error, pc.conn,
                    "failed to get originated routes from db";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "error" => format!("{e}")
                );
                return FsmState::SessionSetup(pc);
            }
        };

        // Ensure the router has a fanout entry for this peer.
        let mut fanout = write_lock!(self.fanout);
        fanout.add_egress(
            self.neighbor.host.ip(),
            crate::fanout::Egress {
                event_tx: Some(read_lock!(self.event_tx).clone()),
                log: self.log.clone(),
            },
        );
        drop(fanout);

        self.send_keepalive(&pc.conn);
        lock!(pc.conn.clock().timers.keepalive_timer).restart();

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
            if let Err(e) =
                self.send_update(update, &pc.conn, ShaperApplication::Current)
            {
                session_log!(self, error, pc.conn,
                    "failed to send update, fsm transition to idle";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "error" => format!("{e}")
                );
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
        let event = match read_lock!(self.event_rx).recv() {
            Ok(event) => {
                session_log!(self, debug, pc.conn,
                    "received fsm event";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "event" => event.title()
                );
                event
            }
            Err(e) => {
                //TODO possible death loop. Should we just panic here? Is it
                // even possible to recover from an error here as it likely
                // means the channel is toast.
                session_log!(self, error, pc.conn,
                    "event rx error: {e}";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "error" => format!("{e}")
                );
                return FsmState::Established(pc);
            }
        };
        match event {
            FsmEvent::Admin(AdminEvent::Reset) => {
                session_log!(self, info, pc.conn,
                    "rx reset, fsm transition to idle";
                    "fsm_state" => format!("{}", self.state()).as_str()
                );
                self.exit_established(pc)
            }
            // When the keepalive timer fires, send a keepalive to the peer.
            FsmEvent::Connection(ConnectionEvent::KeepaliveTimerExpires(
                conn_id,
            )) => {
                self.send_keepalive(&pc.conn);
                // XXX: How has this been working without the timer being reset
                //      after each keepalive is sent?
                lock!(pc.conn.clock().timers.keepalive_timer).restart();
                FsmState::Established(pc)
            }

            // If the hold timer fires, it means we've not received a keepalive
            // from the peer within the hold time - so exit the established
            // state and restart the peer FSM from the connect state.
            FsmEvent::Connection(ConnectionEvent::HoldTimerExpires(
                conn_id,
            )) => {
                session_log!(self, warn, pc.conn,
                    "hold timer expired, fsm transition to idle";
                    "fsm_state" => format!("{}", self.state()).as_str()
                );
                self.counters
                    .hold_timer_expirations
                    .fetch_add(1, Ordering::Relaxed);
                self.send_hold_timer_expired_notification(&pc.conn);
                self.exit_established(pc)
            }

            // We've received an update message from the peer. Reset the hold
            // timer and apply the update to the RIB.
            FsmEvent::Connection(ConnectionEvent::Message {
                msg: Message::Update(m),
                conn_id,
            }) => {
                lock!(pc.conn.clock().timers.hold_timer).reset();
                session_log!(self, info, pc.conn, "received update";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "message" => "update",
                    "message_contents" => format!("{m}").as_str()
                );
                let peer_as = lock!(self.remote_asn).unwrap_or(0);
                self.apply_update(m.clone(), &pc, peer_as);
                lock!(self.message_history).receive(m.into(), None);
                self.counters
                    .updates_received
                    .fetch_add(1, Ordering::Relaxed);
                FsmState::Established(pc)
            }

            FsmEvent::Connection(ConnectionEvent::Message {
                msg: Message::RouteRefresh(m),
                conn_id,
            }) => {
                lock!(pc.conn.clock().timers.hold_timer).reset();
                session_log!(self, info, pc.conn, "received route refresh";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "message" => "route refresh",
                    "message_contents" => format!("{m}").as_str()
                );
                lock!(self.message_history).receive(m.clone().into(), None);
                self.counters
                    .route_refresh_received
                    .fetch_add(1, Ordering::Relaxed);
                if let Err(e) = self.handle_refresh(m, &pc) {
                    session_log!(self, error, pc.conn,
                        "error handling route refresh, fsm transition to idle";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
                    self.exit_established(pc)
                } else {
                    FsmState::Established(pc)
                }
            }

            // We've received a notification from the peer. They are displeased
            // with us. Exit established and restart from the connect state.
            FsmEvent::Connection(ConnectionEvent::Message {
                msg: Message::Notification(m),
                conn_id,
            }) => {
                session_log!(self, warn, pc.conn,
                    "notification received, fsm transition to idle";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "message" => "notification",
                    "message_contents" => format!("{m}")
                );
                lock!(self.message_history).receive(m.into(), None);
                self.counters
                    .notifications_received
                    .fetch_add(1, Ordering::Relaxed);
                self.exit_established(pc)
            }

            // We've received a keepliave from the peer, reset the hold timer
            // and re-enter the established state.
            FsmEvent::Connection(ConnectionEvent::Message {
                msg: Message::KeepAlive,
                conn_id,
            }) => {
                session_log!(self, trace, pc.conn,
                    "keepalive received";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "message" => "keepalive"
                );
                self.counters
                    .keepalives_received
                    .fetch_add(1, Ordering::Relaxed);
                lock!(pc.conn.clock().timers.hold_timer).reset();
                FsmState::Established(pc)
            }

            // An announce request has come from the administrative API or
            // another peer session (redistribution). Send the update to our
            // peer.
            FsmEvent::Admin(AdminEvent::Announce(update)) => {
                if let Err(e) = self.send_update(
                    update,
                    &pc.conn,
                    ShaperApplication::Current,
                ) {
                    session_log!(self, error, pc.conn,
                        "failed to send update, fsm transition to idle";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
                    return self.exit_established(pc);
                }
                FsmState::Established(pc)
            }

            FsmEvent::Session(SessionEvent::IdleHoldTimerExpires) => {
                self.counters
                    .idle_hold_timer_expirations
                    .fetch_add(1, Ordering::Relaxed);
                lock!(self.clock.timers.idle_hold_timer).disable();
                FsmState::Established(pc)
            }

            // On an unexpected message, log a warning and re-enter the
            // established state.
            FsmEvent::Connection(ConnectionEvent::Message {
                msg: Message::Open(om),
                conn_id,
            }) => {
                self.counters
                    .unexpected_open_message
                    .fetch_add(1, Ordering::Relaxed);
                session_log!(self, warn, pc.conn, "unexpected message";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "message" => "open",
                    "message_contents" => format!("{om}").as_str()
                );
                FsmState::Established(pc)
            }

            FsmEvent::Admin(AdminEvent::ShaperChanged(previous)) => {
                match self.originate_update(
                    &pc,
                    ShaperApplication::Difference(previous),
                ) {
                    Err(e) => {
                        session_log!(self, error, pc.conn,
                            "failed to originate update, fsm transition to idle";
                            "fsm_state" => format!("{}", self.state()).as_str(),
                            "error" => format!("{e}")
                        );
                        self.exit_established(pc)
                    }
                    Ok(()) => FsmState::Established(pc),
                }
            }

            FsmEvent::Admin(AdminEvent::ExportPolicyChanged(previous)) => {
                let originated = match self.db.get_origin4() {
                    Ok(value) => value,
                    Err(e) => {
                        //TODO possible death loop. Should we just panic here?
                        session_log!(self, error, pc.conn,
                            "failed to get originated routes from db";
                            "fsm_state" => format!("{}", self.state()).as_str(),
                            "error" => format!("{e}")
                        );
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
                    session_log!(self, error, pc.conn,
                        "failed to send update, fsm transition to idle";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
                    return self.exit_established(pc);
                }

                FsmState::Established(pc)
            }

            FsmEvent::Admin(AdminEvent::PathAttributesChanged) => {
                match self.originate_update(&pc, ShaperApplication::Current) {
                    Err(e) => {
                        session_log!(self, error, pc.conn,
                            "failed to originate update, fsm transition to idle";
                            "fsm_state" => format!("{}", self.state()).as_str(),
                            "error" => format!("{e}")
                        );
                        self.exit_established(pc)
                    }
                    Ok(()) => FsmState::Established(pc),
                }
            }

            FsmEvent::Admin(AdminEvent::SendRouteRefresh) => {
                self.db.mark_bgp_peer_stale(pc.conn.peer().ip());
                self.send_route_refresh(&pc.conn);
                FsmState::Established(pc)
            }

            FsmEvent::Admin(AdminEvent::ReAdvertiseRoutes) => {
                if let Err(e) = self.refresh_react(&pc.conn) {
                    session_log!(self, error, pc.conn,
                        "route re-advertisement error: {e}";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
                    return self.exit_established(pc);
                }
                FsmState::Established(pc)
            }

            FsmEvent::Admin(AdminEvent::CheckerChanged(_previous)) => {
                //TODO
                FsmState::Established(pc)
            }

            // Some unexpeted event, log and re-enter established.
            e => {
                session_log!(self, warn, pc.conn,
                    "unexpected fsm event, ignoring";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "event" => e.title()
                );
                FsmState::Established(pc)
            }
        }
    }

    // Housekeeping items to do when a session shutdown is requested.
    pub fn on_shutdown(&self) {
        session_log_lite!(self, info, "shutting down";
            "fsm_state" => format!("{}", self.state()).as_str()
        );

        // Go back to the beginning of the state machine.
        *(lock!(self.state)) = FsmStateKind::Idle;

        // Reset the shutdown signal and running flag.
        self.shutdown.store(false, Ordering::Release);
        self.running.store(false, Ordering::Release);

        session_log_lite!(self, info, "shutdown complete";
            "fsm_state" => format!("{}", self.state()).as_str()
        );
    }

    /// Send an event to the state machine driving this peer session.
    pub fn send_event(&self, e: FsmEvent<Cnx>) -> Result<(), Error> {
        read_lock!(self.event_tx)
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
        if let Some(checker) = read_lock!(self.router.policy.checker).as_ref() {
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
                    session_log!(self, error, conn,
                        "open checker exec failed: {e}";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
                }
            }
        }
        // Update remote peer info and capabilities in SessionRunner fields
        *lock!(self.remote_asn) = Some(remote_asn);
        *lock!(self.remote_id) = Some(remote_id);
        *lock!(self.capabilities_received) = om.get_capabilities();

        {
            let clock = conn.clock();
            let mut ht = lock!(clock.timers.hold_timer);
            let mut kt = lock!(clock.timers.keepalive_timer);
            let mut theirs = false;
            // XXX: handle peer sending us a holdtime of 0 (keepalives disabled)
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
                    ht.restart();
                    // per BGP RFC section 10
                    kt.interval = Duration::from_secs(requested / 3);
                    kt.restart();
                }
            }
            if !theirs {
                ht.interval = clock.timers.config_hold_time;
                ht.restart();
                kt.interval = clock.timers.config_keepalive_time;
                kt.restart();
            }
        }
        Ok(())
    }

    /// Send a keepalive message to the session peer.
    fn send_keepalive(&self, conn: &Cnx) {
        session_log!(self, trace, conn, "sending keepalive";
            "fsm_state" => format!("{}", self.state()).as_str(),
            "message" => "keepalive"
        );
        if let Err(e) = conn.send(Message::KeepAlive) {
            session_log!(self, error, conn, "failed to send keepalive: {e}";
                "fsm_state" => format!("{}", self.state()).as_str(),
                "error" => format!("{e}")
            );
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
        session_log!(self, info, conn, "sending route refresh";
            "fsm_state" => format!("{}", self.state()).as_str(),
            "message" => "route refresh"
        );
        if let Err(e) = conn.send(Message::RouteRefresh(RouteRefreshMessage {
            afi: Afi::Ipv4 as u16,
            safi: Safi::NlriUnicast as u8,
        })) {
            session_log!(self, error, conn, "failed to send route refresh: {e}";
                "fsm_state" => format!("{}", self.state()).as_str(),
                "error" => format!("{e}")
            );
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

    fn send_collision_resolution_notification(&self, conn: &Cnx) {
        self.send_notification(
            conn,
            ErrorCode::Cease,
            ErrorSubcode::Cease(
                CeaseErrorSubcode::ConnectionCollisionResolution,
            ),
        )
    }

    fn send_fsm_notification(&self, conn: &Cnx) {
        self.send_notification(
            conn,
            ErrorCode::Fsm,
            // Unspecific, FSM doesn't have a defined subcode
            ErrorSubcode::Fsm(0),
        )
    }

    fn send_notification(
        &self,
        conn: &Cnx,
        error_code: ErrorCode,
        error_subcode: ErrorSubcode,
    ) {
        let notification = NotificationMessage {
            error_code,
            error_subcode,
            data: Vec::new(),
        };

        session_log!(self, info, conn,
            "sending notification: {error_code} / {error_subcode}";
            "fsm_state" => format!("{}", self.state()).as_str(),
            "message" => "notification",
            "message_contents" => format!("{notification}").as_str()
        );

        let msg = Message::Notification(notification);
        lock!(self.message_history).send(msg.clone(), None);

        if let Err(e) = conn.send(msg) {
            session_log!(self, error, conn,
                "failed to send notification: {e}";
                "fsm_state" => format!("{}", self.state()).as_str(),
                "error" => format!("{e}")
            );
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
        let capabilities = lock!(self.capabilities_sent).clone();
        let mut msg = match self.asn {
            Asn::FourOctet(asn) => OpenMessage::new4(
                asn,
                lock!(conn.clock().timers.hold_timer).interval.as_secs() as u16,
                self.id,
            ),
            Asn::TwoOctet(asn) => OpenMessage::new2(
                asn,
                lock!(conn.clock().timers.hold_timer).interval.as_secs() as u16,
                self.id,
            ),
        };
        msg.add_capabilities(&capabilities);

        let mut out = Message::from(msg.clone());
        if let Some(shaper) = read_lock!(self.router.policy.shaper).as_ref() {
            let peer_as = lock!(self.remote_asn).unwrap_or(0);
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
                    session_log!(self, error, conn,
                        "open shaper exec failed: {e}";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
                }
            }
        }
        drop(msg);
        lock!(self.message_history).send(out.clone(), None);

        self.counters.opens_sent.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = conn.send(out) {
            session_log!(self, error, conn,
                "send_open failed: {e}";
                "fsm_state" => format!("{}", self.state()).as_str(),
                "error" => format!("{e}")
            );
            self.counters
                .open_send_failure
                .fetch_add(1, Ordering::Relaxed);
            Err(e)
        } else {
            Ok(())
        }
    }

    fn is_ebgp(&self) -> bool {
        if let Some(remote) = *lock!(self.remote_asn) {
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
        if let Some(shaper) = read_lock!(self.router.policy.shaper).as_ref() {
            let peer_as = lock!(self.remote_asn).unwrap_or(0);
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
        let peer_as = lock!(self.remote_asn).unwrap_or(0);

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
        let nexthop = conn.local().ip().to_canonical();

        update
            .path_attributes
            .push(PathAttributeValue::NextHop(nexthop).into());

        if let Some(med) = lock!(self.session).multi_exit_discriminator {
            update
                .path_attributes
                .push(PathAttributeValue::MultiExitDisc(med).into());
        }

        if self.is_ibgp() {
            update.path_attributes.push(
                PathAttributeValue::LocalPref(
                    lock!(self.session).local_pref.unwrap_or(0),
                )
                .into(),
            );
        }

        let cs: Vec<Community> = lock!(self.session)
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
        };

        let out = match self.shape_update(update, shaper_application)? {
            ShaperResult::Emit(msg) => msg,
            ShaperResult::Drop => return Ok(()),
        };

        lock!(self.message_history).send(out.clone(), None);

        self.counters.updates_sent.fetch_add(1, Ordering::Relaxed);

        if let Err(e) = conn.send(out) {
            session_log!(self, error, conn,
                "failed to send update: {e}";
                "fsm_state" => format!("{}", self.state()).as_str(),
                "error" => format!("{e}")
            );
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
        self.connect_retry_counter.fetch_add(1, Ordering::Relaxed);
        lock!(pc.conn.clock().timers.hold_timer).disable();
        lock!(pc.conn.clock().timers.keepalive_timer).disable();

        write_lock!(self.fanout).remove_egress(self.neighbor.host.ip());

        // remove peer prefixes from db
        self.db.remove_bgp_prefixes_from_peer(&pc.conn.peer().ip());

        FsmState::Idle
    }

    /// Apply an update by adding it to our RIB.
    fn apply_update(
        &self,
        mut update: UpdateMessage,
        pc: &PeerConnection<Cnx>,
        peer_as: u32,
    ) {
        if let Err(e) = self.check_update(&update) {
            session_log!(self, warn, pc.conn,
                "update check failed: {e}";
                "fsm_state" => format!("{}", self.state()).as_str(),
                "error" => format!("{e}"),
                "message" => "update",
                "message_contents" => format!("{update}").as_str()
            );
            return;
        }
        self.apply_static_update_policy(&mut update);

        if let Some(checker) = read_lock!(self.router.policy.checker).as_ref() {
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
                    session_log!(self, error, pc.conn,
                        "open checker exec failed: {e}";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "error" => format!("{e}")
                    );
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
        };

        self.update_rib(&update, pc, peer_as);

        // NOTE: for now we are only acting as an edge router. This means we
        //       do not redistribute announcements. If this changes, uncomment
        //       the following to enable redistribution.
        //
        //    self.fanout_update(&update);
    }

    pub fn refresh_react(&self, conn: &Cnx) -> Result<(), Error> {
        let originated = match self.db.get_origin4() {
            Ok(value) => value,
            Err(e) => {
                session_log!(self, error, conn,
                    "failed to get originated routes from db";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "error" => format!("{e}")
                );
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
            self.send_update(update, conn, ShaperApplication::Current)?;
        }
        Ok(())
    }

    fn handle_refresh(
        &self,
        msg: RouteRefreshMessage,
        pc: &PeerConnection<Cnx>,
    ) -> Result<(), Error> {
        if msg.afi != Afi::Ipv4 as u16 {
            return Ok(());
        }
        self.refresh_react(&pc.conn)
    }

    /// Update this router's RIB based on an update message from a peer.
    fn update_rib(
        &self,
        update: &UpdateMessage,
        pc: &PeerConnection<Cnx>,
        peer_as: u32,
    ) {
        self.db.remove_bgp_prefixes(
            update
                .withdrawn
                .iter()
                .map(|w| rdb::Prefix::from(w.as_prefix4()))
                .collect(),
            &pc.conn.peer().ip(),
        );

        let originated = match self.db.get_origin4() {
            Ok(value) => value,
            Err(e) => {
                session_log!(self, error, pc.conn,
                    "failed to get originated routes from db";
                    "fsm_state" => format!("{}", self.state()).as_str(),
                    "error" => format!("{e}")
                );
                Vec::new()
            }
        };

        if !update.nlri.is_empty() {
            // TODO: parse and prefer nexthop in MP_REACH_NLRI
            //
            // Per RFC 4760:
            // """
            // The next hop information carried in the MP_REACH_NLRI path attribute
            // defines the Network Layer address of the router that SHOULD be used
            // as the next hop to the destinations listed in the MP_NLRI attribute
            // in the UPDATE message.
            //
            // [..]
            //
            // An UPDATE message that carries no NLRI, other than the one encoded in
            // the MP_REACH_NLRI attribute, SHOULD NOT carry the NEXT_HOP attribute.
            // If such a message contains the NEXT_HOP attribute, the BGP speaker
            // that receives the message SHOULD ignore this attribute.
            // """
            //
            // i.e.
            // 1) NEXT_HOP SHOULD NOT be sent unless there are no MP_REACH_NLRI
            // 2) NEXT_HOP SHOULD be ignored unless there are no MP_REACH_NLRI
            //
            // The standards do not state whether an implementation can/should send
            // IPv4 Unicast prefixes embedded in an MP_REACH_NLRI attribute or in the
            // classic NLRI field of an Update message. If we participate in MP-BGP
            // and negotiate IPv4 Unicast, it's entirely likely that we'll peer with
            // other BGP speakers falling into any of the combinations:
            // a) MP not negotiated, IPv4 Unicast in NLRI, NEXT_HOP included
            // b) MP negotiated, IPv4 Unicast in NLRI, NEXT_HOP included
            // c) MP negotiated, IPv4 Unicast in NLRI, NEXT_HOP not included
            // d) MP negotiated, IPv4 Unicast in MP_REACH_NLRI, NEXT_HOP included
            // e) MP negotiated, IPv4 Unicast in MP_REACH_NLRI, NEXT_HOP not included
            let nexthop = match update.nexthop4() {
                Some(nh) => nh,
                None => {
                    session_log!(self, warn, pc.conn,
                        "recieved update with nlri, but no nexthop";
                        "fsm_state" => format!("{}", self.state()).as_str(),
                        "message" => "update",
                        "message_contents" => format!("{update}").as_str()
                    );
                    self.counters
                        .update_nexhop_missing
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };

            let mut as_path = Vec::new();
            if let Some(segments_list) = update.as_path() {
                for segments in &segments_list {
                    as_path.extend(segments.value.iter());
                }
            }
            let path = rdb::Path {
                nexthop: nexthop.into(),
                shutdown: update.graceful_shutdown(),
                rib_priority: DEFAULT_RIB_PRIORITY_BGP,
                bgp: Some(BgpPathProperties {
                    origin_as: peer_as,
                    peer: pc.conn.peer().ip(),
                    id: pc.id,
                    med: update.multi_exit_discriminator(),
                    local_pref: update.local_pref(),
                    as_path,
                    stale: None,
                }),
                vlan_id: lock!(self.session).vlan_id,
            };

            self.db.add_bgp_prefixes(
                update
                    .nlri
                    .iter()
                    .filter(|p| !originated.contains(&p.as_prefix4()))
                    .filter(|p| !self.is_v4_martian(&p.as_prefix4()))
                    .map(|n| rdb::Prefix::from(n.as_prefix4()))
                    .collect(),
                path.clone(),
            );
        }

        //TODO(IPv6) iterate through MpReachNlri attributes for IPv6
    }

    /// Perform a set of checks on an update to see if we can accept it.
    fn check_update(&self, update: &UpdateMessage) -> Result<(), Error> {
        self.check_for_self_in_path(update)?;
        self.check_nexthop_self(update)?;
        let info = lock!(self.session);
        if info.enforce_first_as {
            if let Some(peer_as) = *lock!(self.remote_asn) {
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
                    return Err(Error::SelfLoopDetected);
                }
            }
        }
        Ok(())
    }

    /// Returns true if prefix carries a martian value, i.e. the prefix
    /// is not a valid routable IPv4 Unicast subnet. Currently this only
    /// checks if the prefix overlaps with IPv4 Loopback (127.0.0.0/8)
    /// or Multicast (224.0.0.0/4) address space. We deliberately skip
    /// Class E (240.0.0.0/4) and Link-Local (169.254.0.0/16) ranges, as some
    /// networks have already deployed these and cannot feasibly renumber,
    /// and we need to be able to handle these as routable prefixes.
    //TODO similar check needed for v6 once we get full v6 support
    fn is_v4_martian(&self, prefix: &Prefix4) -> bool {
        let first = prefix.value.octets()[0];
        if (first == 127) || (first & 0xf0 == 224) {
            return true;
        }
        false
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
        *lock!(self.remote_asn)
    }

    /// Return how long the BGP peer state machine has been in the current
    /// state.
    pub fn current_state_duration(&self) -> Duration {
        lock!(self.last_state_change).elapsed()
    }

    pub fn update_session_parameters(
        &self,
        cfg: PeerConfig,
        info: SessionInfo,
    ) -> Result<(), Error> {
        let mut reset_needed = self.update_session_config(cfg)?;
        reset_needed |= self.update_session_info(info)?;

        if reset_needed {
            read_lock!(self.event_tx)
                .send(FsmEvent::Admin(AdminEvent::Reset))
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

        {
            let mut guard = lock!(self.session);
            if guard.hold_time.as_secs() != cfg.hold_time {
                guard.hold_time = Duration::from_secs(cfg.hold_time);
                reset_needed = true;
            }

            if guard.keepalive_time.as_secs() != cfg.keepalive {
                guard.keepalive_time = Duration::from_secs(cfg.keepalive);
                reset_needed = true;
            }

            lock!(self.clock.timers.idle_hold_timer).interval =
                Duration::from_secs(cfg.idle_hold_time);

            guard.delay_open_time = Duration::from_secs(cfg.delay_open);
            guard.connect_retry_time = Duration::from_secs(cfg.connect_retry);
        }

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

        current.passive_tcp_establishment = info.passive_tcp_establishment;

        if current.remote_asn != info.remote_asn {
            current.remote_asn = info.remote_asn;
            reset_needed = true;
        }

        if current.remote_id != info.remote_id {
            current.remote_id = info.remote_id;
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

        if current.vlan_id != info.vlan_id {
            current.vlan_id = info.vlan_id;
            reset_needed = true;
        }

        if current.allow_export != info.allow_export {
            let previous = current.allow_export.clone();
            current.allow_export = info.allow_export;
            drop(current);
            read_lock!(self.event_tx)
                .send(FsmEvent::Admin(AdminEvent::ExportPolicyChanged(
                    previous,
                )))
                .map_err(|e| Error::EventSend(e.to_string()))?;
        } else {
            drop(current);
        }

        if path_attributes_changed {
            read_lock!(self.event_tx)
                .send(FsmEvent::Admin(AdminEvent::PathAttributesChanged))
                .map_err(|e| Error::EventSend(e.to_string()))?;
        }

        if refresh_needed {
            read_lock!(self.event_tx)
                .send(FsmEvent::Admin(AdminEvent::SendRouteRefresh))
                .map_err(|e| Error::EventSend(e.to_string()))?;
        }

        Ok(reset_needed)
    }
}
