// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    clock::SessionClock,
    config::PeerConfig,
    connection::{
        BgpConnection, BgpConnector, ConnectionCreator, ConnectionId,
    },
    error::{Error, ExpectationMismatch},
    fanout::Fanout,
    log::{collision_log, session_log, session_log_lite},
    messages::{
        AddPathElement, Afi, Capability, CeaseErrorSubcode, Community,
        ErrorCode, ErrorSubcode, Message, MessageKind, NotificationMessage,
        OpenMessage, PathAttributeValue, RouteRefreshMessage, Safi,
        UpdateMessage,
    },
    policy::{CheckerResult, ShaperResult},
    router::Router,
    IO_TIMEOUT,
};
use mg_common::{lock, read_lock, write_lock};
use rdb::{Asn, BgpPathProperties, Db, ImportExportPolicy, Prefix, Prefix4};
pub use rdb::{DEFAULT_RIB_PRIORITY_BGP, DEFAULT_ROUTE_PRIORITY};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::sync::mpsc::{Receiver, Sender};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::RecvTimeoutError,
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};

const UNIT_SESSION_RUNNER: &str = "session_runner";

/// This wraps a BgpConnection with runtime state learned from the peer's Open
/// message. This encodes all the dynamic (but non-timer related) information
/// for a given connection into the type system (rather than wrapping each
/// individual item in an Option hanging off the SessionRunner). "Later" FSM
/// states and (various helper methods specific to those states) expect a
/// PeerConnection rather than a BgpConnection, because those are states we
/// enter after a BgpConnection has already received (and accepted) an Open.
#[derive(Clone, Debug)]
pub struct PeerConnection<Cnx: BgpConnection> {
    /// The BgpConnection to the peer itself (TCP or Channel)
    pub conn: Cnx,
    /// The actual BGP-ID (Router-ID) learned from the peer (runtime state)
    pub id: u32,
    /// The actual ASN learned from the peer (runtime state)
    pub asn: u32,
    /// The actual capabilities received from the peer (runtime state)
    pub caps: BTreeSet<Capability>,
}

/// This wraps a pair of BgpConnections that have been identified as being a
/// Connection Collision. This condition is detected in either OpenConfirm or
/// OpenSent FSM states, and these invariants indicate which state the FSM was
/// in when the collision was detected.
pub enum CollisionPair<Cnx: BgpConnection> {
    OpenConfirm(PeerConnection<Cnx>, Cnx),
    OpenSent(Cnx, Cnx),
}

/// This is a helper enum to classify what connection an FsmEvent is tied to
/// during a Connection Collision. This was created to work in conjuction with
/// collision_conn_kind() to make life easier when choosing between one of 2
/// active connections (`new`/`exist` handled by the current FSM state), an
/// unexpected connection (in the registry but not being actively handled by the
/// current FSM state), and an unknown connection (not in the registry),
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CollisionConnectionKind<Cnx: BgpConnection> {
    New,
    Exist,
    Unexpected(Cnx),
    Missing,
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
    ConnectionCollision(CollisionPair<Cnx>),

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
    ConnectionCollision,

    /// Sync up with peers.
    SessionSetup,

    /// Able to exchange update, notification and keepliave messages with peers.
    Established,
}

impl FsmStateKind {
    fn as_str(&self) -> &str {
        match self {
            FsmStateKind::Idle => "idle",
            FsmStateKind::Connect => "connect",
            FsmStateKind::Active => "active",
            FsmStateKind::OpenSent => "open sent",
            FsmStateKind::OpenConfirm => "open confirm",
            FsmStateKind::ConnectionCollision => "connection collision",
            FsmStateKind::SessionSetup => "session setup",
            FsmStateKind::Established => "established",
        }
    }
}

impl Display for FsmStateKind {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
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
            FsmState::ConnectionCollision(_) => {
                FsmStateKind::ConnectionCollision
            }
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
    // XXX: We have handlers for this, but no senders. This is likely how
    // `neighbor shutdown` will be implemented.
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
            AdminEvent::Announce(_) => "announce",
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

/// This is a shorthand enum used to represent the different reasons to stop a
/// BgpConnection and/or return to FsmState::Idle. This goes hand in hand with
/// the stop() method to clean up state based on the reason for stopping, as
/// there are consistent patterns in what actions need to be taken when a given
/// "reason" occurs.
pub enum StopReason {
    Reset,
    Shutdown,
    FsmError,
    HoldTimeExpired,
    ConnectionRejected,
    CollisionResolution,
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

    /// Fires when the local systems tcp-syn recieved a syn-ack from the remote
    /// peer and the local system has sent an ack.
    /// i.e.
    /// We have ACKed the peer's connection.
    /// We use this event to indicate an inbound connection has completed.
    TcpConnectionAcked(Cnx),

    /// Fires when the local system has received the final ack in establishing
    /// a TCP connection with the peer.
    /// i.e.
    /// The peer has confirmed our connection.
    /// We use this event to indicate an outbound connection has completed.
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
            SessionEvent::TcpConnectionAcked(_) => {
                write!(f, "tcp connection acked")
            }
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
            SessionEvent::TcpConnectionAcked(_) => "tcp connection acked",
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

    /// Fires when the remote peer sends a TCP fin or the local connection times
    /// out.
    TcpConnectionFails,

    /// Fires when a connection has been detected while processing an open
    /// message. We implement Collision handling in FsmState::ConnectionCollision
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
    /// Expected Router-ID of the remote peer (for validation). None means any
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
    pub active_connections_declined: AtomicU64,
    pub passive_connections_accepted: AtomicU64,
    pub passive_connections_declined: AtomicU64,
    pub transitions_to_idle: AtomicU64,
    pub transitions_to_connect: AtomicU64,
    pub transitions_to_active: AtomicU64,
    pub transitions_to_open_sent: AtomicU64,
    pub transitions_to_open_confirm: AtomicU64,
    pub transitions_to_connection_collision: AtomicU64,
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

/// This is used to represent the "Primary" BgpConnection owned by a
/// SessionRunner. If there are no collisions in progress, this will be the only
/// BgpConnection. This exists so we the Router can know which connection to
/// pull state from when a query arrives for information about a peer.
#[derive(Debug)]
pub enum PrimaryConnection<Cnx: BgpConnection> {
    /// This represents a connection in the "early" FSM states where we haven't
    /// yet learned details about the BGP peer (via Open message).
    Partial(Cnx),
    /// This represents a connection in the "late" FSM states where we know
    /// details details about the BGP peer (via Open message).
    Full(PeerConnection<Cnx>),
}

/// This is the top level object that tracks a BGP session with a peer. There is
/// one SessionRunner per peer (based on IP), which transitions the peer through
/// the Finite State Machine (FSM) via the SessionRunner's fsm_* methods.
/// The FSM entry  point is fsm_start(), which loops indefinitely, cycling
/// between FsmStates, until a shutdown request is observed. Each fsm_* method
/// implements logic to read FSM events in a loop  until an event triggers an
/// FSM state transition. Sometimes the method has its own loop, and sometimes
/// it relies on fsm_start() to send the FSM back into the same state.
///
/// Events that progress the SessionRunner's state machine are sent/received
/// via an FSM Event Queue (one per SessionRunner). The SessionRunner reads
/// FSM events from `event_rx` and takes actions accordingly. New FSM events
/// are generated by sending an FsmEvent to `event_tx`. The SessionRunner owns
/// its FSM Event Queue sender (`event_tx`) primarily to simplify distribution
/// to event generators like the BgpListener, BgpConnector, SessionClock, or
/// ConnectionClock. The SessionRunner provides a handle to event generators by
/// passing them a clone() of `event_tx`.
///
/// A BGP peer's configuration lives in `session`, which is owned by the router
/// this peer is tied to. When the configuration is updated, it is compared
/// against the old config to determine whether any state resets need to occur.
/// For example, changes to HoldTime or KeepaliveTime require a full reset of
/// the BgpConnection since they are negotiated with the peer via Open messages.
///
/// In most cases there is a 1:1 relationship of SessionRunner:BgpConnection,
/// which represents the underlying message passing connection between the local
/// system and the configured peer IP address (defined in `connection.rs`).
/// However, it is entirely possible (and normal) to encounter a transitory
/// condition where more than one connection is open (called a Connection
/// Collision), for example when both BGP peers are non-passive and open a new
/// TCP session at the same time. For this reason, the SessionRunner is capable
/// of tracking multiple connections until the Connection Collision is resolved.
/// RFC 4271 describes allocating one FSM for each configured in addition to
/// one FSM for each inbound connection, so the RFC expects there two be two
/// completely separate FSMs for the two colliding connections (to the same
/// peer) until the Connection Collision is resolved. However, many well-known
/// implementations (e.g. Cisco, FRRouting) implement collision handling
/// via a single FSM, which is the approach we have chosen. We handle this
/// in a dedicated FSM state (ConnectionCollision), where two FSMs (one per
/// connection) are emulated for the lifetime of the collision and the winner
/// becomes the sole connection for the SessionRunner upon resolution. Each
/// connection has its own `ConnectionClock` for timers that are connection
/// specific (e.g. HoldTime, KeepaliveTime), which allows each connection to be
/// handled according to their own state.
///
/// Some notes on timers:
/// RFC 4271 is a bit ambiguous when it comes to timers. In some cases they say
/// to "zero" a timer, but do not elaborate on whether timers start at zero and
/// count up to the interval, or if they start at the interval and count down.
/// They use terms like "reset," "set to zero," "restart," "stop," and "clear"
/// without ever defining these terms (even the IETF mailing list has 20 year
/// old disagreements on whether this is ambiguous, but they never updated the
/// language). Our timers' values start at the interval and then count down.
/// We choose to treat all of this verbiage to mean "stop and reset", i.e. we
/// disable the timer and then set value equal to the interval. The actual timer
/// implementation lives in `clock.rs`.
pub struct SessionRunner<Cnx: BgpConnection> {
    /// FSM Event Queue sender. This handle is owned by the SessionRunner for
    /// the purpose of passing clones to different threads/events that need to
    /// generate FsmEvents to be processed by this SessionRunner's FSM.
    pub event_tx: Sender<FsmEvent<Cnx>>,

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

    event_rx: Receiver<FsmEvent<Cnx>>,
    state: Arc<Mutex<FsmStateKind>>,
    last_state_change: Mutex<Instant>,
    asn: Asn,
    id: u32,

    /// Capabilities to send to the peer
    caps_tx: Arc<Mutex<BTreeSet<Capability>>>,

    shutdown: AtomicBool,
    running: AtomicBool,
    db: Db,
    fanout: Arc<RwLock<Fanout<Cnx>>>,
    router: Arc<Router<Cnx>>,

    /// Registry of active connections indexed by ConnectionId
    connections: Arc<Mutex<BTreeMap<ConnectionId, Cnx>>>,

    /// A handle to the primary connection for a given peer.
    /// Used to expose runtime state of the peer itself, not just the FSM.
    pub primary: Arc<Mutex<Option<PrimaryConnection<Cnx>>>>,

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
            event_rx,
            event_tx: event_tx.clone(),
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
            caps_tx: Arc::new(Mutex::new(BTreeSet::new())),
            connections: Arc::new(Mutex::new(BTreeMap::new())),
            primary: Arc::new(Mutex::new(None)),
        };
        drop(session_info);
        runner
    }

    /// Request a peer session shutdown. Does not shut down the session right
    /// away. Simply sets a flag that the session is to be shut down which will
    /// be acted upon in the state machine loop.
    pub fn shutdown(&self) {
        session_log_lite!(self, info,
            "session runner (peer {}) received shutdown request, setting shutdown flag",
            self.neighbor.host.ip();
        );
        self.shutdown.store(true, Ordering::Release);
    }

    /// Add a connection to the registry. Newly registered connection is
    /// promoted to primary only if there isn't already a primary.
    /// This also starts the receive loop for the connection, ensuring that
    /// messages cannot arrive before the connection is registered.
    fn register_conn(&self, conn: &Cnx) {
        let conn_id = *conn.id();

        // Start the receive loop BEFORE cloning. This consumes the recv loop
        // parameters from the original connection, so the clone won't have them.
        // This prevents race conditions and allows us to avoid Arc wrappers.
        conn.start_recv_loop();

        // Now clone and insert into the registry. The clone will have empty
        // recv loop params since we already started the loop above.
        lock!(self.connections).insert(conn_id, conn.clone());

        // If this was the primary connection, either promote another connection
        // or reset it to None
        if lock!(self.primary).is_none() {
            self.set_primary_conn(Some(PrimaryConnection::Partial(
                conn.clone(),
            )));
        }
    }

    /// Remove a connection from the registry
    fn unregister_conn(&self, conn_id: &ConnectionId) {
        if let Some(conn) = lock!(self.connections).remove(conn_id) {
            // Stop all running clocks to reduce unnecessary noise
            conn.clock().disable_all();
        }

        // If this was the primary connection, either promote another connection
        // or reset it to None
        if let Some(primary_id) = self.get_primary_conn_id() {
            if primary_id == *conn_id {
                self.set_primary_conn(None);
            }
        }
    }

    /// Get a specific connection by ID
    fn get_conn(&self, conn_id: &ConnectionId) -> Option<Cnx> {
        lock!(self.connections).get(conn_id).cloned()
    }

    /// Promote a connection to be the primary for this BGP session
    fn set_primary_conn(&self, primary: Option<PrimaryConnection<Cnx>>) {
        *lock!(self.primary) = primary;
    }

    /// Get the ConnectionId of the primary connection
    pub fn get_primary_conn_id(&self) -> Option<ConnectionId> {
        if let Some(ref primary) = *lock!(self.primary) {
            match primary {
                PrimaryConnection::Partial(ref p) => Some(*p.id()),
                PrimaryConnection::Full(ref pc) => Some(*pc.conn.id()),
            }
        } else {
            None
        }
    }

    /// Clean up all connections associated with this SessionRunner
    fn cleanup_connections(&self) {
        let mut connections = lock!(self.connections);
        // Disable timers before dropping to ensure timers stop immediately
        for conn in connections.values() {
            conn.clock().disable_all();
        }
        connections.clear();
        *lock!(self.primary) = None;
    }

    /// This is the BGP peer state machine entry point. This function only
    /// returns if a shutdown is requested.
    pub fn fsm_start(self: &Arc<Self>) {
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
                session_log_lite!(self, info,
                    "session runner (peer: {}) caught shutdown flag",
                    self.neighbor.host.ip();
                );
                self.on_shutdown();
                return;
            }

            let previous = current.kind();

            // Check what state we are in and call the corresponding handler
            // function. All handler functions return the next state as their
            // return value, stash that in the `current` variable.
            current = match current {
                FsmState::Idle => self.fsm_idle(),
                FsmState::Connect => self.fsm_connect(),
                FsmState::Active => self.fsm_active(),
                FsmState::OpenSent(conn) => self.fsm_open_sent(conn),
                FsmState::OpenConfirm(pc) => self.fsm_open_confirm(pc),
                FsmState::ConnectionCollision(cpair) => {
                    self.fsm_connection_collision(cpair)
                }
                FsmState::SessionSetup(pc) => self.fsm_session_setup(pc),
                FsmState::Established(pc) => self.fsm_established(pc),
            };

            // If we have made a state transition log that and update the
            // appropriate state variables.
            if current.kind() != previous {
                session_log_lite!(
                    self,
                    info,
                    "fsm transition {previous} -> {}",
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
                    FsmStateKind::ConnectionCollision => {
                        self.counters
                            .transitions_to_connection_collision
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
        *lock!(self.caps_tx) = BTreeSet::from([
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
    fn fsm_idle(&self) -> FsmState<Cnx> {
        // Clean up connection registry
        self.cleanup_connections();

        // IdleHoldTimer is the mechanism by which maghemite implements
        // DampPeerOscillation. This holds the peer in Idle until the timer has
        // popped, preventing the connection from flapping. The interval is
        // supplied via PeerConfig as an unsigned int, and is always set to
        // something valid. DampPeerOscillation is disabled if interval == 0.
        {
            let ihl = lock!(self.clock.timers.idle_hold_timer);
            if ihl.interval.is_zero() {
                // If IdleHoldTimer is not configured, send IdleHoldTimerExpires
                // so we immediately move into the next state.
                ihl.stop();
                if let Err(e) = self
                    .event_tx
                    .send(FsmEvent::Session(SessionEvent::IdleHoldTimerExpires))
                {
                    session_log_lite!(self,
                        error,
                        "failed to send IdleHoldTimerExpires event: {e}";
                        "error" => format!("{e}")
                    );
                }
            } else {
                // If IdleHoldTimer is configured (non-zero), start the timer.
                // No events will move the FSM out of Idle until this timer pops
                // except for explicit adminstrative start/restart events.
                ihl.restart();
            }
        }

        loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                return FsmState::Idle;
            }

            let event = match self.event_rx.recv_timeout(IO_TIMEOUT) {
                Ok(event) => {
                    session_log_lite!(self, debug, "received fsm event {}",
                        event.title();
                        "event" => event.title()
                    );
                    event
                }

                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,

                Err(e) => {
                    session_log_lite!(self, error, "event rx error: {e}";
                        "error" => format!("{e}")
                    );
                    continue;
                }
            };

            // The only events we react to are ManualStart, Reset and
            // IdleHoldTimerExpires. ManualStart and Reset are explicit requests
            // to start the FSM, so we skip/disable DampPeerOscillation (by
            // ignoring/stopping the IdleHoldTimer) and move into the next FSM
            // state. Without an explicit Administrative command to start the
            // FSM, we will wait for the IdleHoldTimer to pop.
            match event {
                FsmEvent::Admin(admin_event) => match admin_event {
                    AdminEvent::ManualStart | AdminEvent::Reset => {
                        lock!(self.clock.timers.idle_hold_timer).stop();

                        if lock!(self.session).passive_tcp_establishment {
                            lock!(self.clock.timers.connect_retry_timer).stop();
                            return FsmState::Active;
                        } else {
                            lock!(self.clock.timers.connect_retry_timer)
                                .restart();
                            session_log_lite!(self, debug, "starting connect attempt";);
                            {
                                let session_info = lock!(self.session).clone();
                                if let Err(e) = Cnx::Connector::connect(
                                    self.neighbor.host,
                                    IO_TIMEOUT,
                                    self.log.clone(),
                                    self.event_tx.clone(),
                                    session_info,
                                ) {
                                    session_log_lite!(self, error,
                                        "failed to spawn connection thread: {e}";
                                        "error" => format!("{e}")
                                    );
                                }
                            }
                            return FsmState::Connect;
                        }
                    }

                    // We are already in Idle, so ManualStop is a no-op.
                    // The rest of the admin events are only relevant in Established
                    AdminEvent::ManualStop
                    | AdminEvent::Announce(_)
                    | AdminEvent::ShaperChanged(_)
                    | AdminEvent::ExportPolicyChanged(_)
                    | AdminEvent::CheckerChanged(_)
                    | AdminEvent::SendRouteRefresh
                    | AdminEvent::ReAdvertiseRoutes
                    | AdminEvent::PathAttributesChanged => {
                        let title = admin_event.title();
                        session_log_lite!(self, warn,
                            "unexpected admin fsm event {title}, ignoring";
                            "event" => title
                        );
                        continue;
                    }
                },

                FsmEvent::Session(session_event) => match session_event {
                    // DampPeerOscillations period has ended.
                    // Move into the next FSM State.
                    SessionEvent::IdleHoldTimerExpires => {
                        lock!(self.clock.timers.idle_hold_timer).stop();
                        self.counters
                            .idle_hold_timer_expirations
                            .fetch_add(1, Ordering::Relaxed);

                        if lock!(self.session).passive_tcp_establishment {
                            lock!(self.clock.timers.connect_retry_timer).stop();
                            return FsmState::Active;
                        } else {
                            lock!(self.clock.timers.connect_retry_timer)
                                .restart();
                            session_log_lite!(self, debug, "starting connect attempt";);
                            {
                                let session_info = lock!(self.session).clone();
                                if let Err(e) = Cnx::Connector::connect(
                                    self.neighbor.host,
                                    IO_TIMEOUT,
                                    self.log.clone(),
                                    self.event_tx.clone(),
                                    session_info,
                                ) {
                                    session_log_lite!(self, error,
                                        "failed to spawn connection thread: {e}";
                                        "error" => format!("{e}")
                                    );
                                }
                            }
                            return FsmState::Connect;
                        }
                    }

                    SessionEvent::TcpConnectionAcked(new)
                    | SessionEvent::TcpConnectionConfirmed(new) => {
                        match new.creator() {
                            ConnectionCreator::Dispatcher => {
                                session_log!(self, info, new,
                                    "inbound connection not allowed in idle (peer: {}, conn_id: {})",
                                    new.peer(), new.id().short();
                                );
                                self.counters
                                    .passive_connections_declined
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            ConnectionCreator::Connector => {
                                session_log!(self, info, new,
                                    "outbound connection completed but not allowed in idle (peer: {}, conn_id: {})",
                                    new.peer(), new.id().short();
                                );
                                self.counters
                                    .active_connections_declined
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        if let Some(conn) = self.get_conn(new.id()) {
                            self.stop(
                                Some(&conn),
                                None,
                                StopReason::ConnectionRejected,
                            );
                        }

                        // `new` is never registered so unregister is not needed

                        continue;
                    }

                    // Event 9
                    SessionEvent::ConnectRetryTimerExpires => {
                        session_log_lite!(self, warn,
                            "unexpected session fsm event {} not allowed in this state", session_event.title();
                        );
                        lock!(self.clock.timers.connect_retry_timer).disable();
                        continue;
                    }
                },

                /*
                 * Any other event (Events 9-12, 15-28) received in the Idle state
                 * does not cause change in the state of the local system.
                 */
                FsmEvent::Connection(connection_event) => {
                    match connection_event {
                        // Events 10-12
                        ConnectionEvent::HoldTimerExpires(ref conn_id)
                        | ConnectionEvent::KeepaliveTimerExpires(ref conn_id)
                        | ConnectionEvent::DelayOpenTimerExpires(ref conn_id) =>
                        {
                            match self.get_conn(conn_id) {
                                Some(conn) => {
                                    session_log_lite!(self, warn,
                                        "unexpected connection fsm event {} for known but inactive conn (conn_id: {}), closing..",
                                        connection_event.title(), conn_id.short();
                                    );
                                    self.stop(
                                        Some(&conn),
                                        None,
                                        StopReason::ConnectionRejected,
                                    );
                                }
                                // We should never hit this path, because we
                                // call cleanup_connections() before entering
                                // this loop. If we do hit it, then there is
                                // likely a bug in the cleanup or clock logic.
                                None => {
                                    session_log_lite!(self, warn,
                                        "unexpected connection fsm event {} for unknown conn (conn_id: {}), ignoring..",
                                        connection_event.title(), conn_id.short();
                                    );
                                }
                            }
                            continue;
                        }

                        ConnectionEvent::Message { msg, ref conn_id } => {
                            match self.get_conn(conn_id) {
                                Some(conn) => {
                                    session_log_lite!(self, warn, "unexpected {} message from known but inactive conn (conn_id: {}), closing..",
                                        msg.title(), conn_id.short();
                                        "message" => msg.title(),
                                        "message_contents" => format!("{msg}")
                                    );
                                    self.stop(
                                        Some(&conn),
                                        None,
                                        StopReason::ConnectionRejected,
                                    );
                                }
                                // We should never hit this path, because we
                                // call cleanup_connections() before entering
                                // this loop. If we do hit it, then there is
                                // likely a bug in the cleanup or clock logic.
                                None => {
                                    session_log_lite!(self, warn, "unexpected {} message from unknown conn (conn_id: {})",
                                        msg.title(), conn_id.short();
                                        "message" => msg.title(),
                                        "message_contents" => format!("{msg}")
                                    );
                                }
                            }
                            self.bump_msg_counter(msg.kind(), true);
                            continue;
                        }
                    }
                }
            }
        }
    }

    /// Waiting for a TCP connection to be completed (inbound or outbound).
    /// Passive peers should never enter the Connect state.
    /// The only time non Notification messages are handled in Connect is when
    /// an Open is received while DelayOpenTimer is running. DelayOpen is not
    /// currently implemented, so for now we don't have special handling here.
    /// Note: ConnectRetryTimer needs to be stopped before any state transitions
    /// occur. ConnectRetryTimer is used to trigger a new outbound connection
    /// attempt for non-passive peers while in Active or Connect states, but
    /// should be stopped before transitioning into other FSM states. Outbound
    /// connection attempts are also made in Idle for non-passive peers, but
    /// in Idle this is triggered by a ManualStart/Reset event or upon an
    /// IdleHoldTimeExpires event, rather than ConnectRetryTimerExpires. This
    /// is important because in "later" FSM states, a ConnectRetryTimerExpires
    /// event is considered an FSM error that triggers a Notification and an FSM
    /// transition back to idle. So we need to get it right.
    fn fsm_connect(&self) -> FsmState<Cnx> {
        loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                return FsmState::Idle;
            }

            let event = match self.event_rx.recv_timeout(IO_TIMEOUT) {
                Ok(event) => {
                    session_log_lite!(self,
                        debug,
                        "received fsm event {}", event.title();
                        "event" => event.title()
                    );
                    event
                }

                Err(RecvTimeoutError::Timeout) => continue,

                Err(e) => {
                    session_log_lite!(self,
                        error,
                        "event rx error: {e}";
                        "error" => format!("{e}")
                    );
                    // TODO: Possible death loop. Should we just panic here?
                    continue;
                }
            };

            match event {
                FsmEvent::Admin(admin_event) => match admin_event {
                    AdminEvent::ManualStop => {
                        session_log_lite!(self,
                            info,
                            "rx {}, fsm transition to idle", admin_event.title();
                        );
                        self.stop(None, None, StopReason::Shutdown);
                        return FsmState::Idle;
                    }

                    AdminEvent::Reset => {
                        session_log_lite!(self,
                            info,
                            "rx {}, fsm transition to idle", admin_event.title();
                        );
                        self.stop(None, None, StopReason::Reset);
                        return FsmState::Idle;
                    }

                    // We are already running, so ManualStart is a no-op.
                    // The rest of the admin events are only relevant in Established
                    AdminEvent::ManualStart
                    | AdminEvent::Announce(_)
                    | AdminEvent::ShaperChanged(_)
                    | AdminEvent::ExportPolicyChanged(_)
                    | AdminEvent::CheckerChanged(_)
                    | AdminEvent::SendRouteRefresh
                    | AdminEvent::ReAdvertiseRoutes
                    | AdminEvent::PathAttributesChanged => {
                        let title = admin_event.title();
                        session_log_lite!(self, warn,
                            "unexpected admin fsm event {title}, ignoring";
                            "event" => title
                        );
                        continue;
                    }
                },

                FsmEvent::Session(session_event) => {
                    match session_event {
                        /*
                         * In response to the ConnectRetryTimer_Expires event (Event 9), the
                         * local system:
                         *
                         *   - drops the TCP connection,
                         *
                         *   - restarts the ConnectRetryTimer,
                         *
                         *   - stops the DelayOpenTimer and resets the timer to zero,
                         *
                         *   - initiates a TCP connection to the other BGP peer,
                         *
                         *   - continues to listen for a connection that may be initiated by
                         *     the remote BGP peer, and
                         *
                         *   - stays in the Connect state.
                         */
                        SessionEvent::ConnectRetryTimerExpires => {
                            self.counters
                                .connection_retries
                                .fetch_add(1, Ordering::Relaxed);

                            // Attempt to establish a new connection using BgpConnector
                            {
                                let session_info = lock!(self.session).clone();
                                if let Err(e) = Cnx::Connector::connect(
                                    self.neighbor.host,
                                    IO_TIMEOUT,
                                    self.log.clone(),
                                    self.event_tx.clone(),
                                    session_info,
                                ) {
                                    session_log_lite!(self, error,
                                        "failed to spawn connection thread: {e}";
                                        "error" => format!("{e}")
                                    );
                                }
                            }
                            lock!(self.clock.timers.connect_retry_timer)
                                .restart();
                        }

                        /*
                         * If the TCP connection succeeds (Event 16 or Event 17), the local
                         * system checks the DelayOpen attribute prior to processing.  If the
                         * DelayOpen attribute is set to TRUE, the local system:
                         *
                         *   - stops the ConnectRetryTimer (if running) and sets the
                         *     ConnectRetryTimer to zero,
                         *
                         *   - sets the DelayOpenTimer to the initial value, and
                         *
                         *   - stays in the Connect state.
                         *
                         * If the DelayOpen attribute is set to FALSE, the local system:
                         *
                         *   - stops the ConnectRetryTimer (if running) and sets the
                         *     ConnectRetryTimer to zero,
                         *
                         *   - completes BGP initialization
                         *
                         *   - sends an OPEN message to its peer,
                         *
                         *   - sets the HoldTimer to a large value, and
                         *
                         *   - changes its state to OpenSent.
                         *
                         * A HoldTimer value of 4 minutes is suggested.
                         */
                        SessionEvent::TcpConnectionAcked(accepted)
                        | SessionEvent::TcpConnectionConfirmed(accepted) => {
                            match accepted.creator() {
                                ConnectionCreator::Dispatcher => {
                                    session_log!(self, info, accepted,
                                        "accepted inbound connection from {}", accepted.peer();
                                    );
                                    self.counters
                                        .passive_connections_accepted
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                ConnectionCreator::Connector => {
                                    session_log!(self, info, accepted,
                                        "outbound connection to {} accepted", accepted.peer();
                                    );
                                    self.counters
                                        .active_connections_accepted
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }

                            self.register_conn(&accepted);

                            // DelayOpen can be configured for a peer, but its functionality
                            // is not implemented.  Follow DelayOpen == false instructions.

                            lock!(self.clock.timers.connect_retry_timer).stop();

                            if let Err(e) = self.send_open(&accepted) {
                                session_log!(self, error, accepted,
                                    "failed to send open, fsm transition to idle";
                                    "error" => format!("{e}")
                                );
                                return FsmState::Idle;
                            }

                            lock!(accepted.clock().timers.hold_timer).restart();

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
                            );

                            return FsmState::Idle;
                        }
                    }
                }

                /*
                 * In response to any other events (Events 8, 10-11, 13, 19, 23,
                 * 25-28), the local system:
                 *
                 *   - if the ConnectRetryTimer is running, stops and resets the
                 *     ConnectRetryTimer (sets to zero),
                 *
                 *   - if the DelayOpenTimer is running, stops and resets the
                 *     DelayOpenTimer (sets to zero),
                 *
                 *   - releases all BGP resources,
                 *
                 *   - drops the TCP connection,
                 *
                 *   - increments the ConnectRetryCounter by 1,
                 *
                 *   - performs peer oscillation damping if the DampPeerOscillations
                 *     attribute is set to True, and
                 *
                 *   - changes its state to Idle.
                 */
                FsmEvent::Connection(connection_event) => {
                    let title = connection_event.title();
                    match connection_event {
                        // This is unexpected since DelayOpen isn't implemented.
                        //
                        // A new connection arrives via FsmEvent::Connected
                        // or FsmEvent::TcpConnectionConfirmed without its
                        // recv loop running, i.e. no inbound messages are
                        // pulled from the connection until the recv loop
                        // thread is started by register_conn(). Since
                        // we don't read from the event queue between
                        // registering a new connection and moving into
                        // OpenSent (upon Open send success) or Idle (upon
                        // Open send error), there isn't a chance for
                        // Messages from a new connection to be read while
                        // in Connect.
                        //
                        // If/when we implement DelayOpen, this is where we
                        // need to add handling for Open messages while
                        // DelayOpenTimer is running (enabled && !expired).
                        ConnectionEvent::Message { msg, ref conn_id } => {
                            let title = msg.title();

                            if let Message::Notification(ref n) = msg {
                                session_log_lite!(self, warn,
                                    "rx {title} message (conn_id: {}), fsm transition to idle",
                                    conn_id.short();
                                    "message" => title,
                                    "message_contents" => format!("{n}")
                                );
                                self.bump_msg_counter(msg.kind(), false);
                            } else {
                                session_log_lite!(self, warn,
                                    "rx unexpected {title} message (conn_id: {}), fsm transition to idle",
                                    conn_id.short();
                                    "message" => msg.title(),
                                    "message_contents" => format!("{msg}")
                                );
                                self.bump_msg_counter(msg.kind(), true);
                            }

                            lock!(self.clock.timers.connect_retry_timer).stop();
                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);

                            return FsmState::Idle;
                        }

                        // Events 8 (AutomaticStop, unused), 10-11, 13
                        ConnectionEvent::HoldTimerExpires(ref conn_id)
                        | ConnectionEvent::KeepaliveTimerExpires(ref conn_id)
                        | ConnectionEvent::DelayOpenTimerExpires(ref conn_id) =>
                        {
                            lock!(self.clock.timers.connect_retry_timer).stop();

                            // DelayOpenTimer is stored in the Connection, which
                            // will be dropped in Idle. Skip touching its timer.

                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);

                            session_log_lite!(self, warn,
                                "connection fsm event {title} (conn_id {}) not allowed in this state, fsm transition to idle",
                                conn_id.short();
                            );

                            return FsmState::Idle;
                        }
                    }
                }
            }
        }
    }

    /// Trying to acquire peer by listening for and accepting a TCP connection.
    /// Passive peers only ever live in Active while waiting for connections to
    /// complete; they should never transition to Connect.
    /// The only time non Notification messages are handled in Active is when
    /// an Open is received while DelayOpenTimer is running. DelayOpen is not
    /// currently implemented, so for now we don't have special handling here.
    /// Note: ConnectRetryTimer needs to be stopped before any state transitions
    /// occur. ConnectRetryTimer is used to trigger a new outbound connection
    /// attempt for non-passive peers while in Active or Connect states, but
    /// should be stopped before transitioning into other FSM states. Outbound
    /// connection attempts are also made in Idle for non-passive peers, but
    /// in Idle this is triggered by a ManualStart/Reset event or upon an
    /// IdleHoldTimeExpires event, rather than ConnectRetryTimerExpires. This
    /// is important because in "later" FSM states, a ConnectRetryTimerExpires
    /// event is considered an FSM error that triggers a Notification and an FSM
    /// transition back to idle. So we need to get it right.
    fn fsm_active(&self) -> FsmState<Cnx> {
        loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                return FsmState::Idle;
            }

            let event = match self.event_rx.recv_timeout(IO_TIMEOUT) {
                Ok(event) => {
                    session_log_lite!(self, debug, "received fsm event {}",
                        self.state();
                        "event" => event.title()
                    );
                    event
                }

                Err(RecvTimeoutError::Timeout) => continue,

                Err(e) => {
                    session_log_lite!(self, error, "event rx error: {e}";
                        "error" => format!("{e}")
                    );
                    // TODO: Possible death loop. Should we just panic here?
                    continue;
                }
            };

            // The Dispatcher thread is running independently and will hand off
            // any inbound connections via a Connected event. So pretty much all
            // we need to do is sit and wait for that event or for timers to pop
            match event {
                FsmEvent::Admin(admin_event) => match admin_event {
                    /*
                     * In response to a ManualStop event (Event 2), the local system:
                     *
                     *   - If the DelayOpenTimer is running and the
                     *     SendNOTIFICATIONwithoutOPEN session attribute is set, the
                     *     local system sends a NOTIFICATION with a Cease,
                     *
                     *   - releases all BGP resources including stopping the
                     *     DelayOpenTimer
                     *
                     *   - drops the TCP connection,
                     *
                     *   - sets ConnectRetryCounter to zero,
                     *
                     *   - stops the ConnectRetryTimer and sets the ConnectRetryTimer to
                     *     zero, and
                     *
                     *   - changes its state to Idle.
                     */
                    AdminEvent::ManualStop => {
                        session_log_lite!(self, info,
                            "rx {}, fsm transition to idle", admin_event.title();
                        );
                        self.stop(None, None, StopReason::Shutdown);
                        return FsmState::Idle;
                    }

                    AdminEvent::Reset => {
                        session_log_lite!(self, info,
                            "rx {}, fsm transition to idle", admin_event.title();
                        );
                        self.stop(None, None, StopReason::Reset);
                        return FsmState::Idle;
                    }

                    // We are already running, so ManualStart is a no-op.
                    // The rest of the admin events are only relevant in Established
                    AdminEvent::ManualStart
                    | AdminEvent::Announce(_)
                    | AdminEvent::ShaperChanged(_)
                    | AdminEvent::ExportPolicyChanged(_)
                    | AdminEvent::CheckerChanged(_)
                    | AdminEvent::SendRouteRefresh
                    | AdminEvent::ReAdvertiseRoutes
                    | AdminEvent::PathAttributesChanged => {
                        let title = admin_event.title();
                        session_log_lite!(self, warn,
                            "unexpected admin fsm event {title}, ignoring";
                            "event" => title
                        );
                        continue;
                    }
                },

                /*
                 * In response to any other event (Events 8, 10-11, 13, 19, 23,
                 * 25-28), the local system:
                 *
                 *   - sets the ConnectRetryTimer to zero,
                 *
                 *   - releases all BGP resources,
                 *
                 *   - drops the TCP connection,
                 *
                 *   - increments the ConnectRetryCounter by one,
                 *
                 *   - (optionally) performs peer oscillation damping if the
                 *     DampPeerOscillations attribute is set to TRUE, and
                 *
                 *   - changes its state to Idle.
                 */
                FsmEvent::Connection(connection_event) => {
                    match connection_event {
                        // This is unexpected since DelayOpen isn't
                        // implemented.
                        //
                        // A new connection arrives via FsmEvent::Connected
                        // or FsmEvent::TcpConnectionConfirmed without its
                        // recv loop running, i.e. no inbound messages are
                        // pulled from the connection until the recv loop
                        // thread is started by register_conn(). Since
                        // we don't read from the event queue between
                        // registering a new connection and moving into
                        // OpenSent (upon Open send success) or Idle (upon
                        // Open send error), there isn't a chance for
                        // Messages from a new connection to be read while
                        // in Connect.
                        //
                        // If/when we implement DelayOpen, this is where we
                        // need to add handling for Open messages while
                        // DelayOpenTimer is running (enabled && !expired).
                        ConnectionEvent::Message { msg, ref conn_id } => {
                            let title = msg.title();

                            if let Message::Notification(ref n) = msg {
                                session_log_lite!(self, warn,
                                    "rx {title} message (conn_id: {}), fsm transition to idle",
                                    conn_id.short();
                                    "message" => title,
                                    "message_contents" => format!("{n}")
                                );
                                self.bump_msg_counter(msg.kind(), false);
                            } else {
                                session_log_lite!(self, warn,
                                    "rx unexpected {title} message (conn_id: {}), fsm transition to idle",
                                    conn_id.short();
                                    "message" => msg.title(),
                                    "message_contents" => format!("{msg}")
                                );
                                self.bump_msg_counter(msg.kind(), true);
                            }

                            lock!(self.clock.timers.connect_retry_timer).stop();
                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);
                            self.counters
                                .connection_retries
                                .fetch_add(1, Ordering::Relaxed);

                            return FsmState::Idle;
                        }

                        // Events 8 (Automatic Stop), 10-11, 13
                        ConnectionEvent::HoldTimerExpires(ref conn_id)
                        | ConnectionEvent::KeepaliveTimerExpires(ref conn_id) =>
                        {
                            lock!(self.clock.timers.connect_retry_timer).stop();
                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);
                            self.counters
                                .connection_retries
                                .fetch_add(1, Ordering::Relaxed);

                            session_log_lite!(self, warn,
                                "rx connection fsm event {} (conn_id: {}), but not allowed in this state. fsm transition to idle",
                                connection_event.title(), conn_id.short();
                            );

                            return FsmState::Idle;
                        }

                        ConnectionEvent::DelayOpenTimerExpires(ref conn_id) => {
                            session_log_lite!(self, warn,
                                "rx connection fsm event {} (conn_id: {}), but not allowed in this state. ignoring..",
                                connection_event.title(), conn_id.short();
                            );

                            continue;
                        }
                    }
                }

                FsmEvent::Session(session_event) => match session_event {
                    /*
                     * In response to a ConnectRetryTimer_Expires event (Event 9), the
                     * local system:
                     *
                     *   - restarts the ConnectRetryTimer (with initial value),
                     *
                     *   - initiates a TCP connection to the other BGP peer,
                     *
                     *   - continues to listen for a TCP connection that may be initiated
                     *     by a remote BGP peer, and
                     *
                     *   - changes its state to Connect.
                     */
                    SessionEvent::ConnectRetryTimerExpires => {
                        // RFC 4271 says that in Idle the FSM should restart the
                        // ConnectRetryTimer "In response to a
                        // ManualStart_with_PassiveTcpEstablishment event" even
                        // though it also says that in Active the FSM should
                        // react to a ConnectRetryTimerExpires event by
                        // transitioning to Connect and attempting a new
                        // outbound TCP session, which is exactly the opposite
                        // of what you want to do for a passive peer.
                        if lock!(self.session).passive_tcp_establishment {
                            session_log_lite!(self, info,
                                "rx {} but peer is configured as passive, staying in active",
                                session_event.title();
                            );
                            lock!(self.clock.timers.connect_retry_timer).stop();
                            continue;
                        }

                        session_log_lite!(self, info,
                            "rx {}, fsm transition to connect",
                            session_event.title();
                        );

                        self.counters
                            .connection_retries
                            .fetch_add(1, Ordering::Relaxed);
                        lock!(self.clock.timers.connect_retry_timer).restart();

                        return FsmState::Connect;
                    }

                    // The Dispatcher has accepted a TCP connection initiated by
                    // the peer.
                    SessionEvent::TcpConnectionAcked(accepted) => {
                        session_log!(self, info, accepted,
                            "accepted inbound connection from {}", accepted.peer();
                        );

                        self.counters
                            .passive_connections_accepted
                            .fetch_add(1, Ordering::Relaxed);

                        self.register_conn(&accepted);

                        lock!(self.clock.timers.connect_retry_timer).stop();

                        if let Err(e) = self.send_open(&accepted) {
                            session_log!(self, error, accepted,
                                "failed to send open, fsm transition to idle";
                                "error" => format!("{e}")
                            );
                            return FsmState::Idle;
                        }

                        lock!(accepted.clock().timers.hold_timer).restart();

                        return FsmState::OpenSent(accepted);
                    }

                    // An outbound connection we initiated has been accepted by
                    // the peer. Outbound connections aren't allowed in Active
                    // state, so this shouldn't happen. However, if it does then
                    // it's likely a timing thing as a result of improper
                    // Connector handling (not dropping the TcpStream).
                    SessionEvent::TcpConnectionConfirmed(confirmed) => {
                        session_log!(self, info, confirmed,
                            "outbound connection to peer {} (conn_id: {}) accepted, but not allowed in {}",
                            confirmed.peer(), confirmed.id().short(), self.state();
                        );
                        self.counters
                            .active_connections_declined
                            .fetch_add(1, Ordering::Relaxed);
                        self.stop(
                            Some(&confirmed),
                            None,
                            StopReason::ConnectionRejected,
                        );
                        continue;
                    }

                    SessionEvent::IdleHoldTimerExpires => {
                        session_log_lite!(self, warn,
                            "rx session fsm event {}, but not allowed in {}. ignoring..",
                            session_event.title(), self.state();
                        );
                        continue;
                    }
                },
            };
        }
    }

    /// Waiting for open message from peer.
    fn fsm_open_sent(&self, conn: Cnx) -> FsmState<Cnx> {
        let om = loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                return FsmState::Idle;
            }

            let event = match self.event_rx.recv_timeout(IO_TIMEOUT) {
                Ok(event) => {
                    session_log!(self, debug, conn, "received fsm event {}",
                        event.title(); "event" => event.title()
                    );
                    event
                }

                Err(RecvTimeoutError::Timeout) => continue,

                Err(e) => {
                    session_log!(self, error, conn, "event rx error: {e}";
                        "error" => format!("{e}")
                    );
                    continue;
                }
            };

            // The main thing we really care about in the open sent state is
            // receiving a reciprocal open message from the peer.
            match event {
                FsmEvent::Admin(admin_event) => match admin_event {
                    /*
                     * If a ManualStop event (Event 2) is issued in the OpenSent state,
                     * the local system:
                     *
                     *   - sends the NOTIFICATION with a Cease,
                     *
                     *   - sets the ConnectRetryTimer to zero,
                     *
                     *   - releases all BGP resources,
                     *
                     *   - drops the TCP connection,
                     *
                     *   - sets the ConnectRetryCounter to zero, and
                     *
                     *   - changes its state to Idle.
                     */
                    AdminEvent::ManualStop => {
                        session_log!(self, info, conn, "rx {}, fsm transition to idle",
                            admin_event.title();
                        );
                        self.stop(Some(&conn), None, StopReason::Shutdown);
                        return FsmState::Idle;
                    }

                    // Follow ManualStop logic, but with the appropriate ErrorSubcode
                    AdminEvent::Reset => {
                        session_log!(self, info, conn,
                            "rx {}, fsm transition to idle",
                            admin_event.title();
                        );
                        self.stop(Some(&conn), None, StopReason::Reset);
                        return FsmState::Idle;
                    }

                    // We are already running, so ManualStart is a no-op.
                    // The rest of the admin events are only relevant in Established
                    AdminEvent::ManualStart
                    | AdminEvent::Announce(_)
                    | AdminEvent::ShaperChanged(_)
                    | AdminEvent::ExportPolicyChanged(_)
                    | AdminEvent::CheckerChanged(_)
                    | AdminEvent::SendRouteRefresh
                    | AdminEvent::ReAdvertiseRoutes
                    | AdminEvent::PathAttributesChanged => {
                        let title = admin_event.title();
                        session_log!(self, warn, conn,
                            "unexpected admin fsm event {title}, ignoring";
                            "event" => title
                        );
                        continue;
                    }
                },

                /*
                 * In response to any other event (Events 9, 11-13, 20, 25-28), the
                 * local system:
                 *
                 *   - sends the NOTIFICATION with the Error Code Finite State
                 *     Machine Error,
                 *
                 *   - sets the ConnectRetryTimer to zero,
                 *
                 *   - releases all BGP resources,
                 *
                 *   - drops the TCP connection,
                 *
                 *   - increments the ConnectRetryCounter by 1,
                 *
                 *   - (optionally) performs peer oscillation damping if the
                 *     DampPeerOscillations attribute is set to TRUE, and
                 *
                 *   - changes its state to Idle.
                 */
                FsmEvent::Session(session_event) => match session_event {
                    // Event 9
                    SessionEvent::ConnectRetryTimerExpires
                    // Event 13
                    | SessionEvent::IdleHoldTimerExpires => {
                        let title = session_event.title();
                        session_log!(self, warn, conn,
                            "{title} event not allowed in this state, fsm transition to idle";
                            "event" => title
                        );
                        self.stop(Some(&conn), None, StopReason::FsmError);
                        return FsmState::Idle;
                    }

                    /*
                     * If a TcpConnection_Valid (Event 14), Tcp_CR_Acked (Event 16), or a
                     * TcpConnectionConfirmed event (Event 17) is received, a second TCP
                     * connection may be in progress.  This second TCP connection is
                     * tracked per Connection Collision processing (Section 6.8) until an
                     * OPEN message is received.
                     */
                    SessionEvent::TcpConnectionAcked(new)
                    | SessionEvent::TcpConnectionConfirmed(new) => {
                        let new_creator = new.creator();
                        if new_creator == conn.creator() {
                            collision_log!(self, error, new, conn,
                                "rejected new {} connection for {}: has same creator as existing connection {}",
                                new_creator.direction(),
                                new.id().short(),
                                conn.id().short();
                            );
                            continue;
                        }

                        match new_creator {
                            ConnectionCreator::Dispatcher => {
                                collision_log!(self, info, new, conn,
                                    "new inbound connection from {} (conn_id: {})",
                                    new.peer(), new.id().short();
                                );
                                self.counters
                                    .passive_connections_accepted
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            ConnectionCreator::Connector => {
                                collision_log!(self, info, new, conn,
                                    "outbound connection to {} (conn_id: {}) completed",
                                    new.peer(), new.id().short();
                                );
                                self.counters
                                    .active_connections_accepted
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        if let Err(e) = self.send_open(&new) {
                            collision_log!(self, error, new, conn,
                                "error sending open to new conn, continue with open conn";
                                "error" => format!("{e}")
                            );
                            continue;
                        }

                        self.register_conn(&new);

                        lock!(new.clock().timers.hold_timer).restart();

                        return FsmState::ConnectionCollision(
                            CollisionPair::OpenSent(conn, new),
                        );
                    }
                },

                FsmEvent::Connection(connection_event) => {
                    match connection_event {
                        ConnectionEvent::Message { msg, ref conn_id } => {
                            match self.get_conn(conn_id) {
                                Some(connection) => {
                                    if connection.id() != conn.id() {
                                        session_log!(self, warn, conn,
                                            "rx {} from peer {} for known connection (conn_id: {}) that's unexpected in this state? closing conn",
                                            msg.kind(), conn_id.remote().ip(),
                                            conn_id.short();
                                        );
                                        self.stop(
                                            Some(&connection),
                                            None,
                                            StopReason::FsmError,
                                        );
                                        continue;
                                    }
                                },
                                None => {
                                    session_log!(self, warn, conn,
                                        "rx {} from peer {} for unknown connection (conn_id: {}), ignoring",
                                        msg.kind(), conn_id.remote().ip(),
                                        conn_id.short();
                                    );
                                    continue;
                                }
                            };

                            // Event 19 (BgpOpen)
                            if let Message::Open(om) = msg {
                                // Event 20 (BGPOpen with DelayOpenTimer running)
                                lock!(self.message_history).receive(
                                    om.clone().into(),
                                    Some(*conn_id),
                                );
                                self.counters
                                    .opens_received
                                    .fetch_add(1, Ordering::Relaxed);
                                break om;
                            }

                            session_log!(self, warn, conn,
                                "rx unexpected {} message (conn_id: {}), fsm transition to idle",
                                msg.title(), conn_id.short();
                                "message" => msg.title(),
                                "message_contents" => format!("{msg}")
                            );

                            self.stop(
                                Some(&conn),
                                None,
                                StopReason::FsmError,
                            );

                            lock!(self.clock.timers.connect_retry_timer).stop();
                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);

                            match msg {
                                // Events 25-28 + Route Refresh
                                Message::Open(_) => {}
                                Message::Update(_)
                                | Message::Notification(_)
                                | Message::KeepAlive
                                | Message::RouteRefresh(_) => self.bump_msg_counter(msg.kind(), true),
                            }

                            return FsmState::Idle;
                        }

                        /*
                         * If the HoldTimer_Expires (Event 10), the local system:
                         *
                         *   - sends a NOTIFICATION message with the error code Hold Timer
                         *     Expired,
                         *
                         *   - sets the ConnectRetryTimer to zero,
                         *
                         *   - releases all BGP resources,
                         *
                         *   - drops the TCP connection,
                         *
                         *   - increments the ConnectRetryCounter,
                         *
                         *   - (optionally) performs peer oscillation damping if the
                         *     DampPeerOscillations attribute is set to TRUE, and
                         *
                         *   - changes its state to Idle.
                         */
                        ConnectionEvent::HoldTimerExpires(ref conn_id) => {
                            let title = connection_event.title();
                            match self.get_conn(conn_id) {
                                Some(connection) => {
                                    if connection.id() == conn.id() {
                                        session_log!(self, warn, conn,
                                            "rx {title} (conn_id: {}), fsm transition to idle",
                                            conn_id.short();
                                            "event" => title
                                        );
                                    } else {
                                        session_log!(self, warn, conn,
                                            "rx {title} for known connection (conn_id: {}) that's unexpected in this state? closing conn",
                                            conn_id.short();
                                        );
                                        self.stop(
                                            Some(&connection),
                                            None,
                                            StopReason::FsmError,
                                        );
                                        continue;
                                    }
                                },
                                None => {
                                    session_log!(self, warn, conn,
                                        "rx {title} for unknown connection (conn_id: {}), ignoring..",
                                        conn_id.short();
                                    );
                                    continue;
                                }
                            };
                            self.counters
                                .hold_timer_expirations
                                .fetch_add(1, Ordering::Relaxed);
                            self.stop(Some(&conn), None, StopReason::HoldTimeExpired);
                            return FsmState::Idle;
                        }

                        // Event 11
                        ConnectionEvent::KeepaliveTimerExpires(ref conn_id)
                        // Event 12
                        | ConnectionEvent::DelayOpenTimerExpires(ref conn_id) => {
                            let title = connection_event.title();
                            match self.get_conn(conn_id) {
                                Some(connection) => {
                                    if connection.id() == conn.id() {
                                        session_log!(self, warn, conn,
                                            "rx {title} (conn_id: {}) but event not allowed in this state, fsm transition to idle",
                                            conn_id.short();
                                            "event" => title
                                        );
                                    } else {
                                        session_log!(self, warn, conn,
                                            "rx {title} for known connection (conn_id: {}) that's unexpected in this state? closing conn",
                                            conn_id.short();
                                        );
                                        self.stop(
                                            Some(&connection),
                                            None,
                                            StopReason::FsmError,
                                        );
                                        continue;
                                    }
                                },
                                None => {
                                    session_log!(self, warn, conn,
                                        "rx {title} for unknown connection (conn_id: {}), ignoring..",
                                        conn_id.short();
                                    );
                                    continue;
                                }
                            };
                            self.stop(Some(&conn), None, StopReason::FsmError);
                            return FsmState::Idle;
                        }
                    }
                }
            }
        };

        /*
         * If the BGP message header checking (Event 21) or OPEN message
         * checking detects an error (Event 22)(see Section 6.2), the local
         * system:
         *
         * - sends a NOTIFICATION message with the appropriate error code,
         *
         * - sets the ConnectRetryTimer to zero,
         *
         * - releases all BGP resources,
         *
         * - drops the TCP connection,
         *
         * - increments the ConnectRetryCounter by 1,
         *
         * - (optionally) performs peer oscillation damping if the
         *   DampPeerOscillations attribute is TRUE, and
         *
         * - changes its state to Idle.
         */
        if let Err(e) = self.handle_open(&conn, &om) {
            match e {
                Error::PolicyCheckFailed => {
                    session_log!(self, info, conn,
                        "policy check failed";
                        "error" => format!("{e}")
                    );
                }
                e => {
                    session_log!(self, warn, conn,
                        "failed to handle open message, fsm transition to idle";
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

        /*
         * When an OPEN message is received, all fields are checked for
         * correctness.  If there are no errors in the OPEN message (Event
         * 19), the local system:
         *
         *   - resets the DelayOpenTimer to zero,
         *
         *   - sets the BGP ConnectRetryTimer to zero,
         *
         *   - sends a KEEPALIVE message, and
         *
         *   - sets a KeepaliveTimer (via the text below)
         *
         *   - sets the HoldTimer according to the negotiated value (see
         *     Section 4.2),
         *
         *   - changes its state to OpenConfirm.
         */

        // ACK the open with a keepalive and transition to open confirm.
        self.send_keepalive(&conn);

        lock!(self.clock.timers.connect_retry_timer).stop();
        lock!(conn.clock().timers.keepalive_timer).restart();
        // hold_timer set in handle_open(), enable it here
        lock!(conn.clock().timers.hold_timer).enable();

        let pc = PeerConnection {
            conn,
            id: om.id,
            asn: om.asn(),
            caps: om.get_capabilities(),
        };

        self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));

        FsmState::OpenConfirm(pc)
    }

    /// Waiting for keepalive or notification from peer.
    fn fsm_open_confirm(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        // Check to see if a shutdown has been requested.
        if self.shutdown.load(Ordering::Acquire) {
            return FsmState::Idle;
        }

        let event = match self.event_rx.recv_timeout(IO_TIMEOUT) {
            Ok(event) => {
                session_log!(self, debug, pc.conn,
                     "received fsm event";
                    "event" => event.title()
                );
                event
            }

            Err(RecvTimeoutError::Timeout) => return FsmState::OpenConfirm(pc),

            Err(e) => {
                session_log!(self, error,  pc.conn,
                    "event rx error: {e}";
                    "error" => format!("{e}")
                );
                //TODO possible death loop. Should we just panic here?
                return FsmState::OpenConfirm(pc);
            }
        };

        match event {
            FsmEvent::Admin(admin_event) => match admin_event {
                /*
                 * In response to a ManualStop event (Event 2) initiated by the
                 * operator, the local system:
                 *
                 *   - sends the NOTIFICATION message with a Cease,
                 *
                 *   - releases all BGP resources,
                 *
                 *   - drops the TCP connection,
                 *
                 *   - sets the ConnectRetryCounter to zero,
                 *
                 *   - sets the ConnectRetryTimer to zero, and
                 *
                 *   - changes its state to Idle.
                 */
                AdminEvent::ManualStop => {
                    session_log!(self, info,  pc.conn,
                        "rx {}, fsm transition to idle",
                        admin_event.title();
                    );
                    self.stop(Some(&pc.conn), None, StopReason::Shutdown);
                    FsmState::Idle
                }

                // Follow ManualStop logic, but with the appropriate ErrorSubcode
                AdminEvent::Reset => {
                    session_log!(self, info,  pc.conn,
                        "rx {}, fsm transition to idle",
                        admin_event.title();
                    );
                    self.stop(Some(&pc.conn), None, StopReason::Reset);
                    FsmState::Idle
                }

                AdminEvent::Announce(_)
                | AdminEvent::ShaperChanged(_)
                | AdminEvent::ExportPolicyChanged(_)
                | AdminEvent::CheckerChanged(_)
                | AdminEvent::ManualStart
                | AdminEvent::SendRouteRefresh
                | AdminEvent::ReAdvertiseRoutes
                | AdminEvent::PathAttributesChanged => {
                    let title = admin_event.title();
                    session_log!(self, warn, pc.conn,
                        "unexpected admin fsm event {title}, ignoring";
                        "event" => title
                    );
                    FsmState::OpenConfirm(pc)
                }
            },

            /*
             * In response to any other event (Events 9, 12-13, 20, 27-28), the
             * local system:
             *
             *   - sends a NOTIFICATION with a code of Finite State Machine
             *     Error,
             *   - sets the ConnectRetryTimer to zero,
             *
             *   - releases all BGP resources,
             *
             *   - drops the TCP connection,
             *
             *   - increments the ConnectRetryCounter by 1,
             *
             *   - (optionally) performs peer oscillation damping if the
             *     DampPeerOscillations attribute is set to TRUE, and
             *
             *   - changes its state to Idle.
             */
            FsmEvent::Connection(connection_event) => match connection_event {
                /*
                 * If the HoldTimer_Expires event (Event 10) occurs before a
                 * KEEPALIVE message is received, the local system:
                 *
                 *   - sends the NOTIFICATION message with the Error Code Hold Timer
                 *     Expired,
                 *
                 *   - sets the ConnectRetryTimer to zero,
                 *
                 *   - releases all BGP resources,
                 *
                 *   - drops the TCP connection,
                 *
                 *   - increments the ConnectRetryCounter by 1,
                 *
                 *   - (optionally) performs peer oscillation damping if the
                 *     DampPeerOscillations attribute is set to TRUE, and
                 *
                 *   - changes its state to Idle.
                 */
                ConnectionEvent::HoldTimerExpires(ref conn_id) => {
                    let title = connection_event.title();
                    match self.get_conn(conn_id) {
                        Some(connection) => {
                            if connection.id() == pc.conn.id() {
                                session_log!(self, warn, pc.conn,
                                    "rx {title} (conn_id: {}), fsm transition to idle",
                                    conn_id.short();
                                    "event" => title
                                );
                                self.stop(
                                    Some(&pc.conn),
                                    None,
                                    StopReason::HoldTimeExpired,
                                );
                                FsmState::Idle
                            } else {
                                session_log!(self, warn, pc.conn,
                                    "rx {title} for known connection (conn_id: {}) that's unexpected in this state? closing conn",
                                    conn_id.short();
                                );
                                self.stop(
                                    Some(&connection),
                                    None,
                                    StopReason::FsmError,
                                );
                                FsmState::OpenConfirm(pc)
                            }
                        }
                        None => {
                            session_log!(self, warn, pc.conn,
                                "rx {title} for unknown connection (conn_id: {}), ignoring..",
                                conn_id.short();
                            );
                            FsmState::OpenConfirm(pc)
                        }
                    }
                }

                /*
                 * If the local system receives a KeepaliveTimer_Expires event (Event
                 * 11), the local system:
                 *
                 *   - sends a KEEPALIVE message,
                 *
                 *   - restarts the KeepaliveTimer, and
                 *
                 *   - remains in the OpenConfirmed state.
                 */
                ConnectionEvent::KeepaliveTimerExpires(_conn_id) => {
                    session_log!(self, warn, pc.conn,
                        "keepalive timer expired, generate keepalive";
                    );
                    self.send_keepalive(&pc.conn);
                    lock!(pc.conn.clock().timers.keepalive_timer).restart();
                    FsmState::OpenConfirm(pc)
                }

                // Event 12
                ConnectionEvent::DelayOpenTimerExpires(_conn_id) => {
                    session_log!(self, warn, pc.conn,
                        "delay open timer expires event not allowed in this state, fsm transition to idle";
                    );
                    self.stop(Some(&pc.conn), None, StopReason::FsmError);
                    FsmState::Idle
                }

                ConnectionEvent::Message { msg, conn_id } => {
                    lock!(self.message_history)
                        .receive(msg.clone(), Some(conn_id));

                    // The peer has ACK'd our open message with a keepalive. Start the
                    // session timers and enter session setup.
                    if let Message::KeepAlive = msg {
                        lock!(pc.conn.clock().timers.hold_timer).restart();
                        lock!(pc.conn.clock().timers.keepalive_timer).restart();
                        self.bump_msg_counter(msg.kind(), false);
                        FsmState::SessionSetup(pc)
                    } else {
                        /*
                         * If the local system receives a TcpConnectionFails event (Event 18)
                         * from the underlying TCP or a NOTIFICATION message (Event 25), the
                         * local system:
                         *
                         *   - sets the ConnectRetryTimer to zero,
                         *
                         *   - releases all BGP resources,
                         *
                         *   - drops the TCP connection,
                         *
                         *   - increments the ConnectRetryCounter by 1,
                         *
                         *   - (optionally) performs peer oscillation damping if the
                         *     DampPeerOscillations attribute is set to TRUE, and
                         *
                         *   - changes its state to Idle.
                         */
                        session_log!(self, warn, pc.conn,
                            "unexpected {} received (conn_id: {}), fsm transition to idle",
                            msg.title(), conn_id.short();
                            "message" => "notification",
                            "message_contents" => format!("{msg}")
                        );
                        self.bump_msg_counter(msg.kind(), true);
                        lock!(self.clock.timers.connect_retry_timer).stop();
                        FsmState::Idle
                    }
                }
            },

            FsmEvent::Session(session_event) => match session_event {
                // Event 9
                SessionEvent::ConnectRetryTimerExpires
                // Event 13
                | SessionEvent::IdleHoldTimerExpires => {
                    let title = session_event.title();
                    session_log!(self, warn, pc.conn,
                        "{title} event not allowed in this state, fsm transition to idle";
                        "event" => title
                    );
                    self.stop(Some(&pc.conn), None, StopReason::FsmError);
                    FsmState::Idle
                }

                /*
                 * In the event of a TcpConnection_Valid event (Event 14), or the
                 * success of a TCP connection (Event 16 or Event 17) while in
                 * OpenConfirm, the local system needs to track the second
                 * connection.
                 */
                SessionEvent::TcpConnectionAcked(new)
                | SessionEvent::TcpConnectionConfirmed(new) => {
                    let new_creator = new.creator();
                    if new_creator == pc.conn.creator() {
                        collision_log!(self, error, new, pc.conn,
                            "rejected new {} connection for {}: has same creator as existing connection {}",
                            new_creator.direction(),
                            new.id().short(),
                            pc.conn.id().short();
                        );
                        return FsmState::OpenConfirm(pc);
                    }

                    match new_creator {
                        ConnectionCreator::Dispatcher => {
                            collision_log!(self, info, new, pc.conn,
                                "new inbound connection from {} (conn_id: {})",
                                new.peer(), new.id().short();
                            );
                            self.counters
                                .passive_connections_accepted
                                .fetch_add(1, Ordering::Relaxed);

                        }
                        ConnectionCreator::Connector => {
                            collision_log!(self, info, new, pc.conn,
                                "outbound connection to {} (conn_id: {}) completed",
                                new.peer(), new.id().short();
                            );
                            self.counters
                                .active_connections_accepted
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    if let Err(e) = self.send_open(&new) {
                        collision_log!(self, error, new, pc.conn,
                            "error sending open to new conn, continue with open conn";
                            "error" => format!("{e}")
                        );
                        return FsmState::OpenConfirm(pc);
                    }

                    self.register_conn(&new);

                    lock!(new.clock().timers.hold_timer).restart();

                    FsmState::ConnectionCollision(
                        CollisionPair::OpenConfirm(pc, new),
                    )
                }
            },
        }
    }

    /// Handler for Connection Collisions (RFC 4271 6.8)
    ///
    /// Babysits an existing connection (either in OpenSent or OpenConfirm) and
    /// a new connection (always in OpenSent) until one of the following occurs:
    /// 1. We gain enough info to resolve the collision
    ///    i.e.
    ///    We receive an Open via both connections and can use the peer's BGP-ID
    ///    to determine which connection must be closed.
    /// 2. One of the connections becomes eligble to advance into SessionSetup
    /// 3. An FsmEvent is processed that triggers a shutdown of both connections
    ///    e.g.
    ///    ManualStop / Reset
    /// 4. An error is encountered and one or both connections must be closed
    ///    e.g.
    ///    A connection receives an Update before it receives an Open
    ///
    /// The meta conditions we manage here are effectively:
    /// 1. Is a connection ready to advance into SessionSetup?
    /// 2. Do we have enough information to resolve the collision?
    ///
    /// RFC 4271 states:
    ///
    ///     /*
    ///      *  A BGP implementation will have, at most, one FSM for each configured
    ///      *  peering, plus one FSM for each incoming TCP connection for which the
    ///      *  peer has not yet been identified.  Each FSM corresponds to exactly
    ///      *  one TCP connection.
    ///      */
    ///
    /// Maghemite implements the neighbor FSM via the SessionRunner struct, and
    /// SessionRunners are accessed via a map using the peer's IP address as a
    /// key. Inbound connections (handled by the Dispatcher) are not given their
    /// own SessionRunner. They are instead handed to the SessionRunner mapped
    /// to the peer's IP address via FsmEvent::Connected. Therefore, we handle
    /// collisions by emulating separate FSMs for (at most) two connections in
    /// parallel. To facilitate dual FSM emulation, the ConnectionCollision
    /// pseudo-FsmState was introduced. In ConnectionCollision, we track which
    /// connection an event is tied to, and use a connection's state
    /// (specifically, which Messages have been received) as a proxy for
    /// identifying which real FsmState a connection is in currently. FSM Events
    /// are handled for a connection according to the real FsmState a connection
    /// is currently in.
    fn fsm_connection_collision(
        self: &Arc<Self>,
        conn_pair: CollisionPair<Cnx>,
    ) -> FsmState<Cnx> {
        match conn_pair {
            CollisionPair::OpenConfirm(exist, new) => {
                collision_log!(self, info, new, exist.conn,
                    "collision detected: new connection [{:?}, conn_id: {}], existing connection [{:?}, conn_id: {}]",
                    new.conn(), new.id().short(),
                    exist.conn.conn(), exist.conn.id().short();
                );
                self.connection_collision_open_confirm(exist, new)
            }
            CollisionPair::OpenSent(exist, new) => {
                collision_log!(self, info, new, exist,
                    "collision detected: new connection [{:?}, conn_id: {}], existing connection [{:?}, conn_id: {}]",
                    new.conn(), new.id().short(),
                    exist.conn(), exist.id().short();
                );
                self.connection_collision_open_sent(exist, new)
            }
        }
    }

    /// Handler for collisions when existing connection was in OpenConfirm state
    /// when the new connection was encountered.
    ///
    /// Note: `new` cannot progress into SessionSetup directly from here.
    ///
    /// This is because `new` would need both an Open and a Keepalive to do so,
    /// and once `new` receives an Open, we can (and must) perform Collision
    /// Resolution. Compare this against `exist` which simply needs a Keepalive
    /// to move into SessionSetup. A Keepalive gives us no additional
    /// information for use in Collision Resolution.
    /// i.e.
    /// The next valid BGP Message for `exist` does not change our ability
    /// to do Collision Resolution, but enables it to advance to the next FSM
    /// state. Whereas the next valid BGP Message that would progress `new`
    /// gives us the info needed to perform Collision Resolution, which we must
    /// do once we have the data available to do so.
    fn connection_collision_open_confirm(
        self: &Arc<Self>,
        exist: PeerConnection<Cnx>,
        new: Cnx,
    ) -> FsmState<Cnx> {
        let om = loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                return FsmState::Idle;
            }

            let event = match self.event_rx.recv_timeout(IO_TIMEOUT) {
                Ok(event) => {
                    collision_log!(self, debug, new, exist.conn,
                        "received fsm event {}", event.title();
                        "event" => event.title()
                    );
                    event
                }

                Err(RecvTimeoutError::Timeout) => continue,

                Err(e) => {
                    collision_log!(self, error, new, exist.conn,
                        "event rx error for ({e}), fsm transition to idle";
                        "error" => format!("{e}")
                    );
                    //TODO possible death loop. Should we just panic here?
                    continue;
                }
            };

            match event {
                FsmEvent::Admin(admin_event) => match admin_event {
                    AdminEvent::ManualStop => {
                        collision_log!(self, info, new, exist.conn,
                            "rx manual stop, fsm transition to idle";
                        );
                        self.stop(
                            Some(&new),
                            Some(&exist.conn),
                            StopReason::Shutdown,
                        );
                        return FsmState::Idle;
                    }

                    AdminEvent::Reset => {
                        collision_log!(self, info, new, exist.conn,
                            "rx fsm reset, fsm transition to idle";
                        );
                        self.stop(
                            Some(&new),
                            Some(&exist.conn),
                            StopReason::Reset,
                        );
                        return FsmState::Idle;
                    }

                    AdminEvent::Announce(_)
                    | AdminEvent::ShaperChanged(_)
                    | AdminEvent::ExportPolicyChanged(_)
                    | AdminEvent::CheckerChanged(_)
                    | AdminEvent::ManualStart
                    | AdminEvent::SendRouteRefresh
                    | AdminEvent::ReAdvertiseRoutes
                    | AdminEvent::PathAttributesChanged => {
                        let title = admin_event.title();
                        collision_log!(self, warn, new, exist.conn,
                            "unexpected admin fsm event {title}, ignoring";
                            "event" => title
                        );
                        continue;
                    }
                },

                FsmEvent::Session(session_event) => match session_event {
                    // Event 9
                    SessionEvent::ConnectRetryTimerExpires
                    // Event 13
                    | SessionEvent::IdleHoldTimerExpires => {
                        let title = session_event.title();
                        collision_log!(self, warn, new, exist.conn,
                            "{title} event not allowed in this state, fsm transition to idle";
                            "event" => title
                        );
                        self.stop(Some(&new), Some(&exist.conn), StopReason::FsmError);
                        return FsmState::Idle;
                    }

                    SessionEvent::TcpConnectionAcked(extra)
                    | SessionEvent::TcpConnectionConfirmed(extra) => {
                        match extra.creator() {
                            ConnectionCreator::Dispatcher => {
                                collision_log!(self, info, new, exist.conn,
                                    "new inbound connection (peer: {}, conn_id: {}), but we're already in a collision. rejecting..",
                                    extra.peer(), extra.id().short();
                                );
                                self.counters
                                    .passive_connections_declined
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            ConnectionCreator::Connector => {
                                collision_log!(self, info, new, exist.conn,
                                    "outbound connection completed (peer: {}, conn_id: {}), but we're already in a collision. rejecting..",
                                    extra.peer(), extra.id().short();
                                );
                                self.counters
                                    .active_connections_declined
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        self.stop(
                            Some(&extra),
                            None,
                            StopReason::ConnectionRejected,
                        );
                        continue;
                    }
                },

                FsmEvent::Connection(connection_event) => {
                    match connection_event {
                        ConnectionEvent::HoldTimerExpires(conn_id) => {
                            match self.get_conn(&conn_id) {
                                Some(connection) => {
                                    if conn_id == *new.id() {
                                        collision_log!(self, warn, new, exist.conn,
                                            "hold timer expired (conn_id: {}), fsm transition existing conn back to open confirm",
                                            conn_id.short();
                                        );
                                        self.stop(
                                            Some(&new),
                                            None,
                                            StopReason::HoldTimeExpired,
                                        );
                                        return FsmState::OpenConfirm(exist);
                                    } else if conn_id == *exist.conn.id() {
                                        collision_log!(self, warn, new, exist.conn,
                                            "hold timer expired (conn_id: {}), fsm transition new conn to open sent",
                                            conn_id.short();
                                        );
                                        self.stop(
                                            Some(&exist.conn),
                                            None,
                                            StopReason::HoldTimeExpired,
                                        );
                                        return FsmState::OpenSent(new);
                                    } else {
                                        // If the conn_id is known but not
                                        // involved in this collision, send an
                                        // FsmError to that connection.  We
                                        // shouldn't get to this point, because
                                        // the first connection is only accepted
                                        // (and registered) in Active or Connect,
                                        // and the second connection is only
                                        // accepted (and registered) in OpenSent
                                        // or OpenConfirm. Since the FSM
                                        // advances serially, there should be no
                                        // other opportunity for an additional
                                        // connection to have been registered.
                                        // So this error is likely indicative of
                                        // a bug in the registry handling,
                                        // probably a missing unregister call.
                                        collision_log!(self, warn, new, exist.conn,
                                            "rx open message from peer {} for known connection (conn_id: {}) that isn't part of this collision? closing conn",
                                            conn_id.remote().ip(), conn_id.short();
                                        );
                                        self.stop(
                                            Some(&connection),
                                            None,
                                            StopReason::FsmError,
                                        );
                                        continue;
                                    }
                                }
                                None => {
                                    collision_log!(self, warn, new, exist.conn,
                                        "rx open message from peer {} for unknown connection (conn_id: {}), ignoring",
                                        conn_id.remote().ip(), conn_id.short();
                                    );
                                    continue;
                                }
                            }
                        }

                        /*
                         * If the local system receives a KeepaliveTimer_Expires event (Event
                         * 11), the local system:
                         *
                         *   - sends a KEEPALIVE message,
                         *
                         *   - restarts the KeepaliveTimer, and
                         *
                         *   - remains in the OpenConfirmed state.
                         */
                        ConnectionEvent::KeepaliveTimerExpires(ref conn_id) => {
                            match self.collision_conn_kind(
                                conn_id,
                                exist.conn.id(),
                                new.id(),
                            ) {
                                CollisionConnectionKind::New => {
                                    self.send_keepalive(&new);
                                    lock!(new.clock().timers.keepalive_timer)
                                        .restart();
                                }
                                CollisionConnectionKind::Exist => {
                                    self.send_keepalive(&exist.conn);
                                    lock!(
                                        exist
                                            .conn
                                            .clock()
                                            .timers
                                            .keepalive_timer
                                    )
                                    .restart();
                                }

                                CollisionConnectionKind::Unexpected(
                                    unknown,
                                ) => {
                                    // If the conn_id is known but not involved in
                                    // this collision, send an FsmError to that
                                    // connection.  We shouldn't get to this point,
                                    // because the first connection is only accepted
                                    // (and registered) in Active or Connect, and a
                                    // second connection is only accepted (and
                                    // registered) in OpenSent or OpenConfirm. since
                                    // the FSM advances serially, there should be no
                                    // other opportunity for an additional
                                    // connection to have been registered. So this
                                    // error is indicative of a bug in the registry
                                    // handling, probably a missing unregister call.
                                    collision_log!(self, warn, new, exist.conn,
                                        "rx {} for known connection (conn_id: {}) that isn't part of this collision (likely a bug). closing conn",
                                        connection_event.title(), conn_id.short();
                                    );
                                    self.stop(
                                        Some(&unknown),
                                        None,
                                        StopReason::FsmError,
                                    );
                                }

                                CollisionConnectionKind::Missing => {
                                    // If the conn_id is unknown, there's
                                    // nothing to do since we don't have a
                                    // handle for the connection to send a
                                    // notification. All we can do is ignore it.
                                    collision_log!(self, warn, new, exist.conn,
                                        "rx {} for unknown connection (conn_id: {}), ignoring",
                                        connection_event.title(), conn_id.short();
                                    );
                                }
                            }
                        }

                        // Event 12
                        ConnectionEvent::DelayOpenTimerExpires(ref conn_id) => {
                            match self.collision_conn_kind(
                                conn_id,
                                exist.conn.id(),
                                new.id(),
                            ) {
                                CollisionConnectionKind::New => {
                                    collision_log!(self, warn, new, exist.conn,
                                        "new conn rx {} (conn_id: {}), but event is not allowed. fsm transition existing conn back to open confirm",
                                        connection_event.title(), conn_id.short();
                                    );
                                    self.stop(
                                        Some(&new),
                                        None,
                                        StopReason::FsmError,
                                    );
                                    return FsmState::OpenConfirm(exist);
                                }

                                CollisionConnectionKind::Exist => {
                                    collision_log!(self, warn, new, exist.conn,
                                        "exist conn rx {} (conn_id: {}), fsm transition new conn to open sent",
                                        connection_event.title(), conn_id.short();
                                    );
                                    self.stop(
                                        Some(&exist.conn),
                                        None,
                                        StopReason::FsmError,
                                    );
                                    return FsmState::OpenSent(new);
                                }

                                CollisionConnectionKind::Unexpected(
                                    unknown,
                                ) => {
                                    // If the conn_id is known but not
                                    // involved in this collision, send an
                                    // FsmError to that connection.  We
                                    // shouldn't get to this point, because
                                    // the first connection is only accepted
                                    // (and registered) in Active or Connect,
                                    // and the second connection is only
                                    // accepted (and registered) in OpenSent
                                    // or OpenConfirm. Since the FSM
                                    // advances serially, there should be no
                                    // other opportunity for an additional
                                    // connection to have been registered.
                                    // So this error is likely indicative of
                                    // a bug in the registry handling,
                                    // probably a missing unregister call.
                                    collision_log!(self, warn, new, exist.conn,
                                        "rx {} for known connection (conn_id: {}) that isn't part of this collision? closing connection",
                                        connection_event.title(), conn_id.short();
                                    );
                                    self.stop(
                                        Some(&unknown),
                                        None,
                                        StopReason::FsmError,
                                    );
                                    continue;
                                }

                                CollisionConnectionKind::Missing => {
                                    collision_log!(self, warn, new, exist.conn,
                                        "rx {} for unknown connection (conn_id: {}), ignoring",
                                        connection_event.title(), conn_id.short();
                                    );
                                    continue;
                                }
                            }
                        }

                        ConnectionEvent::Message { msg, ref conn_id } => {
                            let msg_kind = msg.kind();
                            match self.collision_conn_kind(
                                conn_id,
                                exist.conn.id(),
                                new.id(),
                            ) {
                                CollisionConnectionKind::New => {
                                    if let Message::Open(om) = msg {
                                        lock!(self.message_history).receive(
                                            om.clone().into(),
                                            Some(*conn_id),
                                        );

                                        self.bump_msg_counter(msg_kind, false);

                                        if let Err(e) =
                                            self.handle_open(&new, &om)
                                        {
                                            collision_log!(self, warn, new, exist.conn,
                                                "new conn failed to handle open message ({e}), existing conn falls back to open confirm";
                                                "error" => format!("{e}")
                                            );
                                            // notification sent by handle_open(), nothing to do here
                                            self.connect_retry_counter
                                                .fetch_add(
                                                    1,
                                                    Ordering::Relaxed,
                                                );
                                            self.counters
                                                .connection_retries
                                                .fetch_add(
                                                    1,
                                                    Ordering::Relaxed,
                                                );
                                            // peer oscillation damping happens in idle, nothing to do here
                                            return FsmState::OpenConfirm(
                                                exist,
                                            );
                                        }

                                        break om;
                                    } else {
                                        self.bump_msg_counter(msg_kind, true);
                                        collision_log!(self, warn, new, exist.conn,
                                            "rx unexpected {msg_kind} via new conn (conn_id: {}), fsm transition existing conn back to open confirm",
                                            conn_id.short();
                                        );
                                        self.stop(
                                            Some(&new),
                                            None,
                                            StopReason::FsmError,
                                        );
                                        return FsmState::OpenConfirm(exist);
                                    }
                                }

                                CollisionConnectionKind::Exist => {
                                    // If we've hit this point, we know `new`
                                    // hasn't gotten an Open yet (otherwise we'd
                                    // have broken out of this loop) and is
                                    // still in OpenSent. So kill `new` and
                                    // transition `exist` to SessionSetup since
                                    // it's ready.
                                    //
                                    // The RFC is pretty unhelpful when it comes
                                    // to exact FSM handling for collisions
                                    // (particularly for implementations that
                                    // only use one FSM for collisions, rather
                                    // than 2) but it does say that a new
                                    // connection should be tracked until it
                                    // gets an Open.  Well if `exist` gets a
                                    // Keepalive and goes into Established
                                    // before `new` gets an Open, then the
                                    // actual collision resolution will happen
                                    // using the rules of FsmState::Established.
                                    // i.e. We aren't going to allow a non-
                                    // established connection to beat an
                                    // established one
                                    // (CollisionDetectEstablishedState), so we
                                    // send a CollisionResolution notification.
                                    if let Message::KeepAlive = msg {
                                        lock!(
                                            exist
                                                .conn
                                                .clock()
                                                .timers
                                                .hold_timer
                                        )
                                        .restart();
                                        lock!(
                                            exist
                                                .conn
                                                .clock()
                                                .timers
                                                .keepalive_timer
                                        )
                                        .restart();
                                        self.bump_msg_counter(msg_kind, false);
                                        self.stop(
                                            Some(&new),
                                            None,
                                            StopReason::CollisionResolution,
                                        );
                                        return FsmState::SessionSetup(exist);
                                    } else {
                                        self.bump_msg_counter(msg_kind, true);
                                        collision_log!(self, warn, new, exist.conn,
                                            "rx unexpected {msg_kind} for existing connection (conn_id: {}), fsm transition new to open sent",
                                            conn_id.short();
                                        );
                                        self.stop(
                                            Some(&exist.conn),
                                            None,
                                            StopReason::FsmError,
                                        );
                                        return FsmState::OpenSent(new);
                                    }
                                }

                                CollisionConnectionKind::Unexpected(
                                    unknown,
                                ) => {
                                    // If the conn_id is known but not
                                    // involved in this collision, send an
                                    // FsmError to that connection.  We
                                    // shouldn't get to this point, because
                                    // the first connection is only accepted
                                    // (and registered) in Active or Connect,
                                    // and the second connection is only
                                    // accepted (and registered) in OpenSent
                                    // or OpenConfirm. Since the FSM
                                    // advances serially, there should be no
                                    // other opportunity for an additional
                                    // connection to have been registered.
                                    // So this error is likely indicative of
                                    // a bug in the registry handling,
                                    // probably a missing unregister call.
                                    collision_log!(self, warn, new, exist.conn,
                                        "rx unexpected {msg_kind} for known connection (conn_id: {}) that isn't part of this collision? closing conn",
                                        conn_id.short();
                                    );
                                    self.stop(
                                        Some(&unknown),
                                        None,
                                        StopReason::FsmError,
                                    );
                                    self.bump_msg_counter(msg_kind, true);
                                    continue;
                                }

                                CollisionConnectionKind::Missing => {
                                    collision_log!(self, warn, new, exist.conn,
                                        "rx unexpected {msg_kind} for unknown connection (conn_id: {}), ignoring..",
                                        conn_id.remote().ip();
                                    );
                                    self.bump_msg_counter(msg_kind, true);
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        };

        self.resolve_collision(
            exist,
            PeerConnection {
                conn: new,
                id: om.id,
                asn: om.asn(),
                caps: om.get_capabilities(),
            },
        )
    }

    /// Handler for collisions when existing connection was in OpenSent state
    /// when the new connection was encountered.
    ///
    /// Note: Either `new` or `exist` can progress into SessionSetup directly
    /// from here.
    ///
    /// This could happen if one of the two connections receives both an Open and
    /// a Keepalive before the other receives an Open. That would result in one
    /// connection becoming ready to move into SessionSetup before we have the
    /// required to do Collision Resolution.
    ///
    /// However, if we receive an Open from both connections before one of the
    /// connections gets both an Open and a Keepalive, we then can (and must)
    /// perform Collision Resolution.
    ///
    /// Implementation notes:
    /// =====================
    /// The existence of a received Open is used as a proxy for determining what
    /// FsmState a connection is in.
    ///   None => OpenSent,
    ///   Some(_) => OpenConfirm
    ///
    /// Each connection's Open is stored in its own Option<OpenMessage>:
    /// new_open & exist_open
    ///
    /// Example:
    /// ========
    /// A Keepalive is received by `exist`.
    /// If `exist_open.is_none()` is true, there's been an FSM error (per the
    /// rules of OpenSent).  However, if `exist_open.is_some()` is true, then
    /// `exist` is eligible to advance into SessionSetup (per the rules of
    /// OpenConfirm).
    fn connection_collision_open_sent(
        self: &Arc<Self>,
        exist: Cnx,
        new: Cnx,
    ) -> FsmState<Cnx> {
        let mut new_open: Option<OpenMessage> = None;
        let mut exist_open: Option<OpenMessage> = None;
        let (om_new, om_exist) = loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                return FsmState::Idle;
            }

            let event = match self.event_rx.recv_timeout(IO_TIMEOUT) {
                Ok(event) => {
                    collision_log!(self, debug, new, exist,
                        "received fsm event {}", event.title();
                        "event" => event.title()
                    );
                    event
                }

                Err(RecvTimeoutError::Timeout) => continue,

                Err(e) => {
                    collision_log!(self, error, new, exist,
                        "event rx error for ({e}), fsm transition to idle";
                        "error" => format!("{e}")
                    );
                    //TODO possible death loop. Should we just panic here?
                    continue;
                }
            };

            match event {
                FsmEvent::Admin(admin_event) => match admin_event {
                    AdminEvent::ManualStop => {
                        collision_log!(self, info, new, exist,
                            "rx manual stop, fsm transition to idle";
                        );
                        self.stop(
                            Some(&new),
                            Some(&exist),
                            StopReason::Shutdown,
                        );
                        return FsmState::Idle;
                    }

                    AdminEvent::Reset => {
                        collision_log!(self, info, new, exist,
                            "rx fsm reset, fsm transition to idle";
                        );
                        self.stop(Some(&new), Some(&exist), StopReason::Reset);
                        return FsmState::Idle;
                    }

                    AdminEvent::Announce(_)
                    | AdminEvent::ShaperChanged(_)
                    | AdminEvent::ExportPolicyChanged(_)
                    | AdminEvent::CheckerChanged(_)
                    | AdminEvent::ManualStart
                    | AdminEvent::SendRouteRefresh
                    | AdminEvent::ReAdvertiseRoutes
                    | AdminEvent::PathAttributesChanged => {
                        let title = admin_event.title();
                        collision_log!(self, warn, new, exist,
                            "unexpected admin fsm event {title}, ignoring";
                            "event" => title
                        );
                        continue;
                    }
                },

                /*
                 * In response to any other event (Events 9, 11-13, 20, 25-28), the
                 * local system:
                 *
                 *   - sends the NOTIFICATION with the Error Code Finite State
                 *     Machine Error,
                 *
                 *   - sets the ConnectRetryTimer to zero,
                 *
                 *   - releases all BGP resources,
                 *
                 *   - drops the TCP connection,
                 *
                 *   - increments the ConnectRetryCounter by 1,
                 *
                 *   - (optionally) performs peer oscillation damping if the
                 *     DampPeerOscillations attribute is set to TRUE, and
                 *
                 *   - changes its state to Idle.
                 */
                FsmEvent::Session(session_event) => match session_event {
                    // Event 9
                    SessionEvent::ConnectRetryTimerExpires
                    // Event 13
                    | SessionEvent::IdleHoldTimerExpires => {
                        let title = session_event.title();
                        collision_log!(self, warn, new, exist,
                            "{title} event not allowed in this state, fsm transition to idle";
                            "event" => title
                        );
                        self.stop(Some(&new), Some(&exist), StopReason::FsmError);
                        return FsmState::Idle;
                    }

                    /*
                     * If a TcpConnection_Valid (Event 14), Tcp_CR_Acked (Event 16), or a
                     * TcpConnectionConfirmed event (Event 17) is received, a second TCP
                     * connection may be in progress.  This second TCP connection is
                     * tracked per Connection Collision processing (Section 6.8) until an
                     * OPEN message is received.
                     */
                    SessionEvent::TcpConnectionAcked(extra)
                    | SessionEvent::TcpConnectionConfirmed(extra) => {
                        match extra.creator() {
                            ConnectionCreator::Dispatcher => {
                                collision_log!(self, info, new, exist,
                                    "new inbound connection (peer: {}, conn_id: {}), but we're already in a collision. closing..",
                                    extra.peer(), extra.id().short();
                                );
                                self.counters
                                    .passive_connections_declined
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            ConnectionCreator::Connector => {
                                collision_log!(self, info, new, exist,
                                    "outbound connection completed (peer: {}, conn_id: {}), but we're already in a collision. closing..",
                                    extra.peer(), extra.id().short();
                                );
                                self.counters
                                    .active_connections_declined
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        self.stop(
                            Some(&exist),
                            None,
                            StopReason::ConnectionRejected,
                        );
                        // unregister_conn() call is not needed, since we
                        // haven't registered `extra`
                        continue;
                    }
                },

                FsmEvent::Connection(connection_event) => {
                    match connection_event {
                        // XXX: Make sure we always log the message type + conn_id
                        ConnectionEvent::Message { msg, ref conn_id } => {
                            let msg_kind = msg.kind();
                            match self.collision_conn_kind(conn_id, exist.id(), new.id()) {
                                CollisionConnectionKind::Missing => {
                                    collision_log!(self, warn, new, exist,
                                        "rx unexpected {msg_kind} from peer {} for unknown connection (conn_id: {}), ignoring..",
                                        conn_id.remote().ip(), conn_id.short();
                                    );
                                    self.bump_msg_counter(msg_kind, true);
                                    continue;
                                },

                                CollisionConnectionKind::Unexpected(unknown) => {
                                    // If the conn_id is known but not
                                    // involved in this collision, send an
                                    // FsmError to that connection.  We
                                    // shouldn't get to this point, because
                                    // the first connection is only accepted
                                    // (and registered) in Active or Connect
                                    // and a second connection is only
                                    // accepted (and registered) in OpenSent
                                    // or OpenConfirm. since the FSM
                                    // advances serially, there should be no
                                    // other opportunity for an additional
                                    // connection to have been registered. So
                                    // this error is indicative of a bug in
                                    // the registry handling, probably a
                                    // missing unregister call.
                                    collision_log!(self, warn, new, exist,
                                        "rx {msg_kind} for known connection (conn_id: {}) that isn't part of this collision? closing conn",
                                        conn_id.short();
                                    );
                                    self.bump_msg_counter(msg_kind, true);
                                    self.stop(Some(&unknown), None, StopReason::FsmError);
                                    continue;
                                },

                                CollisionConnectionKind::Exist => {
                                    if let Message::Open(om) = msg {
                                        lock!(self.message_history).receive(
                                            om.clone().into(),
                                            Some(*conn_id),
                                        );
                                        match exist_open {
                                            // `exist` is in OpenSent
                                            // Open moves us to OpenConfirm
                                            None => {
                                                self.bump_msg_counter(msg_kind, false);

                                                if let Err(e) = self.handle_open(&exist, &om)
                                                {
                                                    collision_log!(self, warn, new, exist,
                                                        "existing conn failed to handle {msg_kind} ({e}), fallback to new conn";
                                                        "error" => format!("{e}")
                                                    );

                                                    // notification sent by handle_open(), nothing to do here
                                                    self.connect_retry_counter
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    self.counters
                                                        .connection_retries
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    // peer oscillation damping happens in idle, nothing to do here

                                                    match new_open {
                                                        // If `new` has received an Open, it is now in OpenConfirm
                                                        Some(o) => {
                                                            let pc = PeerConnection {
                                                                conn: new,
                                                                id: o.id,
                                                                asn: o.asn(),
                                                                caps: o.get_capabilities()
                                                            };
                                                            self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                                            return FsmState::OpenConfirm(pc);
                                                        }
                                                        // If `new` has not received an Open, it is still in OpenSent
                                                        None => {
                                                            return FsmState::OpenSent(new);
                                                        }
                                                    }
                                                }

                                                if let Some(o_new) = new_open {
                                                    break (o_new, om);
                                                } else {
                                                    exist_open = Some(om);
                                                    continue;
                                                }
                                            }
                                            // `exist` is in OpenConfirm
                                            // Open is an FSM Error.
                                            Some(_) => {
                                                collision_log!(self, warn, new, exist,
                                                    "existing conn rx unexpected {msg_kind} (conn_id: {}), fallback to new conn",
                                                    conn_id.short();
                                                    "message" => "open",
                                                    "message_contents" => format!("{om}").as_str()
                                                );

                                                self.bump_msg_counter(msg_kind, true);
                                                self.stop(Some(&exist), None, StopReason::FsmError);

                                                // RFC 4271 says there's an FSM for
                                                // each configured peer + each
                                                // inbound TCP connection that
                                                // hasn't yet been identified. So in
                                                // theory, an FSM error would only
                                                // affect one connection. We are
                                                // emulating two FSMs for the
                                                // lifetime of a collision, so an
                                                // FSM error on one connection
                                                // would presumably have a blast
                                                // radius of just the errored
                                                // connection and we can attempt
                                                // recovery via the other connection
                                                match new_open {
                                                    // If `new` has received an Open, it is now in OpenConfirm
                                                    Some(o) => {
                                                        let pc = PeerConnection {
                                                            conn: new,
                                                            id: o.id,
                                                            asn: o.asn(),
                                                            caps: o.get_capabilities()
                                                        };
                                                        self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                                        return FsmState::OpenConfirm(pc);
                                                    }
                                                    // If `new` has not received an Open, it is still in OpenSent
                                                    None => {
                                                        return FsmState::OpenSent(new);
                                                    }
                                                }
                                            }
                                        }
                                    } else if let Message::KeepAlive = msg {
                                        match exist_open {
                                            // `exist` is in OpenConfirm
                                            // keepalive means move into
                                            // SessionSetup (Established)
                                            Some(o) => {
                                                self.bump_msg_counter(msg_kind, false);
                                                lock!(new.clock().timers.hold_timer).restart();
                                                lock!(new.clock().timers.keepalive_timer).restart();
                                                self.counters
                                                    .keepalives_received
                                                    .fetch_add(1, Ordering::Relaxed);
                                                let pc = PeerConnection {
                                                    conn: exist,
                                                    id: o.id,
                                                    asn: o.asn(),
                                                    caps: o.get_capabilities()
                                                };
                                                self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                                return FsmState::SessionSetup(pc);
                                            }
                                            // `exist` is in OpenSent
                                            // keepalive means FSM Error
                                            None => {
                                                self.bump_msg_counter(msg_kind, true);
                                                collision_log!(self, warn, new, exist,
                                                    "existing rx unexpected {msg_kind} message (conn_id: {}), fallback to new conn",
                                                    conn_id.short();
                                                    "message" => msg_kind
                                                );

                                                self.stop(
                                                    Some(&exist),
                                                    None,
                                                    StopReason::FsmError,
                                                );

                                                lock!(self.clock.timers.connect_retry_timer).stop();
                                                self.connect_retry_counter
                                                    .fetch_add(1, Ordering::Relaxed);

                                                // RFC 4271 says there's an FSM for
                                                // each configured peer + each
                                                // inbound TCP connection that
                                                // hasn't yet been identified. So in
                                                // theory, an FSM error would only
                                                // affect one connection. We are
                                                // emulating two FSMs for the
                                                // lifetime of a collision, so an
                                                // FSM error on one connection
                                                // would presumably have a blast
                                                // radius of just the errored
                                                // connection and we can attempt
                                                // recovery via the other connection
                                                match new_open {
                                                    None => {
                                                        return FsmState::OpenSent(new);
                                                    }
                                                    Some(o) => {
                                                        let pc = PeerConnection {
                                                            conn: new,
                                                            id: o.id,
                                                            asn: o.asn(),
                                                            caps: o.get_capabilities()
                                                        };
                                                        self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                                        return FsmState::SessionSetup(pc);
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        // Any Message other than Open or Keepalive
                                        self.bump_msg_counter(msg_kind, true);
                                        self.connect_retry_counter
                                            .fetch_add(1, Ordering::Relaxed);
                                        lock!(self.clock.timers.connect_retry_timer).stop();
                                        collision_log!(self, warn, new, exist,
                                            "existing conn rx unexpected {msg_kind} (conn_id: {}), fallback to new conn",
                                            conn_id.short();
                                            "message" => "open",
                                            "message_contents" => format!("{msg}").as_str()
                                        );
                                        match new_open {
                                            // If `new` has received an Open, it is now in OpenConfirm
                                            Some(o) => {
                                                let pc = PeerConnection {
                                                    conn: new,
                                                    id: o.id,
                                                    asn: o.asn(),
                                                    caps: o.get_capabilities()
                                                };
                                                self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                                return FsmState::OpenConfirm(pc);
                                            }
                                            // If `new` has not received an Open, it is still in OpenSent
                                            None => {
                                                return FsmState::OpenSent(new);
                                            }
                                        }
                                    }
                                },

                                CollisionConnectionKind::New => {
                                    if let Message::Open(om) = msg {
                                        lock!(self.message_history).receive(
                                            om.clone().into(),
                                            Some(*conn_id),
                                        );
                                        match new_open {
                                            // `new` is in OpenSent
                                            // Open moves us to OpenConfirm
                                            None => {
                                                self.bump_msg_counter(msg_kind, false);

                                                if let Err(e) = self.handle_open(&new, &om)
                                                {
                                                    collision_log!(self, warn, new, exist,
                                                        "new conn failed to handle open ({e}), fallback to existing conn";
                                                        "error" => format!("{e}")
                                                    );

                                                    // notification sent by handle_open(), nothing to do here
                                                    self.connect_retry_counter
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    self.counters
                                                        .connection_retries
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    // peer oscillation damping happens in idle, nothing to do here

                                                    match exist_open {
                                                        // `exist` is in OpenConfirm
                                                        Some(o) => {
                                                            let pc = PeerConnection {
                                                                conn: exist,
                                                                id: o.id,
                                                                asn: o.asn(),
                                                                caps: o.get_capabilities()
                                                            };
                                                            self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                                            return FsmState::OpenConfirm(pc);
                                                        }
                                                        // `exist` is in OpenSent
                                                        None => {
                                                            return FsmState::OpenSent(exist);
                                                        }
                                                    }
                                                }

                                                if let Some(o_exist) = exist_open {
                                                    break(om, o_exist);
                                                } else {
                                                    new_open = Some(om);
                                                    continue;
                                                }
                                            }
                                            // `new` is in OpenConfirm
                                            // Open is an FSM Error.
                                            Some(_) => {
                                                self.bump_msg_counter(msg_kind, true);
                                                self.connect_retry_counter
                                                    .fetch_add(1, Ordering::Relaxed);
                                                lock!(self.clock.timers.connect_retry_timer).stop();
                                                collision_log!(self, warn, new, exist,
                                                    "new conn rx unexpected {msg_kind} (conn_id: {}), fallback to existing conn",
                                                    conn_id.short();
                                                    "message" => "open",
                                                    "message_contents" => format!("{om}").as_str()
                                                );
                                                match exist_open {
                                                    // If `exist` has received an Open, it is now in OpenConfirm
                                                    Some(o) => {
                                                        let pc = PeerConnection {
                                                            conn: exist,
                                                            id: o.id,
                                                            asn: o.asn(),
                                                            caps: o.get_capabilities()
                                                        };
                                                        self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                                        return FsmState::OpenConfirm(pc);
                                                    }
                                                    // If `exist` has not received an Open, it is still in OpenSent
                                                    None => {
                                                        return FsmState::OpenSent(exist);
                                                    }
                                                }
                                            }
                                        }
                                    } else if let Message::KeepAlive = msg {
                                        match new_open {
                                            // `new` is in OpenConfirm
                                            // keepalive means move into
                                            // SessionSetup (Established)
                                            Some(o) => {
                                                self.bump_msg_counter(msg_kind, false);
                                                lock!(new.clock().timers.hold_timer).restart();
                                                lock!(new.clock().timers.keepalive_timer).restart();
                                                self.counters
                                                    .keepalives_received
                                                    .fetch_add(1, Ordering::Relaxed);
                                                let pc = PeerConnection {
                                                    conn: new,
                                                    id: o.id,
                                                    asn: o.asn(),
                                                    caps: o.get_capabilities()
                                                };
                                                self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                                return FsmState::SessionSetup(pc);
                                            }
                                            // `new` is in OpenSent
                                            // keepalive means FSM Error
                                            None => {
                                                self.bump_msg_counter(msg_kind, true);
                                                collision_log!(self, warn, new, exist,
                                                    "new conn rx unexpected {msg_kind} message (conn_id: {}), fallback to existing conn",
                                                    conn_id.short();
                                                    "message" => msg_kind
                                                );

                                                self.stop(
                                                    Some(&new),
                                                    None,
                                                    StopReason::FsmError,
                                                );

                                                lock!(self.clock.timers.connect_retry_timer).stop();
                                                self.connect_retry_counter
                                                    .fetch_add(1, Ordering::Relaxed);

                                                // RFC 4271 says there's an FSM for
                                                // each configured peer + each
                                                // inbound TCP connection that
                                                // hasn't yet been identified. So in
                                                // theory, an FSM error would only
                                                // affect one connection. We are
                                                // emulating two FSMs for the
                                                // lifetime of a collision, so an
                                                // FSM error on one connection
                                                // would presumably have a blast
                                                // radius of just the errored
                                                // connection and we can attempt
                                                // recovery via the other connection
                                                match exist_open {
                                                    None => {
                                                        return FsmState::OpenSent(exist);
                                                    }
                                                    Some(o) => {
                                                        let pc = PeerConnection {
                                                            conn: exist,
                                                            id: o.id,
                                                            asn: o.asn(),
                                                            caps: o.get_capabilities()
                                                        };
                                                        self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                                        return FsmState::SessionSetup(pc);
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        // Any Message other than Open or Keepalive
                                        self.bump_msg_counter(msg_kind, true);
                                        self.connect_retry_counter
                                            .fetch_add(1, Ordering::Relaxed);
                                        lock!(self.clock.timers.connect_retry_timer).stop();
                                        collision_log!(self, warn, new, exist,
                                            "new conn rx unexpected {msg_kind} (conn_id: {}), fallback to existing conn",
                                            conn_id.short();
                                            "message" => "open",
                                            "message_contents" => format!("{msg}").as_str()
                                        );
                                        match exist_open {
                                            // If `exist` has received an Open, it is now in OpenConfirm
                                            Some(o) => {
                                                let pc = PeerConnection {
                                                    conn: exist,
                                                    id: o.id,
                                                    asn: o.asn(),
                                                    caps: o.get_capabilities()
                                                };
                                                self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                                return FsmState::OpenConfirm(pc);
                                            }
                                            // If `exist` has not received an Open, it is still in OpenSent
                                            None => {
                                                return FsmState::OpenSent(exist);
                                            }
                                        }
                                    }
                                },
                            }
                        }

                        /*
                         * If the HoldTimer_Expires (Event 10), the local system:
                         *
                         *   - sends a NOTIFICATION message with the error code Hold Timer
                         *     Expired,
                         *
                         *   - sets the ConnectRetryTimer to zero,
                         *
                         *   - releases all BGP resources,
                         *
                         *   - drops the TCP connection,
                         *
                         *   - increments the ConnectRetryCounter,
                         *
                         *   - (optionally) performs peer oscillation damping if the
                         *     DampPeerOscillations attribute is set to TRUE, and
                         *
                         *   - changes its state to Idle.
                         */
                        ConnectionEvent::HoldTimerExpires(ref conn_id) => {
                            let title = connection_event.title();

                            match self.collision_conn_kind(conn_id, exist.id(), new.id()) {
                                CollisionConnectionKind::New => {
                                    collision_log!(self, warn, new, exist,
                                        "new conn rx {title} (conn_id: {}), fallback to existing conn",
                                        conn_id.short();
                                        "event" => title
                                    );
                                    self.stop(Some(&new), None, StopReason::HoldTimeExpired);
                                    match exist_open {
                                        None => {
                                            return FsmState::OpenSent(exist);
                                        }
                                        Some(o) => {
                                            let pc = PeerConnection {
                                                conn: exist,
                                                id: o.id,
                                                asn: o.asn(),
                                                caps: o.get_capabilities()
                                            };
                                            self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                            return FsmState::SessionSetup(pc);
                                        }
                                    }
                                },

                                CollisionConnectionKind::Exist => {
                                    collision_log!(self, warn, new, exist,
                                        "existing conn rx {title} (conn_id: {}), fallback to new conn",
                                        conn_id.short();
                                        "event" => title
                                    );
                                    self.stop(Some(&exist), None, StopReason::HoldTimeExpired);
                                    match new_open {
                                        None => {
                                            return FsmState::OpenSent(new);
                                        }
                                        Some(o) => {
                                            let pc = PeerConnection {
                                                conn: new,
                                                id: o.id,
                                                asn: o.asn(),
                                                caps: o.get_capabilities()
                                            };
                                            self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                            return FsmState::SessionSetup(pc);
                                        }
                                    }
                                },

                                CollisionConnectionKind::Unexpected(unknown) => {
                                    collision_log!(self, warn, new, exist,
                                        "rx {title} for known connection (conn_id: {}) that isn't part of this collision? closing conn",
                                        conn_id.short();
                                        "event" => title
                                    );
                                    self.stop(Some(&unknown), None, StopReason::HoldTimeExpired);
                                    continue;
                                },

                                CollisionConnectionKind::Missing => {
                                    collision_log!(self, warn, new, exist,
                                        "rx {title} for unknown connection (conn_id: {}), ignoring..",
                                        conn_id.short();
                                        "event" => title
                                    );
                                    continue;
                                },
                            }

                        }

                        // Event 11
                        ConnectionEvent::KeepaliveTimerExpires(
                            conn_id,
                        )
                        // Event 12
                        | ConnectionEvent::DelayOpenTimerExpires(
                            conn_id,
                        ) => {
                            let title = connection_event.title();

                            match self.collision_conn_kind(&conn_id, exist.id(), new.id()) {
                                CollisionConnectionKind::New => {
                                    collision_log!(self, warn, new, exist,
                                        "new conn rx {title}, but event not allowed in this state, fallback to existing conn";
                                        "event" => title
                                    );
                                    self.stop(Some(&new), None, StopReason::FsmError);
                                    match exist_open {
                                        None => {
                                            return FsmState::OpenSent(exist);
                                        }
                                        Some(o) => {
                                            let pc = PeerConnection {
                                                conn: exist,
                                                id: o.id,
                                                asn: o.asn(),
                                                caps: o.get_capabilities()
                                            };
                                            self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                            return FsmState::SessionSetup(pc);
                                        }
                                    }
                                },

                                CollisionConnectionKind::Exist => {
                                    collision_log!(self, warn, new, exist,
                                        "existing conn rx {title}, but event not allowed in this state, fallback to new conn";
                                        "event" => title
                                    );
                                    self.stop(Some(&exist), None, StopReason::FsmError);
                                    match new_open {
                                        None => {
                                            return FsmState::OpenSent(new);
                                        }
                                        Some(o) => {
                                            let pc = PeerConnection {
                                                conn: new,
                                                id: o.id,
                                                asn: o.asn(),
                                                caps: o.get_capabilities()
                                            };
                                            self.set_primary_conn(Some(PrimaryConnection::Full(pc.clone())));
                                            return FsmState::SessionSetup(pc);
                                        }
                                    }
                                },

                                CollisionConnectionKind::Unexpected(unknown) => {
                                    collision_log!(self, warn, new, exist,
                                        "rx {title} for connection that is known (conn_id: {}) but not part of this collision? closing conn",
                                        conn_id.short();
                                        "event" => title
                                    );
                                    self.stop(Some(&unknown), None, StopReason::FsmError);
                                    continue;
                                },

                                CollisionConnectionKind::Missing => {
                                    collision_log!(self, warn, new, exist,
                                        "rx {title} for unknown connection (conn_id: {}), ignoring..",
                                        conn_id.short();
                                        "event" => title
                                    );
                                    continue;
                                },
                            }
                        }
                    }
                }
            }
        };

        self.resolve_collision(
            PeerConnection {
                conn: exist,
                id: om_exist.id,
                asn: om_exist.asn(),
                caps: om_exist.get_capabilities(),
            },
            PeerConnection {
                conn: new,
                id: om_new.id,
                asn: om_new.asn(),
                caps: om_new.get_capabilities(),
            },
        )
    }

    /// Collision Resolution logic.
    ///
    /// Expects two PeerConnections (two connections in OpenConfirm) since
    /// they both know the peer's BGP-ID and ASN from a received (and valid)
    /// OpenMessage.
    fn resolve_collision(
        &self,
        exist: PeerConnection<Cnx>,
        new: PeerConnection<Cnx>,
    ) -> FsmState<Cnx> {
        /*
         * 1) The BGP Identifier of the local system is compared to the BGP
         *    Identifier of the remote system (as specified in the OPEN
         *    message).  Comparing BGP Identifiers is done by converting them
         *    to host byte order and treating them as 4-octet unsigned
         *    integers.
         *
         * 2) If the value of the local BGP Identifier is less than the
         *    remote one, the local system closes the BGP connection that
         *    already exists (the one that is already in the OpenConfirm
         *    state), and accepts the BGP connection initiated by the remote
         *    system.
         *
         * 3) Otherwise, the local system closes the newly created BGP
         *    connection (the one associated with the newly received OPEN
         *    message), and continues to use the existing one (the one that
         *    is already in the OpenConfirm state).
         *
         *    Unless allowed via configuration, a connection collision with an
         *    existing BGP connection that is in the Established state causes
         *    closing of the newly created connection.
         *
         *    Note that a connection collision cannot be detected with connections
         *    that are in Idle, Connect, or Active states.
         *
         *    Closing the BGP connection (that results from the collision
         *    resolution procedure) is accomplished by sending the NOTIFICATION
         *    message with the Error Code Cease.
         */

        // XXX: Is this the right thing to do?
        //      RIDs or ASNs differing across parallel connections to the same
        //      peer IP seems pretty unlikely to occur organically, but what
        //      what would the alternative be? just take the values from one
        //      connection and assume it matches the other?
        if new.id != exist.id {
            collision_log!(self, error, new.conn, exist.conn,
                "collision error: rx BGP-ID mismatch, {} (new conn {}) != {} (existing conn {}). fsm transition to idle",
                new.id,
                new.conn.id().short(),
                exist.id,
                exist.conn.id().short();
            );
            return FsmState::Idle;
        } else if new.asn != exist.asn {
            collision_log!(self, error, new.conn, exist.conn,
                "collision error: rx ASN mismatch, {} (new conn {}) != {} (existing conn {}). fsm transition to idle",
                new.asn,
                new.conn.id().short(),
                exist.asn,
                exist.conn.id().short();
            );
            return FsmState::Idle;
        }

        collision_log!(self, info, new.conn, exist.conn,
            "collision detected: local id {}, remote id {}",
            self.id, new.id;
        );

        /*
         *  If this connection is to be dropped due to connection collision,
         *  the local system:
         *
         *   - sends a NOTIFICATION with a Cease,
         *
         *   - sets the ConnectRetryTimer to zero,
         *
         *   - releases all BGP resources,
         *
         *   - drops the TCP connection,
         *
         *   - increments the ConnectRetryCounter by 1,
         *
         *   - (optionally) performs peer oscillation damping if the
         *     DampPeerOscillations attribute is set to TRUE, and
         *
         *   - changes its state to Idle.
         */

        // Determine which connection we initiated vs the peer initiated.
        // We use ConnectionCreator to identify who initiated each connection.
        let (our_conn, peer_conn) =
            if exist.conn.creator() == ConnectionCreator::Connector {
                // exist is the connection we initiated (outbound)
                // new is the connection peer initiated (inbound)
                (exist, new)
            } else {
                // new is the connection we initiated (outbound)
                // exist is the connection peer initiated (inbound)
                (new, exist)
            };

        if self.id > peer_conn.id {
            // Our RID is higher, we win. Kill the inbound connection to death.
            collision_log!(self, info, our_conn.conn, peer_conn.conn,
                "collision resolution: our outbound conn ({}) wins with higher RID ({} > {})",
                our_conn.conn.id().short(), self.id, peer_conn.id;
            );

            self.stop(
                Some(&peer_conn.conn),
                None,
                StopReason::CollisionResolution,
            );

            lock!(our_conn.conn.clock().timers.hold_timer).restart();
            lock!(our_conn.conn.clock().timers.keepalive_timer).restart();

            self.set_primary_conn(Some(PrimaryConnection::Full(
                our_conn.clone(),
            )));

            return FsmState::SessionSetup(our_conn);
        }

        // Our RID is lower, we lose. Toss the outbound connection to the wolves
        collision_log!(self, info, peer_conn.conn, our_conn.conn,
            "collision resolution: peer's outbound conn ({}) wins ({} >= {})",
            peer_conn.conn.id().short(), peer_conn.id, self.id;
        );

        self.stop(Some(&our_conn.conn), None, StopReason::CollisionResolution);

        lock!(self.clock.timers.connect_retry_timer).stop();
        self.counters
            .connection_retries
            .fetch_add(1, Ordering::Relaxed);

        lock!(peer_conn.conn.clock().timers.hold_timer).restart();
        lock!(peer_conn.conn.clock().timers.keepalive_timer).restart();

        self.set_primary_conn(Some(PrimaryConnection::Full(peer_conn.clone())));

        FsmState::SessionSetup(peer_conn)
    }

    fn collision_conn_kind(
        &self,
        rx: &ConnectionId,
        exist: &ConnectionId,
        new: &ConnectionId,
    ) -> CollisionConnectionKind<Cnx> {
        match self.get_conn(rx) {
            Some(conn) => {
                if rx == new {
                    CollisionConnectionKind::New
                } else if rx == exist {
                    CollisionConnectionKind::Exist
                } else {
                    CollisionConnectionKind::Unexpected(conn)
                }
            }
            None => CollisionConnectionKind::Missing,
        }
    }

    /// Sync up with peers.
    fn fsm_session_setup(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        // Check to see if a shutdown has been requested.
        if self.shutdown.load(Ordering::Acquire) {
            return FsmState::Idle;
        }

        // Collect the prefixes this router is originating.
        let originated = match self.db.get_origin4() {
            Ok(value) => value,
            Err(e) => {
                //TODO possible death loop. Should we just panic here?
                session_log!(self, error, pc.conn,
                    "failed to get originated routes from db";
                    "error" => format!("{e}")
                );
                return FsmState::SessionSetup(pc);
            }
        };

        // Ensure the router has a fanout entry for this peer.
        write_lock!(self.fanout).add_egress(
            self.neighbor.host.ip(),
            crate::fanout::Egress {
                event_tx: Some(self.event_tx.clone()),
                log: self.log.clone(),
            },
        );

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
                self.send_update(update, &pc, ShaperApplication::Current)
            {
                session_log!(self, error, pc.conn,
                    "failed to send update, fsm transition to idle";
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
        if let Err(e) = self.send_update(update, pc, sa) {
            anyhow::bail!("shaper changed: sending update to peer failed {e}");
        }
        Ok(())
    }

    /// Able to exchange update, notification and keepliave messages with peers.
    fn fsm_established(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        // Check to see if a shutdown has been requested.
        if self.shutdown.load(Ordering::Acquire) {
            return self.exit_established(pc);
        }

        let event = match self.event_rx.recv_timeout(IO_TIMEOUT) {
            Ok(event) => {
                session_log!(self, debug, pc.conn,
                    "received fsm event";
                    "event" => event.title()
                );
                event
            }

            Err(RecvTimeoutError::Timeout) => return FsmState::Established(pc),

            Err(e) => {
                //TODO possible death loop. Should we just panic here? Is it
                // even possible to recover from an error here as it likely
                // means the channel is toast.
                session_log!(self, error, pc.conn,
                    "event rx error: {e}";
                    "error" => format!("{e}")
                );
                return FsmState::Established(pc);
            }
        };
        match event {
            FsmEvent::Admin(admin_event) => match admin_event {
                AdminEvent::ManualStop => {
                    self.stop(Some(&pc.conn), None, StopReason::Shutdown);
                    self.exit_established(pc)
                }

                AdminEvent::Reset => {
                    self.stop(Some(&pc.conn), None, StopReason::Reset);
                    self.exit_established(pc)
                }

                // An announce request has come from the administrative API or
                // another peer session (redistribution). Send the update to our
                // peer.
                AdminEvent::Announce(update) => {
                    if let Err(e) = self.send_update(
                        update,
                        &pc,
                        ShaperApplication::Current,
                    ) {
                        session_log!(self, error, pc.conn,
                            "failed to send update, fsm transition to idle";
                            "error" => format!("{e}")
                        );
                        return self.exit_established(pc);
                    }
                    FsmState::Established(pc)
                }

                AdminEvent::ShaperChanged(previous) => {
                    match self.originate_update(
                        &pc,
                        ShaperApplication::Difference(previous),
                    ) {
                        Err(e) => {
                            session_log!(self, error, pc.conn,
                                "failed to originate update, fsm transition to idle";
                                "error" => format!("{e}")
                            );
                            self.exit_established(pc)
                        }
                        Ok(()) => FsmState::Established(pc),
                    }
                }

                AdminEvent::ExportPolicyChanged(previous) => {
                    let originated = match self.db.get_origin4() {
                        Ok(value) => value,
                        Err(e) => {
                            //TODO possible death loop. Should we just panic here?
                            session_log!(self, error, pc.conn,
                                "failed to get originated routes from db";
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

                    let to_withdraw: BTreeSet<&Prefix4> = originated_before
                        .difference(&originated_after)
                        .collect();

                    let to_announce: BTreeSet<&Prefix4> = originated_after
                        .difference(&originated_before)
                        .collect();

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
                        &pc,
                        ShaperApplication::Current,
                    ) {
                        session_log!(self, error, pc.conn,
                            "failed to send update, fsm transition to idle";
                            "error" => format!("{e}")
                        );
                        return self.exit_established(pc);
                    }

                    FsmState::Established(pc)
                }

                AdminEvent::CheckerChanged(_previous) => {
                    //TODO
                    FsmState::Established(pc)
                }

                AdminEvent::SendRouteRefresh => {
                    self.db.mark_bgp_peer_stale(pc.conn.peer().ip());
                    // XXX: Update for IPv6
                    self.send_route_refresh(&pc.conn);
                    FsmState::Established(pc)
                }

                AdminEvent::ReAdvertiseRoutes => {
                    if let Err(e) = self.refresh_react(&pc) {
                        session_log!(self, error, pc.conn,
                            "route re-advertisement error: {e}";
                            "error" => format!("{e}")
                        );
                        return self.exit_established(pc);
                    }
                    FsmState::Established(pc)
                }

                AdminEvent::PathAttributesChanged => {
                    match self.originate_update(&pc, ShaperApplication::Current)
                    {
                        Err(e) => {
                            session_log!(self, error, pc.conn,
                                "failed to originate update, fsm transition to idle";
                                "error" => format!("{e}")
                            );
                            self.exit_established(pc)
                        }
                        Ok(()) => FsmState::Established(pc),
                    }
                }

                AdminEvent::ManualStart => {
                    let title = admin_event.title();
                    session_log_lite!(self, warn,
                        "unexpected admin fsm event {title}, ignoring";
                        "event" => title
                    );
                    FsmState::Established(pc)
                }
            },

            FsmEvent::Session(session_event) => match session_event {
                SessionEvent::ConnectRetryTimerExpires => {
                    session_log!(self, info,  pc.conn,
                        "rx {}, fsm transition to idle",
                        session_event.title();
                    );
                    self.stop(Some(&pc.conn), None, StopReason::FsmError);
                    self.exit_established(pc)
                }

                SessionEvent::IdleHoldTimerExpires => {
                    session_log!(self, info,  pc.conn,
                        "rx delay open timer expires, fsm transition to idle";
                    );
                    self.stop(Some(&pc.conn), None, StopReason::FsmError);
                    self.exit_established(pc)
                }

                SessionEvent::TcpConnectionAcked(new)
                | SessionEvent::TcpConnectionConfirmed(new) => {
                    match new.creator() {
                        ConnectionCreator::Dispatcher => {
                            session_log!(self, info, new,
                                "inbound connection not allowed in established (peer: {}, conn_id: {})",
                                new.peer(), new.id().short();
                            );
                            self.counters
                                .passive_connections_declined
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        ConnectionCreator::Connector => {
                            session_log!(self, info, new,
                                "outbound connection completed but not allowed in established (peer: {}, conn_id: {})",
                                new.peer(), new.id().short();
                            );
                            self.counters
                                .active_connections_declined
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    self.stop(Some(&new), None, StopReason::ConnectionRejected);
                    FsmState::Established(pc)
                }
            },

            FsmEvent::Connection(connection_event) => match connection_event {
                /*
                 *   If the HoldTimer_Expires event occurs (Event 10), the local
                 *   system:
                 *
                 *   - sends a NOTIFICATION message with the Error Code Hold Timer
                 *     Expired,
                 *
                 *   - sets the ConnectRetryTimer to zero,
                 *
                 *   - releases all BGP resources,
                 *
                 *   - drops the TCP connection,
                 *
                 *   - increments the ConnectRetryCounter by 1,
                 *
                 *   - (optionally) performs peer oscillation damping if the
                 *     DampPeerOscillations attribute is set to TRUE, and
                 *
                 *   - changes its state to Idle.
                 */
                ConnectionEvent::HoldTimerExpires(ref conn_id) => {
                    if *conn_id == *pc.conn.id() {
                        // If the HoldTimer fires, it means we've not received a
                        // Keepalive or Update from the peer within the hold time.
                        // So exit Established and restart the peer FSM from Idle
                        session_log!(self, warn, pc.conn,
                            "hold timer expired, fsm transition to idle";
                        );
                        self.counters
                            .hold_timer_expirations
                            .fetch_add(1, Ordering::Relaxed);
                        self.stop(
                            Some(&pc.conn),
                            None,
                            StopReason::HoldTimeExpired,
                        );
                        self.exit_established(pc)
                    } else {
                        session_log!(self, warn, pc.conn,
                            "rx {} for unexpected known connection (conn_id: {}). closing..",
                            connection_event.title(), conn_id.short();
                            "event" => connection_event.title()
                        );
                        if let Some(conn) = self.get_conn(conn_id) {
                            self.stop(
                                Some(&conn),
                                None,
                                StopReason::HoldTimeExpired,
                            );
                        }
                        FsmState::Established(pc)
                    }
                }

                /*
                 *   If the KeepaliveTimer_Expires event occurs (Event 11), the local
                 *   system:
                 *
                 *     - sends a KEEPALIVE message, and
                 *
                 *     - restarts its KeepaliveTimer, unless the negotiated HoldTime
                 *       value is zero.
                 */
                ConnectionEvent::KeepaliveTimerExpires(ref conn_id) => {
                    if *conn_id == *pc.conn.id() {
                        self.send_keepalive(&pc.conn);
                    } else {
                        session_log!(self, warn, pc.conn,
                            "rx {} for unexpected known connection (conn_id: {}). closing..",
                            connection_event.title(), conn_id.short();
                            "event" => connection_event.title()
                        );
                        if let Some(conn) = self.get_conn(conn_id) {
                            self.stop(Some(&conn), None, StopReason::FsmError);
                        }
                    }
                    FsmState::Established(pc)
                }

                ConnectionEvent::DelayOpenTimerExpires(ref conn_id) => {
                    if *conn_id == *pc.conn.id() {
                        session_log!(self, info,  pc.conn,
                            "rx delay open timer expires, fsm transition to idle";
                        );
                        self.stop(Some(&pc.conn), None, StopReason::FsmError);
                        self.exit_established(pc)
                    } else {
                        session_log!(self, warn, pc.conn,
                            "rx {} for unexpected known connection (conn_id: {}). closing..",
                            connection_event.title(), conn_id.short();
                            "event" => connection_event.title()
                        );
                        if let Some(conn) = self.get_conn(conn_id) {
                            self.stop(Some(&conn), None, StopReason::FsmError);
                        }
                        FsmState::Established(pc)
                    }
                }

                ConnectionEvent::Message { msg, ref conn_id } => {
                    let msg_kind = msg.kind();

                    if *conn_id != *pc.conn.id() {
                        if let Some(conn) = self.get_conn(conn_id) {
                            session_log!(self, warn, pc.conn,
                                "rx {msg_kind} for unexpected known connection (conn_id: {}). closing..",
                                conn_id.short();
                                "message" => msg_kind,
                                "message_contents" => format!("{msg}")
                            );
                            self.stop(Some(&conn), None, StopReason::FsmError);
                        } else {
                            session_log!(self, warn, pc.conn,
                                "rx {msg_kind} for unknown connection (conn_id: {}). ignoring..",
                                conn_id.short();
                                "message" => msg_kind,
                                "message_contents" => format!("{msg}")
                            );
                        }
                        return FsmState::Established(pc);
                    }

                    match msg {
                        /*
                         *  If a valid OPEN message (BGPOpen (Event 19)) is received, and if
                         *  the CollisionDetectEstablishedState optional attribute is TRUE,
                         *  the OPEN message will be checked to see if it collides (Section
                         *  6.8) with any other connection.  If the BGP implementation
                         *  determines that this connection needs to be terminated, it will
                         *  process an OpenCollisionDump event (Event 23).  If this connection
                         *  needs to be terminated, the local system:
                         *
                         *    - sends a NOTIFICATION with a Cease,
                         *
                         *    - sets the ConnectRetryTimer to zero,
                         *
                         *    - deletes all routes associated with this connection,
                         *
                         *    - releases all BGP resources,
                         *
                         *    - drops the TCP connection,
                         *
                         *    - increments the ConnectRetryCounter by 1,
                         *
                         *    - (optionally) performs peer oscillation damping if the
                         *      DampPeerOscillations is set to TRUE, and
                         *
                         *    - changes its state to Idle.
                         */
                        Message::Open(om) => {
                            session_log!(self, warn, pc.conn,
                                "unexpected {msg_kind} (conn_id {}), fsm transition to idle",
                                conn_id.short();
                                "message" => "open",
                                "message_contents" => format!("{om}").as_str()
                            );
                            self.bump_msg_counter(msg_kind, true);
                            // The above RFC excerpt explains proper Open
                            // handling if CollisionDetectEstablishedState is
                            // enabled, but doesn't explain proper handling if
                            // it is NOT enabled (and we don't support this
                            // option). So instead of sending a Cease as if we
                            // were resolving a collision, we send an FSM Error.
                            self.stop(
                                Some(&pc.conn),
                                None,
                                StopReason::FsmError,
                            );
                            self.exit_established(pc)
                        }

                        /*
                         *  If the local system receives an UPDATE message (Event 27), the
                         *  local system:
                         *
                         *    - processes the message,
                         *
                         *    - restarts its HoldTimer, if the negotiated HoldTime value is
                         *      non-zero, and
                         *
                         *    - remains in the Established state.
                         */
                        Message::Update(m) => {
                            lock!(pc.conn.clock().timers.hold_timer).reset();
                            session_log!(self, info, pc.conn, "received {msg_kind} (conn_id: {})",
                                conn_id.short();
                                "message" => "update",
                                "message_contents" => format!("{m}").as_str()
                            );
                            self.apply_update(m.clone(), &pc);
                            lock!(self.message_history).receive(m.into(), None);
                            self.bump_msg_counter(msg_kind, false);
                            FsmState::Established(pc)
                        }

                        /*
                         *  If the local system receives a NOTIFICATION message (Event 24 or
                         *  Event 25) or a TcpConnectionFails (Event 18) from the underlying
                         *  TCP, the local system:
                         *
                         *    - sets the ConnectRetryTimer to zero,
                         *
                         *    - deletes all routes associated with this connection,
                         *
                         *    - releases all the BGP resources,
                         *
                         *    - drops the TCP connection,
                         *
                         *    - increments the ConnectRetryCounter by 1,
                         *
                         *    - changes its state to Idle.
                         */
                        Message::Notification(m) => {
                            // We've received a notification from the peer. They are
                            // displeased with us. Exit established and restart from
                            // the idle state.
                            session_log!(self, warn, pc.conn,
                                "{msg_kind} received (conn_id: {}), fsm transition to idle",
                                conn_id.short();
                                "message" => "notification",
                                "message_contents" => format!("{m}")
                            );
                            lock!(self.message_history).receive(m.into(), None);
                            self.bump_msg_counter(msg_kind, false);
                            self.exit_established(pc)
                        }

                        /*
                         *  If the local system receives a KEEPALIVE message (Event 26), the
                         *  local system:
                         *
                         *    - restarts its HoldTimer, if the negotiated HoldTime value is
                         *      non-zero, and
                         *
                         *    - remains in the Established state.
                         */
                        Message::KeepAlive => {
                            session_log!(self, trace, pc.conn,
                                "keepalive received (conn_id: {})", conn_id.short();
                                "message" => "keepalive"
                            );
                            self.bump_msg_counter(msg_kind, false);
                            lock!(pc.conn.clock().timers.hold_timer).reset();
                            FsmState::Established(pc)
                        }

                        /*
                         *   RFC 2918:
                         *
                         *   If a BGP speaker receives from its peer a ROUTE-REFRESH message with
                         *   the <AFI, SAFI> that the speaker didn't advertise to the peer at the
                         *   session establishment time via capability advertisement, the speaker
                         *   shall ignore such a message.  Otherwise, the BGP speaker shall re-
                         *   advertise to that peer the Adj-RIB-Out of the <AFI, SAFI> carried in
                         *   the message, based on its outbound route filtering policy.
                         */
                        Message::RouteRefresh(m) => {
                            lock!(pc.conn.clock().timers.hold_timer).reset();
                            session_log!(self, info, pc.conn,
                                "received route refresh (conn_id: {})",
                                conn_id.short();
                                "message" => "route refresh",
                                "message_contents" => format!("{m}").as_str()
                            );
                            lock!(self.message_history)
                                .receive(m.clone().into(), None);
                            self.bump_msg_counter(msg_kind, false);
                            if let Err(e) = self.handle_refresh(m, &pc) {
                                session_log!(self, error, pc.conn,
                                    "error handling route refresh (conn_id: {}), fsm transition to idle",
                                    conn_id.short();
                                    "error" => format!("{e}")
                                );
                                self.exit_established(pc)
                            } else {
                                FsmState::Established(pc)
                            }
                        }
                    }
                }
            },
        }
    }

    // Housekeeping items to do when a session shutdown is requested.
    pub fn on_shutdown(&self) {
        session_log_lite!(self, info,
            "session runner (peer {}): shutdown start",
            self.neighbor.host.ip();
        );

        self.cleanup_connections();

        // Disable session-level timers
        self.clock.stop_all();

        let previous = self.state();
        let next = FsmStateKind::Idle;
        if previous != next {
            session_log_lite!(
                self,
                info,
                "fsm transition {previous} -> {next}";
            );
            // Go back to the beginning of the state machine.
            *(lock!(self.state)) = next;
        }

        // Reset the shutdown signal and running flag.
        self.shutdown.store(false, Ordering::Release);
        self.running.store(false, Ordering::Release);

        session_log_lite!(self, info,
            "session runner (peer {}): shutdown complete",
            self.neighbor.host.ip();
        );
    }

    /// Send an event to the state machine driving this peer session.
    pub fn send_event(&self, e: FsmEvent<Cnx>) -> Result<(), Error> {
        self.event_tx
            .send(e)
            .map_err(|e| Error::ChannelSend(e.to_string()))
    }

    /// Handle an open message
    fn handle_open(&self, conn: &Cnx, om: &OpenMessage) -> Result<(), Error> {
        let remote_asn = om.asn();
        if let Some(expected_remote_asn) = lock!(self.session).remote_asn {
            if remote_asn != expected_remote_asn {
                self.send_notification(
                    conn,
                    ErrorCode::Open,
                    ErrorSubcode::Open(
                        crate::messages::OpenErrorSubcode::BadPeerAS,
                    ),
                );
                self.unregister_conn(conn.id());
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
                        // XXX: This can probably be removed with more robust
                        //      policy handling
                        self.unregister_conn(conn.id());
                        return Err(Error::PolicyCheckFailed);
                    }
                },
                Err(e) => {
                    session_log!(self, error, conn,
                        "open checker exec failed: {e}";
                        "error" => format!("{e}")
                    );
                    // XXX: This can probably be removed with more robust
                    //      policy handling
                    self.unregister_conn(conn.id());
                }
            }
        }

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
                    self.unregister_conn(conn.id());
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
            "message" => "keepalive"
        );
        if let Err(e) = conn.send(Message::KeepAlive) {
            session_log!(self, error, conn, "failed to send keepalive: {e}";
                "error" => e.to_string()
            );
            self.counters
                .keepalive_send_failure
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters
                .keepalives_sent
                .fetch_add(1, Ordering::Relaxed);
            lock!(conn.clock().timers.keepalive_timer).restart();
        }
    }

    fn send_route_refresh(&self, conn: &Cnx) {
        session_log!(self, info, conn, "sending route refresh";
            "message" => "route refresh"
        );
        if let Err(e) = conn.send(Message::RouteRefresh(RouteRefreshMessage {
            afi: Afi::Ipv4 as u16,
            safi: Safi::NlriUnicast as u8,
        })) {
            session_log!(self, error, conn, "failed to send route refresh: {e}";
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

    fn send_rejected_notification(&self, conn: &Cnx) {
        self.send_notification(
            conn,
            ErrorCode::Cease,
            ErrorSubcode::Cease(CeaseErrorSubcode::ConnectionRejected),
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

    fn send_admin_shutdown_notification(&self, conn: &Cnx) {
        self.send_notification(
            conn,
            ErrorCode::Cease,
            ErrorSubcode::Cease(CeaseErrorSubcode::AdministrativeShutdown),
        )
    }

    fn send_admin_reset_notification(&self, conn: &Cnx) {
        self.send_notification(
            conn,
            ErrorCode::Cease,
            ErrorSubcode::Cease(CeaseErrorSubcode::AdministrativeReset),
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
            "message" => "notification",
            "message_contents" => format!("{notification}").as_str()
        );

        let msg = Message::Notification(notification);
        lock!(self.message_history).send(msg.clone(), None);

        if let Err(e) = conn.send(msg) {
            session_log!(self, error, conn,
                "failed to send notification: {e}";
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
        let capabilities = lock!(self.caps_tx).clone();
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
                    session_log!(self, error, conn,
                        "open shaper exec failed: {e}";
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

    fn is_ebgp(&self) -> Option<bool> {
        if let Some(PrimaryConnection::Full(ref pc)) = *lock!(self.primary) {
            if pc.asn != self.asn.as_u32() {
                return Some(true);
            } else {
                return Some(false);
            }
        }
        None
    }

    fn is_ibgp(&self) -> Option<bool> {
        if let Some(PrimaryConnection::Full(ref pc)) = *lock!(self.primary) {
            if pc.asn == self.asn.as_u32() {
                return Some(true);
            } else {
                return Some(false);
            }
        }
        None
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
        pc: &PeerConnection<Cnx>,
        shaper_application: ShaperApplication,
    ) -> Result<(), Error> {
        let nexthop = pc.conn.local().ip().to_canonical();

        update
            .path_attributes
            .push(PathAttributeValue::NextHop(nexthop).into());

        if let Some(med) = lock!(self.session).multi_exit_discriminator {
            update
                .path_attributes
                .push(PathAttributeValue::MultiExitDisc(med).into());
        }

        if let Some(ibgp) = self.is_ibgp() {
            if ibgp {
                update.path_attributes.push(
                    PathAttributeValue::LocalPref(
                        lock!(self.session).local_pref.unwrap_or(0),
                    )
                    .into(),
                );
            }
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

        session_log!(self, info, pc.conn, "sending update";
            "message" => "update",
            "message_contents" => format!("{out}")
        );

        if let Err(e) = pc.conn.send(out) {
            session_log!(self, error, pc.conn,
                "failed to send update: {e}";
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
    /// to the idle state.
    fn exit_established(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        lock!(pc.conn.clock().timers.hold_timer).disable();
        lock!(pc.conn.clock().timers.keepalive_timer).disable();
        lock!(self.clock.timers.connect_retry_timer).stop();
        self.connect_retry_counter.fetch_add(1, Ordering::Relaxed);

        write_lock!(self.fanout).remove_egress(self.neighbor.host.ip());

        // remove peer prefixes from db
        self.db.remove_bgp_prefixes_from_peer(&pc.conn.peer().ip());

        FsmState::Idle
    }

    fn bump_msg_counter(&self, msg: MessageKind, unexpected: bool) {
        match msg {
            MessageKind::Open => {
                self.counters.opens_received.fetch_add(1, Ordering::Relaxed);
                self.counters
                    .unexpected_open_message
                    .fetch_add(1, Ordering::Relaxed);
            }
            MessageKind::Notification => {
                self.counters
                    .notifications_received
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .unexpected_notification_message
                    .fetch_add(1, Ordering::Relaxed);
            }
            MessageKind::KeepAlive => {
                self.counters
                    .keepalives_received
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .unexpected_keepalive_message
                    .fetch_add(1, Ordering::Relaxed);
            }
            MessageKind::Update => {
                self.counters
                    .updates_received
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .unexpected_update_message
                    .fetch_add(1, Ordering::Relaxed);
            }
            MessageKind::RouteRefresh => {
                self.counters
                    .route_refresh_received
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .unexpected_route_refresh_message
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        if unexpected {
            match msg {
                MessageKind::Open => {
                    self.counters
                        .unexpected_open_message
                        .fetch_add(1, Ordering::Relaxed);
                }
                MessageKind::Notification => {
                    self.counters
                        .unexpected_notification_message
                        .fetch_add(1, Ordering::Relaxed);
                }
                MessageKind::KeepAlive => {
                    self.counters
                        .unexpected_keepalive_message
                        .fetch_add(1, Ordering::Relaxed);
                }
                MessageKind::Update => {
                    self.counters
                        .unexpected_update_message
                        .fetch_add(1, Ordering::Relaxed);
                }
                MessageKind::RouteRefresh => {
                    self.counters
                        .unexpected_route_refresh_message
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn stop(
        &self,
        conn1: Option<&Cnx>,
        conn2: Option<&Cnx>,
        reason: StopReason,
    ) {
        match reason {
            StopReason::Reset => {
                if let Some(c1) = conn1 {
                    self.send_admin_reset_notification(c1);
                }
                if let Some(c2) = conn2 {
                    self.send_admin_reset_notification(c2);
                }
                self.counters
                    .connect_retry_counter
                    .store(0, Ordering::Relaxed);
                self.counters
                    .connection_retries
                    .fetch_add(1, Ordering::Relaxed);
                lock!(self.clock.timers.connect_retry_timer).stop();
            }

            StopReason::Shutdown => {
                if let Some(c1) = conn1 {
                    self.send_admin_shutdown_notification(c1);
                }
                if let Some(c2) = conn2 {
                    self.send_admin_shutdown_notification(c2);
                }
                self.counters
                    .connect_retry_counter
                    .store(0, Ordering::Relaxed);
                self.counters
                    .connection_retries
                    .fetch_add(1, Ordering::Relaxed);
                lock!(self.clock.timers.connect_retry_timer).stop();
            }

            StopReason::FsmError => {
                if let Some(c1) = conn1 {
                    self.send_fsm_notification(c1)
                }
                if let Some(c2) = conn2 {
                    self.send_fsm_notification(c2)
                }
                self.counters
                    .connect_retry_counter
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .connection_retries
                    .fetch_add(1, Ordering::Relaxed);
                lock!(self.clock.timers.connect_retry_timer).stop();
            }

            StopReason::HoldTimeExpired => {
                if let Some(c1) = conn1 {
                    self.send_hold_timer_expired_notification(c1);
                    lock!(c1.clock().timers.hold_timer).disable();
                }
                if let Some(c2) = conn2 {
                    self.send_hold_timer_expired_notification(c2);
                    lock!(c2.clock().timers.hold_timer).disable();
                }
                self.counters
                    .hold_timer_expirations
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .connect_retry_counter
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .connection_retries
                    .fetch_add(1, Ordering::Relaxed);
                lock!(self.clock.timers.connect_retry_timer).stop();
            }

            StopReason::ConnectionRejected => {
                if let Some(c1) = conn1 {
                    self.send_rejected_notification(c1);
                }
                if let Some(c2) = conn2 {
                    self.send_rejected_notification(c2);
                }
            }

            StopReason::CollisionResolution => {
                if let Some(c1) = conn1 {
                    self.send_collision_resolution_notification(c1);
                }
                if let Some(c2) = conn2 {
                    self.send_collision_resolution_notification(c2);
                }
            }
        }

        if let Some(c1) = conn1 {
            self.unregister_conn(c1.id());
        }

        if let Some(c2) = conn2 {
            self.unregister_conn(c2.id());
        }
    }

    /// Apply an update by adding it to our RIB.
    fn apply_update(
        &self,
        mut update: UpdateMessage,
        pc: &PeerConnection<Cnx>,
    ) {
        if let Err(e) = self.check_update(&update, pc.asn) {
            session_log!(self, warn, pc.conn,
                "update check failed: {e}";
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
                pc.asn,
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

        self.update_rib(&update, pc);

        // NOTE: for now we are only acting as an edge router. This means we
        //       do not redistribute announcements. If this changes, uncomment
        //       the following to enable redistribution.
        //
        //    self.fanout_update(&update);
    }

    pub fn refresh_react(&self, pc: &PeerConnection<Cnx>) -> Result<(), Error> {
        // XXX: Update for IPv6
        let originated = match self.db.get_origin4() {
            Ok(value) => value,
            Err(e) => {
                session_log!(self, error, pc.conn,
                    "failed to get originated routes from db";
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
            self.send_update(update, pc, ShaperApplication::Current)?;
        }
        Ok(())
    }

    fn handle_refresh(
        &self,
        msg: RouteRefreshMessage,
        pc: &PeerConnection<Cnx>,
    ) -> Result<(), Error> {
        // XXX: Update for IPv6
        if msg.afi != Afi::Ipv4 as u16 {
            return Ok(());
        }
        self.refresh_react(pc)
    }

    /// Update this router's RIB based on an update message from a peer.
    fn update_rib(&self, update: &UpdateMessage, pc: &PeerConnection<Cnx>) {
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
                    origin_as: pc.asn,
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
    fn check_update(
        &self,
        update: &UpdateMessage,
        peer_as: u32,
    ) -> Result<(), Error> {
        self.check_for_self_in_path(update)?;
        self.check_nexthop_self(update)?;
        let info = lock!(self.session);
        if info.enforce_first_as {
            self.enforce_first_as(update, peer_as)?;
        }
        Ok(())
    }

    fn apply_static_update_policy(&self, update: &mut UpdateMessage) {
        if let Some(ebgp) = self.is_ebgp() {
            if ebgp {
                update.clear_local_pref()
            }
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
        if let Some(PrimaryConnection::Full(ref pc)) = *lock!(self.primary) {
            return Some(pc.asn);
        }
        None
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
            self.event_tx
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
            self.event_tx
                .send(FsmEvent::Admin(AdminEvent::ExportPolicyChanged(
                    previous,
                )))
                .map_err(|e| Error::EventSend(e.to_string()))?;
        } else {
            drop(current);
        }

        if path_attributes_changed {
            self.event_tx
                .send(FsmEvent::Admin(AdminEvent::PathAttributesChanged))
                .map_err(|e| Error::EventSend(e.to_string()))?;
        }

        if refresh_needed {
            self.event_tx
                .send(FsmEvent::Admin(AdminEvent::SendRouteRefresh))
                .map_err(|e| Error::EventSend(e.to_string()))?;
        }

        Ok(reset_needed)
    }
}
