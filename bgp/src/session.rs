// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    clock::SessionClock,
    config::PeerConfig,
    connection::{
        BgpConnection, BgpConnector, ConnectionDirection, ConnectionId,
    },
    error::{Error, ExpectationMismatch},
    fanout::{Fanout4, Fanout6},
    log::{collision_log, session_log, session_log_lite},
    messages::{
        AddPathElement, Afi, BgpNexthop, Capability, CeaseErrorSubcode,
        Community, ErrorCode, ErrorSubcode, Message, MessageKind,
        MessageParseError, MpReachNlri, MpUnreachNlri, NotificationMessage,
        OpenMessage, PathAttributeValue, RouteRefreshMessage, Safi,
        UpdateMessage,
    },
    params::{
        BgpCapability, DynamicTimerInfo, Ipv4UnicastConfig, Ipv6UnicastConfig,
        JitterRange, PeerCounters, PeerInfo, PeerTimers, StaticTimerInfo,
        TimerConfig,
    },
    policy::{CheckerResult, ShaperResult},
    recv_event_loop, recv_event_return,
    router::Router,
};
use mg_common::{lock, read_lock, write_lock};
use rdb::{
    AddressFamily, Asn, BgpPathProperties, Db, ImportExportPolicy4,
    ImportExportPolicy6, Prefix, Prefix4, Prefix6, TypedImportExportPolicy,
};
pub use rdb::{DEFAULT_RIB_PRIORITY_BGP, DEFAULT_ROUTE_PRIORITY};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::{
    collections::{BTreeSet, VecDeque},
    fmt::{self, Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, Sender},
    },
    time::{Duration, Instant},
};

const UNIT_SESSION_RUNNER: &str = "session_runner";

/// The runtime state of an address-family for a given peer.
/// This is instantiated after capability negotiation has completed.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub enum AfiSafiState {
    /// Not configured for this session. We did not advertise this capability
    /// in our OPEN message, so the peer's support is irrelevant.
    #[default]
    Unconfigured,

    /// We advertised this capability but the peer did not. Routes for this
    /// AFI/SAFI will be ignored.
    Advertised,

    /// Successfully negotiated with peer. Routes for this AFI/SAFI will be
    /// processed.
    Negotiated,
}

impl AfiSafiState {
    pub fn negotiated(&self) -> bool {
        matches!(self, Self::Negotiated)
    }
}

impl Display for AfiSafiState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unconfigured => write!(f, "Unconfigured"),
            Self::Advertised => write!(f, "Advertised"),
            Self::Negotiated => write!(f, "Negotiated"),
        }
    }
}

/// This wraps a BgpConnection with runtime state learned from the peer's Open
/// message. This encodes all the dynamic (but non-timer related) information
/// for a given connection into the type system (rather than wrapping each
/// individual item in an Option hanging off the SessionRunner). "Later" FSM
/// states and (various helper methods specific to those states) expect a
/// PeerConnection rather than a BgpConnection, because those are states we
/// enter after a BgpConnection has already received (and accepted) an Open.
#[derive(Debug)]
pub struct PeerConnection<Cnx: BgpConnection> {
    /// The BgpConnection to the peer itself (TCP or Channel)
    pub conn: Arc<Cnx>,
    /// The actual BGP-ID (Router-ID) learned from the peer (runtime state)
    pub id: u32,
    /// The actual ASN learned from the peer (runtime state)
    pub asn: u32,
    /// The actual capabilities received from the peer (runtime state)
    pub caps: BTreeSet<Capability>,
    /// This peer's AFI/SAFI state for IPv4 Unicast
    pub ipv4_unicast: AfiSafiState,
    /// This peer's AFI/SAFI state for IPv6 Unicast
    pub ipv6_unicast: AfiSafiState,
}

impl<Cnx: BgpConnection> Clone for PeerConnection<Cnx> {
    fn clone(&self) -> Self {
        PeerConnection {
            conn: Arc::clone(&self.conn),
            id: self.id,
            asn: self.asn,
            caps: self.caps.clone(),
            ipv4_unicast: self.ipv4_unicast,
            ipv6_unicast: self.ipv6_unicast,
        }
    }
}

/// This wraps a pair of BgpConnections that have been identified as being a
/// Connection Collision. This condition is detected in either OpenConfirm or
/// OpenSent FSM states, and these invariants indicate which state the FSM was
/// in when the collision was detected.
pub enum CollisionPair<Cnx: BgpConnection> {
    OpenConfirm(PeerConnection<Cnx>, Arc<Cnx>),
    OpenSent(Arc<Cnx>, Arc<Cnx>),
}

/// This is a helper enum to classify what connection an FsmEvent is tied to
/// during a Connection Collision. This was created to work in conjuction with
/// collision_conn_kind() to make life easier when choosing between one of 2
/// active connections (`new`/`exist` handled by the current FSM state), an
/// unexpected connection (in the registry but not being actively handled by the
/// current FSM state), and an unknown connection (not in the registry),
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollisionConnectionKind<Cnx: BgpConnection> {
    New,
    Exist,
    Unexpected(Arc<Cnx>),
    Missing,
}

/// Pure function to determine which connection wins in a collision.
///
/// ```text
///    RFC 4271 Section 6.8
///
///    1) The BGP Identifier of the local system is compared to the BGP
///       Identifier of the remote system (as specified in the OPEN
///       message).  Comparing BGP Identifiers is done by converting them
///       to host byte order and treating them as 4-octet unsigned
///       integers.
///
///    2) If the value of the local BGP Identifier is less than the
///       remote one, the local system closes the BGP connection that
///       already exists (the one that is already in the OpenConfirm
///       state), and accepts the BGP connection initiated by the remote
///       system.
///
///    3) Otherwise, the local system closes the newly created BGP
///       connection (the one associated with the newly received OPEN
///       message), and continues to use the existing one (the one that
///       is already in the OpenConfirm state).
///
///       Unless allowed via configuration, a connection collision with an
///       existing BGP connection that is in the Established state causes
///       closing of the newly created connection.
///
///       Note that a connection collision cannot be detected with connections
///       that are in Idle, Connect, or Active states.
///
///       Closing the BGP connection (that results from the collision
///       resolution procedure) is accomplished by sending the NOTIFICATION
///       message with the Error Code Cease.
/// ```
///
/// # Arguments
/// * `exist_direction` - direction of the existing connection (Inbound or Outbound)
/// * `local_bgp_id`  - Our BGP Identifier
/// * `remote_bgp_id` - Peer's BGP Identifier
///
/// # Returns
/// `CollisionResolution` indicating whether exist or new connection wins
pub fn collision_resolution(
    exist_direction: ConnectionDirection,
    local_bgp_id: u32,
    remote_bgp_id: u32,
) -> CollisionResolution {
    if local_bgp_id < remote_bgp_id {
        // The peer has a higher RID, keep the connection they initiated
        match exist_direction {
            ConnectionDirection::Inbound => CollisionResolution::ExistWins,
            ConnectionDirection::Outbound => CollisionResolution::NewWins,
        }
    } else {
        // The local system has a higher RID, keep the connection we initiated
        match exist_direction {
            ConnectionDirection::Inbound => CollisionResolution::NewWins,
            ConnectionDirection::Outbound => CollisionResolution::ExistWins,
        }
    }
}

/// Pure function to select the next-hop to be used for NLRI of this AFI/SAFI
fn select_nexthop(
    nlri_afi: Afi,
    local_ip: IpAddr,
    configured_nexthop: Option<IpAddr>,
) -> Result<BgpNexthop, Error> {
    // Canonicalize the local_ip to handle IPv4-mapped IPv6 addresses
    let local_ip = local_ip.to_canonical();

    // If next-hop is configured, use it (with validation)
    if let Some(nexthop) = configured_nexthop {
        return match (nlri_afi, nexthop) {
            (Afi::Ipv4, IpAddr::V4(ipv4)) => Ok(BgpNexthop::Ipv4(ipv4)),
            (Afi::Ipv6, IpAddr::V6(ipv6)) => Ok(BgpNexthop::Ipv6Single(ipv6)),
            // XXX: Extended Next-Hop
            (Afi::Ipv4, IpAddr::V6(_)) => Err(Error::InvalidAddress(
                "IPv4 routes require IPv4 next-hop (configured mismatch)"
                    .into(),
            )),
            // XXX: Extended Next-Hop
            (Afi::Ipv6, IpAddr::V4(_)) => Err(Error::InvalidAddress(
                "IPv6 routes require IPv6 next-hop (configured mismatch)"
                    .into(),
            )),
        };
    }

    // Otherwise use the local IP of the TCP connection as the next-hop
    match (nlri_afi, local_ip) {
        (Afi::Ipv4, IpAddr::V4(ipv4)) => Ok(BgpNexthop::Ipv4(ipv4)),
        (Afi::Ipv6, IpAddr::V6(ipv6)) => Ok(BgpNexthop::Ipv6Single(ipv6)),
        (Afi::Ipv4, IpAddr::V6(_)) => {
            Err(Error::InvalidAddress(
                "IPv4 routes require IPv4 next-hop (Extended Next-Hop not negotiated)".into()
            ))
        }
        (Afi::Ipv6, IpAddr::V4(_)) => {
            Err(Error::InvalidAddress(
                "IPv6 routes require IPv6 next-hop".into()
            ))
        }
    }
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
    OpenSent(Arc<Cnx>),

    /// Waiting for keepalive or notification from peer.
    OpenConfirm(PeerConnection<Cnx>),

    /// Waiting for Open from incoming connection to perform Collision Resolution.
    ConnectionCollision(CollisionPair<Cnx>),

    /// Sync up with peers.
    SessionSetup(PeerConnection<Cnx>),

    /// Able to exchange update, notification and keepalive messages with peers.
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

    /// Waiting for keepalive or notification from peer.
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

/// IPv4 route update - either an announcement or withdrawal, never both.
///
/// RFC 7606 requires that UPDATE messages not mix reachable and unreachable
/// NLRI. This type enforces that constraint at compile time.
#[derive(Clone, Debug)]
pub enum RouteUpdate4 {
    Announce(Vec<Prefix4>),
    Withdraw(Vec<Prefix4>),
}

/// IPv6 route update - either an announcement or withdrawal, never both.
///
/// RFC 7606 requires that UPDATE messages not mix reachable and unreachable
/// NLRI. This type enforces that constraint at compile time.
#[derive(Clone, Debug)]
pub enum RouteUpdate6 {
    Announce(Vec<Prefix6>),
    Withdraw(Vec<Prefix6>),
}

/// Route update for a specific address family.
///
/// RFC 7606 requires that UPDATE messages not mix reachable and unreachable
/// NLRI. The inner `RouteUpdate4`/`RouteUpdate6` types enforce this by only
/// allowing either an announcement OR a withdrawal, never both.
#[derive(Clone, Debug)]
pub enum RouteUpdate {
    V4(RouteUpdate4),
    V6(RouteUpdate6),
}

impl RouteUpdate {
    pub fn is_empty(&self) -> bool {
        match self {
            RouteUpdate::V4(RouteUpdate4::Announce(nlri)) => nlri.is_empty(),
            RouteUpdate::V4(RouteUpdate4::Withdraw(withdrawn)) => {
                withdrawn.is_empty()
            }
            RouteUpdate::V6(RouteUpdate6::Announce(nlri)) => nlri.is_empty(),
            RouteUpdate::V6(RouteUpdate6::Withdraw(withdrawn)) => {
                withdrawn.is_empty()
            }
        }
    }

    pub fn afi(&self) -> Afi {
        match self {
            RouteUpdate::V4(_) => Afi::Ipv4,
            RouteUpdate::V6(_) => Afi::Ipv6,
        }
    }

    pub fn nlri_count(&self) -> usize {
        match self {
            RouteUpdate::V4(RouteUpdate4::Announce(nlri)) => nlri.len(),
            RouteUpdate::V4(RouteUpdate4::Withdraw(_)) => 0,
            RouteUpdate::V6(RouteUpdate6::Announce(nlri)) => nlri.len(),
            RouteUpdate::V6(RouteUpdate6::Withdraw(_)) => 0,
        }
    }

    pub fn withdrawn_count(&self) -> usize {
        match self {
            RouteUpdate::V4(RouteUpdate4::Announce(_)) => 0,
            RouteUpdate::V4(RouteUpdate4::Withdraw(withdrawn)) => {
                withdrawn.len()
            }
            RouteUpdate::V6(RouteUpdate6::Announce(_)) => 0,
            RouteUpdate::V6(RouteUpdate6::Withdraw(withdrawn)) => {
                withdrawn.len()
            }
        }
    }

    pub fn is_announcement(&self) -> bool {
        matches!(
            self,
            RouteUpdate::V4(RouteUpdate4::Announce(_))
                | RouteUpdate::V6(RouteUpdate6::Announce(_))
        )
    }

    pub fn is_withdrawal(&self) -> bool {
        matches!(
            self,
            RouteUpdate::V4(RouteUpdate4::Withdraw(_))
                | RouteUpdate::V6(RouteUpdate6::Withdraw(_))
        )
    }
}

impl Display for RouteUpdate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RouteUpdate::V4(RouteUpdate4::Announce(nlri)) => {
                write!(f, "ipv4 announce {} prefixes", nlri.len())
            }
            RouteUpdate::V4(RouteUpdate4::Withdraw(withdrawn)) => {
                write!(f, "ipv4 withdraw {} prefixes", withdrawn.len())
            }
            RouteUpdate::V6(RouteUpdate6::Announce(nlri)) => {
                write!(f, "ipv6 announce {} prefixes", nlri.len())
            }
            RouteUpdate::V6(RouteUpdate6::Withdraw(withdrawn)) => {
                write!(f, "ipv6 withdraw {} prefixes", withdrawn.len())
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum AdminEvent {
    /// Announce/withdraw routes for a specific address family.
    /// The session layer will build the appropriate UPDATE message.
    Announce(RouteUpdate),

    // The shaper for the router has changed. Event contains previous checker.
    // Current shaper is available in the router policy object.
    ShaperChanged(Option<rhai::AST>),

    /// Fires when an export policy has changed.
    /// Contains the previous policy for determining routes to re-advertise.
    ExportPolicyChanged(TypedImportExportPolicy),

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
    SendRouteRefresh(Afi),

    /// Fires when we need to re-send our routes to the peer.
    ReAdvertiseRoutes(Afi),
}

impl AdminEvent {
    fn title(&self) -> &'static str {
        match self {
            AdminEvent::Announce(_) => "announce routes",
            AdminEvent::ShaperChanged(_) => "shaper changed",
            AdminEvent::CheckerChanged(_) => "checker changed",
            AdminEvent::ExportPolicyChanged(p) => match p {
                TypedImportExportPolicy::V4(_) => "ipv4 export policy changed",
                TypedImportExportPolicy::V6(_) => "ipv6 export policy changed",
            },
            AdminEvent::Reset => "reset",
            AdminEvent::ManualStart => "manual start",
            AdminEvent::ManualStop => "manual stop",
            AdminEvent::SendRouteRefresh(af) => match af {
                Afi::Ipv4 => "route refresh needed (ipv4 unicast)",
                Afi::Ipv6 => "route refresh needed (ipv6 unicast)",
            },
            AdminEvent::ReAdvertiseRoutes(af) => match af {
                Afi::Ipv4 => "re-advertise routes (ipv4 unicast)",
                Afi::Ipv6 => "re-advertise routes (ipv6 unicast)",
            },
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
    IoError,
    /// A parse error occurred that requires session reset with specific
    /// error codes (per RFC 7606). This is used when the connection layer
    /// reports a `ParseErrorAction::SessionReset`.
    ParseError {
        error_code: ErrorCode,
        error_subcode: ErrorSubcode,
    },
}

/// FsmEvents pertaining to a specific Connection
#[derive(Debug)]
pub enum ConnectionEvent {
    /// A new message from the peer has been received.
    Message { msg: Message, conn_id: ConnectionId },

    /// Fires when the connection's hold timer expires.
    HoldTimerExpires(ConnectionId),

    /// Fires when the connection's keepalive timer expires.
    KeepaliveTimerExpires(ConnectionId),

    /// Fires when the connection's delay open timer expires.
    DelayOpenTimerExpires(ConnectionId),

    /// Fatal message parse error.
    /// Connection layer has logged the error and sends this event for
    /// fatal errors. All ParseError events are fatal - session should send
    /// NOTIFICATION and reset.
    /// Note: If we decide to implement RFC 4760 "AFI/SAFI disable" error
    ///       handling, we likely would just update our response to this.
    ParseError {
        conn_id: ConnectionId,
        error: MessageParseError,
    },

    /// Fires when the recv loop exits due to IO error (connection closed,
    /// timeout, etc.) This signals that the underlying TCP connection
    /// has failed and the SessionRunner should handle the connection loss
    /// appropriately. The specific error is logged at the connection layer.
    TcpConnectionFails(ConnectionId),
}

impl ConnectionEvent {
    fn title(&self) -> &'static str {
        match self {
            ConnectionEvent::Message { msg, .. } => msg.title(),
            ConnectionEvent::HoldTimerExpires(_) => "hold timer expires",
            ConnectionEvent::KeepaliveTimerExpires(_) => {
                "keepalive timer expires"
            }
            ConnectionEvent::DelayOpenTimerExpires(_) => {
                "delay open timer expires"
            }
            ConnectionEvent::ParseError { .. } => "parse error",
            ConnectionEvent::TcpConnectionFails(_) => "tcp connection fails",
        }
    }
}

/// Session-level events that persist across connections
#[derive(Debug)]
pub enum SessionEvent<Cnx: BgpConnection> {
    /// Fires when the session's connect retry timer expires.
    ConnectRetryTimerExpires,

    /// Fires when the session's idle hold timer expires.
    IdleHoldTimerExpires,

    /// Fires when an inbound connection has completed.
    /// The remote peer initiated a TCP connection with a TCP SYN, we confirmed
    /// the connection with a TCP SYN-ACK, and the remote peer has `acked` the
    /// connection with the final TCP ACK.
    /// i.e.
    /// The peer has `acked` the connection they initiated.
    TcpConnectionAcked(Cnx),

    /// Fires when an outbound connection has completed.
    /// The local system initiated a TCP connection with a TCP SYN, and the
    /// remote peer has `confirmed` it with a TCP SYN-ACK.
    /// i.e.
    /// The peer has `confirmed` the connection we initiated.
    TcpConnectionConfirmed(Cnx),
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
#[derive(Debug)]
pub enum FsmEvent<Cnx: BgpConnection> {
    /// Events triggered by an Administrative action
    Admin(AdminEvent),

    /// Events specific to a single Connection.
    Connection(ConnectionEvent),

    /// Session-level events that persist across connections
    Session(SessionEvent<Cnx>),
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
#[derive(Debug)]
pub enum UnusedEvent {
    /// Local system administrator manually starts the peer connection, but has
    /// [`Session::passive_tcp_establishment`] enabled which indicates that the
    /// peer will listen prior to establishing the connection. Functionality is
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

    /// Fires when a connection has been detected while processing an open
    /// message. We implement Collision handling in FsmState::ConnectionCollision
    OpenCollisionDump,
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
    /// IPv4 Unicast address family configuration (None = disabled)
    pub ipv4_unicast: Option<Ipv4UnicastConfig>,
    /// IPv6 Unicast address family configuration (None = disabled)
    pub ipv6_unicast: Option<Ipv6UnicastConfig>,
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
    /// Jitter range for connect_retry timer
    /// (None = disabled)
    /// RFC 4271 recommends 0.75-1.0 range to prevent synchronized behavior
    pub connect_retry_jitter: Option<JitterRange>,
    /// Jitter range for idle_hold timer
    /// (None = disabled)
    pub idle_hold_jitter: Option<JitterRange>,
    /// Enable deterministic collision resolution in Established state.
    /// When true, uses BGP-ID comparison per RFC 4271 §6.8 for collision
    /// resolution even when one connection is already in Established state.
    /// When false, Established connection always wins (timing-based resolution).
    pub deterministic_collision_resolution: bool,
}

impl SessionInfo {
    /// Create a SessionInfo from a PeerConfig with minimal defaults for policy fields.
    /// This is used when only timer configuration is available (e.g., in tests).
    pub fn from_peer_config(peer_config: &crate::config::PeerConfig) -> Self {
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
            ipv4_unicast: Some(Ipv4UnicastConfig {
                nexthop: None,
                import_policy: ImportExportPolicy4::default(),
                export_policy: ImportExportPolicy4::default(),
            }),
            ipv6_unicast: None,
            vlan_id: None,
            connect_retry_time: Duration::from_secs(peer_config.connect_retry),
            keepalive_time: Duration::from_secs(peer_config.keepalive),
            hold_time: Duration::from_secs(peer_config.hold_time),
            idle_hold_time: Duration::from_secs(peer_config.idle_hold_time),
            delay_open_time: Duration::from_secs(peer_config.delay_open),
            resolution: Duration::from_millis(peer_config.resolution),
            idle_hold_jitter: Some(JitterRange {
                min: 0.75,
                max: 1.0,
            }),
            connect_retry_jitter: None,
            deterministic_collision_resolution: false,
        }
    }
}

/// Information about a neighbor (peer).
#[derive(Debug, Clone)]
pub struct NeighborInfo {
    pub name: Arc<Mutex<String>>,
    pub peer_group: String,
    pub host: SocketAddr,
}

/// Session endpoint that combines the event sender with session configuration.
/// This is used in addr_to_session map to provide both communication channel
/// and policy information for each peer.
pub struct SessionEndpoint<Cnx: BgpConnection> {
    /// Event sender for FSM events to this session
    pub event_tx: Sender<FsmEvent<Cnx>>,

    /// Session configuration including policy settings
    pub config: Arc<Mutex<SessionInfo>>,
}

impl<Cnx: BgpConnection> Clone for SessionEndpoint<Cnx> {
    fn clone(&self) -> Self {
        Self {
            event_tx: self.event_tx.clone(),
            config: Arc::clone(&self.config),
        }
    }
}

pub const MAX_MESSAGE_HISTORY: usize = 1024;

/// A message history entry is a BGP message with an associated timestamp and connection ID
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistoryEntry {
    timestamp: chrono::DateTime<chrono::Utc>,
    message: Message,
    connection_id: ConnectionId,
}

/// Message history for a BGP session
#[derive(Default, Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistory {
    pub received: VecDeque<MessageHistoryEntry>,
    pub sent: VecDeque<MessageHistoryEntry>,
}

impl MessageHistory {
    fn receive(&mut self, msg: Message, connection_id: ConnectionId) {
        if self.received.len() >= MAX_MESSAGE_HISTORY {
            self.received.pop_back();
        }
        self.received.push_front(MessageHistoryEntry {
            message: msg,
            timestamp: chrono::Utc::now(),
            connection_id,
        });
    }

    fn send(&mut self, msg: Message, connection_id: ConnectionId) {
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

pub const MAX_FSM_HISTORY_ALL: usize = 1024;
pub const MAX_FSM_HISTORY_MAJOR: usize = 1024;

/// Category of FSM event for filtering and display purposes
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum FsmEventCategory {
    Admin,
    Connection,
    Session,
    StateTransition,
}

/// Serializable record of an FSM event with full context
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FsmEventRecord {
    /// UTC timestamp when event occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// High-level event category
    pub event_category: FsmEventCategory,

    /// Specific event type as string (e.g., "ManualStart", "HoldTimerExpires")
    pub event_type: String,

    /// FSM state at time of event
    pub current_state: FsmStateKind,

    /// Previous state if this caused a transition
    pub previous_state: Option<FsmStateKind>,

    /// Connection ID if event is connection-specific
    pub connection_id: Option<ConnectionId>,

    /// Additional event details (e.g., "Received OPEN", "Admin command")
    pub details: Option<String>,
}

/// Dual-buffer FSM event history for comprehensive and strategic visibility
///
/// The 'all' buffer records every FSM event including high-frequency timer events,
/// useful for detailed debugging of recent behavior. The 'major' buffer records only
/// significant events (state transitions, admin commands, new connections) that
/// provide long-term strategic visibility into session lifecycle.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct FsmEventHistory {
    /// All FSM events (high frequency, includes all timers)
    pub all: VecDeque<FsmEventRecord>,

    /// Major events only (state transitions, admin, new connections)
    pub major: VecDeque<FsmEventRecord>,
}

impl FsmEventHistory {
    pub fn new() -> Self {
        Self {
            all: VecDeque::with_capacity(MAX_FSM_HISTORY_ALL),
            major: VecDeque::with_capacity(MAX_FSM_HISTORY_MAJOR),
        }
    }

    /// Record an event in 'all' buffer (rolling FIFO)
    pub fn record_all(&mut self, event: FsmEventRecord) {
        if self.all.len() >= MAX_FSM_HISTORY_ALL {
            self.all.pop_back();
        }
        self.all.push_front(event);
    }

    /// Record an event in 'major' buffer (rolling FIFO)
    pub fn record_major(&mut self, event: FsmEventRecord) {
        if self.major.len() >= MAX_FSM_HISTORY_MAJOR {
            self.major.pop_back();
        }
        self.major.push_front(event);
    }

    /// Record in both buffers if event is major, otherwise just 'all'
    pub fn record(&mut self, event: FsmEventRecord, is_major: bool) {
        self.record_all(event.clone());
        if is_major {
            self.record_major(event);
        }
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
    pub connector_panics: AtomicU64,
}

pub enum ShaperApplication {
    Current,
    Difference(Option<rhai::AST>),
}

/// This is used to represent a BgpConnection based on what progress it's made
/// through the FSM.
#[derive(Debug)]
pub enum ConnectionKind<Cnx: BgpConnection> {
    /// This represents a connection in the "early" FSM states where we haven't
    /// yet learned details about the BGP peer (via Open message).
    /// i.e.
    /// OpenSent or earlier.
    Partial(Arc<Cnx>),
    /// This represents a connection in the "late" FSM states where we know
    /// details details about the BGP peer (via Open message).
    /// i.e.
    /// OpenConfirm or later.
    Full(PeerConnection<Cnx>),
}

impl<Cnx: BgpConnection> Clone for ConnectionKind<Cnx> {
    fn clone(&self) -> Self {
        match self {
            ConnectionKind::Partial(arc) => {
                ConnectionKind::Partial(Arc::clone(arc))
            }
            ConnectionKind::Full(pc) => ConnectionKind::Full(pc.clone()),
        }
    }
}

impl<Cnx: BgpConnection> ConnectionKind<Cnx> {
    /// Get the connection ID regardless of maturity state
    pub fn id(&self) -> ConnectionId {
        match self {
            ConnectionKind::Partial(c) => *c.id(),
            ConnectionKind::Full(pc) => *pc.conn.id(),
        }
    }

    /// Check if this is a Full (mature) connection
    pub fn is_full(&self) -> bool {
        matches!(self, ConnectionKind::Full(_))
    }

    /// Get a reference to the underlying connection (Arc<Cnx>)
    pub fn connection(&self) -> &Arc<Cnx> {
        match self {
            ConnectionKind::Partial(c) => c,
            ConnectionKind::Full(pc) => &pc.conn,
        }
    }
}

/// Convenience macro for accessing session-level timers with less verbosity
macro_rules! session_timer {
    ($self:expr, $timer:ident) => {
        lock!($self.clock.timers.$timer)
    };
}
/// Convenience macro for accessing connection-level timers with less verbosity
macro_rules! conn_timer {
    ($conn:expr, $timer:ident) => {
        lock!($conn.clock().timers.$timer)
    };
}
/// Convenience macro for calculating connect() timeout.
/// The connect() timeout is currently calculated as 1/3 of the configured
/// ConnectRetryTime. This allows user configuration to influence the timeout
/// and ensures a Connector thread will wrap up before ConnectRetryTimeExpires.
macro_rules! connect_timeout {
    ($self:expr) => {
        lock!($self.clock.timers.connect_retry).interval / 3
    };
}

/// Determines AFI/SAFI state based on capability negotiation.
///
/// Returns (ipv4_unicast, ipv6_unicast) states:
/// - Negotiated: Both sides advertised the capability
/// - Advertised: We advertised but peer did not
/// - Unconfigured: We did not advertise (not configured)
macro_rules! active_afi {
    ($self:expr, $their_caps:ident) => {{
        let cap4 = Capability::ipv4_unicast();
        let cap6 = Capability::ipv6_unicast();
        let our_caps = lock!($self.caps_tx);

        let ipv4_state = if our_caps.contains(&cap4) {
            if $their_caps.contains(&cap4) {
                AfiSafiState::Negotiated
            } else {
                AfiSafiState::Advertised
            }
        } else {
            AfiSafiState::Unconfigured
        };

        let ipv6_state = if our_caps.contains(&cap6) {
            if $their_caps.contains(&cap6) {
                AfiSafiState::Negotiated
            } else {
                AfiSafiState::Advertised
            }
        } else {
            AfiSafiState::Unconfigured
        };

        (ipv4_state, ipv6_state)
    }};
}

/// Registry for tracking active connections
#[derive(Debug)]
pub enum ConnectionRegistry<Cnx: BgpConnection> {
    /// No connections registered
    Empty,
    /// Single connection registered with its maturity state
    Single { active: ConnectionKind<Cnx> },
    /// During a collision, there are two connections.
    /// first = the connection the FSM is actively managing
    /// second = the incoming connection during collision window
    Collision {
        first: ConnectionKind<Cnx>,
        second: ConnectionKind<Cnx>,
    },
}

impl<Cnx: BgpConnection> ConnectionRegistry<Cnx> {
    /// Create a new empty registry
    pub fn new() -> Self {
        ConnectionRegistry::Empty
    }

    /// Register a new connection with its maturity state.
    /// Returns error if at capacity.
    pub fn register(&mut self, conn: ConnectionKind<Cnx>) -> Result<(), Error> {
        let new_state = match std::mem::replace(self, ConnectionRegistry::Empty)
        {
            ConnectionRegistry::Empty => {
                ConnectionRegistry::Single { active: conn }
            }
            ConnectionRegistry::Single { active: first } => {
                ConnectionRegistry::Collision {
                    first,
                    second: conn,
                }
            }
            collision @ ConnectionRegistry::Collision { .. } => {
                // Restore the collision state and return error
                *self = collision;
                return Err(Error::RegistryFull(
                    "registry already has maximum connections".into(),
                ));
            }
        };
        *self = new_state;
        Ok(())
    }

    /// Remove a connection by ID. Returns the connection if found.
    pub fn remove(
        &mut self,
        conn_id: &ConnectionId,
    ) -> Option<ConnectionKind<Cnx>> {
        match std::mem::replace(self, ConnectionRegistry::Empty) {
            ConnectionRegistry::Empty => None,
            ConnectionRegistry::Single { active } => {
                if active.id() == *conn_id {
                    *self = ConnectionRegistry::Empty;
                    Some(active)
                } else {
                    // Restore state if ID doesn't match
                    *self = ConnectionRegistry::Single { active };
                    None
                }
            }
            ConnectionRegistry::Collision { first, second } => {
                if first.id() == *conn_id {
                    // Remove first, keep second
                    *self = ConnectionRegistry::Single { active: second };
                    Some(first)
                } else if second.id() == *conn_id {
                    // Remove second, keep first
                    *self = ConnectionRegistry::Single { active: first };
                    Some(second)
                } else {
                    // Restore state if ID doesn't match
                    *self = ConnectionRegistry::Collision { first, second };
                    None
                }
            }
        }
    }

    /// Clear all connections and return to Empty state
    pub fn clear(&mut self) {
        *self = ConnectionRegistry::Empty;
    }

    /// Get the number of registered connections
    pub fn count(&self) -> u8 {
        match self {
            ConnectionRegistry::Empty => 0,
            ConnectionRegistry::Single { .. } => 1,
            ConnectionRegistry::Collision { .. } => 2,
        }
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        matches!(self, ConnectionRegistry::Empty)
    }

    /// Get all ConnectionIds currently registered
    pub fn connection_ids(&self) -> Vec<ConnectionId> {
        match self {
            ConnectionRegistry::Empty => Vec::new(),
            ConnectionRegistry::Single { active } => {
                vec![active.id()]
            }
            ConnectionRegistry::Collision { first, second } => {
                vec![first.id(), second.id()]
            }
        }
    }

    /// Get all connections currently registered
    pub fn all_connections(&self) -> Vec<&ConnectionKind<Cnx>> {
        match self {
            ConnectionRegistry::Empty => Vec::new(),
            ConnectionRegistry::Single { active } => vec![active],
            ConnectionRegistry::Collision { first, second } => {
                vec![first, second]
            }
        }
    }

    /// Get the primary (actively managed) connection, if one exists.
    ///
    /// Single: returns the only connection.
    /// Collision: returns the first connection (actively managed by FSM).
    /// Empty: returns None.
    pub fn primary(&self) -> Option<&ConnectionKind<Cnx>> {
        match self {
            ConnectionRegistry::Empty => None,
            ConnectionRegistry::Single { active } => Some(active),
            ConnectionRegistry::Collision { first, .. } => Some(first),
        }
    }

    /// Upgrade a connection from Partial to Full maturity.
    /// Finds the connection by ID and replaces it with the Full version.
    /// This is used when a Partial connection receives and accepts an Open message.
    pub fn upgrade_to_full(&mut self, peer_conn: PeerConnection<Cnx>) {
        let conn_id = *peer_conn.conn.id();
        match self {
            ConnectionRegistry::Single {
                active: ConnectionKind::Partial(_),
            } => {
                *self = ConnectionRegistry::Single {
                    active: ConnectionKind::Full(peer_conn),
                };
            }
            ConnectionRegistry::Single {
                active: ConnectionKind::Full(_),
            } => {
                // Already Full, this shouldn't happen normally
            }
            ConnectionRegistry::Collision { first, second } => {
                if match first {
                    ConnectionKind::Partial(c) => *c.id() == conn_id,
                    ConnectionKind::Full(pc) => *pc.conn.id() == conn_id,
                } && let ConnectionKind::Partial(_) = first
                {
                    *first = ConnectionKind::Full(peer_conn);
                } else if match second {
                    ConnectionKind::Partial(c) => *c.id() == conn_id,
                    ConnectionKind::Full(pc) => *pc.conn.id() == conn_id,
                } && let ConnectionKind::Partial(_) = second
                {
                    *second = ConnectionKind::Full(peer_conn);
                }
            }
            ConnectionRegistry::Empty => {
                // Empty, shouldn't upgrade to Full
            }
        }
    }
}

impl<Cnx: BgpConnection> Default for ConnectionRegistry<Cnx> {
    fn default() -> Self {
        Self::new()
    }
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
pub struct SessionRunner<Cnx: BgpConnection + 'static> {
    /// FSM Event Queue sender. This handle is owned by the SessionRunner for
    /// the purpose of passing clones to different threads/events that need to
    /// generate FsmEvents to be processed by this SessionRunner's FSM.
    pub event_tx: Sender<FsmEvent<Cnx>>,

    /// Information about the neighbor this session is to peer with.
    pub neighbor: NeighborInfo,

    /// A log of the last `MAX_MESSAGE_HISTORY` messages. Keepalives are not
    /// included in message history.
    pub message_history: Arc<Mutex<MessageHistory>>,

    /// Dual-buffer FSM event history (all events + major events only)
    pub fsm_event_history: Arc<Mutex<FsmEventHistory>>,

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
    pub caps_tx: Arc<Mutex<BTreeSet<Capability>>>,

    shutdown: AtomicBool,
    running: AtomicBool,
    db: Db,
    fanout4: Arc<RwLock<Fanout4<Cnx>>>,
    fanout6: Arc<RwLock<Fanout6<Cnx>>>,
    router: Arc<Router<Cnx>>,

    /// Registry of active connections with typestate enforcement
    /// Ensures at most 2 connections (primary + collision during negotiation)
    /// Now stores the primary connection directly with its maturity state via ConnectionKind
    connection_registry: Arc<Mutex<ConnectionRegistry<Cnx>>>,

    /// Handle to the currently running connector thread, if any.
    /// Used to track outbound connection attempts and prevent duplicate spawns.
    connector_handle: Mutex<Option<std::thread::JoinHandle<()>>>,

    log: Logger,
}

unsafe impl<Cnx: BgpConnection> Send for SessionRunner<Cnx> {}
unsafe impl<Cnx: BgpConnection> Sync for SessionRunner<Cnx> {}

/// Result of collision resolution indicating which connection won per RFC 4271 §6.8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollisionResolution {
    /// The "existing" connection wins
    ExistWins,
    /// The "new" connection wins
    NewWins,
}

impl<Cnx: BgpConnection + 'static> Drop for SessionRunner<Cnx> {
    fn drop(&mut self) {
        let peer_ip = self.neighbor.host.ip();
        let final_state = *lock!(self.state);
        session_log_lite!(
            self,
            debug,
            "dropping session runner for peer {peer_ip} (final state: {final_state})"
        );
    }
}

impl<Cnx: BgpConnection + 'static> SessionRunner<Cnx> {
    /// Create a new BGP session runner. Only creates the session runner
    /// object. Must call `start` to begin the peering state machine.
    pub fn new(
        session: Arc<Mutex<SessionInfo>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
        event_tx: Sender<FsmEvent<Cnx>>,
        neighbor: NeighborInfo,
        router: Arc<Router<Cnx>>,
    ) -> SessionRunner<Cnx> {
        let session_info = lock!(session);
        let runner = SessionRunner {
            session: session.clone(),
            connect_retry_counter: AtomicU64::new(0),
            event_rx,
            event_tx: event_tx.clone(),
            asn: router.config.asn,
            id: router.config.id,
            neighbor,
            state: Arc::new(Mutex::new(FsmStateKind::Idle)),
            last_state_change: Mutex::new(Instant::now()),
            clock: Arc::new(SessionClock::new(
                session_info.resolution,
                session_info.connect_retry_time,
                session_info.idle_hold_time,
                session_info.connect_retry_jitter,
                session_info.idle_hold_jitter,
                event_tx.clone(),
                router.log.clone(),
            )),
            log: router.log.clone(),
            shutdown: AtomicBool::new(false),
            running: AtomicBool::new(false),
            fanout4: router.fanout4.clone(),
            fanout6: router.fanout6.clone(),
            router: router.clone(),
            message_history: Arc::new(Mutex::new(MessageHistory::default())),
            fsm_event_history: Arc::new(Mutex::new(FsmEventHistory::new())),
            counters: Arc::new(SessionCounters::default()),
            db: router.db.clone(),
            caps_tx: Arc::new(Mutex::new(BTreeSet::new())),
            connection_registry: Arc::new(
                Mutex::new(ConnectionRegistry::new()),
            ),
            connector_handle: Mutex::new(None),
        };
        drop(session_info);
        runner
    }

    /// Request a peer session shutdown. Does not shut down the session right
    /// away. Simply sets a flag that the session is to be shut down which will
    /// be acted upon in the state machine loop.
    pub fn shutdown(&self) {
        session_log_lite!(
            self,
            info,
            "session runner (peer {}) received shutdown request, setting shutdown flag",
            self.neighbor.host.ip();
        );
        self.shutdown.store(true, Ordering::Release);
    }

    /// Join a connector thread and handle any panic, logging appropriately
    /// and updating panic counters.
    fn join_connector_thread(
        &self,
        handle: std::thread::JoinHandle<()>,
        context: &str,
    ) {
        match handle.join() {
            Ok(()) => {
                session_log_lite!(
                    self,
                    debug,
                    "connector thread completed successfully";
                    "context" => context
                );
            }
            Err(e) => {
                session_log_lite!(
                    self,
                    error,
                    "connector thread panicked: {e:?}";
                    "context" => context,
                    "panic" => format!("{e:?}")
                );
                self.counters
                    .connector_panics
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Initiate an outbound connection attempt to the BGP peer.
    /// Checks for existing connection attempts, joins finished ones (detecting panics),
    /// and initiates a new connection only if safe to do so.
    fn initiate_connection(&self, timeout: Duration) {
        // Clone session info first, before acquiring any locks
        let session_info = lock!(self.session).clone();

        // First critical section: check and join old connector thread
        {
            let mut handle_guard = lock!(self.connector_handle);

            if let Some(old_handle) = handle_guard.take() {
                // If thread is still running, put the handle back. Don't spawn.
                if !old_handle.is_finished() {
                    // The only time we should realistically expect to encounter
                    // this is if the FSM has made a trip back through Idle and
                    // is transitioning into Connect before ConnectRetryTimer
                    // pops. The FSM moves to Idle upon an Error or an admin
                    // event. Once there, it transitions to Connect upon another
                    // admin event or when IdleHoldTimer pops.
                    // i.e.
                    // We should only expect to hit this condition if:
                    // 1. Connection is not passive (Connector is irrelevant for
                    //    passive connections)
                    // 2. Connector thread is started
                    // 3. FSM transitions to Idle
                    // 4. IdleHoldTimerExpires or admin event pushes FSM out
                    //    of Idle
                    // 5. Connector thread is still running
                    *handle_guard = Some(old_handle);
                    session_log_lite!(
                        self,
                        debug,
                        "connector already running, skipping spawn"
                    );
                    return;
                }

                // Thread finished, join to check for panics
                self.join_connector_thread(old_handle, "checking previous");
            }
            // release lock before calling connect
        }

        let handle = match Cnx::Connector::connect(
            self.neighbor.host,
            timeout,
            self.log.clone(),
            self.event_tx.clone(),
            session_info,
        ) {
            Ok(h) => h,
            Err(e) => {
                session_log_lite!(
                    self,
                    error,
                    "failed to spawn connection thread: {e}";
                    "error" => format!("{e}")
                );
                return;
            }
        };

        *lock!(self.connector_handle) = Some(handle);
        session_log_lite!(self, debug, "spawned new connector thread");
    }

    /// Add a connection to the registry. Newly registered connection is
    /// promoted to primary only if there isn't already a primary.
    /// This also starts the receive loop for the connection, ensuring that
    /// messages cannot arrive before the connection is registered.
    fn register_conn(&self, conn: Arc<Cnx>) -> Result<(), Error> {
        // Start the recv loop before registration
        conn.start_recv_loop()?;

        // Register the connection in the registry with Partial maturity
        // This will return an error if the registry is already at capacity (2 connections)
        lock!(self.connection_registry)
            .register(ConnectionKind::Partial(Arc::clone(&conn)))?;

        // Connection is now registered with the registry as the source of truth
        // No need to maintain a separate primary field
        Ok(())
    }

    /// Remove a connection from the registry
    fn unregister_conn(&self, conn_id: &ConnectionId) {
        // Remove from connection registry
        if let Some(conn_kind) = lock!(self.connection_registry).remove(conn_id)
        {
            // Extract the Arc from the ConnectionKind
            let conn = match conn_kind {
                ConnectionKind::Partial(c) => c,
                ConnectionKind::Full(pc) => pc.conn,
            };
            // Stop all running clocks to reduce unnecessary noise
            conn.clock().disable_all();
            // The recv loop JoinHandle is owned by the connection's recv_loop_state field,
            // so it will be cleaned up when the Arc<Cnx> is dropped
        }
    }

    /// Get a specific connection by ID
    fn get_conn(&self, conn_id: &ConnectionId) -> Option<Arc<Cnx>> {
        let registry = lock!(self.connection_registry);
        match &*registry {
            ConnectionRegistry::Empty => None,
            ConnectionRegistry::Single { active } => {
                if active.id() == *conn_id {
                    Some(Arc::clone(active.connection()))
                } else {
                    None
                }
            }
            ConnectionRegistry::Collision { first, second } => {
                if first.id() == *conn_id {
                    Some(Arc::clone(first.connection()))
                } else if second.id() == *conn_id {
                    Some(Arc::clone(second.connection()))
                } else {
                    None
                }
            }
        }
    }

    /// Validate that an event's connection ID matches the expected active connection.
    ///
    /// Returns `true` if the event is for the active connection. Unexpected connections
    /// (still in registry) are stopped with FsmError. Unknown connections (not in registry)
    /// are logged and ignored.
    ///
    /// # Arguments
    ///
    /// * `event_conn_id` - Connection ID from the FSM event
    /// * `active_conn` - Currently active connection
    /// * `event_title` - Event description for logging
    ///
    /// # Returns
    ///
    /// `true` if event should be processed, `false` if already handled
    fn validate_active_connection(
        &self,
        event_conn_id: &ConnectionId,
        active_conn: &Arc<Cnx>,
        event_title: &str,
    ) -> bool {
        if *event_conn_id == *active_conn.id() {
            return true;
        }

        match self.get_conn(event_conn_id) {
            Some(conn) => {
                // Unexpected: connection still in registry
                session_log!(
                    self,
                    warn,
                    active_conn,
                    "rx {} for unexpected connection (conn_id: {}), closing",
                    event_title,
                    event_conn_id.short();
                    "event" => event_title
                );
                self.stop(Some(&conn), None, StopReason::FsmError);
            }
            None => {
                // Unknown: connection not in registry
                session_log!(
                    self,
                    warn,
                    active_conn,
                    "rx {} for unknown connection (conn_id: {}), ignoring",
                    event_title,
                    event_conn_id.short();
                    "event" => event_title
                );
            }
        }

        false
    }

    /// Extract connection ID and additional context from FSM event
    fn extract_event_context(
        event: &FsmEvent<Cnx>,
    ) -> (FsmEventCategory, Option<ConnectionId>, Option<String>) {
        match event {
            FsmEvent::Admin(_) => (FsmEventCategory::Admin, None, None),
            FsmEvent::Connection(ce) => {
                let conn_id = match ce {
                    ConnectionEvent::Message { conn_id, msg } => {
                        let details = format!("received {}", msg.title());
                        return (
                            FsmEventCategory::Connection,
                            Some(*conn_id),
                            Some(details),
                        );
                    }
                    ConnectionEvent::ParseError { conn_id, error } => {
                        return (
                            FsmEventCategory::Connection,
                            Some(*conn_id),
                            Some(error.description()),
                        );
                    }
                    ConnectionEvent::HoldTimerExpires(id)
                    | ConnectionEvent::KeepaliveTimerExpires(id)
                    | ConnectionEvent::DelayOpenTimerExpires(id) => Some(*id),
                    ConnectionEvent::TcpConnectionFails(conn_id) => {
                        Some(*conn_id)
                    }
                };
                (FsmEventCategory::Connection, conn_id, None)
            }
            FsmEvent::Session(se) => {
                let (conn_id, details) = match se {
                    SessionEvent::TcpConnectionAcked(conn) => {
                        let details = format!("inbound from {}", conn.peer());
                        (Some(*conn.id()), Some(details))
                    }
                    SessionEvent::TcpConnectionConfirmed(conn) => {
                        let details = format!("outbound to {}", conn.peer());
                        (Some(*conn.id()), Some(details))
                    }
                    _ => (None, None),
                };
                (FsmEventCategory::Session, conn_id, details)
            }
        }
    }

    /// Create FSM event record from event
    fn create_event_record(
        &self,
        event: &FsmEvent<Cnx>,
        current_state: FsmStateKind,
        previous_state: Option<FsmStateKind>,
    ) -> FsmEventRecord {
        let (category, connection_id, details) =
            Self::extract_event_context(event);
        let event_type = event.title().to_string();

        FsmEventRecord {
            timestamp: chrono::Utc::now(),
            event_category: category,
            event_type,
            current_state,
            previous_state,
            connection_id,
            details,
        }
    }

    /// Determine if event is "major" (should be in major buffer)
    /// Major events: all admin events, new TCP connections, state transitions
    fn is_major_event(event: &FsmEvent<Cnx>) -> bool {
        match event {
            FsmEvent::Admin(_) => true, // All admin events are major
            FsmEvent::Session(se) => matches!(
                se,
                SessionEvent::TcpConnectionAcked(_)
                    | SessionEvent::TcpConnectionConfirmed(_)
            ),
            FsmEvent::Connection(_) => false, // Major only if causes state transition
        }
    }

    /// Record FSM event in history buffers
    fn record_fsm_event(
        &self,
        event: &FsmEvent<Cnx>,
        current_state: FsmStateKind,
        previous_state: Option<FsmStateKind>,
    ) {
        let record =
            self.create_event_record(event, current_state, previous_state);
        let is_major = Self::is_major_event(event) || previous_state.is_some();

        lock!(self.fsm_event_history).record(record, is_major);
    }

    /// Clean up all connections associated with this SessionRunner
    fn cleanup_connections(&self) {
        let mut registry = lock!(self.connection_registry);
        // Disable timers before dropping to ensure timers stop immediately
        for ck in registry.all_connections() {
            let conn = match ck {
                ConnectionKind::Partial(c) => c,
                ConnectionKind::Full(pc) => &pc.conn,
            };
            conn.clock().disable_all();
        }
        registry.clear();
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
        session_log_lite!(
            self,
            info,
            "starting peer state machine";
            "params" => format!("{:?}", lock!(self.session))
        );
        let mut current = FsmState::<Cnx>::Idle;

        loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                session_log_lite!(
                    self,
                    info,
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

                // Record state transition as a major event in FSM history
                let transition_record = FsmEventRecord {
                    timestamp: chrono::Utc::now(),
                    event_category: FsmEventCategory::StateTransition,
                    event_type: format!(
                        "{:?} -> {:?}",
                        previous,
                        current.kind()
                    ),
                    current_state: current.kind(),
                    previous_state: Some(previous),
                    connection_id: None,
                    details: Some("State transition".to_string()),
                };
                lock!(self.fsm_event_history).record_major(transition_record);

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
        let mut caps = BTreeSet::from([
            //Capability::EnhancedRouteRefresh{},
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
        if lock!(self.session).ipv4_unicast.is_some() {
            caps.insert(Capability::ipv4_unicast());
        }
        if lock!(self.session).ipv6_unicast.is_some() {
            caps.insert(Capability::ipv6_unicast());
        }
        *lock!(self.caps_tx) = caps;
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
        //
        // Note: There is no special handling here for the first trip through
        //       Idle. If IdleHoldTime is zero we move out of Idle without
        //       waiting for a ManualStart or Reset, else we wait for
        //       IdleHoldtimeExpires to pop before moving out of Idle.
        {
            let ihl = session_timer!(self, idle_hold);
            if ihl.interval.is_zero() {
                // IdleHoldTimer is not configured.
                // Immediately move into the next state.
                ihl.stop();
                drop(ihl);
                return self.transition_from_idle();
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

            let event = recv_event_loop!(self, self.event_rx, lite);

            // The only events we react to are ManualStart, Reset and
            // IdleHoldTimerExpires. ManualStart and Reset are explicit requests
            // to start the FSM, so we skip/disable DampPeerOscillation (by
            // ignoring/stopping the IdleHoldTimer) and move into the next FSM
            // state. Without an explicit Administrative command to start the
            // FSM, we will wait for the IdleHoldTimer to pop.
            match event {
                FsmEvent::Admin(admin_event) => match admin_event {
                    AdminEvent::ManualStart | AdminEvent::Reset => {
                        session_timer!(self, idle_hold).stop();

                        return self.transition_from_idle();
                    }

                    // We are already in Idle, so ManualStop is a no-op.
                    // The rest of the admin events are only relevant in Established
                    AdminEvent::ManualStop
                    | AdminEvent::Announce(_)
                    | AdminEvent::ShaperChanged(_)
                    | AdminEvent::ExportPolicyChanged(_)
                    | AdminEvent::CheckerChanged(_)
                    | AdminEvent::SendRouteRefresh(_)
                    | AdminEvent::ReAdvertiseRoutes(_) => {
                        let title = admin_event.title();
                        session_log_lite!(
                            self,
                            warn,
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
                        if !session_timer!(self, idle_hold).enabled() {
                            continue;
                        }

                        session_timer!(self, idle_hold).stop();
                        self.counters
                            .idle_hold_timer_expirations
                            .fetch_add(1, Ordering::Relaxed);

                        return self.transition_from_idle();
                    }

                    SessionEvent::TcpConnectionAcked(new)
                    | SessionEvent::TcpConnectionConfirmed(new) => {
                        match new.direction() {
                            ConnectionDirection::Inbound => {
                                session_log!(
                                    self,
                                    info,
                                    new,
                                    "inbound connection not allowed in idle (peer: {}, conn_id: {})",
                                    new.peer(),
                                    new.id().short()
                                );
                                self.counters
                                    .passive_connections_declined
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            ConnectionDirection::Outbound => {
                                session_log!(
                                    self,
                                    info,
                                    new,
                                    "outbound connection completed but not allowed in idle (peer: {}, conn_id: {})",
                                    new.peer(),
                                    new.id().short()
                                );
                                self.counters
                                    .active_connections_declined
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        // Silently drop the rejected connection without
                        // sending notification. RFC 4271 says Idle "refuses
                        // all incoming BGP connections" but doesn't mandate
                        // sending notifications. Sending Connection Rejected
                        // Notifications can contribute to death spirals when
                        // peers have unsynchronized startup timing. The peer
                        // will detect the connection closure via TCP/channel
                        // and handle it appropriately.

                        continue;
                    }

                    // RFC 4271 FSM Event 9
                    SessionEvent::ConnectRetryTimerExpires => {
                        if !session_timer!(self, connect_retry).enabled() {
                            continue;
                        }
                        session_log_lite!(
                            self,
                            warn,
                            "unexpected session fsm event {} not allowed in this state",
                            session_event.title();
                        );
                        session_timer!(self, connect_retry).disable();
                        continue;
                    }
                },

                /*
                 * Any other event (Events 9-12, 15-28) received in the Idle state
                 * does not cause change in the state of the local system.
                 */
                FsmEvent::Connection(connection_event) => {
                    // We should never hit this path, because we call
                    // cleanup_connections() before entering this loop. If we do hit
                    // it, then there is likely a bug in the cleanup or clock logic.
                    match connection_event {
                        // Events 10-12
                        ConnectionEvent::HoldTimerExpires(ref conn_id)
                        | ConnectionEvent::KeepaliveTimerExpires(ref conn_id)
                        | ConnectionEvent::DelayOpenTimerExpires(ref conn_id) =>
                        {
                            match self.get_conn(conn_id) {
                                Some(conn) => {
                                    session_log_lite!(
                                        self,
                                        warn,
                                        "unexpected connection fsm event {} for known but inactive conn (conn_id: {}), closing..",
                                        connection_event.title(),
                                        conn_id.short();
                                    );
                                    self.stop(
                                        Some(&conn),
                                        None,
                                        StopReason::FsmError,
                                    );
                                }
                                None => {
                                    session_log_lite!(
                                        self,
                                        warn,
                                        "unexpected connection fsm event {} for unknown conn (conn_id: {}), ignoring..",
                                        connection_event.title(),
                                        conn_id.short();
                                    );
                                }
                            }
                            continue;
                        }

                        ConnectionEvent::Message { msg, ref conn_id } => {
                            match self.get_conn(conn_id) {
                                Some(conn) => {
                                    session_log_lite!(
                                        self,
                                        warn,
                                        "unexpected {} message from known but inactive conn (conn_id: {}), closing..",
                                        msg.title(),
                                        conn_id.short();
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
                                    session_log_lite!(
                                        self,
                                        warn,
                                        "unexpected {} message from unknown conn (conn_id: {})",
                                        msg.title(),
                                        conn_id.short();
                                        "message" => msg.title(),
                                        "message_contents" => format!("{msg}")
                                    );
                                }
                            }
                            self.bump_msg_counter(msg.kind(), true);
                            continue;
                        }

                        ConnectionEvent::TcpConnectionFails(ref conn_id)
                        | ConnectionEvent::ParseError { ref conn_id, .. } => {
                            // Idle doesn't own a connection, so this can't be
                            // related to the current FSM. Log and ignore.
                            session_log_lite!(
                                self,
                                debug,
                                "{} (conn_id: {}) in Idle state, ignoring",
                                connection_event.title(),
                                conn_id.short()
                            );
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
    /// A non-passive peer only moves from Connect into Active if a connection
    /// fails while DelayOpenTimer is running. So we would not expect to see a
    /// non-passive peer in Active until after DelayOpen is implemented.
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

            let event = recv_event_loop!(self, self.event_rx, lite);

            match event {
                FsmEvent::Admin(admin_event) => match admin_event {
                    AdminEvent::ManualStop => {
                        session_log_lite!(
                            self,
                            info,
                            "rx {}, fsm transition to idle",
                            admin_event.title()
                        );
                        self.stop(None, None, StopReason::Shutdown);
                        return FsmState::Idle;
                    }

                    AdminEvent::Reset => {
                        session_log_lite!(
                            self,
                            info,
                            "rx {}, fsm transition to idle",
                            admin_event.title()
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
                    | AdminEvent::SendRouteRefresh(_)
                    | AdminEvent::ReAdvertiseRoutes(_) => {
                        let title = admin_event.title();
                        session_log_lite!(
                            self,
                            warn,
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
                            if !session_timer!(self, connect_retry).enabled() {
                                continue;
                            }
                            self.counters
                                .connection_retries
                                .fetch_add(1, Ordering::Relaxed);

                            // Initiate connection, which properly handles thread lifecycle
                            let timeout = connect_timeout!(self);
                            self.initiate_connection(timeout);

                            session_timer!(self, connect_retry).restart();
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
                         */
                        SessionEvent::TcpConnectionAcked(accepted)
                        | SessionEvent::TcpConnectionConfirmed(accepted) => {
                            let accepted = Arc::new(accepted);
                            session_log!(
                                self,
                                info,
                                &accepted,
                                "accepted {} connection from {}",
                                accepted.direction(),
                                accepted.peer()
                            );
                            match accepted.direction() {
                                ConnectionDirection::Inbound => {
                                    self.counters
                                        .passive_connections_accepted
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                ConnectionDirection::Outbound => {
                                    self.counters
                                        .active_connections_accepted
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }

                            // DelayOpen can be configured for a peer, but its functionality
                            // is not implemented.  Follow DelayOpen == false instructions.

                            session_timer!(self, connect_retry).stop();

                            if let Err(e) = self.send_open(&accepted) {
                                session_log!(
                                    self,
                                    error,
                                    &accepted,
                                    "failed to send open, fsm transition to idle";
                                    "error" => format!("{e}")
                                );
                                return FsmState::Idle;
                            }

                            if let Err(e) =
                                self.register_conn(Arc::clone(&accepted))
                            {
                                session_log!(
                                    self,
                                    error,
                                    &accepted,
                                    "failed to register connection, fsm transition to idle";
                                    "error" => format!("{e}")
                                );
                                return FsmState::Idle;
                            }

                            conn_timer!(&accepted, hold).restart();

                            return FsmState::OpenSent(accepted);
                        }

                        // RFC 4271 FSM Event 13
                        SessionEvent::IdleHoldTimerExpires => {
                            if !session_timer!(self, idle_hold).enabled() {
                                continue;
                            }
                            session_timer!(self, idle_hold).stop();
                            session_log_lite!(
                                self,
                                warn,
                                "BUG: {} event not expected in this state, ignoring",
                                session_event.title()
                            );
                            continue;
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
                        // A new connection arrives via TcpConnectionAcked
                        // or TcpConnectionConfirmed without its recv loop
                        // running, i.e. no inbound messages are read from the
                        // connection until the recv loop thread is started by
                        // register_conn(). Since we don't read from the event
                        // queue between registering a new connection and moving
                        // into OpenSent (upon Open send success) or Idle (upon
                        // Open send error), there isn't a chance for Messages
                        // from a new connection to be read while in Connect.
                        //
                        // If/when we implement DelayOpen, this is where we
                        // need to handle Open messages while DelayOpenTimer is
                        // running (enabled && !expired). We'll also need to
                        // hang onto the new connection between new connection
                        // and DelayOpenExpires events.
                        //
                        // Note: Connection ID validation is not performed here
                        // because we don't expect Messages for any connections,
                        // so we always transition to Idle on any message. When
                        // DelayOpen is added, we'll need to validate conn_id
                        // against the connection before processing it.
                        ConnectionEvent::Message { msg, ref conn_id } => {
                            let title = msg.title();

                            if let Message::Notification(ref n) = msg {
                                session_log_lite!(
                                    self,
                                    warn,
                                    "rx {title} message (conn_id: {}), fsm transition to idle",
                                    conn_id.short();
                                    "message" => title,
                                    "message_contents" => format!("{n}")
                                );
                                self.bump_msg_counter(msg.kind(), false);
                            } else {
                                session_log_lite!(
                                    self,
                                    warn,
                                    "rx unexpected {title} message (conn_id: {}), fsm transition to idle",
                                    conn_id.short();
                                    "message" => msg.title(),
                                    "message_contents" => format!("{msg}")
                                );
                                self.bump_msg_counter(msg.kind(), true);
                            }

                            session_timer!(self, connect_retry).stop();
                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);

                            return FsmState::Idle;
                        }

                        // Events 8 (AutomaticStop, unused), 10-11, 13
                        ConnectionEvent::HoldTimerExpires(ref conn_id)
                        | ConnectionEvent::KeepaliveTimerExpires(ref conn_id)
                        | ConnectionEvent::DelayOpenTimerExpires(ref conn_id) =>
                        {
                            // Stop the specific timer that fired
                            if let Some(conn) = self.get_conn(conn_id) {
                                match connection_event {
                                    ConnectionEvent::HoldTimerExpires(_) => {
                                        conn_timer!(conn, hold).stop();
                                    }
                                    ConnectionEvent::KeepaliveTimerExpires(
                                        _,
                                    ) => {
                                        conn_timer!(conn, keepalive).stop();
                                    }
                                    ConnectionEvent::DelayOpenTimerExpires(
                                        _,
                                    ) => {
                                        conn_timer!(conn, delay_open).stop();
                                    }
                                    _ => {}
                                }
                            }

                            session_log_lite!(
                                self,
                                warn,
                                "BUG: connection fsm event {title} (conn_id {}) not expected in this state, ignoring",
                                conn_id.short()
                            );

                            continue;
                        }

                        ConnectionEvent::TcpConnectionFails(ref conn_id)
                        | ConnectionEvent::ParseError { ref conn_id, .. } => {
                            // Connect doesn't own a connection, so this can't
                            // be related to the current FSM. Log and ignore.
                            // Note: If we add support for DelayOpen, we could
                            //       own a BgpConnection while DelayOpenTimer is
                            //       running. This would need to be updated to
                            //       do conn_id validation.
                            session_log_lite!(
                                self,
                                debug,
                                "{} (conn_id: {}) in Connect state, ignoring",
                                connection_event.title(),
                                conn_id.short()
                            );
                            continue;
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

            let event = recv_event_loop!(self, self.event_rx, lite);

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
                        session_log_lite!(
                            self,
                            info,
                            "rx {}, fsm transition to idle",
                            admin_event.title()
                        );
                        self.stop(None, None, StopReason::Shutdown);
                        return FsmState::Idle;
                    }

                    AdminEvent::Reset => {
                        session_log_lite!(
                            self,
                            info,
                            "rx {}, fsm transition to idle",
                            admin_event.title()
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
                    | AdminEvent::SendRouteRefresh(_)
                    | AdminEvent::ReAdvertiseRoutes(_) => {
                        let title = admin_event.title();
                        session_log_lite!(
                            self,
                            warn,
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
                        // This is unexpected since DelayOpen isn't implemented.
                        //
                        // A new connection arrives via TcpConnectionAcked
                        // or TcpConnectionConfirmed without its recv loop
                        // running, i.e. no inbound messages are read from the
                        // connection until the recv loop thread is started by
                        // register_conn(). Since we don't read from the event
                        // queue between registering a new connection and moving
                        // into OpenSent (upon Open send success) or Idle (upon
                        // Open send error), there isn't a chance for Messages
                        // from a new connection to be read while in Connect.
                        //
                        // If/when we implement DelayOpen, this is where we
                        // need to handle Open messages while DelayOpenTimer
                        // is running (enabled && !expired). We'll also need to
                        // hang onto the new connection between new connection
                        // and DelayOpenExpires events.
                        //
                        // Note: Connection ID validation is not performed here
                        // because we don't expect Messages for any connections,
                        // so we always transition to Idle on any message. When
                        // DelayOpen is added, we'll need to validate conn_id
                        // against the connection before processing it.
                        ConnectionEvent::Message { msg, ref conn_id } => {
                            let title = msg.title();

                            if let Message::Notification(ref n) = msg {
                                session_log_lite!(
                                    self,
                                    warn,
                                    "rx {title} message (conn_id: {}), fsm transition to idle",
                                    conn_id.short();
                                    "message" => title,
                                    "message_contents" => format!("{n}")
                                );
                                self.bump_msg_counter(msg.kind(), false);
                            } else {
                                session_log_lite!(
                                    self,
                                    warn,
                                    "rx unexpected {title} message (conn_id: {}), fsm transition to idle",
                                    conn_id.short();
                                    "message" => msg.title(),
                                    "message_contents" => format!("{msg}")
                                );
                                self.bump_msg_counter(msg.kind(), true);
                            }

                            session_timer!(self, connect_retry).stop();
                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);
                            self.counters
                                .connection_retries
                                .fetch_add(1, Ordering::Relaxed);

                            return FsmState::Idle;
                        }

                        // Events 8 (Automatic Stop), 10, 13
                        ConnectionEvent::HoldTimerExpires(ref conn_id) => {
                            let Some(conn) = self.get_conn(conn_id) else {
                                continue;
                            };
                            if !conn_timer!(conn, hold).enabled() {
                                continue;
                            }
                            conn_timer!(conn, hold).stop();

                            session_log_lite!(
                                self,
                                warn,
                                "BUG: rx connection fsm event {} (conn_id: {}), not expected in this state, ignoring",
                                connection_event.title(),
                                conn_id.short()
                            );

                            continue;
                        }

                        // RFC 4271 FSM Event 11
                        ConnectionEvent::KeepaliveTimerExpires(ref conn_id) => {
                            let Some(conn) = self.get_conn(conn_id) else {
                                continue;
                            };
                            if !conn_timer!(conn, keepalive).enabled() {
                                continue;
                            }
                            conn_timer!(conn, keepalive).stop();

                            session_log_lite!(
                                self,
                                warn,
                                "BUG: rx connection fsm event {} (conn_id: {}), not expected in this state, ignoring",
                                connection_event.title(),
                                conn_id.short()
                            );

                            continue;
                        }

                        ConnectionEvent::DelayOpenTimerExpires(ref conn_id) => {
                            if let Some(conn) = self.get_conn(conn_id)
                                && !conn_timer!(conn, delay_open).enabled()
                            {
                                continue;
                            }
                            session_log_lite!(
                                self,
                                warn,
                                "rx connection fsm event {} (conn_id: {}), but not allowed in this state. ignoring..",
                                connection_event.title(),
                                conn_id.short()
                            );

                            continue;
                        }

                        ConnectionEvent::TcpConnectionFails(ref conn_id)
                        | ConnectionEvent::ParseError { ref conn_id, .. } => {
                            // Active doesn't own a connection, so this can't
                            // be related to the current FSM. Log and ignore.
                            // Note: If we add support for DelayOpen, we could
                            //       own a BgpConnection while DelayOpenTimer is
                            //       running. This would need to be updated to
                            //       do conn_id validation.
                            session_log_lite!(
                                self,
                                debug,
                                "{} (conn_id: {}) in Active state, ignoring",
                                connection_event.title(),
                                conn_id.short()
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
                        if !session_timer!(self, connect_retry).enabled() {
                            continue;
                        }
                        // RFC 4271 says that in Idle the FSM should restart the
                        // ConnectRetryTimer "In response to a
                        // ManualStart_with_PassiveTcpEstablishment event" even
                        // though it also says that in Active the FSM should
                        // react to a ConnectRetryTimerExpires event by
                        // transitioning to Connect and attempting a new
                        // outbound TCP session, which is exactly the opposite
                        // of what you want to do for a passive peer.
                        if lock!(self.session).passive_tcp_establishment {
                            session_log_lite!(
                                self,
                                info,
                                "rx {} but peer is configured as passive, staying in active",
                                session_event.title()
                            );
                            session_timer!(self, connect_retry).stop();
                            continue;
                        }

                        session_log_lite!(
                            self,
                            info,
                            "rx {}, fsm transition to connect",
                            session_event.title()
                        );

                        self.counters
                            .connection_retries
                            .fetch_add(1, Ordering::Relaxed);
                        session_timer!(self, connect_retry).restart();

                        return FsmState::Connect;
                    }

                    // The Dispatcher has accepted a TCP connection initiated by
                    // the peer.
                    SessionEvent::TcpConnectionAcked(accepted) => {
                        let accepted = Arc::new(accepted);
                        session_log!(
                            self,
                            info,
                            &accepted,
                            "accepted inbound connection from {}",
                            accepted.peer()
                        );

                        self.counters
                            .passive_connections_accepted
                            .fetch_add(1, Ordering::Relaxed);

                        session_timer!(self, connect_retry).stop();

                        if let Err(e) = self.send_open(&accepted) {
                            session_log!(
                                self,
                                error,
                                &accepted,
                                "failed to send open, fsm transition to idle";
                                "error" => format!("{e}")
                            );
                            return FsmState::Idle;
                        }

                        if let Err(e) =
                            self.register_conn(Arc::clone(&accepted))
                        {
                            session_log!(
                                self,
                                error,
                                &accepted,
                                "failed to register connection, fsm transition to idle";
                                "error" => format!("{e}")
                            );
                            return FsmState::Idle;
                        }

                        conn_timer!(&accepted, hold).restart();

                        return FsmState::OpenSent(accepted);
                    }

                    // An outbound connection we initiated has been accepted by
                    // the peer. Outbound connections aren't allowed in Active
                    // state, so this shouldn't happen. However, if it does then
                    // it's likely a timing thing as a result of improper
                    // Connector handling (not dropping the TcpStream).
                    SessionEvent::TcpConnectionConfirmed(confirmed) => {
                        session_log!(
                            self,
                            info,
                            confirmed,
                            "outbound connection to peer {} (conn_id: {}) accepted, but not allowed in {}",
                            confirmed.peer(),
                            confirmed.id().short(),
                            self.state()
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
                        if !session_timer!(self, idle_hold).enabled() {
                            continue;
                        }
                        session_log_lite!(
                            self,
                            warn,
                            "rx session fsm event {}, but not allowed in {}. ignoring..",
                            session_event.title(),
                            self.state()
                        );
                        continue;
                    }
                },
            };
        }
    }

    /// Waiting for open message from peer.
    fn fsm_open_sent(&self, conn: Arc<Cnx>) -> FsmState<Cnx> {
        let om = loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                return FsmState::Idle;
            }

            let event = recv_event_loop!(self, self.event_rx, conn, conn);

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
                        session_log!(
                            self,
                            info,
                            conn,
                            "rx {}, fsm transition to idle",
                            admin_event.title()
                        );
                        self.stop(Some(&conn), None, StopReason::Shutdown);
                        return FsmState::Idle;
                    }

                    // Follow ManualStop logic, but with the appropriate ErrorSubcode
                    AdminEvent::Reset => {
                        session_log!(
                            self,
                            info,
                            conn,
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
                    | AdminEvent::SendRouteRefresh(_)
                    | AdminEvent::ReAdvertiseRoutes(_) => {
                        let title = admin_event.title();
                        session_log!(
                            self,
                            warn,
                            conn,
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
                    // RFC 4271 FSM Event 9
                    SessionEvent::ConnectRetryTimerExpires => {
                        if !session_timer!(self, connect_retry).enabled() {
                            continue;
                        }
                        session_timer!(self, connect_retry).stop();
                        let title = session_event.title();
                        session_log!(
                            self,
                            warn,
                            conn,
                            "BUG: {title} event not expected in this state (conn_id: {}), ignoring",
                            conn.id().short();
                            "event" => title
                        );
                        continue;
                    }

                    // RFC 4271 FSM Event 13
                    SessionEvent::IdleHoldTimerExpires => {
                        if !session_timer!(self, idle_hold).enabled() {
                            continue;
                        }
                        session_timer!(self, idle_hold).stop();
                        let title = session_event.title();
                        session_log!(
                            self,
                            warn,
                            conn,
                            "BUG: {title} event not expected in this state (conn_id: {}), ignoring",
                            conn.id().short();
                            "event" => title
                        );
                        continue;
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
                        let new = Arc::new(new);
                        let new_direction = new.direction();
                        if new_direction == conn.direction() {
                            collision_log!(
                                self,
                                error,
                                &new,
                                &conn,
                                "rejected new {new_direction} connection ({}): multiple {new_direction} connections not allowed",
                                new.id().short()
                            );
                            continue;
                        }

                        collision_log!(
                            self,
                            info,
                            &new,
                            &conn,
                            "collision detected: new {new_direction} connection from {} (conn_id: {})",
                            new.peer(),
                            new.id().short()
                        );

                        match new_direction {
                            ConnectionDirection::Inbound => {
                                self.counters
                                    .passive_connections_accepted
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            ConnectionDirection::Outbound => {
                                self.counters
                                    .active_connections_accepted
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        if let Err(e) = self.send_open(&new) {
                            collision_log!(
                                self,
                                error,
                                &new,
                                &conn,
                                "error sending open to new conn, continue with open conn";
                                "error" => format!("{e}")
                            );
                            // Stop the new connection since it failed to
                            // send Open. This unregisters the connection
                            // and prevents future attempts to send on the
                            // already-closed connection.
                            self.stop(Some(&new), None, StopReason::IoError);
                            continue;
                        }

                        if let Err(e) = self.register_conn(Arc::clone(&new)) {
                            collision_log!(
                                self,
                                error,
                                &new,
                                &conn,
                                "failed to register new connection in collision, stopping new conn";
                                "error" => format!("{e}")
                            );
                            self.stop(Some(&new), None, StopReason::IoError);
                            continue;
                        }

                        conn_timer!(&new, hold).restart();

                        return FsmState::ConnectionCollision(
                            CollisionPair::OpenSent(conn, new),
                        );
                    }
                },

                FsmEvent::Connection(connection_event) => {
                    match connection_event {
                        ConnectionEvent::Message { msg, ref conn_id } => {
                            if !self.validate_active_connection(
                                conn_id,
                                &conn,
                                msg.title(),
                            ) {
                                continue;
                            }

                            // RFC 4271 FSM Event 19
                            if let Message::Open(om) = msg {
                                lock!(self.message_history)
                                    .receive(om.clone().into(), *conn_id);
                                self.counters
                                    .opens_received
                                    .fetch_add(1, Ordering::Relaxed);
                                break om;
                            }

                            session_timer!(self, connect_retry).stop();
                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);

                            session_log!(
                                self,
                                warn,
                                conn,
                                "rx unexpected {} message (conn_id: {}), fsm transition to idle",
                                msg.title(),
                                conn_id.short();
                                "message" => msg.title(),
                                "message_contents" => format!("{msg}")
                            );
                            self.bump_msg_counter(msg.kind(), true);
                            self.stop(Some(&conn), None, StopReason::FsmError);

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
                            if !conn_timer!(conn, hold).enabled() {
                                continue;
                            }
                            let title = connection_event.title();
                            match self.get_conn(conn_id) {
                                Some(connection) => {
                                    if connection.id() == conn.id() {
                                        session_log!(
                                            self,
                                            warn,
                                            conn,
                                            "rx {title} (conn_id: {}), fsm transition to idle",
                                            conn_id.short();
                                            "event" => title
                                        );
                                    } else {
                                        session_log!(
                                            self,
                                            warn,
                                            conn,
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
                                }
                                None => {
                                    session_log!(
                                        self,
                                        warn,
                                        conn,
                                        "rx {title} for unknown connection (conn_id: {}), ignoring..",
                                        conn_id.short();
                                    );
                                    continue;
                                }
                            };
                            self.counters
                                .hold_timer_expirations
                                .fetch_add(1, Ordering::Relaxed);
                            self.stop(
                                Some(&conn),
                                None,
                                StopReason::HoldTimeExpired,
                            );
                            return FsmState::Idle;
                        }

                        // RFC 4271 FSM Event 11
                        ConnectionEvent::KeepaliveTimerExpires(ref conn_id) => {
                            if !conn_timer!(conn, keepalive).enabled() {
                                continue;
                            }
                            let title = connection_event.title();
                            match self.get_conn(conn_id) {
                                Some(connection) => {
                                    if connection.id() == conn.id() {
                                        session_log!(
                                            self,
                                            warn,
                                            conn,
                                            "rx {title} (conn_id: {}) but event not allowed in this state, fsm transition to idle",
                                            conn_id.short();
                                            "event" => title
                                        );
                                    } else {
                                        session_log!(
                                            self,
                                            warn,
                                            conn,
                                            "rx {title} for known connection (conn_id: {}) that's unexpected in this state? closing conn",
                                            conn_id.short()
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

                        // RFC 4271 FSM Event 12
                        ConnectionEvent::DelayOpenTimerExpires(ref conn_id) => {
                            if !conn_timer!(conn, delay_open).enabled() {
                                continue;
                            }
                            let title = connection_event.title();
                            match self.get_conn(conn_id) {
                                Some(connection) => {
                                    if connection.id() == conn.id() {
                                        session_log!(
                                            self,
                                            warn,
                                            conn,
                                            "rx {title} (conn_id: {}) but event not allowed in this state, fsm transition to idle",
                                            conn_id.short();
                                            "event" => title
                                        );
                                    } else {
                                        session_log!(
                                            self,
                                            warn,
                                            conn,
                                            "rx {title} for known connection (conn_id: {}) that's unexpected in this state? closing conn",
                                            conn_id.short()
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
                                    session_log!(
                                        self,
                                        warn,
                                        conn,
                                        "rx {title} for unknown connection (conn_id: {}), ignoring..",
                                        conn_id.short()
                                    );
                                    continue;
                                }
                            };
                            self.stop(Some(&conn), None, StopReason::FsmError);
                            return FsmState::Idle;
                        }

                        ConnectionEvent::ParseError {
                            ref conn_id,
                            ref error,
                        } => {
                            if !self.validate_active_connection(
                                conn_id,
                                &conn,
                                connection_event.title(),
                            ) {
                                continue;
                            }

                            // In OpenSent state, all parse errors are fatal.
                            // We haven't completed the handshake yet.
                            let (error_code, error_subcode) =
                                error.error_codes();
                            session_log!(
                                self,
                                warn,
                                conn,
                                "rx {} (conn_id: {}): {}, fsm transition to idle",
                                connection_event.title(), conn_id.short(), error;
                                "error_code" => format!("{error_code:?}"),
                                "error_subcode" => format!("{error_subcode:?}")
                            );
                            let stop_reason = StopReason::ParseError {
                                error_code,
                                error_subcode,
                            };

                            session_timer!(self, connect_retry).stop();
                            self.connect_retry_counter
                                .fetch_add(1, Ordering::Relaxed);
                            self.stop(Some(&conn), None, stop_reason);

                            return FsmState::Idle;
                        }

                        ConnectionEvent::TcpConnectionFails(ref conn_id) => {
                            if !self.validate_active_connection(
                                conn_id,
                                &conn,
                                connection_event.title(),
                            ) {
                                continue;
                            }

                            session_log!(
                                self,
                                warn,
                                conn,
                                "rx {} (conn_id: {}), fsm transition to idle",
                                connection_event.title(), conn_id.short();
                            );
                            self.stop(Some(&conn), None, StopReason::IoError);
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
                    session_log!(
                        self,
                        info,
                        conn,
                        "policy check failed";
                        "error" => format!("{e}")
                    );
                }
                e => {
                    session_log!(
                        self,
                        warn,
                        conn,
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

        session_timer!(self, connect_retry).stop();
        conn_timer!(conn, keepalive).restart();
        // hold_timer set in handle_open(), enable it here
        conn_timer!(conn, hold).enable();

        let caps = om.get_capabilities();
        let (ipv4_unicast, ipv6_unicast) = active_afi!(self, caps);

        let pc = PeerConnection {
            conn,
            id: om.id,
            asn: om.asn(),
            caps,
            ipv4_unicast,
            ipv6_unicast,
        };

        // Upgrade this connection from Partial to Full in the registry
        lock!(self.connection_registry).upgrade_to_full(pc.clone());

        FsmState::OpenConfirm(pc)
    }

    /// Waiting for keepalive or notification from peer.
    fn fsm_open_confirm(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        // Check to see if a shutdown has been requested.
        if self.shutdown.load(Ordering::Acquire) {
            return FsmState::Idle;
        }

        let event = recv_event_return!(
            self,
            self.event_rx,
            FsmState::OpenConfirm(pc),
            pc.conn
        );

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
                    session_log!(
                        self,
                        info,
                        pc.conn,
                        "rx {}, fsm transition to idle",
                        admin_event.title();
                    );
                    self.stop(Some(&pc.conn), None, StopReason::Shutdown);
                    FsmState::Idle
                }

                // Follow ManualStop logic, but with the appropriate ErrorSubcode
                AdminEvent::Reset => {
                    session_log!(
                        self,
                        info,
                        pc.conn,
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
                | AdminEvent::SendRouteRefresh(_)
                | AdminEvent::ReAdvertiseRoutes(_) => {
                    let title = admin_event.title();
                    session_log!(
                        self,
                        warn,
                        pc.conn,
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
                    if !self.validate_active_connection(
                        conn_id,
                        &pc.conn,
                        "hold timer expires",
                    ) {
                        return FsmState::OpenConfirm(pc);
                    }

                    if !conn_timer!(pc.conn, hold).enabled() {
                        return FsmState::OpenConfirm(pc);
                    }

                    session_log!(
                        self,
                        warn,
                        pc.conn,
                        "hold timer expired, fsm transition to idle"
                    );
                    self.stop(
                        Some(&pc.conn),
                        None,
                        StopReason::HoldTimeExpired,
                    );
                    FsmState::Idle
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
                    if !self.validate_active_connection(
                        conn_id,
                        &pc.conn,
                        "keepalive timer expires",
                    ) {
                        return FsmState::OpenConfirm(pc);
                    }

                    if !conn_timer!(pc.conn, keepalive).enabled() {
                        return FsmState::OpenConfirm(pc);
                    }

                    session_log!(
                        self,
                        info,
                        pc.conn,
                        "keepalive timer expired, generate keepalive"
                    );
                    self.send_keepalive(&pc.conn);
                    conn_timer!(pc.conn, keepalive).restart();
                    FsmState::OpenConfirm(pc)
                }

                // RFC 4271 FSM Event 12
                ConnectionEvent::DelayOpenTimerExpires(ref conn_id) => {
                    if !self.validate_active_connection(
                        conn_id,
                        &pc.conn,
                        "delay open timer expires",
                    ) {
                        return FsmState::OpenConfirm(pc);
                    }

                    if !conn_timer!(pc.conn, delay_open).enabled() {
                        return FsmState::OpenConfirm(pc);
                    }

                    session_log!(
                        self,
                        warn,
                        pc.conn,
                        "delay open timer expires event not allowed in this state, fsm transition to idle"
                    );
                    self.stop(Some(&pc.conn), None, StopReason::FsmError);
                    FsmState::Idle
                }

                ConnectionEvent::Message { msg, conn_id } => {
                    if !self.validate_active_connection(
                        &conn_id,
                        &pc.conn,
                        msg.title(),
                    ) {
                        self.bump_msg_counter(msg.kind(), true);
                        return FsmState::OpenConfirm(pc);
                    }

                    lock!(self.message_history).receive(msg.clone(), conn_id);

                    // The peer has ACK'd our open message with a keepalive. Start the
                    // session timers and enter session setup.
                    if let Message::KeepAlive = msg {
                        conn_timer!(pc.conn, hold).restart();
                        conn_timer!(pc.conn, keepalive).restart();
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
                        session_log!(
                            self,
                            warn,
                            pc.conn,
                            "unexpected {} received (conn_id: {}), fsm transition to idle",
                            msg.title(),
                            conn_id.short();
                            "message" => "notification",
                            "message_contents" => format!("{msg}")
                        );
                        self.bump_msg_counter(msg.kind(), true);
                        session_timer!(self, connect_retry).stop();
                        FsmState::Idle
                    }
                }

                ConnectionEvent::ParseError {
                    ref conn_id,
                    ref error,
                } => {
                    if !self.validate_active_connection(
                        conn_id,
                        &pc.conn,
                        connection_event.title(),
                    ) {
                        return FsmState::OpenConfirm(pc);
                    }

                    // In OpenConfirm state, all parse errors are fatal.
                    // We haven't completed the handshake yet.
                    let (error_code, error_subcode) = error.error_codes();
                    session_log!(
                        self,
                        warn,
                        pc.conn,
                        "rx {} (conn_id: {}): {}, fsm transition to idle",
                        connection_event.title(), conn_id.short(), error;
                        "error_code" => format!("{error_code:?}"),
                        "error_subcode" => format!("{error_subcode:?}")
                    );
                    let stop_reason = StopReason::ParseError {
                        error_code,
                        error_subcode,
                    };

                    session_timer!(self, connect_retry).stop();
                    self.stop(Some(&pc.conn), None, stop_reason);
                    FsmState::Idle
                }

                ConnectionEvent::TcpConnectionFails(ref conn_id) => {
                    if !self.validate_active_connection(
                        conn_id,
                        &pc.conn,
                        connection_event.title(),
                    ) {
                        return FsmState::OpenConfirm(pc);
                    }

                    session_log!(
                        self,
                        warn,
                        pc.conn,
                        "rx {} (conn_id: {}), fsm transition to idle",
                        connection_event.title(), conn_id.short();
                    );
                    self.stop(Some(&pc.conn), None, StopReason::IoError);
                    FsmState::Idle
                }
            },

            FsmEvent::Session(session_event) => match session_event {
                // RFC 4271 FSM Event 9
                SessionEvent::ConnectRetryTimerExpires => {
                    if !session_timer!(self, connect_retry).enabled() {
                        return FsmState::OpenConfirm(pc);
                    }
                    session_timer!(self, connect_retry).stop();
                    let title = session_event.title();
                    session_log!(
                        self,
                        warn,
                        pc.conn,
                        "BUG: {title} event not expected in this state (conn_id: {}), ignoring",
                        pc.conn.id().short();
                        "event" => title
                    );
                    FsmState::OpenConfirm(pc)
                }

                // RFC 4271 FSM Event 13
                SessionEvent::IdleHoldTimerExpires => {
                    if !session_timer!(self, idle_hold).enabled() {
                        return FsmState::OpenConfirm(pc);
                    }
                    session_timer!(self, idle_hold).stop();
                    let title = session_event.title();
                    session_log!(
                        self,
                        warn,
                        pc.conn,
                        "BUG: {title} event not expected in this state (conn_id: {}), ignoring",
                        pc.conn.id().short();
                        "event" => title
                    );
                    FsmState::OpenConfirm(pc)
                }

                /*
                 * In the event of a TcpConnection_Valid event (Event 14), or the
                 * success of a TCP connection (Event 16 or Event 17) while in
                 * OpenConfirm, the local system needs to track the second
                 * connection.
                 */
                SessionEvent::TcpConnectionAcked(new)
                | SessionEvent::TcpConnectionConfirmed(new) => {
                    let new = Arc::new(new);
                    let new_direction = new.direction();
                    if new_direction == pc.conn.direction() {
                        collision_log!(
                            self,
                            error,
                            &new,
                            &pc.conn,
                            "rejected new {new_direction} connection ({}): multiple {new_direction} connections not allowed",
                            new.id().short()
                        );
                        return FsmState::OpenConfirm(pc);
                    }

                    match new_direction {
                        ConnectionDirection::Inbound => {
                            collision_log!(
                                self,
                                info,
                                &new,
                                &pc.conn,
                                "collision detected: new inbound connection from {} (conn_id: {})",
                                new.peer(),
                                new.id().short()
                            );
                            self.counters
                                .passive_connections_accepted
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        ConnectionDirection::Outbound => {
                            collision_log!(
                                self,
                                info,
                                &new,
                                &pc.conn,
                                "collision detected: outbound connection to {} (conn_id: {}) completed",
                                new.peer(),
                                new.id().short()
                            );
                            self.counters
                                .active_connections_accepted
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    if let Err(e) = self.send_open(&new) {
                        collision_log!(self, error, &new, &pc.conn,
                            "error sending open to new conn, continue with open conn";
                            "error" => format!("{e}")
                        );
                        // Stop the new connection since it failed to send Open.
                        // This unregisters the connection and prevents future
                        // attempts to send on the already-closed connection.
                        self.stop(Some(&new), None, StopReason::IoError);
                        return FsmState::OpenConfirm(pc);
                    }

                    if let Err(e) = self.register_conn(Arc::clone(&new)) {
                        collision_log!(
                            self,
                            error,
                            &new,
                            &pc.conn,
                            "failed to register new connection in collision, stopping new conn";
                            "error" => format!("{e}")
                        );
                        self.stop(Some(&new), None, StopReason::IoError);
                        return FsmState::OpenConfirm(pc);
                    }

                    conn_timer!(&new, hold).restart();

                    FsmState::ConnectionCollision(CollisionPair::OpenConfirm(
                        pc, new,
                    ))
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
                collision_log!(
                    self,
                    info,
                    new,
                    exist.conn,
                    "collision detected: new connection [{:?}, conn_id: {}], existing connection [{:?}, conn_id: {}]",
                    new.conn(),
                    new.id().short(),
                    exist.conn.conn(),
                    exist.conn.id().short()
                );
                self.connection_collision_open_confirm(exist, new)
            }
            CollisionPair::OpenSent(exist, new) => {
                collision_log!(
                    self,
                    info,
                    new,
                    exist,
                    "collision detected: new connection [{:?}, conn_id: {}], existing connection [{:?}, conn_id: {}]",
                    new.conn(),
                    new.id().short(),
                    exist.conn(),
                    exist.id().short()
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
        new: Arc<Cnx>,
    ) -> FsmState<Cnx> {
        let om = loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                return FsmState::Idle;
            }

            let event = recv_event_loop!(
                self,
                self.event_rx,
                collision,
                new,
                exist.conn
            );

            match event {
                FsmEvent::Admin(admin_event) => match admin_event {
                    AdminEvent::ManualStop => {
                        collision_log!(
                            self,
                            info,
                            new,
                            exist.conn,
                            "rx manual stop, fsm transition to idle"
                        );
                        self.stop(
                            Some(&new),
                            Some(&exist.conn),
                            StopReason::Shutdown,
                        );
                        return FsmState::Idle;
                    }

                    AdminEvent::Reset => {
                        collision_log!(
                            self,
                            info,
                            new,
                            exist.conn,
                            "rx fsm reset, fsm transition to idle"
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
                    | AdminEvent::SendRouteRefresh(_)
                    | AdminEvent::ReAdvertiseRoutes(_) => {
                        let title = admin_event.title();
                        collision_log!(
                            self,
                            warn,
                            new,
                            exist.conn,
                            "unexpected admin fsm event {title}, ignoring";
                            "event" => title
                        );
                        continue;
                    }
                },

                FsmEvent::Session(session_event) => match session_event {
                    // RFC 4271 FSM Event 9
                    SessionEvent::ConnectRetryTimerExpires => {
                        if !session_timer!(self, connect_retry).enabled() {
                            continue;
                        }
                        session_timer!(self, connect_retry).stop();
                        let title = session_event.title();
                        collision_log!(
                            self,
                            warn,
                            new,
                            exist.conn,
                            "BUG: {title} event not expected in this state (exist_conn_id: {}, new_conn_id: {}), ignoring",
                            exist.conn.id().short(),
                            new.id().short();
                            "event" => title
                        );
                        continue;
                    }

                    // RFC 4271 FSM Event 13
                    SessionEvent::IdleHoldTimerExpires => {
                        if !session_timer!(self, idle_hold).enabled() {
                            continue;
                        }
                        session_timer!(self, idle_hold).stop();
                        let title = session_event.title();
                        collision_log!(
                            self,
                            warn,
                            new,
                            exist.conn,
                            "BUG: {title} event not expected in this state (exist_conn_id: {}, new_conn_id: {}), ignoring",
                            exist.conn.id().short(),
                            new.id().short();
                            "event" => title
                        );
                        continue;
                    }

                    SessionEvent::TcpConnectionAcked(extra)
                    | SessionEvent::TcpConnectionConfirmed(extra) => {
                        match extra.direction() {
                            ConnectionDirection::Inbound => {
                                collision_log!(
                                    self,
                                    info,
                                    new,
                                    exist.conn,
                                    "new inbound connection (peer: {}, conn_id: {}), but we're already in a collision. rejecting..",
                                    extra.peer(),
                                    extra.id().short()
                                );
                                self.counters
                                    .passive_connections_declined
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            ConnectionDirection::Outbound => {
                                collision_log!(
                                    self,
                                    info,
                                    new,
                                    exist.conn,
                                    "outbound connection completed (peer: {}, conn_id: {}), but we're already in a collision. rejecting..",
                                    extra.peer(),
                                    extra.id().short()
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
                                    if !conn_timer!(connection, hold).enabled()
                                    {
                                        continue;
                                    }
                                    if conn_id == *new.id() {
                                        collision_log!(
                                            self,
                                            warn,
                                            new,
                                            exist.conn,
                                            "hold timer expired (conn_id: {}), fsm transition existing conn back to open confirm",
                                            conn_id.short()
                                        );
                                        self.stop(
                                            Some(&new),
                                            None,
                                            StopReason::HoldTimeExpired,
                                        );
                                        return FsmState::OpenConfirm(exist);
                                    } else if conn_id == *exist.conn.id() {
                                        collision_log!(
                                            self,
                                            warn,
                                            new,
                                            exist.conn,
                                            "hold timer expired (conn_id: {}), fsm transition new conn to open sent",
                                            conn_id.short()
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
                                        collision_log!(
                                            self,
                                            warn,
                                            new,
                                            exist.conn,
                                            "rx open message from peer {} for known connection (conn_id: {}) that isn't part of this collision? closing conn",
                                            conn_id.remote().ip(),
                                            conn_id.short()
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
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx open message from peer {} for unknown connection (conn_id: {}), ignoring",
                                        conn_id.remote().ip(),
                                        conn_id.short()
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
                                    if !conn_timer!(new, keepalive).enabled() {
                                        continue;
                                    }
                                    self.send_keepalive(&new);
                                    conn_timer!(new, keepalive).restart();
                                }
                                CollisionConnectionKind::Exist => {
                                    if !conn_timer!(exist.conn, keepalive)
                                        .enabled()
                                    {
                                        continue;
                                    }
                                    self.send_keepalive(&exist.conn);
                                    conn_timer!(exist.conn, keepalive)
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
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx {} for known connection (conn_id: {}) that isn't part of this collision (likely a bug). closing conn",
                                        connection_event.title(),
                                        conn_id.short()
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
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx {} for unknown connection (conn_id: {}), ignoring",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                }
                            }
                        }

                        // RFC 4271 FSM Event 12
                        ConnectionEvent::DelayOpenTimerExpires(ref conn_id) => {
                            match self.collision_conn_kind(
                                conn_id,
                                exist.conn.id(),
                                new.id(),
                            ) {
                                CollisionConnectionKind::New => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "new conn rx {} (conn_id: {}), but event is not allowed. fsm transition existing conn back to open confirm",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                    self.stop(
                                        Some(&new),
                                        None,
                                        StopReason::FsmError,
                                    );
                                    return FsmState::OpenConfirm(exist);
                                }

                                CollisionConnectionKind::Exist => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "exist conn rx {} (conn_id: {}), fsm transition new conn to open sent",
                                        connection_event.title(),
                                        conn_id.short()
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
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx {} for known connection (conn_id: {}) that isn't part of this collision? closing connection",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                    self.stop(
                                        Some(&unknown),
                                        None,
                                        StopReason::FsmError,
                                    );
                                    continue;
                                }

                                CollisionConnectionKind::Missing => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx {} for unknown connection (conn_id: {}), ignoring",
                                        connection_event.title(),
                                        conn_id.short()
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
                                            *conn_id,
                                        );

                                        self.bump_msg_counter(msg_kind, false);

                                        if let Err(e) =
                                            self.handle_open(&new, &om)
                                        {
                                            collision_log!(
                                                self,
                                                warn,
                                                new,
                                                exist.conn,
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
                                        collision_log!(
                                            self,
                                            warn,
                                            new,
                                            exist.conn,
                                            "rx unexpected {msg_kind} via new conn (conn_id: {}), fsm transition existing conn back to open confirm",
                                            conn_id.short()
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
                                        conn_timer!(exist.conn, hold).restart();
                                        conn_timer!(exist.conn, keepalive)
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
                                        collision_log!(
                                            self,
                                            warn,
                                            new,
                                            exist.conn,
                                            "rx unexpected {msg_kind} for existing connection (conn_id: {}), fsm transition new to open sent",
                                            conn_id.short()
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
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx unexpected {msg_kind} for known connection (conn_id: {}) that isn't part of this collision? closing conn",
                                        conn_id.short()
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
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx unexpected {msg_kind} for unknown connection (conn_id: {}), ignoring..",
                                        conn_id.remote().ip()
                                    );
                                    self.bump_msg_counter(msg_kind, true);
                                    continue;
                                }
                            }
                        }

                        ConnectionEvent::ParseError {
                            ref conn_id,
                            ref error,
                        } => {
                            // In ConnectionCollision state, a parse error on
                            // either connection should result in that
                            // connection being closed and the other connection
                            // proceeding.
                            // All ParseError events are fatal - get error codes for NOTIFICATION.
                            let (error_code, error_subcode) =
                                error.error_codes();
                            let stop_reason = StopReason::ParseError {
                                error_code,
                                error_subcode,
                            };

                            match self.collision_conn_kind(
                                conn_id,
                                exist.conn.id(),
                                new.id(),
                            ) {
                                CollisionConnectionKind::New => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx {} on new connection (conn_id: {}): {}, keeping existing",
                                        connection_event.title(), conn_id.short(), error;
                                    );
                                    self.stop(Some(&new), None, stop_reason);
                                    return FsmState::OpenConfirm(exist);
                                }
                                CollisionConnectionKind::Exist => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx {} on existing connection (conn_id: {}): {}, keeping new",
                                        connection_event.title(), conn_id.short(), error;
                                    );
                                    self.stop(
                                        Some(&exist.conn),
                                        None,
                                        stop_reason,
                                    );
                                    return FsmState::OpenSent(new);
                                }
                                CollisionConnectionKind::Unexpected(
                                    unknown,
                                ) => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx {} for known connection (conn_id: {}) not in collision, closing",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                    self.stop(
                                        Some(&unknown),
                                        None,
                                        stop_reason,
                                    );
                                    continue;
                                }
                                CollisionConnectionKind::Missing => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx {} for unknown connection (conn_id: {}), ignoring",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                    continue;
                                }
                            }
                        }

                        // In ConnectionCollision state, a failed TCP connection
                        // on either connection should result in that connection
                        // being closed and the other connection proceeding.
                        ConnectionEvent::TcpConnectionFails(ref conn_id) => {
                            match self.collision_conn_kind(
                                conn_id,
                                exist.conn.id(),
                                new.id(),
                            ) {
                                CollisionConnectionKind::New => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx {} on new connection (conn_id: {}), keeping existing",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                    self.stop(
                                        Some(&new),
                                        None,
                                        StopReason::IoError,
                                    );
                                    return FsmState::OpenConfirm(exist);
                                }
                                CollisionConnectionKind::Exist => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx {} on existing connection (conn_id: {}), keeping new",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                    self.stop(
                                        Some(&exist.conn),
                                        None,
                                        StopReason::IoError,
                                    );
                                    return FsmState::OpenSent(new);
                                }
                                CollisionConnectionKind::Unexpected(
                                    unknown,
                                ) => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx {} for known connection (conn_id: {}) not in collision, closing",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                    self.stop(
                                        Some(&unknown),
                                        None,
                                        StopReason::IoError,
                                    );
                                    continue;
                                }
                                CollisionConnectionKind::Missing => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist.conn,
                                        "rx {} for unknown connection (conn_id: {}), ignoring",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        };

        collision_log!(
            self,
            info,
            &exist.conn,
            &new,
            "collision detected: local id {}, remote id {}",
            self.id,
            om.id
        );

        match collision_resolution(exist.conn.direction(), self.id, om.id) {
            CollisionResolution::ExistWins => {
                // Existing connection wins
                collision_log!(
                    self,
                    info,
                    &exist.conn,
                    &new,
                    "collision resolution: local system wins with higher RID ({} > {})",
                    self.id,
                    om.id
                );

                self.stop(Some(&new), None, StopReason::CollisionResolution);

                conn_timer!(exist.conn, hold).restart();
                conn_timer!(exist.conn, keepalive).restart();
                self.send_keepalive(&exist.conn);

                // Upgrade existing connection from Partial to Full in the registry
                lock!(self.connection_registry).upgrade_to_full(exist.clone());

                FsmState::OpenConfirm(exist)
            }
            CollisionResolution::NewWins => {
                // New connection wins
                collision_log!(
                    self,
                    info,
                    &exist.conn,
                    &new,
                    "collision resolution: peer wins with higher RID ({} >= {})",
                    om.id,
                    self.id
                );

                self.stop(
                    Some(&exist.conn),
                    None,
                    StopReason::CollisionResolution,
                );

                session_timer!(self, connect_retry).stop();
                self.counters
                    .connection_retries
                    .fetch_add(1, Ordering::Relaxed);

                let caps = om.get_capabilities();
                let (ipv4_unicast, ipv6_unicast) = active_afi!(self, caps);

                let new_pc = PeerConnection {
                    conn: new,
                    id: om.id,
                    asn: om.asn(),
                    caps,
                    ipv4_unicast,
                    ipv6_unicast,
                };

                conn_timer!(new_pc.conn, hold).restart();
                conn_timer!(new_pc.conn, keepalive).restart();
                self.send_keepalive(&new_pc.conn);

                // Upgrade new connection from Partial to Full in the registry
                lock!(self.connection_registry).upgrade_to_full(new_pc.clone());

                FsmState::OpenConfirm(new_pc)
            }
        }
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
        exist: Arc<Cnx>,
        new: Arc<Cnx>,
    ) -> FsmState<Cnx> {
        loop {
            // Check to see if a shutdown has been requested.
            if self.shutdown.load(Ordering::Acquire) {
                return FsmState::Idle;
            }

            let event =
                recv_event_loop!(self, self.event_rx, collision, new, exist);

            match event {
                FsmEvent::Admin(admin_event) => match admin_event {
                    AdminEvent::ManualStop => {
                        collision_log!(
                            self,
                            info,
                            new,
                            exist,
                            "rx manual stop, fsm transition to idle"
                        );
                        self.stop(
                            Some(&new),
                            Some(&exist),
                            StopReason::Shutdown,
                        );
                        return FsmState::Idle;
                    }

                    AdminEvent::Reset => {
                        collision_log!(
                            self,
                            info,
                            new,
                            exist,
                            "rx fsm reset, fsm transition to idle"
                        );
                        self.stop(Some(&new), Some(&exist), StopReason::Reset);
                        return FsmState::Idle;
                    }

                    AdminEvent::Announce(_)
                    | AdminEvent::ShaperChanged(_)
                    | AdminEvent::ExportPolicyChanged(_)
                    | AdminEvent::CheckerChanged(_)
                    | AdminEvent::ManualStart
                    | AdminEvent::SendRouteRefresh(_)
                    | AdminEvent::ReAdvertiseRoutes(_) => {
                        let title = admin_event.title();
                        collision_log!(
                            self,
                            warn,
                            new,
                            exist,
                            "unexpected admin fsm event {title}, ignoring";
                            "event" => title
                        );
                        continue;
                    }
                },

                // This applies to both OpenSent and OpenConfirm
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
                    // RFC 4271 FSM Event 9
                    SessionEvent::ConnectRetryTimerExpires => {
                        if !session_timer!(self, connect_retry).enabled() {
                            continue;
                        }
                        let title = session_event.title();
                        collision_log!(
                            self,
                            warn,
                            new,
                            exist,
                            "{title} event not allowed in this state, fsm transition to idle";
                            "event" => title
                        );
                        self.stop(
                            Some(&new),
                            Some(&exist),
                            StopReason::FsmError,
                        );
                        return FsmState::Idle;
                    }

                    // RFC 4271 FSM Event 13
                    SessionEvent::IdleHoldTimerExpires => {
                        if !session_timer!(self, idle_hold).enabled() {
                            continue;
                        }
                        let title = session_event.title();
                        collision_log!(
                            self,
                            warn,
                            new,
                            exist,
                            "{title} event not allowed in this state, fsm transition to idle";
                            "event" => title
                        );
                        self.stop(
                            Some(&new),
                            Some(&exist),
                            StopReason::FsmError,
                        );
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
                        match extra.direction() {
                            ConnectionDirection::Inbound => {
                                collision_log!(self, info, new, exist,
                                    "new inbound connection (peer: {}, conn_id: {}), but we're already in a collision. closing..",
                                    extra.peer(), extra.id().short();
                                );
                                self.counters
                                    .passive_connections_declined
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            ConnectionDirection::Outbound => {
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
                                        // RFC 4271 FSM Event 19
                                        lock!(self.message_history).receive(
                                            om.clone().into(),
                                            *conn_id,
                                        );

                                        self.bump_msg_counter(msg_kind, false);

                                        if let Err(e) = self.handle_open(&exist, &om) {
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
                                            self.stop(Some(&exist), None, StopReason::FsmError);
                                            return FsmState::OpenSent(new);
                                        }

                                        // Resolve collision on first Open - don't wait for both
                                        collision_log!(self, info, exist, new,
                                            "exist conn received Open (conn_id: {}), resolving collision immediately",
                                            conn_id.short();
                                        );

                                        match collision_resolution(
                                            exist.direction(),
                                            self.id,
                                            om.id,
                                        ) {
                                            CollisionResolution::ExistWins => {
                                                // Existing connection wins
                                                collision_log!(self, info, exist, new,
                                                    "exist conn wins collision, close new conn",
                                                );

                                                self.stop(Some(&new), None, StopReason::CollisionResolution);

                                                conn_timer!(exist, hold).restart();
                                                conn_timer!(exist, keepalive).restart();

                                                let caps = om.get_capabilities();
                                                let (ipv4_unicast, ipv6_unicast) = active_afi!(self, caps);

                                                let exist_pc = PeerConnection {
                                                    conn: exist.clone(),
                                                    id: om.id,
                                                    asn: om.asn(),
                                                    caps,
                                                    ipv4_unicast,
                                                    ipv6_unicast,
                                                };

                                                // Upgrade existing connection from Partial to Full in the registry
                                                lock!(self.connection_registry).upgrade_to_full(exist_pc.clone());

                                                self.send_keepalive(&exist_pc.conn);
                                                return FsmState::OpenConfirm(exist_pc);
                                            }
                                            CollisionResolution::NewWins => {
                                                // New connection wins
                                                collision_log!(
                                                    self,
                                                    info,
                                                    exist,
                                                    new,
                                                    "new conn wins collision, close exist conn",
                                                );

                                                self.stop(Some(&exist), None, StopReason::CollisionResolution);
                                                session_timer!(self, connect_retry).stop();
                                                self.counters
                                                    .connection_retries
                                                    .fetch_add(1, Ordering::Relaxed);

                                                return FsmState::OpenSent(new);
                                            }
                                        }
                                    } else {
                                        // Any message other than Open is an FSM error for OpenSent
                                        self.bump_msg_counter(msg_kind, true);
                                        collision_log!(
                                            self,
                                            warn,
                                            new,
                                            exist,
                                            "existing conn rx unexpected {msg_kind} (conn_id: {}), fallback to new conn",
                                            conn_id.short();
                                            "message" => msg_kind
                                        );

                                        self.stop(Some(&exist), None, StopReason::FsmError);
                                        session_timer!(self, connect_retry).stop();
                                        self.connect_retry_counter
                                            .fetch_add(1, Ordering::Relaxed);

                                        return FsmState::OpenSent(new);
                                    }
                                },

                                CollisionConnectionKind::New => {
                                    if let Message::Open(om) = msg {
                                        // RFC 4271 FSM Event 19
                                        lock!(self.message_history).receive(
                                            om.clone().into(),
                                            *conn_id,
                                        );

                                        self.bump_msg_counter(msg_kind, false);

                                        if let Err(e) = self.handle_open(&new, &om) {
                                            collision_log!(
                                                self,
                                                warn,
                                                new,
                                                exist,
                                                "new conn failed to handle {msg_kind} ({e}), fallback to existing conn";
                                                "error" => format!("{e}")
                                            );

                                            // notification sent by handle_open(), nothing to do here
                                            self.connect_retry_counter
                                                .fetch_add(1, Ordering::Relaxed);
                                            self.counters
                                                .connection_retries
                                                .fetch_add(1, Ordering::Relaxed);
                                            self.stop(Some(&new), None, StopReason::FsmError);
                                            return FsmState::OpenSent(exist);
                                        }

                                        self.send_keepalive(&new);

                                        // Resolve collision on first Open - don't wait for both
                                        collision_log!(
                                            self,
                                            info,
                                            new,
                                            exist,
                                            "new conn received Open (conn_id: {}), resolving collision immediately",
                                            conn_id.short()
                                        );

                                        match collision_resolution(
                                            exist.direction(),
                                            self.id,
                                            om.id,
                                        ) {
                                            CollisionResolution::ExistWins => {
                                                // Existing connection wins
                                                collision_log!(
                                                    self,
                                                    info,
                                                    new,
                                                    exist,
                                                    "exist conn wins collision, closing new"
                                                );

                                                self.stop(Some(&new), None, StopReason::CollisionResolution);
                                                session_timer!(self, connect_retry).stop();
                                                self.counters
                                                    .connection_retries
                                                    .fetch_add(1, Ordering::Relaxed);

                                                return FsmState::OpenSent(exist);
                                            }
                                            CollisionResolution::NewWins => {
                                                // New connection wins
                                                collision_log!(
                                                    self,
                                                    info,
                                                    new,
                                                    exist,
                                                    "new conn wins collision, closing exist"
                                                );

                                                self.stop(Some(&exist), None, StopReason::CollisionResolution);

                                                let caps = om.get_capabilities();
                                                let (ipv4_unicast, ipv6_unicast) = active_afi!(self, caps);

                                                let new_pc = PeerConnection {
                                                    conn: new.clone(),
                                                    id: om.id,
                                                    asn: om.asn(),
                                                    caps,
                                                    ipv4_unicast,
                                                    ipv6_unicast,
                                                };

                                                conn_timer!(new, hold).restart();
                                                conn_timer!(new, keepalive).restart();

                                                // Upgrade new connection from Partial to Full in the registry
                                                lock!(self.connection_registry).upgrade_to_full(new_pc.clone());

                                                self.send_keepalive(&new_pc.conn);

                                                return FsmState::OpenConfirm(new_pc);
                                            }
                                        }
                                    } else {
                                        // Any message other than Open is an FSM error for OpenSent
                                        self.bump_msg_counter(msg_kind, true);
                                        collision_log!(
                                            self,
                                            warn,
                                            new,
                                            exist,
                                            "new conn rx unexpected {msg_kind} (conn_id: {}), fallback to existing conn",
                                            conn_id.short();
                                            "message" => msg_kind
                                        );

                                        self.stop(Some(&new), None, StopReason::FsmError);
                                        session_timer!(self, connect_retry).stop();
                                        self.connect_retry_counter
                                            .fetch_add(1, Ordering::Relaxed);

                                        return FsmState::OpenSent(exist);
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
                                    if !conn_timer!(new, hold).enabled() {
                                        continue;
                                    }
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "new conn rx {title} (conn_id: {}), fallback to existing conn",
                                        conn_id.short();
                                        "event" => title
                                    );
                                    self.stop(Some(&new), None, StopReason::HoldTimeExpired);
                                    return FsmState::OpenSent(exist);
                                },

                                CollisionConnectionKind::Exist => {
                                    if !conn_timer!(exist, hold).enabled() {
                                        continue;
                                    }
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "existing conn rx {title} (conn_id: {}), fallback to new conn",
                                        conn_id.short();
                                        "event" => title
                                    );
                                    self.stop(Some(&exist), None, StopReason::HoldTimeExpired);
                                    return FsmState::OpenSent(new);
                                },

                                CollisionConnectionKind::Unexpected(unknown) => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "rx {title} for known connection (conn_id: {}) that isn't part of this collision? closing conn",
                                        conn_id.short();
                                        "event" => title
                                    );
                                    self.stop(Some(&unknown), None, StopReason::HoldTimeExpired);
                                    continue;
                                },

                                CollisionConnectionKind::Missing => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "rx {title} for unknown connection (conn_id: {}), ignoring..",
                                        conn_id.short();
                                        "event" => title
                                    );
                                    continue;
                                },
                            }

                        }

                        // RFC 4271 FSM Event 11
                        ConnectionEvent::KeepaliveTimerExpires(
                            conn_id,
                        )
                        // RFC 4271 FSM Event 12
                        | ConnectionEvent::DelayOpenTimerExpires(
                            conn_id,
                        ) => {
                            let title = connection_event.title();

                            match self.collision_conn_kind(&conn_id, exist.id(), new.id()) {
                                CollisionConnectionKind::New => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "new conn rx {title}, but event not allowed in this state, fallback to existing conn";
                                        "event" => title
                                    );
                                    self.stop(Some(&new), None, StopReason::FsmError);
                                    return FsmState::OpenSent(exist);
                                },

                                CollisionConnectionKind::Exist => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "existing conn rx {title}, but event not allowed in this state, fallback to new conn";
                                        "event" => title
                                    );
                                    self.stop(Some(&exist), None, StopReason::FsmError);
                                    return FsmState::OpenSent(new);
                                },

                                CollisionConnectionKind::Unexpected(unknown) => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "rx {title} for connection that is known (conn_id: {}) but not part of this collision? closing conn",
                                        conn_id.short();
                                        "event" => title
                                    );
                                    self.stop(Some(&unknown), None, StopReason::FsmError);
                                    continue;
                                },

                                CollisionConnectionKind::Missing => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "rx {title} for unknown connection (conn_id: {}), ignoring..",
                                        conn_id.short();
                                        "event" => title
                                    );
                                    continue;
                                },
                            }
                        }

                        ConnectionEvent::ParseError {
                            ref conn_id,
                            ref error,
                        } => {
                            // In ConnectionCollision (OpenSent) state, a parse
                            // error on either connection should result in that
                            // connection being closed and the other connection
                            // proceeding.
                            // All ParseError events are fatal - get error codes for NOTIFICATION.
                            let (error_code, error_subcode) = error.error_codes();
                            let stop_reason = StopReason::ParseError {
                                error_code,
                                error_subcode,
                            };

                            match self.collision_conn_kind(
                                conn_id,
                                exist.id(),
                                new.id(),
                            ) {
                                CollisionConnectionKind::New => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "rx {} on new connection (conn_id: {}): {}, keeping existing",
                                        connection_event.title(), conn_id.short(), error;
                                    );
                                    self.stop(
                                        Some(&new),
                                        None,
                                        stop_reason,
                                    );
                                    return FsmState::OpenSent(exist);
                                }
                                CollisionConnectionKind::Exist => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "rx {} on existing connection (conn_id: {}): {}, keeping new",
                                        connection_event.title(), conn_id.short(), error;
                                    );
                                    self.stop(
                                        Some(&exist),
                                        None,
                                        stop_reason,
                                    );
                                    return FsmState::OpenSent(new);
                                }
                                CollisionConnectionKind::Unexpected(unknown) => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "rx {} for known connection (conn_id: {}) not in collision, closing",
                                        connection_event.title(), conn_id.short()
                                    );
                                    self.stop(
                                        Some(&unknown),
                                        None,
                                        stop_reason,
                                    );
                                    continue;
                                }
                                CollisionConnectionKind::Missing => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "rx {} for unknown connection (conn_id: {}), ignoring",
                                        connection_event.title(), conn_id.short()
                                    );
                                    continue;
                                }
                            }
                        }

                        // In ConnectionCollision state, a failed TCP connection
                        // on either connection should result in that connection
                        // being closed and the other connection proceeding.
                        ConnectionEvent::TcpConnectionFails(ref conn_id) => {
                            match self.collision_conn_kind(
                                conn_id,
                                exist.id(),
                                new.id(),
                            ) {
                                CollisionConnectionKind::New => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "rx {} on new connection (conn_id: {}), keeping existing",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                    self.stop(
                                        Some(&new),
                                        None,
                                        StopReason::IoError,
                                    );
                                    return FsmState::OpenSent(exist);
                                }
                                CollisionConnectionKind::Exist => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "rx {} on existing connection (conn_id: {}), keeping new",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                    self.stop(
                                        Some(&exist),
                                        None,
                                        StopReason::IoError,
                                    );
                                    return FsmState::OpenSent(new);
                                }
                                CollisionConnectionKind::Unexpected(
                                    unknown,
                                ) => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "rx {} for known connection (conn_id: {}) not in collision, closing",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                    self.stop(
                                        Some(&unknown),
                                        None,
                                        StopReason::IoError,
                                    );
                                    continue;
                                }
                                CollisionConnectionKind::Missing => {
                                    collision_log!(
                                        self,
                                        warn,
                                        new,
                                        exist,
                                        "rx {} for unknown connection (conn_id: {}), ignoring",
                                        connection_event.title(),
                                        conn_id.short()
                                    );
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Collision Resolution logic.
    ///
    /// Performs Connection Collision Resolution per RFC 4271 6.8.
    ///
    /// The winning connection is returned to the FSM state that aligns with
    /// the messages received by the connection. We send Full connections to
    /// OpenConfirm instead of SessionSetup because they haven't received a
    /// Keepalive yet. We know this because a Full connection either:
    ///  - Came directly from OpenConfirm (waiting for Keepalive)
    ///  - Came from OpenSent and just received an Open (no Keepalive yet)
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
        let originated4 = if pc.ipv4_unicast.negotiated() {
            match self.db.get_origin4() {
                Ok(value) => value,
                Err(e) => {
                    //TODO possible death loop. Should we just panic here?
                    session_log!(
                        self,
                        error,
                        pc.conn,
                        "failed to get originated routes from db";
                        "error" => format!("{e}")
                    );
                    return FsmState::SessionSetup(pc);
                }
            }
        } else {
            Vec::new()
        };

        let originated6 = if pc.ipv6_unicast.negotiated() {
            match self.db.get_origin6() {
                Ok(value) => value,
                Err(e) => {
                    //TODO possible death loop. Should we just panic here?
                    session_log!(
                        self,
                        error,
                        pc.conn,
                        "failed to get originated routes from db";
                        "error" => format!("{e}")
                    );
                    return FsmState::SessionSetup(pc);
                }
            }
        } else {
            Vec::new()
        };

        // Ensure the router has a fanout entry for this peer.
        if pc.ipv4_unicast.negotiated() {
            write_lock!(self.fanout4).add_egress(
                self.neighbor.host.ip(),
                crate::fanout::Egress {
                    event_tx: Some(self.event_tx.clone()),
                    log: self.log.clone(),
                },
            );
        }
        if pc.ipv6_unicast.negotiated() {
            write_lock!(self.fanout6).add_egress(
                self.neighbor.host.ip(),
                crate::fanout::Egress {
                    event_tx: Some(self.event_tx.clone()),
                    log: self.log.clone(),
                },
            );
        }

        self.send_keepalive(&pc.conn);
        conn_timer!(pc.conn, keepalive).restart();

        // Send an update to our peer with the IPv4 Unicast prefixes this router
        // is originating.
        if !originated4.is_empty()
            && let Err(e) = self.send_update(
                RouteUpdate::V4(RouteUpdate4::Announce(originated4)),
                &pc,
                ShaperApplication::Current,
            )
        {
            session_log!(
                self,
                error,
                pc.conn,
                "failed to send originated IPv4 routes: {e}";
                "error" => format!("{e}")
            );
            return self.exit_established(pc);
        }

        // Send IPv6 Unicast prefixes using MP-BGP encoding
        if !originated6.is_empty()
            && let Err(e) = self.send_update(
                RouteUpdate::V6(RouteUpdate6::Announce(originated6)),
                &pc,
                ShaperApplication::Current,
            )
        {
            session_log!(
                self,
                error,
                pc.conn,
                "failed to send originated IPv6 routes: {e}";
                "error" => format!("{e}")
            );
            return self.exit_established(pc);
        }

        // Transition to the established state.
        FsmState::Established(pc)
    }

    fn originate_update(
        &self,
        pc: &PeerConnection<Cnx>,
        _sa: ShaperApplication,
    ) -> anyhow::Result<()> {
        // Get originated IPv4 routes
        let originated4 = match self.db.get_origin4() {
            Ok(originated) => originated,
            Err(e) => {
                anyhow::bail!("failed to get originated IPv4 from db: {e}");
            }
        };

        if !originated4.is_empty() {
            self.send_update(
                RouteUpdate::V4(RouteUpdate4::Announce(originated4)),
                pc,
                ShaperApplication::Current,
            )?;
        }

        // Get originated IPv6 routes
        let originated6 = match self.db.get_origin6() {
            Ok(originated) => originated,
            Err(e) => {
                anyhow::bail!("failed to get originated IPv6 from db: {e}");
            }
        };

        if !originated6.is_empty() {
            self.send_update(
                RouteUpdate::V6(RouteUpdate6::Announce(originated6)),
                pc,
                ShaperApplication::Current,
            )?;
        }

        Ok(())
    }

    /// Able to exchange update, notification and keepliave messages with peers.
    fn fsm_established(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        // Check to see if a shutdown has been requested.
        if self.shutdown.load(Ordering::Acquire) {
            return self.exit_established(pc);
        }

        let event = recv_event_return!(
            self,
            self.event_rx,
            FsmState::Established(pc),
            pc.conn
        );
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

                // Handle route announcements from fanout layer
                AdminEvent::Announce(route_update) => {
                    // XXX: Send a route-refresh to our peer in the event we
                    //      remove an originated route. This is needed if our
                    //      peer is advertising a route that we're originating,
                    //      and we decide to stop originating it. In other BGP
                    //      stacks, local paths coexist in the RIB with learned
                    //      paths (local having precedent) and withdrawal of the
                    //      local path would result in the learned path getting
                    //      installed. We don't do this or store routes in the
                    //      adj-rib-in pre-policy, so a route-refresh is the
                    //      only mechanism we really have to trigger a re-learn
                    //      of the route without changing the current design.
                    session_log!(
                        self,
                        debug,
                        pc.conn,
                        "received route-update event: {route_update}"
                    );

                    if let Err(e) = self.send_update(
                        route_update,
                        &pc,
                        ShaperApplication::Current,
                    ) {
                        session_log!(
                            self,
                            error,
                            pc.conn,
                            "failed to send update from announce-routes: {e}";
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
                            session_log!(
                                self,
                                error,
                                pc.conn,
                                "failed to originate update, fsm transition to idle";
                                "error" => format!("{e}")
                            );
                            self.exit_established(pc)
                        }
                        Ok(()) => FsmState::Established(pc),
                    }
                }

                AdminEvent::ExportPolicyChanged(previous) => {
                    match previous {
                        TypedImportExportPolicy::V4(previous4) => {
                            let originated = match self.db.get_origin4() {
                                Ok(value) => value,
                                Err(e) => {
                                    session_log!(
                                        self,
                                        error,
                                        pc.conn,
                                        "failed to get originated IPv4 routes from db";
                                        "error" => format!("{e}")
                                    );
                                    return FsmState::SessionSetup(pc);
                                }
                            };

                            // Determine which routes to announce/withdraw based on policy change
                            let session = lock!(self.session);
                            let originated_before: BTreeSet<Prefix4> =
                                match previous4 {
                                    ImportExportPolicy4::NoFiltering => {
                                        originated.iter().cloned().collect()
                                    }
                                    ImportExportPolicy4::Allow(ref list) => {
                                        originated
                                            .iter()
                                            .cloned()
                                            .filter(|x| list.contains(x))
                                            .collect()
                                    }
                                };

                            let originated_after: BTreeSet<Prefix4> =
                                match session
                                    .ipv4_unicast
                                    .as_ref()
                                    .map(|c| &c.export_policy)
                                {
                                    Some(ImportExportPolicy4::NoFiltering)
                                    | None => {
                                        originated.iter().cloned().collect()
                                    }
                                    Some(ImportExportPolicy4::Allow(list)) => {
                                        originated
                                            .clone()
                                            .into_iter()
                                            .filter(|x| list.contains(x))
                                            .collect()
                                    }
                                };
                            drop(session);

                            let to_withdraw: Vec<Prefix4> = originated_before
                                .difference(&originated_after)
                                .cloned()
                                .collect();

                            let to_announce: Vec<Prefix4> = originated_after
                                .difference(&originated_before)
                                .cloned()
                                .collect();

                            // Per RFC 7606, send announcements and withdrawals as
                            // separate UPDATE messages.
                            if !to_announce.is_empty()
                                && let Err(e) = self.send_update(
                                    RouteUpdate::V4(RouteUpdate4::Announce(
                                        to_announce,
                                    )),
                                    &pc,
                                    ShaperApplication::Current,
                                )
                            {
                                session_log!(
                                    self,
                                    error,
                                    pc.conn,
                                    "failed to send IPv4 export policy announce: {e}";
                                    "error" => format!("{e}")
                                );
                                return self.exit_established(pc);
                            }

                            if !to_withdraw.is_empty()
                                && let Err(e) = self.send_update(
                                    RouteUpdate::V4(RouteUpdate4::Withdraw(
                                        to_withdraw,
                                    )),
                                    &pc,
                                    ShaperApplication::Current,
                                )
                            {
                                session_log!(
                                    self,
                                    error,
                                    pc.conn,
                                    "failed to send IPv4 export policy withdraw: {e}";
                                    "error" => format!("{e}")
                                );
                                return self.exit_established(pc);
                            }

                            FsmState::Established(pc)
                        }
                        TypedImportExportPolicy::V6(previous6) => {
                            let originated = match self.db.get_origin6() {
                                Ok(value) => value,
                                Err(e) => {
                                    session_log!(
                                        self,
                                        error,
                                        pc.conn,
                                        "failed to get originated IPv6 routes from db";
                                        "error" => format!("{e}")
                                    );
                                    return FsmState::SessionSetup(pc);
                                }
                            };

                            // Determine which routes to announce/withdraw based on policy change
                            let session = lock!(self.session);
                            let originated_before: BTreeSet<Prefix6> =
                                match previous6 {
                                    ImportExportPolicy6::NoFiltering => {
                                        originated.iter().cloned().collect()
                                    }
                                    ImportExportPolicy6::Allow(ref list) => {
                                        originated
                                            .iter()
                                            .cloned()
                                            .filter(|x| list.contains(x))
                                            .collect()
                                    }
                                };

                            let originated_after: BTreeSet<Prefix6> =
                                match session
                                    .ipv6_unicast
                                    .as_ref()
                                    .map(|c| &c.export_policy)
                                {
                                    Some(ImportExportPolicy6::NoFiltering)
                                    | None => {
                                        originated.iter().cloned().collect()
                                    }
                                    Some(ImportExportPolicy6::Allow(list)) => {
                                        originated
                                            .clone()
                                            .into_iter()
                                            .filter(|x| list.contains(x))
                                            .collect()
                                    }
                                };
                            drop(session);

                            let to_withdraw: Vec<Prefix6> = originated_before
                                .difference(&originated_after)
                                .cloned()
                                .collect();

                            let to_announce: Vec<Prefix6> = originated_after
                                .difference(&originated_before)
                                .cloned()
                                .collect();

                            // Per RFC 7606, send announcements and withdrawals as
                            // separate UPDATE messages.
                            if !to_announce.is_empty()
                                && let Err(e) = self.send_update(
                                    RouteUpdate::V6(RouteUpdate6::Announce(
                                        to_announce,
                                    )),
                                    &pc,
                                    ShaperApplication::Current,
                                )
                            {
                                session_log!(
                                    self,
                                    error,
                                    pc.conn,
                                    "failed to send IPv6 export policy announce: {e}";
                                    "error" => format!("{e}")
                                );
                                return self.exit_established(pc);
                            }

                            if !to_withdraw.is_empty()
                                && let Err(e) = self.send_update(
                                    RouteUpdate::V6(RouteUpdate6::Withdraw(
                                        to_withdraw,
                                    )),
                                    &pc,
                                    ShaperApplication::Current,
                                )
                            {
                                session_log!(
                                    self,
                                    error,
                                    pc.conn,
                                    "failed to send IPv6 export policy withdraw: {e}";
                                    "error" => format!("{e}")
                                );
                                return self.exit_established(pc);
                            }

                            FsmState::Established(pc)
                        }
                    }
                }

                AdminEvent::CheckerChanged(_previous) => {
                    //TODO
                    FsmState::Established(pc)
                }

                AdminEvent::SendRouteRefresh(af) => {
                    self.db.mark_bgp_peer_stale(
                        pc.conn.peer().ip(),
                        AddressFamily::from(af),
                    );
                    self.send_route_refresh(&pc.conn, af);
                    FsmState::Established(pc)
                }

                AdminEvent::ReAdvertiseRoutes(af) => {
                    if let Err(e) = self.refresh_react(af, &pc) {
                        session_log!(
                            self,
                            error,
                            pc.conn,
                            "route re-advertisement error: {e}";
                            "error" => format!("{e}")
                        );
                        return self.exit_established(pc);
                    }
                    FsmState::Established(pc)
                }

                AdminEvent::ManualStart => {
                    let title = admin_event.title();
                    session_log_lite!(
                        self,
                        warn,
                        "unexpected admin fsm event {title}, ignoring";
                        "event" => title
                    );
                    FsmState::Established(pc)
                }
            },

            FsmEvent::Session(session_event) => match session_event {
                SessionEvent::ConnectRetryTimerExpires => {
                    if !session_timer!(self, connect_retry).enabled() {
                        return FsmState::Established(pc);
                    }
                    session_timer!(self, connect_retry).stop();
                    session_log!(
                        self,
                        warn,
                        pc.conn,
                        "BUG: rx {} (conn_id: {}), not expected in this state, ignoring",
                        session_event.title(),
                        pc.conn.id().short()
                    );
                    FsmState::Established(pc)
                }

                SessionEvent::IdleHoldTimerExpires => {
                    if !session_timer!(self, idle_hold).enabled() {
                        return FsmState::Established(pc);
                    }
                    session_timer!(self, idle_hold).stop();
                    session_log!(
                        self,
                        warn,
                        pc.conn,
                        "BUG: rx idle hold timer expires (conn_id: {}), not expected in this state, ignoring",
                        pc.conn.id().short()
                    );
                    FsmState::Established(pc)
                }

                SessionEvent::TcpConnectionAcked(new)
                | SessionEvent::TcpConnectionConfirmed(new) => {
                    match new.direction() {
                        ConnectionDirection::Inbound => {
                            session_log!(
                                self,
                                info,
                                new,
                                "inbound connection not allowed in established (peer: {}, conn_id: {})",
                                new.peer(),
                                new.id().short()
                            );
                            self.counters
                                .passive_connections_declined
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        ConnectionDirection::Outbound => {
                            session_log!(
                                self,
                                info,
                                new,
                                "outbound connection completed but not allowed in established (peer: {}, conn_id: {})",
                                new.peer(),
                                new.id().short()
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
                    if !self.validate_active_connection(
                        conn_id,
                        &pc.conn,
                        "hold timer expires",
                    ) {
                        return FsmState::Established(pc);
                    }

                    if !conn_timer!(pc.conn, hold).enabled() {
                        return FsmState::Established(pc);
                    }

                    session_log!(
                        self,
                        warn,
                        pc.conn,
                        "hold timer expired, fsm transition to idle"
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
                    if !self.validate_active_connection(
                        conn_id,
                        &pc.conn,
                        "keepalive timer expires",
                    ) {
                        return FsmState::Established(pc);
                    }

                    if !conn_timer!(pc.conn, keepalive).enabled() {
                        return FsmState::Established(pc);
                    }

                    self.send_keepalive(&pc.conn);
                    FsmState::Established(pc)
                }

                ConnectionEvent::DelayOpenTimerExpires(ref conn_id) => {
                    if !self.validate_active_connection(
                        conn_id,
                        &pc.conn,
                        "delay open timer expires",
                    ) {
                        return FsmState::Established(pc);
                    }

                    if !conn_timer!(pc.conn, delay_open).enabled() {
                        return FsmState::Established(pc);
                    }

                    conn_timer!(pc.conn, delay_open).stop();
                    session_log!(
                        self,
                        warn,
                        pc.conn,
                        "BUG: rx delay open timer expires (conn_id: {}), not expected in this state, ignoring",
                        pc.conn.id().short()
                    );
                    FsmState::Established(pc)
                }

                ConnectionEvent::Message { msg, ref conn_id } => {
                    let msg_kind = msg.kind();

                    // ** Special Handling **
                    if *conn_id != *pc.conn.id() {
                        if let Some(incoming_conn) = self.get_conn(conn_id) {
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
                            if let Message::Open(om) = &msg {
                                // This applies to situations where we enter
                                // ConnectionCollision from OpenConfirm and the
                                // existing connection gets a Keepalive before
                                // the new/colliding connection got an Open.
                                //
                                // In that case, we transition out of
                                // ConnectionCollision and into Established with
                                // the existing connection, but we deliberately
                                // do not close or unregister the new connection
                                // so we can handle its Open when it arrives.
                                // This allows us to delay collision resolution
                                // until receipt of an Open message (aligning
                                // better with the expectations of RFC 4271)
                                // even if the existing connection moves into
                                // Established prior to collision resolution.
                                //
                                // If we find ourselves in this situation, the
                                // RFC specifies an optional boolean attribute
                                // to influnce the resolution behavior
                                // (CollisionDetectEstablishedState), which
                                // effectively boils down to:
                                // if false:
                                //   The Established connection always wins.
                                //   This means timing is _sometimes_ the
                                //   deciding factor when choosing a connection
                                //   to retain, but only if an Open isn't
                                //   received on the new connection until
                                //   after .
                                // if true:
                                //   Collision resolution is performed based
                                //   on the BGP-ID of each peer as per the
                                //   procedure outlined in Section 6.8. and the
                                //   Established connection is not guaranteed
                                //   to survive (taking timing out of the
                                //   picture and making collision resolution
                                //   more deterministic, in an idealistic sort
                                //   of way).
                                //
                                // Note: This is not a full implementation of
                                //       CollisionDetectEstablishedState.
                                //
                                // Rather, it is simply a lever for us to
                                // choose whether to ensure determinism in
                                // collision resolution (i.e. by forcing the
                                // use of BGP-ID as tie-breaker) or not
                                // (sticking to "first to Established wins")
                                // for the scenario described above. A full
                                // implementation would involve registration
                                // and tracking of new connections that complete
                                // while in Established (likely warranting
                                // an additional CollisionPair variant and
                                // collision_detection_* method) and adding
                                // full handling for connections to go into
                                // and out of Established while a collision is
                                // underway. At the time of writing this, a full
                                // implementation is not believed to be worth
                                // the added complexity and maintenance burden.
                                if lock!(self.session)
                                    .deterministic_collision_resolution
                                {
                                    // Determine which connection wins using pure function
                                    let resolution = collision_resolution(
                                        pc.conn.direction(),
                                        om.id,
                                        self.id,
                                    );

                                    session_log!(self,
                                        info,
                                        pc.conn,
                                        "collision detected in established state (conn_id: {}), collision_detect_established_state enabled",
                                        conn_id.short();
                                        "message" => "open",
                                        "message_contents" => format!("{om}"),
                                        "resolution" => format!("{:?}", resolution)
                                    );

                                    match resolution {
                                        CollisionResolution::ExistWins => {
                                            // pc wins: close incoming_conn, stay Established
                                            self.bump_msg_counter(
                                                msg_kind, true,
                                            );
                                            self.stop(
                                                Some(&incoming_conn),
                                                None,
                                                StopReason::CollisionResolution,
                                            );
                                            return FsmState::Established(pc);
                                        }
                                        CollisionResolution::NewWins => {
                                            // incoming_conn wins: close pc, transition to SessionSetup
                                            self.bump_msg_counter(
                                                msg_kind, false,
                                            );

                                            let caps = om.get_capabilities();
                                            let (ipv4_unicast, ipv6_unicast) =
                                                active_afi!(self, caps);

                                            let new_pc = PeerConnection {
                                                conn: incoming_conn.clone(),
                                                id: om.id,
                                                asn: om.asn(),
                                                caps,
                                                ipv4_unicast,
                                                ipv6_unicast,
                                            };

                                            // Clean up the old established connection
                                            self.cleanup_established(&pc);
                                            self.stop(
                                                Some(&pc.conn),
                                                None,
                                                StopReason::CollisionResolution,
                                            );

                                            // Prepare the winning connection
                                            conn_timer!(new_pc.conn, hold)
                                                .restart();
                                            conn_timer!(new_pc.conn, keepalive)
                                                .restart();
                                            self.send_keepalive(&new_pc.conn);

                                            // Upgrade new connection from
                                            // Partial to Full in the registry
                                            lock!(self.connection_registry)
                                                .upgrade_to_full(
                                                    new_pc.clone(),
                                                );

                                            return FsmState::SessionSetup(
                                                new_pc,
                                            );
                                        }
                                    }
                                } else {
                                    session_log!(
                                        self,
                                        info,
                                        pc.conn,
                                        "collision detected in established state (conn_id: {}), resolving",
                                        conn_id.short();
                                        "message" => "open",
                                        "message_contents" => format!("{om}")
                                    );
                                    self.bump_msg_counter(msg_kind, true);
                                    self.stop(
                                        Some(&incoming_conn),
                                        None,
                                        StopReason::ConnectionRejected,
                                    );
                                    return FsmState::Established(pc);
                                }
                            } else {
                                // No special case for anything other than Open
                                session_log!(
                                    self,
                                    warn,
                                    pc.conn,
                                    "rx {msg_kind} for unexpected known connection (conn_id: {}). closing..",
                                    conn_id.short();
                                    "message" => msg_kind,
                                    "message_contents" => format!("{msg}")
                                );
                                self.stop(
                                    Some(&incoming_conn),
                                    None,
                                    StopReason::FsmError,
                                );
                            }
                        } else {
                            session_log!(
                                self,
                                warn,
                                pc.conn,
                                "rx {msg_kind} for unknown connection (conn_id: {}). ignoring..",
                                conn_id.short();
                                "message" => msg_kind,
                                "message_contents" => format!("{msg}")
                            );
                        }
                        return FsmState::Established(pc);
                    }

                    match msg {
                        Message::Open(om) => {
                            // Unexpected Open on the active connection while in Established.
                            // All collision cases (Open from non-active connections) are
                            // handled above before reaching this match block.
                            session_log!(
                                self,
                                warn,
                                pc.conn,
                                "unexpected {msg_kind} on active connection, fsm transition to idle";
                                "message" => "open",
                                "message_contents" => format!("{om}")
                            );
                            self.bump_msg_counter(msg_kind, true);
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
                            conn_timer!(pc.conn, hold).reset();
                            session_log!(
                                self,
                                info,
                                pc.conn,
                                "received {msg_kind} (conn_id: {})",
                                conn_id.short();
                                "message" => "update",
                                "message_contents" => format!("{m}")
                            );
                            self.apply_update(m.clone(), &pc);
                            lock!(self.message_history)
                                .receive(m.into(), *conn_id);
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
                        Message::Notification(ref m) => {
                            // We've received a notification from the peer. They are
                            // displeased with us. Exit established and restart from
                            // the idle state.
                            session_log!(
                                self,
                                warn,
                                pc.conn,
                                "{msg_kind} received (conn_id: {}), fsm transition to idle",
                                conn_id.short();
                                "message" => "notification",
                                "message_contents" => format!("{m}")
                            );
                            lock!(self.message_history)
                                .receive(m.clone().into(), *conn_id);
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
                            session_log!(
                                self,
                                trace,
                                pc.conn,
                                "keepalive received (conn_id: {})",
                                conn_id.short();
                                "message" => "keepalive"
                            );
                            self.bump_msg_counter(msg_kind, false);
                            conn_timer!(pc.conn, hold).reset();
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
                            conn_timer!(pc.conn, hold).reset();
                            session_log!(
                                self,
                                info,
                                pc.conn,
                                "received route refresh (conn_id: {})",
                                conn_id.short();
                                "message" => "route refresh",
                                "message_contents" => format!("{m}").as_str()
                            );
                            lock!(self.message_history)
                                .receive(m.clone().into(), *conn_id);
                            self.bump_msg_counter(msg_kind, false);
                            if let Err(e) = self.handle_refresh(m, &pc) {
                                session_log!(
                                    self,
                                    error,
                                    pc.conn,
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

                ConnectionEvent::ParseError {
                    ref conn_id,
                    ref error,
                } => {
                    if !self.validate_active_connection(
                        conn_id,
                        &pc.conn,
                        connection_event.title(),
                    ) {
                        return FsmState::Established(pc);
                    }

                    // All ParseError events are fatal - send NOTIFICATION and reset.
                    // TreatAsWithdraw is now handled via UpdateMessage.treat_as_withdraw flag.
                    let (error_code, error_subcode) = error.error_codes();
                    session_log!(
                        self,
                        error,
                        pc.conn,
                        "rx {} (conn_id: {}): {}, session reset",
                        connection_event.title(), conn_id.short(), error;
                        "error_code" => format!("{error_code:?}"),
                        "error_subcode" => format!("{error_subcode:?}")
                    );
                    self.send_notification(&pc.conn, error_code, error_subcode);
                    self.exit_established(pc)
                }

                ConnectionEvent::TcpConnectionFails(ref conn_id) => {
                    if !self.validate_active_connection(
                        conn_id,
                        &pc.conn,
                        connection_event.title(),
                    ) {
                        return FsmState::Established(pc);
                    }

                    session_log!(
                        self,
                        warn,
                        pc.conn,
                        "rx {} (conn_id: {}), fsm transition to idle",
                        connection_event.title(), conn_id.short();
                    );
                    self.stop(Some(&pc.conn), None, StopReason::IoError);
                    self.exit_established(pc)
                }
            },
        }
    }

    // Housekeeping items to do when a session shutdown is requested.
    pub fn on_shutdown(&self) {
        session_log_lite!(
            self,
            info,
            "session runner (peer {}): shutdown start",
            self.neighbor.host.ip()
        );

        self.cleanup_connections();

        // Join the connector thread if one is running to ensure clean shutdown
        if let Some(handle) = lock!(self.connector_handle).take() {
            session_log_lite!(
                self,
                debug,
                "joining connector thread during shutdown"
            );
            self.join_connector_thread(handle, "shutdown");
        }

        // Disable session-level timers
        self.clock.stop_all();

        let previous = self.state();
        let next = FsmStateKind::Idle;
        if previous != next {
            session_log_lite!(
                self,
                info,
                "fsm transition {previous} -> {next}"
            );
            // Go back to the beginning of the state machine.
            *(lock!(self.state)) = next;
        }

        // Reset the shutdown signal and running flag.
        self.shutdown.store(false, Ordering::Release);
        self.running.store(false, Ordering::Release);

        session_log_lite!(
            self,
            info,
            "session runner (peer {}): shutdown complete",
            self.neighbor.host.ip()
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
        if let Some(expected_remote_asn) = lock!(self.session).remote_asn
            && remote_asn != expected_remote_asn
        {
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
                    session_log!(
                        self,
                        error,
                        conn,
                        "open checker exec failed: {e}";
                        "error" => format!("{e}")
                    );
                }
            }
        }

        {
            let clock = conn.clock();
            let mut ht = lock!(clock.timers.hold);
            let mut kt = lock!(clock.timers.keepalive);
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
        session_log!(
            self,
            trace,
            conn,
            "sending keepalive";
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
            conn_timer!(conn, keepalive).restart();
        }
    }

    fn send_route_refresh(&self, conn: &Cnx, af: Afi) {
        session_log!(
            self,
            info,
            conn,
            "sending route refresh";
            "message" => "route refresh"
        );
        let rr = Message::RouteRefresh(RouteRefreshMessage {
            afi: af as u16,
            safi: Safi::Unicast as u8,
        });
        if let Err(e) = conn.send(rr) {
            session_log!(
                self,
                error,
                conn,
                "failed to send route refresh: {e}";
                "error" => format!("{e}")
            );
            self.counters
                .route_refresh_send_failure
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters
                .route_refresh_sent
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

        session_log!(
            self,
            info,
            conn,
            "sending notification: {error_code} / {error_subcode}";
            "message" => "notification",
            "message_contents" => format!("{notification}")
        );

        let msg = Message::Notification(notification);
        lock!(self.message_history).send(msg.clone(), *conn.id());

        if let Err(e) = conn.send(msg) {
            session_log!(
                self,
                error,
                conn,
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
        // pull hold_time from config, not the clock
        let hold_time = lock!(self.session).hold_time;
        let mut msg = match self.asn {
            Asn::FourOctet(asn) => {
                OpenMessage::new4(asn, hold_time.as_secs() as u16, self.id)
            }
            Asn::TwoOctet(asn) => {
                OpenMessage::new2(asn, hold_time.as_secs() as u16, self.id)
            }
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
                    session_log!(
                        self,
                        error,
                        conn,
                        "open shaper exec failed: {e}";
                        "error" => format!("{e}")
                    );
                }
            }
        }
        drop(msg);
        lock!(self.message_history).send(out.clone(), *conn.id());

        self.counters.opens_sent.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = conn.send(out) {
            session_log!(
                self,
                error,
                conn,
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
        // Query the registry's primary connection
        if let Some(ConnectionKind::Full(pc)) =
            lock!(self.connection_registry).primary()
        {
            if pc.asn != self.asn.as_u32() {
                return Some(true);
            } else {
                return Some(false);
            }
        }
        None
    }

    fn is_ibgp(&self) -> Option<bool> {
        // Query the registry's primary connection
        if let Some(ConnectionKind::Full(pc)) =
            lock!(self.connection_registry).primary()
        {
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

    /// Derive the next-hop used in Updates carrying NLRI of this AFI/SAFI.
    /// This is a wrapper of select_nexthop which collects all the relevant
    /// state and config needed for the actual selection to occur.
    fn derive_nexthop(
        &self,
        nlri_afi: Afi,
        pc: &PeerConnection<Cnx>,
    ) -> Result<BgpNexthop, Error> {
        let configured_nexthop = match nlri_afi {
            Afi::Ipv4 => lock!(self.session)
                .ipv4_unicast
                .as_ref()
                .and_then(|cfg| cfg.nexthop),
            Afi::Ipv6 => lock!(self.session)
                .ipv6_unicast
                .as_ref()
                .and_then(|cfg| cfg.nexthop),
        };

        select_nexthop(nlri_afi, pc.conn.local().ip(), configured_nexthop)
    }

    /// Add peer-specific path attributes to an UPDATE message.
    /// This adds MED, LOCAL_PREF, and Communities based on session configuration.
    fn enrich_update(
        &self,
        update: &mut UpdateMessage,
        _pc: &PeerConnection<Cnx>,
    ) -> Result<(), Error> {
        let session = lock!(self.session);

        // Add MED if configured
        if let Some(med) = session.multi_exit_discriminator {
            update
                .path_attributes
                .push(PathAttributeValue::MultiExitDisc(med).into());
        }

        // Add LOCAL_PREF for iBGP
        if self.is_ibgp().unwrap_or(false) {
            let local_pref = session.local_pref.unwrap_or(0);
            update
                .path_attributes
                .push(PathAttributeValue::LocalPref(local_pref).into());
        }

        // Add communities
        let communities: Vec<Community> = session
            .communities
            .clone()
            .into_iter()
            .map(Community::from)
            .collect();

        if !communities.is_empty() {
            update
                .path_attributes
                .push(PathAttributeValue::Communities(communities).into());
        }

        Ok(())
    }

    /// Apply export policy filtering to UPDATE message.
    /// Filters NLRI based on per-AF export policy configuration.
    fn apply_export_policy(
        &self,
        update: &mut UpdateMessage,
    ) -> Result<(), Error> {
        let session = lock!(self.session);

        // Filter traditional NLRI field (IPv4) using IPv4 export policy
        if let Some(config4) = &session.ipv4_unicast
            && let ImportExportPolicy4::Allow(ref policy4) =
                config4.export_policy
        {
            update.nlri.retain(|p| policy4.contains(p));
        }

        // Filter MP_REACH_NLRI using the appropriate per-AF policy
        if let Some(reach) = update.mp_reach_mut() {
            match reach {
                MpReachNlri::Ipv4Unicast(reach4) => {
                    if let Some(config4) = &session.ipv4_unicast
                        && let ImportExportPolicy4::Allow(ref policy4) =
                            config4.export_policy
                    {
                        reach4.nlri.retain(|p| policy4.contains(p));
                    }
                }
                MpReachNlri::Ipv6Unicast(reach6) => {
                    if let Some(config6) = &session.ipv6_unicast
                        && let ImportExportPolicy6::Allow(ref policy6) =
                            config6.export_policy
                    {
                        reach6.nlri.retain(|p| policy6.contains(p));
                    }
                }
            }
        }

        Ok(())
    }

    /// Build and send a peer-specific UPDATE message.
    ///
    /// This constructs UPDATE messages from type-safe routes and handles:
    /// - Peer-specific next-hop derivation
    /// - AFI-specific encoding (Traditional for IPv4, MP-BGP for IPv6)
    /// - Addition of session-specific attributes (MED, LOCAL_PREF, Communities)
    /// - Export policy filtering
    /// - Shaper policy application
    ///
    /// # Arguments
    /// * `route_update` - Type-safe route update (V4 or V6)
    /// * `pc` - Peer connection (provides next-hop and enrichment context)
    /// * `shaper_application` - How to apply export shaper policy
    fn send_update(
        &self,
        route_update: RouteUpdate,
        pc: &PeerConnection<Cnx>,
        shaper_application: ShaperApplication,
    ) -> Result<(), Error> {
        // XXX: Handle more originated routes than can fit in a single Update

        // Early exit if nothing to send
        if route_update.is_empty() {
            return Ok(());
        }

        // Build the UpdateMessage based on variant. RFC 7606 compliance:
        // Each RouteUpdate is either an announcement OR withdrawal, never both.
        let mut update = match route_update {
            RouteUpdate::V4(RouteUpdate4::Announce(nlri)) => {
                let nh4 = match self.derive_nexthop(Afi::Ipv4, pc)? {
                    BgpNexthop::Ipv4(addr) => addr,
                    _ => {
                        return Err(Error::InvalidAddress(
                            "IPv4 routes require IPv4 next-hop".into(),
                        ));
                    }
                };

                let mut path_attributes = self.router.base_attributes();
                path_attributes.push(PathAttributeValue::NextHop(nh4).into());

                UpdateMessage {
                    withdrawn: vec![],
                    path_attributes,
                    nlri,
                    ..Default::default()
                }
            }
            RouteUpdate::V4(RouteUpdate4::Withdraw(withdrawn)) => {
                // Traditional withdrawals don't need path attributes
                UpdateMessage {
                    withdrawn,
                    path_attributes: vec![],
                    nlri: vec![],
                    ..Default::default()
                }
            }
            RouteUpdate::V6(RouteUpdate6::Announce(nlri)) => {
                let nh6 = self.derive_nexthop(Afi::Ipv6, pc)?;
                if matches!(nh6, BgpNexthop::Ipv4(_)) {
                    return Err(Error::InvalidAddress(
                        "IPv6 routes require IPv6 next-hop".into(),
                    ));
                }

                let mut path_attrs = self.router.base_attributes();
                let reach = MpReachNlri::ipv6_unicast(nh6, nlri);
                path_attrs.push(PathAttributeValue::MpReachNlri(reach).into());

                UpdateMessage {
                    withdrawn: vec![],
                    path_attributes: path_attrs,
                    nlri: vec![],
                    ..Default::default()
                }
            }
            RouteUpdate::V6(RouteUpdate6::Withdraw(withdrawn)) => {
                // MP_UNREACH_NLRI for IPv6 withdrawals
                let unreach = MpUnreachNlri::ipv6_unicast(withdrawn);
                let path_attrs =
                    vec![PathAttributeValue::MpUnreachNlri(unreach).into()];

                UpdateMessage {
                    withdrawn: vec![],
                    path_attributes: path_attrs,
                    nlri: vec![],
                    ..Default::default()
                }
            }
        };

        // 3. Add peer-specific enrichments
        self.enrich_update(&mut update, pc)?;

        // 4. Apply export policy filtering
        self.apply_export_policy(&mut update)?;

        // Check if update was completely filtered out
        let has_content = !update.nlri.is_empty()
            || !update.withdrawn.is_empty()
            || update.path_attributes.iter().any(|a| {
                matches!(
                    a.value,
                    PathAttributeValue::MpReachNlri(_)
                        | PathAttributeValue::MpUnreachNlri(_)
                )
            });

        if !has_content {
            session_log!(
                self,
                debug,
                pc.conn,
                "update completely filtered by export policy";
            );
            return Ok(());
        }

        // 5. Apply shaper policy
        let shaped_update =
            match self.shape_update(update, shaper_application)? {
                ShaperResult::Emit(msg) => msg,
                ShaperResult::Drop => {
                    session_log!(
                        self,
                        debug,
                        pc.conn,
                        "update dropped by shaper policy";
                    );
                    return Ok(());
                }
            };

        // 6. Send the message
        self.send_update_message(shaped_update, pc)
    }

    /// Send a pre-constructed UPDATE message to peer.
    /// This is the LOW-LEVEL send operation extracted from old send_update().
    fn send_update_message(
        &self,
        update: Message,
        pc: &PeerConnection<Cnx>,
    ) -> Result<(), Error> {
        // Record in message history
        lock!(self.message_history).send(update.clone(), *pc.conn.id());

        // Update counters
        self.counters.updates_sent.fetch_add(1, Ordering::Relaxed);

        // Log
        session_log!(
            self,
            info,
            pc.conn,
            "sending update";
            "message" => "update",
            "message_contents" => format!("{update}")
        );

        // Send
        if let Err(e) = pc.conn.send(update) {
            session_log!(
                self,
                error,
                pc.conn,
                "failed to send update: {e}";
                "error" => format!("{e}")
            );
            self.counters
                .update_send_failure
                .fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }

        Ok(())
    }

    fn transition_from_idle(&self) -> FsmState<Cnx> {
        // peer is passive
        if lock!(self.session).passive_tcp_establishment {
            session_timer!(self, connect_retry).stop();
            return FsmState::Active;
        }

        // peer is active
        session_timer!(self, connect_retry).restart();
        session_log_lite!(self, debug, "starting connect attempt";);
        // Evaluate timeout before calling to avoid holding timer lock
        let timeout = connect_timeout!(self);
        self.initiate_connection(timeout);
        FsmState::Connect
    }

    /// Remove prefixes received from the session peer from our RIB and issue a
    /// withdraw to the peer.
    fn cleanup_established(&self, pc: &PeerConnection<Cnx>) {
        conn_timer!(pc.conn, hold).disable();
        conn_timer!(pc.conn, keepalive).disable();
        session_timer!(self, connect_retry).stop();
        self.connect_retry_counter.fetch_add(1, Ordering::Relaxed);

        if pc.ipv4_unicast.negotiated() {
            write_lock!(self.fanout4).remove_egress(self.neighbor.host.ip());
        }
        if pc.ipv6_unicast.negotiated() {
            write_lock!(self.fanout6).remove_egress(self.neighbor.host.ip());
        }

        // remove peer prefixes from db
        self.db.remove_bgp_prefixes_from_peer(&pc.conn.peer().ip());
    }

    /// Exit the established state into Idle.
    fn exit_established(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        self.cleanup_established(&pc);
        FsmState::Idle
    }

    fn bump_msg_counter(&self, msg: MessageKind, unexpected: bool) {
        match msg {
            MessageKind::Open => {
                self.counters.opens_received.fetch_add(1, Ordering::Relaxed);
            }
            MessageKind::Notification => {
                self.counters
                    .notifications_received
                    .fetch_add(1, Ordering::Relaxed);
            }
            MessageKind::KeepAlive => {
                self.counters
                    .keepalives_received
                    .fetch_add(1, Ordering::Relaxed);
            }
            MessageKind::Update => {
                self.counters
                    .updates_received
                    .fetch_add(1, Ordering::Relaxed);
            }
            MessageKind::RouteRefresh => {
                self.counters
                    .route_refresh_received
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

    /// Helper method to centralize the cleanup process for connections needing
    /// to be stopped. When looking at the FSM description in RFC 4271, there
    /// are a lot of commonalities as to what items need to be updated upon a
    /// given error condition, regardless of what FSM state that error condition
    /// was encountered in. This method is intended to centralize many of these
    /// situations into a single location. The StopReason enum is used to
    /// indicate which condition was encountered so we know what set of items
    /// need to be updated.
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
                session_timer!(self, connect_retry).stop();
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
                session_timer!(self, connect_retry).stop();
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
                session_timer!(self, connect_retry).stop();
            }

            StopReason::HoldTimeExpired => {
                if let Some(c1) = conn1 {
                    self.send_hold_timer_expired_notification(c1);
                    conn_timer!(c1, hold).disable();
                }
                if let Some(c2) = conn2 {
                    self.send_hold_timer_expired_notification(c2);
                    conn_timer!(c2, hold).disable();
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
                session_timer!(self, connect_retry).stop();
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
            StopReason::IoError => {}

            StopReason::ParseError {
                error_code,
                error_subcode,
            } => {
                if let Some(c1) = conn1 {
                    self.send_notification(c1, error_code, error_subcode);
                }
                if let Some(c2) = conn2 {
                    self.send_notification(c2, error_code, error_subcode);
                }
                self.counters
                    .connect_retry_counter
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .connection_retries
                    .fetch_add(1, Ordering::Relaxed);
                session_timer!(self, connect_retry).stop();
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
            session_log!(
                self,
                warn,
                pc.conn,
                "update check failed: {e}";
                "error" => format!("{e}"),
                "message" => "update",
                "message_contents" => format!("{update}")
            );
            return;
        }

        // Filter MP-BGP attributes based on negotiation state.
        // Attributes for unnegotiated AFI/SAFIs are silently removed.
        // Note: This function currently never fails, but we keep the error
        // handling pattern for future extensibility.
        if let Err(e) = self.check_afi_safi_negotiation(&mut update, pc) {
            session_log!(
                self,
                error,
                pc.conn,
                "AFI/SAFI negotiation check failed: {e}";
                "error" => format!("{e}"),
                "message" => "update"
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
                    session_log!(
                        self,
                        error,
                        pc.conn,
                        "open checker exec failed: {e}";
                        "error" => format!("{e}")
                    );
                }
            }
        }

        {
            let session = lock!(self.session);

            // Filter traditional NLRI field (IPv4) using IPv4 import policy
            if let Some(config4) = &session.ipv4_unicast
                && let ImportExportPolicy4::Allow(ref policy4) =
                    config4.import_policy
            {
                update.nlri.retain(|p| policy4.contains(p));
            }

            // Filter MP_REACH_NLRI using the appropriate per-AF policy
            if let Some(reach) = update.mp_reach_mut() {
                match reach {
                    MpReachNlri::Ipv4Unicast(reach4) => {
                        if let Some(config4) = &session.ipv4_unicast
                            && let ImportExportPolicy4::Allow(ref policy4) =
                                config4.import_policy
                        {
                            reach4.nlri.retain(|p| policy4.contains(p));
                        }
                    }
                    MpReachNlri::Ipv6Unicast(reach6) => {
                        if let Some(config6) = &session.ipv6_unicast
                            && let ImportExportPolicy6::Allow(ref policy6) =
                                config6.import_policy
                        {
                            reach6.nlri.retain(|p| policy6.contains(p));
                        }
                    }
                }
            }
        }

        self.update_rib(&update, pc);

        // NOTE: for now we are only acting as an edge router. This means we
        //       do not redistribute announcements. If this changes, uncomment
        //       the following to enable redistribution.
        //
        //    self.fanout_update(&update);
    }

    /// Filter MP-BGP attributes based on AFI/SAFI negotiation state.
    ///
    /// This checks whether the AFI/SAFI in MP_REACH_NLRI and MP_UNREACH_NLRI
    /// attributes was negotiated with the peer during capability exchange.
    /// Attributes for unnegotiated AFI/SAFIs are silently filtered out
    /// (logged as warnings but not treated as errors).
    ///
    /// This approach aligns with RFC 4760 Section 7's "AFI/SAFI disable"
    /// concept: routes for unnegotiated address families are simply ignored.
    ///
    /// ## Note on Error Handling
    ///
    /// Structural errors (duplicate attributes, malformed wire format,
    /// unsupported AFI/SAFI values) are caught during parsing in
    /// `UpdateMessage::from_wire()` and `connection_tcp.rs`, which triggers
    /// appropriate error handling per RFC 7606. This function only handles
    /// the negotiation state check.
    fn check_afi_safi_negotiation(
        &self,
        update: &mut UpdateMessage,
        pc: &PeerConnection<Cnx>,
    ) -> Result<(), Error> {
        // We'll rebuild the attributes list, filtering out unnegotiated AFI/SAFIs.
        // Note: AFI/SAFI and NLRI validation happens during parsing (from_wire),
        // so we only need to check negotiation state here.
        let mut validated_attributes = Vec::new();

        for attr in &update.path_attributes {
            match &attr.value {
                PathAttributeValue::MpReachNlri(mp_reach) => {
                    // AFI/SAFI and nexthop/NLRI are already validated during
                    // parsing (from_wire). We only need to check negotiation.
                    let afi = mp_reach.afi();
                    let safi = mp_reach.safi();

                    // RFC 4760 §3: Check reserved byte (must be 0, but must be ignored)
                    let reserved = match mp_reach {
                        crate::messages::MpReachNlri::Ipv4Unicast(inner) => {
                            inner.reserved
                        }
                        crate::messages::MpReachNlri::Ipv6Unicast(inner) => {
                            inner.reserved
                        }
                    };
                    if reserved != 0 {
                        session_log!(
                            self,
                            warn,
                            pc.conn,
                            "MP_REACH_NLRI reserved byte is non-zero: {} (RFC 2858 'Number of SNPAs', obsoleted by RFC 4760)",
                            reserved;
                        );
                    }

                    // Check if AFI/SAFI was negotiated
                    let afi_state = match (afi, safi) {
                        (Afi::Ipv4, Safi::Unicast) => pc.ipv4_unicast,
                        (Afi::Ipv6, Safi::Unicast) => pc.ipv6_unicast,
                    };

                    if !afi_state.negotiated() {
                        session_log!(
                            self,
                            warn,
                            pc.conn,
                            "MP_REACH_NLRI for unnegotiated AFI/SAFI: {}/{}",
                            afi, safi;
                        );

                        // Don't send notification - just filter silently
                        continue;
                    }

                    // The attribute is already validated, keep it
                    validated_attributes.push(attr.clone());
                }

                PathAttributeValue::MpUnreachNlri(mp_unreach) => {
                    // AFI/SAFI and withdrawn routes are already validated during
                    // parsing (from_wire). We only need to check negotiation.
                    let afi = mp_unreach.afi();
                    let safi = mp_unreach.safi();

                    // Check if AFI/SAFI was negotiated
                    let afi_state = match (afi, safi) {
                        (Afi::Ipv4, Safi::Unicast) => pc.ipv4_unicast,
                        (Afi::Ipv6, Safi::Unicast) => pc.ipv6_unicast,
                    };

                    if !afi_state.negotiated() {
                        session_log!(
                            self,
                            warn,
                            pc.conn,
                            "MP_UNREACH_NLRI for unnegotiated AFI/SAFI: {}/{}",
                            afi, safi;
                        );

                        // Don't send notification - just filter silently
                        continue;
                    }

                    // The attribute is already validated, keep it
                    validated_attributes.push(attr.clone());
                }

                _ => {
                    // Keep all other attributes as-is
                    validated_attributes.push(attr.clone());
                }
            }
        }

        update.path_attributes = validated_attributes;
        Ok(())
    }

    pub fn refresh_react4(
        &self,
        pc: &PeerConnection<Cnx>,
    ) -> Result<(), Error> {
        let originated = match self.db.get_origin4() {
            Ok(value) => value,
            Err(e) => {
                session_log!(
                    self,
                    error,
                    pc.conn,
                    "failed to get originated IPv4 routes from db";
                    "error" => format!("{e}")
                );
                // This is not a protocol level issue
                return Ok(());
            }
        };

        if !originated.is_empty() {
            self.send_update(
                RouteUpdate::V4(RouteUpdate4::Announce(originated)),
                pc,
                ShaperApplication::Current,
            )?;
        }
        Ok(())
    }

    pub fn refresh_react6(
        &self,
        pc: &PeerConnection<Cnx>,
    ) -> Result<(), Error> {
        let originated = match self.db.get_origin6() {
            Ok(value) => value,
            Err(e) => {
                session_log!(
                    self,
                    error,
                    pc.conn,
                    "failed to get originated IPv6 routes from db";
                    "error" => format!("{e}")
                );
                // This is not a protocol level issue
                return Ok(());
            }
        };

        if !originated.is_empty() {
            self.send_update(
                RouteUpdate::V6(RouteUpdate6::Announce(originated)),
                pc,
                ShaperApplication::Current,
            )?;
        }
        Ok(())
    }

    fn refresh_react(
        &self,
        af: Afi,
        pc: &PeerConnection<Cnx>,
    ) -> Result<(), Error> {
        match af {
            Afi::Ipv4 => self.refresh_react4(pc),
            Afi::Ipv6 => self.refresh_react6(pc),
        }
    }

    fn handle_refresh(
        &self,
        msg: RouteRefreshMessage,
        pc: &PeerConnection<Cnx>,
    ) -> Result<(), Error> {
        if msg.safi != Safi::Unicast as u8 {
            return Err(Error::UnsupportedAddressFamily(msg.afi, msg.safi));
        }

        let af = match Afi::try_from(msg.afi) {
            Ok(afi) => afi,
            Err(_) => {
                return Err(Error::UnsupportedAddressFamily(msg.afi, msg.safi));
            }
        };

        self.refresh_react(af, pc)
    }

    /// Update this router's RIB based on an update message from a peer.
    fn update_rib(&self, update: &UpdateMessage, pc: &PeerConnection<Cnx>) {
        let originated4 = match self.db.get_origin4() {
            Ok(value) => value,
            Err(e) => {
                session_log!(
                    self,
                    error,
                    pc.conn,
                    "failed to get originated ipv4 routes from db: {e}";
                    "error" => format!("{e}")
                );
                Vec::new()
            }
        };

        let nexthop = match update.nexthop() {
            Ok(nh) => match nh {
                BgpNexthop::Ipv4(ip4) => IpAddr::V4(ip4),
                BgpNexthop::Ipv6Single(ip6) => IpAddr::V6(ip6),
                BgpNexthop::Ipv6Double(addrs) => IpAddr::V6(addrs.global),
            },
            Err(e) => {
                session_log!(
                    self,
                    warn,
                    pc.conn,
                    "error parsing nexthop from update: {e}";
                    "error" => format!("{e}"),
                    "message" => "update",
                    "message_contents" => format!("{update}").as_str()
                );
                self.counters
                    .update_nexhop_missing
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        let withdrawn: Vec<Prefix> = update
            .withdrawn
            .iter()
            .filter(|p| !originated4.contains(p) && p.valid_for_rib())
            .copied()
            .map(Prefix::V4)
            .collect();

        self.db
            .remove_bgp_prefixes(&withdrawn, &pc.conn.peer().ip());

        let nlri: Vec<Prefix> = update
            .nlri
            .iter()
            .filter(|p| {
                !originated4.contains(p)
                    && p.valid_for_rib()
                    && !self.prefix_via_self(Prefix::V4(**p), nexthop)
            })
            .copied()
            .map(Prefix::V4)
            .collect();

        if !nlri.is_empty() {
            let mut as_path = Vec::new();
            if let Some(segments_list) = update.as_path() {
                for segments in &segments_list {
                    as_path.extend(segments.value.iter());
                }
            }
            let path = rdb::Path {
                nexthop,
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

            self.db.add_bgp_prefixes(&nlri, path.clone());
        }

        // Process MP_REACH_NLRI for IPv4 and IPv6 routes
        if let Some(reach) = update.mp_reach() {
            match reach {
                MpReachNlri::Ipv4Unicast(reach4) => {
                    let mp_nexthop = match &reach4.nexthop {
                        BgpNexthop::Ipv4(ip4) => IpAddr::V4(*ip4),
                        BgpNexthop::Ipv6Single(ip6) => IpAddr::V6(*ip6),
                        BgpNexthop::Ipv6Double(addrs) => {
                            IpAddr::V6(addrs.global)
                        }
                    };

                    let mp_nlri4: Vec<Prefix> = reach4
                        .nlri
                        .iter()
                        .filter(|p| {
                            !originated4.contains(p)
                                && p.valid_for_rib()
                                && !self.prefix_via_self(
                                    Prefix::V4(**p),
                                    mp_nexthop,
                                )
                        })
                        .copied()
                        .map(Prefix::V4)
                        .collect();

                    if !mp_nlri4.is_empty() {
                        let mut as_path = Vec::new();
                        if let Some(segments_list) = update.as_path() {
                            for segments in &segments_list {
                                as_path.extend(segments.value.iter());
                            }
                        }
                        let path4 = rdb::Path {
                            nexthop: mp_nexthop,
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

                        self.db.add_bgp_prefixes(&mp_nlri4, path4);
                    }
                }
                MpReachNlri::Ipv6Unicast(reach6) => {
                    let originated6 = match self.db.get_origin6() {
                        Ok(value) => value,
                        Err(e) => {
                            session_log!(
                                self,
                                error,
                                pc.conn,
                                "failed to get originated ipv6 routes from db: {e}";
                                "error" => format!("{e}")
                            );
                            Vec::new()
                        }
                    };

                    let nexthop6 = match &reach6.nexthop {
                        BgpNexthop::Ipv6Single(ip6) => IpAddr::V6(*ip6),
                        BgpNexthop::Ipv6Double(addrs) => {
                            IpAddr::V6(addrs.global)
                        }
                        BgpNexthop::Ipv4(ip4) => {
                            // IPv4 nexthop for IPv6 routes is unusual but possible
                            // in some configurations (e.g., IPv4-mapped IPv6)
                            session_log!(
                                self,
                                warn,
                                pc.conn,
                                "IPv4 nexthop in IPv6 MP_REACH_NLRI";
                                "nexthop" => format!("{ip4}")
                            );
                            IpAddr::V4(*ip4)
                        }
                    };

                    let nlri6: Vec<Prefix> = reach6
                        .nlri
                        .iter()
                        .filter(|p| {
                            !originated6.contains(p)
                                && p.valid_for_rib()
                                && !self
                                    .prefix_via_self(Prefix::V6(**p), nexthop6)
                        })
                        .copied()
                        .map(Prefix::V6)
                        .collect();

                    if !nlri6.is_empty() {
                        let mut as_path = Vec::new();
                        if let Some(segments_list) = update.as_path() {
                            for segments in &segments_list {
                                as_path.extend(segments.value.iter());
                            }
                        }
                        let path6 = rdb::Path {
                            nexthop: nexthop6,
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

                        self.db.add_bgp_prefixes(&nlri6, path6);
                    }
                }
            }
        }

        // Process MP_UNREACH_NLRI for IPv4 and IPv6 withdrawals
        if let Some(unreach) = update.mp_unreach() {
            match unreach {
                MpUnreachNlri::Ipv4Unicast(unreach4) => {
                    let mp_withdrawn4: Vec<Prefix> = unreach4
                        .withdrawn
                        .iter()
                        .filter(|p| {
                            !originated4.contains(p) && p.valid_for_rib()
                        })
                        .copied()
                        .map(Prefix::V4)
                        .collect();

                    self.db.remove_bgp_prefixes(
                        &mp_withdrawn4,
                        &pc.conn.peer().ip(),
                    );
                }
                MpUnreachNlri::Ipv6Unicast(unreach6) => {
                    let originated6 = match self.db.get_origin6() {
                        Ok(value) => value,
                        Err(e) => {
                            session_log!(
                                self,
                                error,
                                pc.conn,
                                "failed to get originated ipv6 routes for withdrawal: {e}";
                                "error" => format!("{e}")
                            );
                            Vec::new()
                        }
                    };

                    let withdrawn6: Vec<Prefix> = unreach6
                        .withdrawn
                        .iter()
                        .filter(|p| {
                            !originated6.contains(p) && p.valid_for_rib()
                        })
                        .copied()
                        .map(Prefix::V6)
                        .collect();

                    self.db
                        .remove_bgp_prefixes(&withdrawn6, &pc.conn.peer().ip());
                }
            }
        }
    }

    /// Perform a set of checks on an update to see if we can accept it.
    fn check_update(
        &self,
        update: &UpdateMessage,
        peer_as: u32,
    ) -> Result<(), Error> {
        // Path vector routing and prefix validation
        self.check_for_self_in_path(update)?;

        // Optional enforce-first-AS validation
        let info = lock!(self.session);
        if info.enforce_first_as {
            self.enforce_first_as(update, peer_as)?;
        }
        Ok(())
    }

    fn apply_static_update_policy(&self, update: &mut UpdateMessage) {
        if self.is_ebgp().unwrap_or(false) {
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

    /// Do not accept routes advertised with themselves as the next-hop.
    /// e.g.
    /// Do not allow 2001::1/32 with a nexthop of 2001::1
    fn prefix_via_self(&self, prefix: Prefix, nexthop: IpAddr) -> bool {
        match (prefix, nexthop) {
            (Prefix::V4(p4), IpAddr::V4(ip4)) => {
                p4.length == Prefix4::HOST_MASK && p4.value == ip4
            }
            (Prefix::V6(p6), IpAddr::V6(ip6)) => {
                p6.length == Prefix6::HOST_MASK && p6.value == ip6
            }
            _ => false,
        }
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

    /// Return the current BGP peer state of this session runner.
    pub fn state(&self) -> FsmStateKind {
        *lock!(self.state)
    }

    /// Return the learned remote ASN of the peer (if any).
    pub fn remote_asn(&self) -> Option<u32> {
        // Query the registry's primary connection
        if let Some(ConnectionKind::Full(pc)) =
            lock!(self.connection_registry).primary()
        {
            return Some(pc.asn);
        }
        None
    }

    /// Return the learned remote BGP-ID of the peer (if any).
    pub fn remote_id(&self) -> Option<u32> {
        // Query the registry's primary connection
        if let Some(ConnectionKind::Full(pc)) =
            lock!(self.connection_registry).primary()
        {
            return Some(pc.id);
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

            session_timer!(self, idle_hold).interval =
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
        let mut readvertise_needed4 = false;
        let mut readvertise_needed6 = false;
        let mut refresh_needed4 = false;
        let mut refresh_needed6 = false;
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
            readvertise_needed4 = true;
            readvertise_needed6 = true;
        }

        if current.communities != info.communities {
            current.communities.clone_from(&info.communities);
            readvertise_needed4 = true;
            readvertise_needed6 = true;
        }

        if current.local_pref != info.local_pref {
            current.local_pref = info.local_pref;
            refresh_needed4 = true;
            refresh_needed6 = true;
        }

        if current.enforce_first_as != info.enforce_first_as {
            current.enforce_first_as = info.enforce_first_as;
            // XXX: handle more gracefully.
            //      disabling = send route refresh
            //      enabling = run rib walker + delete paths failing check
            reset_needed = true;
        }

        // Handle per-AF import policy changes (trigger route refresh)
        if current.ipv4_unicast.as_ref().map(|c| &c.import_policy)
            != info.ipv4_unicast.as_ref().map(|c| &c.import_policy)
        {
            current.ipv4_unicast = info.ipv4_unicast.clone();
            refresh_needed4 = true;
        }

        if current.ipv6_unicast.as_ref().map(|c| &c.import_policy)
            != info.ipv6_unicast.as_ref().map(|c| &c.import_policy)
        {
            current.ipv6_unicast = info.ipv6_unicast.clone();
            refresh_needed6 = true;
        }

        // Handle per-AF nexthop override changes (trigger re-advertisement)
        if current.ipv4_unicast.as_ref().map(|c| c.nexthop)
            != info.ipv4_unicast.as_ref().map(|c| c.nexthop)
        {
            current.ipv4_unicast = info.ipv4_unicast.clone();
            readvertise_needed4 = true;
        }

        if current.ipv6_unicast.as_ref().map(|c| c.nexthop)
            != info.ipv6_unicast.as_ref().map(|c| c.nexthop)
        {
            current.ipv6_unicast = info.ipv6_unicast.clone();
            readvertise_needed6 = true;
        }

        if current.vlan_id != info.vlan_id {
            current.vlan_id = info.vlan_id;
            reset_needed = true;
        }

        // Update jitter settings (no session reset required)
        if current.connect_retry_jitter != info.connect_retry_jitter {
            current.connect_retry_jitter = info.connect_retry_jitter;
            lock!(self.clock.timers.connect_retry)
                .set_jitter_range(info.connect_retry_jitter);
        }

        if current.idle_hold_jitter != info.idle_hold_jitter {
            current.idle_hold_jitter = info.idle_hold_jitter;
            lock!(self.clock.timers.idle_hold)
                .set_jitter_range(info.idle_hold_jitter);
        }

        // Handle per-AF export policy changes
        if current.ipv4_unicast.as_ref().map(|c| &c.export_policy)
            != info.ipv4_unicast.as_ref().map(|c| &c.export_policy)
        {
            if let Some(previous4) = current
                .ipv4_unicast
                .as_ref()
                .map(|c| c.export_policy.clone())
            {
                current.ipv4_unicast = info.ipv4_unicast.clone();
                self.event_tx
                    .send(FsmEvent::Admin(AdminEvent::ExportPolicyChanged(
                        TypedImportExportPolicy::V4(previous4),
                    )))
                    .map_err(|e| Error::EventSend(e.to_string()))?;
            } else {
                current.ipv4_unicast = info.ipv4_unicast.clone();
            }
        }

        if current.ipv6_unicast.as_ref().map(|c| &c.export_policy)
            != info.ipv6_unicast.as_ref().map(|c| &c.export_policy)
        {
            if let Some(previous6) = current
                .ipv6_unicast
                .as_ref()
                .map(|c| c.export_policy.clone())
            {
                current.ipv6_unicast = info.ipv6_unicast.clone();
                self.event_tx
                    .send(FsmEvent::Admin(AdminEvent::ExportPolicyChanged(
                        TypedImportExportPolicy::V6(previous6),
                    )))
                    .map_err(|e| Error::EventSend(e.to_string()))?;
            } else {
                current.ipv6_unicast = info.ipv6_unicast.clone();
            }
        }

        drop(current);

        if readvertise_needed4 {
            self.event_tx
                .send(FsmEvent::Admin(AdminEvent::ReAdvertiseRoutes(Afi::Ipv4)))
                .map_err(|e| Error::EventSend(e.to_string()))?;
        }

        if readvertise_needed6 {
            self.event_tx
                .send(FsmEvent::Admin(AdminEvent::ReAdvertiseRoutes(Afi::Ipv6)))
                .map_err(|e| Error::EventSend(e.to_string()))?;
        }

        if refresh_needed4 {
            self.event_tx
                .send(FsmEvent::Admin(AdminEvent::SendRouteRefresh(Afi::Ipv4)))
                .map_err(|e| Error::EventSend(e.to_string()))?;
        }

        if refresh_needed6 {
            self.event_tx
                .send(FsmEvent::Admin(AdminEvent::SendRouteRefresh(Afi::Ipv6)))
                .map_err(|e| Error::EventSend(e.to_string()))?;
        }

        Ok(reset_needed)
    }

    /// Get all registered connections
    pub fn all_connections(&self) -> Vec<ConnectionKind<Cnx>> {
        lock!(self.connection_registry)
            .all_connections()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get the primary (actively managed) connection, if one exists
    pub fn primary_connection(&self) -> Option<ConnectionKind<Cnx>> {
        lock!(self.connection_registry).primary().cloned()
    }

    /// Get the number of connections owned by this SessionRunner
    pub fn connection_count(&self) -> u8 {
        lock!(self.connection_registry).count()
    }

    fn get_counters(&self) -> PeerCounters {
        PeerCounters::from(self.counters.as_ref())
    }

    pub fn get_peer_info(&self) -> PeerInfo {
        let fsm_state = self.state();
        let dur = self.current_state_duration().as_millis() % u64::MAX as u128;
        let fsm_state_duration = dur as u64;
        let counters = self.get_counters();
        let name = lock!(self.neighbor.name).clone();
        let peer_group = self.neighbor.peer_group.clone();

        // Extract config and runtime state WITHOUT holding any locks long-term
        let (ipv4_unicast, ipv6_unicast, timer_config) = {
            let session_conf = lock!(self.session);
            let ipv4 = session_conf.ipv4_unicast.clone().unwrap_or(
                Ipv4UnicastConfig {
                    nexthop: None,
                    import_policy: Default::default(),
                    export_policy: Default::default(),
                },
            );
            let ipv6 = session_conf.ipv6_unicast.clone().unwrap_or(
                Ipv6UnicastConfig {
                    nexthop: None,
                    import_policy: Default::default(),
                    export_policy: Default::default(),
                },
            );
            let timers = TimerConfig::from_session_info(&session_conf);
            (ipv4, ipv6, timers)
        }; // Lock dropped here!

        // Get timer runtime state from clocks (no SessionInfo lock needed)
        let session_timers = self.clock.get_timer_snapshot();

        // Build PeerTimers from snapshots
        let timers = match self.primary_connection() {
            Some(primary) => {
                let conn_timers =
                    primary.connection().clock().get_timer_snapshot();
                PeerTimers {
                    hold: conn_timers.hold,
                    keepalive: conn_timers.keepalive,
                    connect_retry: StaticTimerInfo {
                        configured: timer_config.connect_retry_time,
                        remaining: session_timers.connect_retry_remaining,
                    },
                    connect_retry_jitter: session_timers.connect_retry_jitter,
                    idle_hold: StaticTimerInfo {
                        configured: timer_config.idle_hold_time,
                        remaining: session_timers.idle_hold_remaining,
                    },
                    idle_hold_jitter: session_timers.idle_hold_jitter,
                    delay_open: StaticTimerInfo {
                        configured: timer_config.delay_open_time,
                        remaining: conn_timers.delay_open_remaining,
                    },
                }
            }
            None => {
                // No connection - use configured values
                PeerTimers {
                    hold: DynamicTimerInfo {
                        configured: timer_config.hold_time,
                        negotiated: timer_config.hold_time,
                        remaining: timer_config.hold_time,
                    },
                    keepalive: DynamicTimerInfo {
                        configured: timer_config.keepalive_time,
                        negotiated: timer_config.keepalive_time,
                        remaining: timer_config.keepalive_time,
                    },
                    connect_retry: StaticTimerInfo {
                        configured: timer_config.connect_retry_time,
                        remaining: session_timers.connect_retry_remaining,
                    },
                    connect_retry_jitter: session_timers.connect_retry_jitter,
                    idle_hold: StaticTimerInfo {
                        configured: timer_config.idle_hold_time,
                        remaining: session_timers.idle_hold_remaining,
                    },
                    idle_hold_jitter: session_timers.idle_hold_jitter,
                    delay_open: StaticTimerInfo {
                        configured: timer_config.delay_open_time,
                        remaining: timer_config.delay_open_time,
                    },
                }
            }
        };

        // Build and return PeerInfo
        match self.primary_connection() {
            Some(pconn) => match pconn {
                ConnectionKind::Partial(conn) => {
                    let local = conn.local();
                    let remote = conn.peer();
                    PeerInfo {
                        name,
                        peer_group: peer_group.clone(),
                        fsm_state,
                        fsm_state_duration,
                        asn: None,
                        id: None,
                        local_ip: local.ip(),
                        remote_ip: remote.ip(),
                        local_tcp_port: local.port(),
                        remote_tcp_port: remote.port(),
                        received_capabilities: vec![],
                        timers,
                        counters,
                        ipv4_unicast,
                        ipv6_unicast,
                    }
                }
                ConnectionKind::Full(pc) => {
                    let local = pc.conn.local();
                    let remote = pc.conn.peer();
                    let received_capabilities =
                        pc.caps.iter().map(BgpCapability::from).collect();
                    PeerInfo {
                        name,
                        peer_group: peer_group.clone(),
                        fsm_state,
                        fsm_state_duration,
                        asn: Some(pc.asn),
                        id: Some(pc.id),
                        local_ip: local.ip(),
                        remote_ip: remote.ip(),
                        local_tcp_port: local.port(),
                        remote_tcp_port: remote.port(),
                        received_capabilities,
                        timers,
                        counters,
                        ipv4_unicast,
                        ipv6_unicast,
                    }
                }
            },
            None => {
                let remote_ip = self.neighbor.host.ip();
                // We don't have an active connection, so just display the
                // configured next-hop if it's set or use the unspec addr if not
                let local_ip = match remote_ip {
                    IpAddr::V4(_) => ipv4_unicast
                        .nexthop
                        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    IpAddr::V6(_) => ipv6_unicast
                        .nexthop
                        .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                };

                PeerInfo {
                    name,
                    peer_group: peer_group.clone(),
                    fsm_state,
                    fsm_state_duration,
                    asn: None,
                    id: None,
                    local_ip,
                    remote_ip,
                    local_tcp_port: 0u16,
                    remote_tcp_port: self.neighbor.host.port(),
                    received_capabilities: vec![],
                    timers,
                    counters,
                    ipv4_unicast,
                    ipv6_unicast,
                }
            }
        }
    }
}

// ============================================================================
// API Compatibility Types (VERSION_INITIAL / v1.0.0)
// ============================================================================
// These types maintain backward compatibility with the INITIAL API version.
// They support IPv4-only message history via the /bgp/message-history endpoint (v1).
// Never used internally - always convert from current types at API boundary.
//
// Delete these types when VERSION_INITIAL is retired.

// V1 API compatibility type for message history entry (IPv4-only with MessageV1)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistoryEntryV1 {
    timestamp: chrono::DateTime<chrono::Utc>,
    message: crate::messages::MessageV1,
}

impl From<MessageHistoryEntry> for MessageHistoryEntryV1 {
    fn from(entry: MessageHistoryEntry) -> Self {
        Self {
            timestamp: entry.timestamp,
            message: crate::messages::MessageV1::from(entry.message),
        }
    }
}

// V1 API compatibility type for message history collection
#[derive(Default, Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistoryV1 {
    pub received: VecDeque<MessageHistoryEntryV1>,
    pub sent: VecDeque<MessageHistoryEntryV1>,
}

impl From<MessageHistory> for MessageHistoryV1 {
    fn from(history: MessageHistory) -> Self {
        Self {
            received: history
                .received
                .into_iter()
                .map(MessageHistoryEntryV1::from)
                .collect(),
            sent: history
                .sent
                .into_iter()
                .map(MessageHistoryEntryV1::from)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_common::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_resolve_collision_decision() {
        use crate::connection::ConnectionDirection;
        use crate::session::collision_resolution;

        // Case 1: Local wins (higher BGP ID), Connector (ours) is exist
        // Local BGP ID (100) > Remote (50), exist is Connector (ours)
        // Expected: ExistWins
        assert_eq!(
            collision_resolution(
                ConnectionDirection::Outbound,
                100, // local
                50,  // remote
            ),
            CollisionResolution::ExistWins
        );

        // Case 2: Local wins, Dispatcher (theirs) is exist
        // Local BGP ID (100) > Remote (50), exist is Dispatcher (theirs), so new is Connector (ours)
        // Our connection wins, so NewWins
        // Expected: NewWins
        assert_eq!(
            collision_resolution(
                ConnectionDirection::Inbound,
                100, // local
                50,  // remote
            ),
            CollisionResolution::NewWins
        );

        // Case 3: Remote wins (higher BGP ID), Dispatcher (theirs) is exist
        // Local BGP ID (50) < Remote (100), exist is Dispatcher (theirs)
        // Expected: ExistWins
        assert_eq!(
            collision_resolution(
                ConnectionDirection::Inbound,
                50,  // local
                100, // remote
            ),
            CollisionResolution::ExistWins
        );

        // Case 4: Remote wins, Connector (theirs) is exist
        // Local BGP ID (50) < Remote (100), exist is Connector (theirs)
        // Expected: NewWins
        assert_eq!(
            collision_resolution(
                ConnectionDirection::Outbound,
                50,  // local
                100, // remote
            ),
            CollisionResolution::NewWins
        );
    }

    #[test]
    fn test_fsm_event_history_all_buffer_rolling() {
        let mut history = FsmEventHistory::new();

        // Fill beyond capacity (1024)
        for i in 0..1500 {
            let record = FsmEventRecord {
                timestamp: chrono::Utc::now(),
                event_category: FsmEventCategory::Connection,
                event_type: format!("Event {}", i),
                current_state: FsmStateKind::Established,
                previous_state: None,
                connection_id: None,
                details: None,
            };
            history.record_all(record);
        }

        // Should be capped at 1024
        assert_eq!(history.all.len(), MAX_FSM_HISTORY_ALL);

        // Most recent should be Event 1499
        assert_eq!(history.all.front().unwrap().event_type, "Event 1499");

        // Oldest should be Event 476 (1500 - 1024)
        assert_eq!(history.all.back().unwrap().event_type, "Event 476");
    }

    #[test]
    fn test_fsm_event_history_major_buffer_rolling() {
        let mut history = FsmEventHistory::new();

        // Fill beyond capacity (1024)
        for i in 0..1500 {
            let record = FsmEventRecord {
                timestamp: chrono::Utc::now(),
                event_category: FsmEventCategory::Admin,
                event_type: format!("Major {}", i),
                current_state: FsmStateKind::Idle,
                previous_state: None,
                connection_id: None,
                details: None,
            };
            history.record_major(record);
        }

        // Should be capped at 1024
        assert_eq!(history.major.len(), MAX_FSM_HISTORY_MAJOR);

        // Most recent should be Major 1499
        assert_eq!(history.major.front().unwrap().event_type, "Major 1499");

        // Oldest should be Major 476 (1500 - 1024)
        assert_eq!(history.major.back().unwrap().event_type, "Major 476");
    }

    #[test]
    fn test_fsm_event_history_major_filtering() {
        let mut history = FsmEventHistory::new();

        // Record 100 all events, 10 major
        for i in 0..100 {
            let record = FsmEventRecord {
                timestamp: chrono::Utc::now(),
                event_category: if i % 10 == 0 {
                    FsmEventCategory::Admin
                } else {
                    FsmEventCategory::Connection
                },
                event_type: format!("Event {}", i),
                current_state: FsmStateKind::Established,
                previous_state: None,
                connection_id: None,
                details: None,
            };
            let is_major = i % 10 == 0;
            history.record(record, is_major);
        }

        // All buffer should have all 100 events
        assert_eq!(history.all.len(), 100);

        // Major buffer should have only 10 events
        assert_eq!(history.major.len(), 10);

        // Verify major events are the ones divisible by 10
        for (idx, event) in history.major.iter().enumerate() {
            // Events are in reverse order (most recent first)
            let expected_num = 90 - (idx * 10);
            assert_eq!(event.event_type, format!("Event {}", expected_num));
        }
    }

    #[test]
    fn test_fsm_event_record_creation() {
        // Test that we can create records with all fields
        let record = FsmEventRecord {
            timestamp: chrono::Utc::now(),
            event_category: FsmEventCategory::StateTransition,
            event_type: "Idle -> Connect".to_string(),
            current_state: FsmStateKind::Connect,
            previous_state: Some(FsmStateKind::Idle),
            connection_id: None,
            details: Some("State transition".to_string()),
        };

        assert_eq!(record.event_type, "Idle -> Connect");
        assert_eq!(record.current_state, FsmStateKind::Connect);
        assert_eq!(record.previous_state, Some(FsmStateKind::Idle));
        assert!(record.details.is_some());
    }

    // =========================================================================
    // RouteUpdate tests
    // =========================================================================

    #[test]
    fn route_update_is_announcement_and_withdrawal() {
        let v4_announce =
            RouteUpdate::V4(RouteUpdate4::Announce(vec![Prefix4::new(
                ip!("10.0.0.0"),
                8,
            )]));
        assert!(v4_announce.is_announcement());
        assert!(!v4_announce.is_withdrawal());

        let v4_withdraw =
            RouteUpdate::V4(RouteUpdate4::Withdraw(vec![Prefix4::new(
                ip!("10.0.0.0"),
                8,
            )]));
        assert!(!v4_withdraw.is_announcement());
        assert!(v4_withdraw.is_withdrawal());

        let v6_announce =
            RouteUpdate::V6(RouteUpdate6::Announce(vec![Prefix6::new(
                ip!("2001:db8::"),
                32,
            )]));
        assert!(v6_announce.is_announcement());
        assert!(!v6_announce.is_withdrawal());

        let v6_withdraw =
            RouteUpdate::V6(RouteUpdate6::Withdraw(vec![Prefix6::new(
                ip!("2001:db8::"),
                32,
            )]));
        assert!(!v6_withdraw.is_announcement());
        assert!(v6_withdraw.is_withdrawal());
    }

    #[test]
    fn test_select_nexthop_ipv4_configured() {
        // When IPv4 nexthop is configured, it should be used (takes precedence)
        let configured_nh = ip!("10.0.0.1");
        let local_ip = ip!("10.0.0.2");

        let result = select_nexthop(Afi::Ipv4, local_ip, Some(configured_nh));
        assert!(result.is_ok());
        match result.unwrap() {
            BgpNexthop::Ipv4(addr) => {
                let expected: Ipv4Addr = ip!("10.0.0.1");
                assert_eq!(addr, expected);
            }
            _ => panic!("Expected IPv4 nexthop"),
        }
    }

    #[test]
    fn test_select_nexthop_ipv6_configured() {
        // When IPv6 nexthop is configured, it should be used (takes precedence)
        let configured_nh = ip!("2001:db8::1");
        let local_ip = ip!("2001:db8::2");

        let result = select_nexthop(Afi::Ipv6, local_ip, Some(configured_nh));
        assert!(result.is_ok());
        match result.unwrap() {
            BgpNexthop::Ipv6Single(addr) => {
                let expected: Ipv6Addr = ip!("2001:db8::1");
                assert_eq!(addr, expected);
            }
            _ => panic!("Expected IPv6 nexthop"),
        }
    }

    #[test]
    fn test_select_nexthop_ipv4_fallback_pure_ipv4() {
        // No nexthop configured, pure IPv4 local_ip should be used for IPv4 routes
        let local_ip = ip!("10.0.0.1");

        let result = select_nexthop(Afi::Ipv4, local_ip, None);
        assert!(result.is_ok());
        match result.unwrap() {
            BgpNexthop::Ipv4(addr) => {
                let expected: Ipv4Addr = ip!("10.0.0.1");
                assert_eq!(addr, expected);
            }
            _ => panic!("Expected IPv4 nexthop"),
        }
    }

    #[test]
    fn test_select_nexthop_ipv4_fallback_mapped_ipv4() {
        // No nexthop configured, IPv4-mapped IPv6 local_ip should be canonicalized
        // internally by select_nexthop. This is the common case when listening on
        // [::]:179 with v6_only=false.
        let mapped = ip!("::ffff:10.0.0.1");

        let result = select_nexthop(Afi::Ipv4, mapped, None);
        assert!(result.is_ok());
        match result.unwrap() {
            BgpNexthop::Ipv4(addr) => {
                let expected: Ipv4Addr = ip!("10.0.0.1");
                assert_eq!(addr, expected);
            }
            _ => panic!("Expected IPv4 nexthop from canonicalized address"),
        }
    }

    #[test]
    fn test_select_nexthop_ipv6_fallback_pure_ipv6() {
        // No nexthop configured, pure IPv6 local_ip should be used for IPv6 routes
        let local_ip = ip!("2001:db8::1");

        let result = select_nexthop(Afi::Ipv6, local_ip, None);
        assert!(result.is_ok());
        match result.unwrap() {
            BgpNexthop::Ipv6Single(addr) => {
                let expected: Ipv6Addr = ip!("2001:db8::1");
                assert_eq!(addr, expected);
            }
            _ => panic!("Expected IPv6 nexthop"),
        }
    }

    #[test]
    fn test_select_nexthop_wrong_af_ipv4_route_ipv6_nexthop() {
        // IPv4 route with IPv6 nexthop configured is a mismatch (error)
        let nexthop = ip!("2001:db8::1");
        let local_ip = ip!("10.0.0.1");

        let result = select_nexthop(Afi::Ipv4, local_ip, Some(nexthop));
        // Should error because IPv4 route needs IPv4 nexthop
        assert!(result.is_err());
    }

    #[test]
    fn test_select_nexthop_wrong_af_ipv6_route_ipv4_nexthop() {
        // IPv6 route with IPv4 nexthop configured is a mismatch (error)
        let nexthop = ip!("10.0.0.1");
        let local_ip = ip!("2001:db8::1");

        let result = select_nexthop(Afi::Ipv6, local_ip, Some(nexthop));
        // Should error because IPv6 route needs IPv6 nexthop
        assert!(result.is_err());
    }

    #[test]
    fn test_select_nexthop_cross_af_ipv4_routes_ipv6_local_ip_error() {
        // IPv4 route with pure IPv6 local_ip and no configured nexthop = error
        let local_ip = ip!("2001:db8::1");

        let result = select_nexthop(Afi::Ipv4, local_ip, None);
        // Should error because cannot derive IPv4 nexthop from IPv6 connection
        assert!(result.is_err());
    }

    #[test]
    fn test_select_nexthop_cross_af_ipv6_routes_ipv4_local_ip_error() {
        // IPv6 route with pure IPv4 local_ip and no configured nexthop = error
        let local_ip = ip!("10.0.0.1");

        let result = select_nexthop(Afi::Ipv6, local_ip, None);
        // Should error because cannot derive IPv6 nexthop from IPv4 connection
        assert!(result.is_err());
    }
}
