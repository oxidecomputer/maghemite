use crate::state::BgpState;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::{interval, Interval};

pub struct SessionState {
    pub fsm_state: FsmState,
}

pub enum FsmState {
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
    /// - BgpOpen -> OpenConfigm (only during delay_open interval)
    Connect,

    /// Trying to acquire peer by listening for and accepting a TCP connection.
    Active,

    /// Waiting for open message from peer.
    OpenSent,

    /// Waiting for keepaliave or notification from peer.
    OpenConfirm,

    /// Able to exchange update, notification and keepliave messages with peers.
    Established,
}

pub enum FsmEvent {
    /// Local system administrator manually starts the peer connection.
    ManualStart = 1,

    /// Local system administrator manually stops the peer connection
    ManualStop = 2,

    /// Local system automatically starts the BGP connection
    AutomaticStart = 3,

    /// Local system administrator manually starts the peer connection, but has
    /// [`Session::passive_tcp_establishment`] enabled which indicates that the
    /// peer wil listen prior to establishing the connection.
    PassiveManualStart = 4,

    /// Local system automatically starts the BGP connection with the
    /// [`Session::passive_tcp_establishment`] enable which indicates that the
    /// peer will listen prior to establishing a connection.
    PassiveAutomaticStart = 5,

    /// Local system automatically starts the BGP peer connection with peer
    /// oscillation damping enabled.
    DampedAutomaticStart = 6,

    /// Local system automatically starts the BGP peer connection with peer
    /// oscillation and damping enabled and passive tcp establishment enabled.
    PassiveDampedAutomaticStart = 7,

    /// Local system automatically stops connection.
    AutomaticStop = 8,

    /// Fires when the [`Session::connect_retry_timer`] expires.
    ConnectRetryTimerExpires = 9,

    /// Fires when the [`Session::hold_timer`] expires.
    HoldTimerExpires = 10,

    /// Fires when the [`Session::keepalive_timer`] expires.
    KeepaliveTimerExpires = 11,

    /// Fires when the [`Session::delay_open_timer`] expires.
    DelayOpenTimerExpires = 12,

    /// Fires when the [`Session::idle_hold_timer`] expires.
    IdleHoldTimerExpires = 13,

    /// Fires when the local system gets a TCP connection request with a valid
    /// source/destination IP address/port.
    TcpConnectionValid = 14,

    /// Fires when the local syste gets a TCP connection request with an invalid
    /// source/destination IP address/port.
    TcpConnectionInvalid = 15,

    /// Fires when the local systems tcp-syn recieved a syn-ack from the remote
    /// peer and the local system has sent an ack.
    TcpConnectionAcked = 16,

    /// Fires when the local system as recieved the final ack in establishing a
    /// TCP connection with the peer.
    TcpConnectionConfirmed = 17,

    /// Fires when the remote peer sends a TCP fin or the local connection times
    /// out.
    TcpConnectionFails = 18,

    /// Fires when a valid BGP open message has been received.
    BgpOpen = 19,

    /// Fires when a valid BGP open message has been received when
    /// [`Session::delay_open`] is set.
    DelayedBgpOpen = 20,

    /// Fires when an invalid BGP header has been received.
    BgpHeaderErr = 21,

    /// Fires when a BGP open message has been recieved with errors.
    BgpOpenMsgErr = 22,

    /// Fires when a connection has been detected while processing an open
    /// message.
    OpenCollissionDump = 23,

    /// Fires when a notification with a version error is received.
    NotifyMsgVerErr = 24,

    /// Fires when a notify message is received.
    NotifyMsg = 25,

    /// Fires when a keepalive message is received.
    KeepAliveMsg = 26,

    /// Fires when an update message is received.
    UpdateMsg = 27,

    /// Fires when an invalid update message is received.
    UpdateMsgErr = 28,
}

pub struct Session {
    pub bgp_state: Arc<Mutex<BgpState>>,
    pub session_state: Arc<Mutex<SessionState>>,

    // Required Attributes
    /// Track how many times a connection has been attempted.
    pub connect_retry_counter: u64,

    /// How long to wait between connection attempts.
    pub connect_retry_timer: Interval,

    /// How long to keep a session alive between keepalive, update and/or
    /// notification messages.
    pub hold_timer: Interval,

    /// How often to send out keepalive messages.
    pub keepalive_timer: Interval,

    // Optional Attributes
    /// Start the peer session automatically.
    pub allow_automatic_start: bool,

    /// Restart the peer session automatically.
    pub allow_automatic_restart: bool,

    /// Stop the peer automatically under certain conditions.
    /// TODO: list conditions
    pub allow_automatic_stop: bool,

    /// Increase/decrease the idle_hold_timer in response to peer connectivity
    /// flapping.
    pub damp_peer_oscillations: bool,

    /// Amount of time that a peer is held in the idle state.
    pub idle_hold_timer: Interval,

    /// Allow connections from peers that are not explicitly configured.
    pub accept_connections_unconfigured_peers: bool,

    /// Detect open message collisions when in the established state.
    pub collision_detect_established_state: bool,

    /// Delay sending out the initial open message.
    pub delay_open: bool,

    /// Interval to wait before sending out an open message.
    pub delay_open_timer: Interval,

    /// Passively wait for the remote BGP peer to establish a TCP connection.
    pub passive_tcp_establishment: bool,

    /// Allow sending notification messages without first sending an open
    /// message.
    pub send_notification_without_open: bool,

    /// Enable fine-grained tracking and logging of TCP connection state.
    pub track_tcp_state: bool,
}

impl Session {
    pub fn new(
        bgp_state: Arc<Mutex<BgpState>>,
        connect_retry_time: Duration,
        hold_time: Duration,
        keepalive_time: Duration,
        idle_hold_time: Duration,
        delay_open_time: Duration,
    ) -> Session {
        Session {
            bgp_state,
            session_state: Arc::new(Mutex::new(SessionState {
                fsm_state: FsmState::Idle,
            })),
            connect_retry_counter: 0,
            connect_retry_timer: interval(connect_retry_time),
            hold_timer: interval(hold_time),
            keepalive_timer: interval(keepalive_time),
            allow_automatic_start: false,
            allow_automatic_restart: false,
            allow_automatic_stop: false,
            damp_peer_oscillations: false,
            idle_hold_timer: interval(idle_hold_time),
            accept_connections_unconfigured_peers: false,
            collision_detect_established_state: false,
            delay_open: true,
            delay_open_timer: interval(delay_open_time),
            passive_tcp_establishment: false,
            send_notification_without_open: false,
            track_tcp_state: false,
        }
    }
}
