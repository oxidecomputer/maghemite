use crate::clock::Clock;
use crate::connection::BgpConnection;
use crate::messages::{Message, OpenMessage};
use crate::state::BgpState;
use slog::{debug, info, warn, Logger};
use std::fmt::{self, Display, Formatter};
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    OpenConfirm(Cnx),

    /// Able to exchange update, notification and keepliave messages with peers.
    Established(Cnx),
}

impl<Cnx: BgpConnection> Display for FsmState<Cnx> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let kind: FsmStateKind = self.into();
        write!(f, "{}", kind)
    }
}

//XXX
#[derive(Debug, PartialEq, Eq)]
pub enum FsmStateKind {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
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
            FsmState::Established(_) => FsmStateKind::Established,
        }
    }
}

pub enum FsmEvent<Cnx: BgpConnection> {
    Transition(FsmStateKind, FsmStateKind),

    Message(Message),

    Connected(Cnx),

    // from spec follows
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
}

impl<Cnx: BgpConnection> fmt::Debug for FsmEvent<Cnx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transition(from, to) => {
                write!(f, "transition {from:?} -> {to:?}")
            }
            Self::Message(message) => write!(f, "message {message:?}"),
            Self::Connected(_) => write!(f, "connected"),
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
            Self::IdleHoldTimerExpires => write!(f, "idle hold timeer expires"),
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
        }
    }
}

pub struct Session {
    // Required Attributes
    /// Track how many times a connection has been attempted.
    pub connect_retry_counter: u64,

    // Optional Attributes
    /// Start the peer session automatically.
    pub allow_automatic_start: bool,

    /// Stop the peer automatically under certain conditions.
    /// TODO: list conditions
    pub allow_automatic_stop: bool,

    /// Increase/decrease the idle_hold_timer in response to peer connectivity
    /// flapping.
    pub damp_peer_oscillations: bool,

    /// Allow connections from peers that are not explicitly configured.
    pub accept_connections_unconfigured_peers: bool,

    /// Detect open message collisions when in the established state.
    pub collision_detect_established_state: bool,

    /// Delay sending out the initial open message.
    pub delay_open: bool,

    /// Passively wait for the remote BGP peer to establish a TCP connection.
    pub passive_tcp_establishment: bool,

    /// Allow sending notification messages without first sending an open
    /// message.
    pub send_notification_without_open: bool,

    /// Enable fine-grained tracking and logging of TCP connection state.
    pub track_tcp_state: bool,
}

impl Session {
    pub fn new() -> Arc<Mutex<Session>> {
        Arc::new(Mutex::new(Session {
            connect_retry_counter: 0,
            allow_automatic_start: false,
            allow_automatic_stop: false,
            damp_peer_oscillations: false,
            accept_connections_unconfigured_peers: false,
            collision_detect_established_state: false,
            delay_open: true,
            passive_tcp_establishment: false,
            send_notification_without_open: false,
            track_tcp_state: false,
        }))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Asn {
    TwoOctet(u16),
    FourOctet(u32),
}

impl std::fmt::Display for Asn {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Asn::TwoOctet(asn) => write!(f, "{}", asn),
            Asn::FourOctet(asn) => write!(f, "{}", asn),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NeighborInfo {
    pub name: String,
    pub host: SocketAddr,
}

pub struct SessionRunner<Cnx: BgpConnection> {
    session: Arc<Mutex<Session>>,
    event_rx: Receiver<FsmEvent<Cnx>>,
    event_tx: Sender<FsmEvent<Cnx>>,
    _bgp_state: Arc<Mutex<BgpState>>,

    asn: Asn,
    id: u32,

    neighbor: NeighborInfo,

    log: Logger,

    clock: Clock,
    bind_addr: Option<SocketAddr>,
}

impl<Cnx: BgpConnection + 'static> SessionRunner<Cnx> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connect_retry_time: Duration,
        keepalive_time: Duration,
        hold_time: Duration,
        idle_hold_time: Duration,
        delay_open_time: Duration,
        session: Arc<Mutex<Session>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
        event_tx: Sender<FsmEvent<Cnx>>,
        bgp_state: Arc<Mutex<BgpState>>,
        neighbor: NeighborInfo,
        asn: Asn,
        id: u32,
        resolution: Duration,
        bind_addr: Option<SocketAddr>,
        log: Logger,
    ) -> SessionRunner<Cnx> {
        SessionRunner {
            session,
            event_rx,
            event_tx: event_tx.clone(),
            _bgp_state: bgp_state,
            asn,
            id,
            neighbor,
            clock: Clock::new(
                resolution,
                connect_retry_time,
                keepalive_time,
                hold_time,
                idle_hold_time,
                delay_open_time,
                event_tx.clone(),
            ),
            bind_addr,
            log,
        }
    }

    pub fn start(&mut self) {
        info!(self.log, "starting peer state machine");
        let mut current = FsmState::<Cnx>::Idle;
        loop {
            let current_state: FsmStateKind = (&current).into();
            let next_state = match current {
                FsmState::Idle => {
                    current = self.idle();
                    (&current).into()
                }

                FsmState::Connect => {
                    current = self.on_connect();
                    (&current).into()
                }

                FsmState::Active(conn) => {
                    current = self.on_active(conn);
                    (&current).into()
                }

                FsmState::OpenSent(conn) => {
                    current = self.on_open_sent(conn);
                    (&current).into()
                }

                FsmState::OpenConfirm(conn) => {
                    current = self.on_open_confirm(conn);
                    (&current).into()
                }

                FsmState::Established(conn) => {
                    current = self.on_established(conn);
                    (&current).into()
                }
            };

            if current_state != next_state {
                info!(
                    self.log,
                    "[{}/{}] {} -> {}",
                    self.id,
                    self.neighbor.name,
                    current_state,
                    next_state,
                );
            }
        }
    }

    fn idle(&mut self) -> FsmState<Cnx> {
        //TODO(unwrap)
        match self.event_rx.recv().unwrap() {
            FsmEvent::ManualStart => FsmState::Connect,
            x => {
                warn!(self.log, "Event {:?} not allowed in idle", x);
                FsmState::Idle
            }
        }
    }

    fn on_connect(&mut self) -> FsmState<Cnx> {
        self.session.lock().unwrap().connect_retry_counter = 0;
        let conn =
            Cnx::new(self.bind_addr, self.neighbor.host, self.log.clone());
        conn.connect(self.event_tx.clone(), self.clock.resolution);
        self.clock.timers.connect_retry_timer.enable();
        loop {
            //TODO(unwrap)
            match self.event_rx.recv().unwrap() {
                FsmEvent::ConnectRetryTimerExpires => {
                    conn.connect(self.event_tx.clone(), self.clock.resolution);
                }
                FsmEvent::Connected(accepted) => {
                    self.clock.timers.connect_retry_timer.disable();
                    self.send_open(&accepted);
                    return FsmState::OpenSent(accepted);
                }
                FsmEvent::TcpConnectionConfirmed => {
                    self.clock.timers.connect_retry_timer.disable();
                    self.send_open(&conn);
                    return FsmState::OpenSent(conn);
                }
                x => {
                    warn!(self.log, "Event {:?} not allowed in connect", x);
                    continue;
                }
            }
        }
    }

    fn on_active(&mut self, conn: Cnx) -> FsmState<Cnx> {
        let om =
            match self.event_rx.recv().unwrap() {
                FsmEvent::Message(Message::Open(om)) => om,
                other => {
                    warn!(self.log,
                    "active: expected open message, received {:#?}, ignoring",
                    other);
                    return FsmState::Active(conn);
                }
            };
        if !self.open_is_valid(om) {
            return FsmState::Active(conn);
        }
        self.send_keepalive(&conn);
        FsmState::OpenConfirm(conn)
    }

    fn on_open_sent(&mut self, conn: Cnx) -> FsmState<Cnx> {
        let om = match self.event_rx.recv().unwrap() {
            FsmEvent::Message(Message::Open(om)) => om,
            other => {
                warn!(
                    self.log,
                    "open sent: expected open, received {:#?}, ignoring", other
                );
                return FsmState::Active(conn);
            }
        };
        if !self.open_is_valid(om) {
            return FsmState::Active(conn);
        }
        self.send_keepalive(&conn);
        FsmState::OpenConfirm(conn)
    }

    fn open_is_valid(&self, _om: OpenMessage) -> bool {
        //TODO
        true
    }

    fn send_keepalive(&self, conn: &Cnx) {
        debug!(self.log, "sending keepalive");
        //TODO(unwrap)
        conn.send(Message::KeepAlive).unwrap();
    }

    fn send_open(&self, conn: &Cnx) {
        let msg = match self.asn {
            Asn::FourOctet(asn) => OpenMessage::new4(
                asn,
                self.clock.timers.hold_timer.interval.as_secs() as u16,
                self.id,
            ),
            Asn::TwoOctet(asn) => OpenMessage::new2(
                asn,
                self.clock.timers.hold_timer.interval.as_secs() as u16,
                self.id,
            ),
        };
        // TODO(unwrap)
        conn.send(msg.into()).unwrap();
    }

    fn on_open_confirm(&mut self, conn: Cnx) -> FsmState<Cnx> {
        //TODO(unwrap)
        match self.event_rx.recv().unwrap() {
            FsmEvent::Message(Message::KeepAlive) => {
                self.clock.timers.hold_timer.reset();
                self.clock.timers.hold_timer.enable();
                self.clock.timers.keepalive_timer.reset();
                self.clock.timers.keepalive_timer.enable();
                FsmState::Established(conn)
            }
            FsmEvent::Message(Message::Notification(m)) => {
                warn!(self.log, "notification received: {:#?}", m);
                self.session.lock().unwrap().connect_retry_counter += 1;
                self.clock.timers.hold_timer.disable();
                self.clock.timers.keepalive_timer.disable();
                FsmState::Connect
            }
            other => {
                warn!(
                    self.log,
                    "Event {:?} not expected in open confirm, ignoring", other
                );
                FsmState::OpenConfirm(conn)
            }
        }
    }

    fn on_established(&mut self, conn: Cnx) -> FsmState<Cnx> {
        match self.event_rx.recv().unwrap() {
            FsmEvent::KeepaliveTimerExpires => {
                self.send_keepalive(&conn);
                FsmState::Established(conn)
            }
            FsmEvent::HoldTimerExpires => {
                warn!(self.log, "hold timer expired");
                self.session.lock().unwrap().connect_retry_counter += 1;
                self.clock.timers.hold_timer.disable();
                self.clock.timers.keepalive_timer.disable();
                FsmState::Connect
            }
            FsmEvent::Message(Message::Open(m)) => {
                warn!(
                    self.log,
                    "established: expected open message, \
                    received {:#?}, ignoring",
                    m
                );
                FsmState::Established(conn)
            }
            FsmEvent::Message(Message::Update(m)) => {
                self.clock.timers.hold_timer.reset();
                info!(self.log, "update received: {:#?}", m);

                //TODO apply update

                FsmState::Established(conn)
            }
            FsmEvent::Message(Message::Notification(m)) => {
                warn!(self.log, "notification received: {:#?}", m);
                self.session.lock().unwrap().connect_retry_counter += 1;
                FsmState::Connect
            }
            FsmEvent::Message(Message::KeepAlive) => {
                debug!(self.log, "keepalive received");
                self.clock.timers.hold_timer.reset();
                FsmState::Established(conn)
            }
            _ => {
                todo!()
            }
        }
    }
}
