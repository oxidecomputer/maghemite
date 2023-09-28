use crate::clock::Clock;
use crate::connection::BgpConnection;
use crate::error::Error;
use crate::fanout::Fanout;
use crate::messages::{
    AddPathElement, As4PathSegment, AsPathType, Capability, Message,
    OpenMessage, OptionalParameter, PathAttributeValue, PathOrigin,
    UpdateMessage,
};
use crate::{dbg, inf, wrn};
use rdb::{Db, Prefix4, Route4Key};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct PeerConnection<Cnx: BgpConnection> {
    conn: Cnx,
    id: u32,
}

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

impl<Cnx: BgpConnection> Display for FsmState<Cnx> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let kind: FsmStateKind = self.into();
        write!(f, "{}", kind)
    }
}

//XXX
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema,
)]
pub enum FsmStateKind {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    SessionSetup,
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

#[derive(Clone)]
pub enum FsmEvent<Cnx: BgpConnection> {
    Transition(FsmStateKind, FsmStateKind),

    Message(Message),

    Connected(Cnx),

    // Instructs peer to announce the update
    Announce(UpdateMessage),

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
            Self::Announce(update) => write!(f, "update {update:?}"),
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

    /// The ASN of the remote peer.
    pub remote_asn: Option<u32>,
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
            remote_asn: None,
        }))
    }
}

//XXX move to rdb
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
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

impl From<u32> for Asn {
    fn from(value: u32) -> Asn {
        Asn::FourOctet(value)
    }
}

impl From<u16> for Asn {
    fn from(value: u16) -> Asn {
        Asn::TwoOctet(value)
    }
}

#[derive(Debug, Clone)]
pub struct NeighborInfo {
    pub name: String,
    pub host: SocketAddr,
}

pub struct SessionRunner<Cnx: BgpConnection> {
    pub event_tx: Sender<FsmEvent<Cnx>>,
    pub neighbor: NeighborInfo,

    session: Arc<Mutex<Session>>,
    event_rx: Receiver<FsmEvent<Cnx>>,

    state: Arc<Mutex<FsmStateKind>>,
    last_state_change: Mutex<Instant>,

    asn: Asn,
    id: u32,

    log: Logger,

    clock: Clock,
    bind_addr: Option<SocketAddr>,
    shutdown: AtomicBool,
    running: AtomicBool,

    db: Db,
    fanout: Arc<RwLock<Fanout<Cnx>>>,
}

unsafe impl<Cnx: BgpConnection> Send for SessionRunner<Cnx> {}
unsafe impl<Cnx: BgpConnection> Sync for SessionRunner<Cnx> {}

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
        neighbor: NeighborInfo,
        asn: Asn,
        id: u32,
        resolution: Duration,
        bind_addr: Option<SocketAddr>,
        db: Db,
        fanout: Arc<RwLock<Fanout<Cnx>>>,
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
            ),
            bind_addr,
            log,
            shutdown: AtomicBool::new(false),
            running: AtomicBool::new(false),
            fanout,
            db,
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    pub fn start(&self) {
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return; // we are already running
        };

        dbg!(self; "starting peer state machine");
        let mut current = FsmState::<Cnx>::Idle;
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                inf!(self; "shutting down");
                *(self.state.lock().unwrap()) = FsmStateKind::Idle;
                self.shutdown.store(false, Ordering::Release);
                self.running.store(false, Ordering::Release);
                inf!(self; "shutdown complete");
                return;
            }
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

                FsmState::SessionSetup(conn) => {
                    current = self.session_setup(conn);
                    (&current).into()
                }

                FsmState::Established(conn) => {
                    current = self.on_established(conn);
                    (&current).into()
                }
            };

            if current_state != next_state {
                inf!(self; "{} -> {}", current_state, next_state);
                *(self.state.lock().unwrap()) = next_state;
                *(self.last_state_change.lock().unwrap()) = Instant::now();
            }
        }
    }

    pub fn send_event(&self, e: FsmEvent<Cnx>) -> Result<(), Error> {
        self.event_tx
            .send(e)
            .map_err(|e| Error::ChannelSend(e.to_string()))
    }

    fn idle(&self) -> FsmState<Cnx> {
        //TODO(unwrap)
        match self.event_rx.recv().unwrap() {
            FsmEvent::ManualStart => FsmState::Connect,
            x => {
                wrn!(self; "event {:?} not allowed in idle", x);
                FsmState::Idle
            }
        }
    }

    fn on_connect(&self) -> FsmState<Cnx> {
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
                    inf!(self; "accepted connection from {}", accepted.peer());
                    self.clock.timers.connect_retry_timer.disable();
                    self.send_open(&accepted);
                    self.clock.timers.hold_timer.reset();
                    self.clock.timers.hold_timer.enable();
                    return FsmState::OpenSent(accepted);
                }
                FsmEvent::TcpConnectionConfirmed => {
                    inf!(self; "connected to {}", conn.peer());
                    self.clock.timers.connect_retry_timer.disable();
                    self.send_open(&conn);
                    self.clock.timers.hold_timer.reset();
                    self.clock.timers.hold_timer.enable();
                    return FsmState::OpenSent(conn);
                }
                x => {
                    wrn!(self; "event {:?} not allowed in connect", x);
                    continue;
                }
            }
        }
    }

    fn on_active(&self, conn: Cnx) -> FsmState<Cnx> {
        let om = match self.event_rx.recv().unwrap() {
            FsmEvent::Message(Message::Open(om)) => om,
            other => {
                wrn!(self;
                    "active: expected open message, received {:#?}, ignoring",
                    other);
                return FsmState::Active(conn);
            }
        };
        if !self.open_is_valid(&om) {
            return FsmState::Active(conn);
        }
        self.send_keepalive(&conn);
        FsmState::OpenConfirm(PeerConnection { conn, id: om.id })
    }

    fn on_open_sent(&self, conn: Cnx) -> FsmState<Cnx> {
        let om = match self.event_rx.recv().unwrap() {
            FsmEvent::Message(Message::Open(om)) => om,
            FsmEvent::HoldTimerExpires => {
                wrn!(self; "open sent: hold timer expired");
                return FsmState::Connect;
            }
            other => {
                wrn!(
                    self;
                    "open sent: expected open, received {:#?}, ignoring", other
                );
                return FsmState::Active(conn);
            }
        };
        if !self.open_is_valid(&om) {
            return FsmState::Active(conn);
        }
        self.send_keepalive(&conn);
        FsmState::OpenConfirm(PeerConnection { conn, id: om.id })
    }

    fn open_is_valid(&self, om: &OpenMessage) -> bool {
        //TODO

        let mut remote_asn = om.asn as u32;
        for p in &om.parameters {
            if let OptionalParameter::Capabilities(caps) = p {
                for c in caps {
                    if let Capability::FourOctetAs { asn } = c {
                        remote_asn = *asn;
                    }
                }
            }
        }
        self.session.lock().unwrap().remote_asn = Some(remote_asn);
        true
    }

    fn send_keepalive(&self, conn: &Cnx) {
        dbg!(self; "sending keepalive");
        //TODO(unwrap)
        conn.send(Message::KeepAlive).unwrap();
    }

    fn send_open(&self, conn: &Cnx) {
        let mut msg = match self.asn {
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
        // TODO negotiate capabilities
        msg.add_capabilities(&[
            //Capability::RouteRefresh{},
            //Capability::EnhancedRouteRefresh{},
            Capability::MultiprotocolExtensions {
                afi: 1,  //IP
                safi: 1, //NLRI for unicast
            },
            //Capability::GracefulRestart{},
            Capability::AddPath {
                elements: vec![AddPathElement {
                    afi: 1,          //IP
                    safi: 1,         //NLRI for unicast
                    send_receive: 1, //receive
                }],
            },
        ]);
        // TODO(unwrap)
        conn.send(msg.into()).unwrap();
    }

    fn send_update(&self, update: UpdateMessage, conn: &Cnx) {
        // TODO(unwrap)
        conn.send(update.into()).unwrap();
    }

    fn on_open_confirm(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        //TODO(unwrap)
        match self.event_rx.recv().unwrap() {
            FsmEvent::Message(Message::KeepAlive) => {
                self.clock.timers.hold_timer.reset();
                self.clock.timers.hold_timer.enable();
                self.clock.timers.keepalive_timer.reset();
                self.clock.timers.keepalive_timer.enable();
                FsmState::SessionSetup(pc)
            }
            FsmEvent::Message(Message::Notification(m)) => {
                wrn!(self; "notification received: {:#?}", m);
                self.session.lock().unwrap().connect_retry_counter += 1;
                self.clock.timers.hold_timer.disable();
                self.clock.timers.keepalive_timer.disable();
                FsmState::Connect
            }
            other => {
                wrn!(
                    self;
                    "event {:?} not expected in open confirm, ignoring", other
                );
                FsmState::OpenConfirm(pc)
            }
        }
    }

    fn session_setup(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        let originated = self.db.get_originated4().unwrap();
        let mut m = BTreeMap::<Ipv4Addr, Vec<Prefix4>>::new();
        for o in originated {
            match m.get_mut(&o.nexthop) {
                Some(ref mut prefixes) => {
                    prefixes.push(o.prefix);
                }
                None => {
                    m.insert(o.nexthop, vec![o.prefix]);
                }
            }
        }

        let mut fanout = self.fanout.write().unwrap();
        if fanout.is_empty() {
            fanout.add_egress(
                self.neighbor.host.ip(),
                crate::fanout::Egress {
                    event_tx: Some(self.event_tx.clone()),
                },
            );
        }
        drop(fanout);

        for (nexthop, prefixes) in m {
            let asn = match self.asn {
                Asn::TwoOctet(asn) => asn as u32,
                Asn::FourOctet(asn) => asn,
            };
            let mut update = UpdateMessage {
                path_attributes: vec![
                    PathAttributeValue::Origin(PathOrigin::Egp).into(),
                    PathAttributeValue::NextHop(nexthop.into()).into(),
                    PathAttributeValue::AsPath(vec![As4PathSegment {
                        typ: AsPathType::AsSequence,
                        value: vec![asn],
                    }])
                    .into(),
                ],
                ..Default::default()
            };
            for p in prefixes {
                update.nlri.push(p.into());
                self.db
                    .add_origin4(Route4Key { prefix: p, nexthop })
                    .unwrap();
            }
            self.send_keepalive(&pc.conn);
            self.fanout.read().unwrap().send_all(&update);
            self.send_update(update, &pc.conn);
        }
        FsmState::Established(pc)
    }

    fn on_established(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        match self.event_rx.recv().unwrap() {
            FsmEvent::KeepaliveTimerExpires => {
                self.send_keepalive(&pc.conn);
                FsmState::Established(pc)
            }
            FsmEvent::HoldTimerExpires => {
                wrn!(self; "hold timer expired");
                self.exit_established(pc)
            }
            FsmEvent::Message(Message::Update(m)) => {
                self.clock.timers.hold_timer.reset();
                inf!(self; "update received: {:#?}", m);

                self.apply_update(m, pc.id);

                FsmState::Established(pc)
            }
            FsmEvent::Message(Message::Notification(m)) => {
                wrn!(self; "notification received: {:#?}", m);
                self.exit_established(pc)
            }
            FsmEvent::Message(Message::KeepAlive) => {
                dbg!(self; "keepalive received");
                self.clock.timers.hold_timer.reset();
                FsmState::Established(pc)
            }
            FsmEvent::Message(m) => {
                wrn!(
                    self;
                    "established: unexpected message {:#?}",
                    m
                );
                FsmState::Established(pc)
            }
            FsmEvent::Announce(update) => {
                self.send_update(update, &pc.conn);
                FsmState::Established(pc)
            }
            _ => {
                todo!()
            }
        }
    }

    fn exit_established(&self, pc: PeerConnection<Cnx>) -> FsmState<Cnx> {
        self.session.lock().unwrap().connect_retry_counter += 1;
        self.clock.timers.hold_timer.disable();
        self.clock.timers.keepalive_timer.disable();

        self.fanout
            .write()
            .unwrap()
            .remove_egress(self.neighbor.host.ip());

        //TODO need to remove from Router::addr_to_session also

        // remove peer prefixes from db
        let withdraw = self.db.remove_peer_nexthop4(pc.id);

        // propagate a withdraw message through fanout
        let mut m = BTreeMap::<Ipv4Addr, Vec<Prefix4>>::new();
        for o in withdraw {
            match m.get_mut(&o.nexthop) {
                Some(ref mut prefixes) => {
                    prefixes.push(o.prefix);
                }
                None => {
                    m.insert(o.nexthop, vec![o.prefix]);
                }
            }
        }

        for (nexthop, prefixes) in m {
            let mut update = UpdateMessage {
                path_attributes: vec![PathAttributeValue::NextHop(
                    nexthop.into(),
                )
                .into()],
                ..Default::default()
            };
            for p in prefixes {
                update.withdrawn.push(p.into());
                self.db
                    .add_origin4(Route4Key { prefix: p, nexthop })
                    .unwrap();
            }
            self.fanout.read().unwrap().send_all(&update);
        }

        FsmState::Connect
    }

    fn apply_update(&self, update: UpdateMessage, id: u32) {
        if let Err(e) = self.check_update(&update) {
            wrn!(
                self;
                "Update check failed for {:#?}: {e}. Ignoring",
                update,
            );
            return;
        }
        self.add_to_rib(&update, id);
        self.fanout_update(&update);
    }

    fn add_to_rib(&self, update: &UpdateMessage, id: u32) {
        let nexthop = match update.nexthop4() {
            Some(nh) => nh,
            None => {
                wrn!(self; "update with no nexthop recieved {update:#?}");
                return;
            }
        };

        for w in &update.withdrawn {
            let k = rdb::Route4ImportKey {
                prefix: w.into(),
                nexthop,
                id,
            };
            self.db.remove_nexthop4(k);
        }

        for n in &update.nlri {
            let k = rdb::Route4ImportKey {
                prefix: n.into(),
                nexthop,
                id,
            };
            self.db.set_nexthop4(k);
        }

        //TODO iterate through MpReachNlri attributes for IPv6
    }

    fn check_update(&self, update: &UpdateMessage) -> Result<(), Error> {
        self.check_for_self_in_path(update)
    }

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

    fn fanout_update(&self, update: &UpdateMessage) {
        let fanout = self.fanout.read().unwrap();
        fanout.send(self.neighbor.host.ip(), update);
    }

    pub fn state(&self) -> FsmStateKind {
        *self.state.lock().unwrap()
    }

    pub fn remote_asn(&self) -> Option<u32> {
        self.session.lock().unwrap().remote_asn
    }

    pub fn current_state_duration(&self) -> Duration {
        self.last_state_change.lock().unwrap().elapsed()
    }
}
