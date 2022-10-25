use crate::messages::{
    Header, Message, MessageType, NotificationMessage, OpenMessage,
    UpdateMessage,
};
use crate::state::BgpState;
use slog::{error, info, warn, Logger};
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
use std::time::Duration;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tokio::time::{interval, Interval};

#[derive(Debug)]
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
    Connect(TcpStream),

    /// Trying to acquire peer by listening for and accepting a TCP connection.
    Active(TcpStream),

    /// Waiting for open message from peer.
    OpenSent(TcpStream),

    /// Waiting for keepaliave or notification from peer.
    OpenConfirm(TcpStream),

    /// Able to exchange update, notification and keepliave messages with peers.
    Established(TcpStream),
}

impl Display for FsmState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let kind: FsmStateKind = self.into();
        write!(f, "{}", kind)
    }
}

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

impl From<&FsmState> for FsmStateKind {
    fn from(s: &FsmState) -> FsmStateKind {
        match s {
            FsmState::Idle => FsmStateKind::Idle,
            FsmState::Connect(_) => FsmStateKind::Connect,
            FsmState::Active(_) => FsmStateKind::Active,
            FsmState::OpenSent(_) => FsmStateKind::OpenSent,
            FsmState::OpenConfirm(_) => FsmStateKind::OpenConfirm,
            FsmState::Established(_) => FsmStateKind::Established,
        }
    }
}

#[derive(Debug)]
pub enum FsmEvent {

    Transition(FsmStateKind, FsmStateKind),

    Message(Message),

    Connected(TcpStream),

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
        idle_hold_time: Duration,
        delay_open_time: Duration,
    ) -> Arc<Mutex<Session>> {
        Arc::new(Mutex::new(Session {
            connect_retry_counter: 0,
            allow_automatic_start: false,
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

pub struct SessionRunner {
    session: Arc<Mutex<Session>>,
    event_rx: Receiver<FsmEvent>,
    event_tx: Sender<FsmEvent>,
    _bgp_state: Arc<Mutex<BgpState>>,

    /// How long to wait between connection attempts.
    pub connect_retry_timer: Interval,

    /// How often to send out keepalive messages.
    pub keepalive_timer: Interval,

    /// How long to keep a session alive between keepalive, update and/or
    /// notification messages.
    pub hold_timer: Interval,

    asn: Asn,
    id: u32,

    neighbor: NeighborInfo,

    log: Logger,
}

impl SessionRunner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connect_retry_time: Duration,
        keepalive_time: Duration,
        hold_time: Duration,
        session: Arc<Mutex<Session>>,
        event_rx: Receiver<FsmEvent>,
        event_tx: Sender<FsmEvent>,
        bgp_state: Arc<Mutex<BgpState>>,
        neighbor: NeighborInfo,
        asn: Asn,
        id: u32,
        log: Logger,
    ) -> SessionRunner {
        SessionRunner {
            session,
            event_rx,
            event_tx: event_tx,
            _bgp_state: bgp_state,
            connect_retry_timer: interval(connect_retry_time),
            keepalive_timer: interval(keepalive_time),
            hold_timer: interval(hold_time),
            asn,
            id,
            neighbor,
            log,
        }
    }

    pub async fn start(&mut self) {
        let mut current = FsmState::Idle;
        loop {
            let current_state: FsmStateKind = (&current).into();
            let next_state = match current {
                FsmState::Idle => {
                    current = self.idle().await;
                    (&current).into()
                }

                FsmState::Connect(stream) => {
                    current = self.on_connect(stream).await;
                    (&current).into()
                }

                FsmState::Active(stream) => {
                    current = self.on_active(stream).await;
                    (&current).into()
                }

                FsmState::OpenSent(stream) => {
                    current = self.on_open_sent(stream).await;
                    (&current).into()
                }

                FsmState::OpenConfirm(stream) => {
                    current = self.on_open_confirm(stream).await;
                    (&current).into()
                }

                FsmState::Established(stream) => {
                    current = self.on_established(stream).await;
                    (&current).into()
                }
            };

            if current_state != next_state {
                self.event_tx.send(
                    FsmEvent::Transition(current_state, next_state)
                ).await.unwrap()
            }
        }
    }

    async fn idle(&mut self) -> FsmState {
        match self.event_rx.recv().await {
            None => FsmState::Idle,
            Some(FsmEvent::ManualStart) => self.on_start().await,
            x => {
                warn!(self.log, "Event {:?} not allowed in idle, ignoring", x);
                FsmState::Idle
            }
        }
    }

    async fn on_start(&mut self) -> FsmState {
        self.session.lock().await.connect_retry_counter = 0;

        loop {
            tokio::select! {
                _ = self.connect_retry_timer.tick() => {
                    let stream = TcpStream::connect(
                        &self.neighbor.host).await.unwrap();
                    return FsmState::Connect(stream)
                }
                result = self.event_rx.recv() => {
                    match result.unwrap() {
                        FsmEvent::Connected(stream) => return FsmState::Active(stream),
                        _ => continue,
                    }
                }
            }
        }
    }

    async fn recv_header(stream: &mut TcpStream) -> std::io::Result<Header> {
        let mut buf = [0u8; 19];
        let mut i = 0;
        loop {
            stream.readable().await?;
            //stream.read_exact(&mut buf).await?;
            let n = stream.try_read(&mut buf[i..])?;
            i += n;
            if i < 19 {
                continue;
            }
            match Header::from_wire(&buf) {
                Ok(h) => return Ok(h),
                Err(_) => continue,
            };
        }
    }

    async fn recv_msg(
        stream: &mut TcpStream,
        event_tx: &Sender<FsmEvent>,
    ) -> std::io::Result<Message> {
        loop {
            let hdr = Self::recv_header(stream).await?;
            let mut msgbuf = vec![0u8; (hdr.length - 19) as usize];
            stream.read_exact(&mut msgbuf).await.unwrap();

            let msg: Message = match hdr.typ {
                MessageType::Open => match OpenMessage::from_wire(&msgbuf) {
                    Ok(m) => m.into(),
                    Err(_) => continue,
                },
                MessageType::Update => {
                    match UpdateMessage::from_wire(&msgbuf) {
                        Ok(m) => m.into(),
                        Err(_) => continue,
                    }
                }
                MessageType::Notification => {
                    match NotificationMessage::from_wire(&msgbuf) {
                        Ok(m) => m.into(),
                        Err(_) => continue,
                    }
                }
                MessageType::KeepAlive => Message::KeepAlive,
            };

            event_tx.send(FsmEvent::Message(msg.clone())).await.unwrap();
            return Ok(msg);
        }
    }

    async fn on_connect(&mut self, mut stream: TcpStream) -> FsmState {
        self.send_open(&mut stream).await;
        FsmState::OpenSent(stream)
    }

    async fn on_active(&mut self, mut stream: TcpStream) -> FsmState {
        let msg = Self::recv_msg(&mut stream, &self.event_tx).await;
        let om =
            match msg {
                Ok(Message::Open(om)) => om,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        return FsmState::Active(stream);
                    } else {
                        error!(self.log, "on active recv: {:#?}", e);
                        return self.on_start().await;
                    }
                }
                other => {
                    warn!(self.log,
                    "active: expected open message, received {:#?}, ignoring",
                    other);
                    return FsmState::Active(stream);
                }
            };
        if !self.open_is_valid(om) {
            return FsmState::Active(stream);
        }
        self.send_keepalive(&mut stream).await;
        FsmState::OpenConfirm(stream)
    }

    async fn on_open_sent(&mut self, mut stream: TcpStream) -> FsmState {
        let msg = Self::recv_msg(&mut stream, &self.event_tx).await;
        let om = match msg {
            Ok(Message::Open(om)) => om,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    return FsmState::OpenSent(stream);
                } else {
                    error!(self.log, "on open sent recv: {:#?}", e);
                    return self.on_start().await;
                }
            }
            other => {
                warn!(
                    self.log,
                    "open sent: expected open, received {:#?}, ignoring", other
                );
                return FsmState::Active(stream);
            }
        };
        if !self.open_is_valid(om) {
            return FsmState::Active(stream);
        }
        self.send_keepalive(&mut stream).await;
        FsmState::OpenConfirm(stream)
    }

    fn open_is_valid(&self, _om: OpenMessage) -> bool {
        //TODO
        true
    }

    async fn send_keepalive(&self, stream: &mut TcpStream) {
        let header = Header {
            length: 19,
            typ: MessageType::KeepAlive,
        };
        let header_buf = header.to_wire();
        stream.write_all(&header_buf).await.unwrap();
    }

    async fn send_open(&self, stream: &mut TcpStream) {
        let msg = match self.asn {
            Asn::FourOctet(asn) => OpenMessage::new4(
                asn,
                self.hold_timer.period().as_secs() as u16,
                self.id,
            ),
            Asn::TwoOctet(asn) => OpenMessage::new2(
                asn,
                self.hold_timer.period().as_secs() as u16,
                self.id,
            ),
        };
        let msg_buf = msg.to_wire().unwrap();
        let header = Header {
            length: msg_buf.len() as u16 + 19,
            typ: MessageType::Open,
        };
        let mut header_buf = header.to_wire().to_vec();
        header_buf.extend_from_slice(&msg_buf);
        stream.writable().await.unwrap();
        stream.write_all(&header_buf).await.unwrap();
    }

    async fn on_open_confirm(&mut self, mut stream: TcpStream) -> FsmState {
        let msg = Self::recv_msg(&mut stream, &self.event_tx).await;
        match msg {
            Ok(Message::KeepAlive) => {
                self.keepalive_timer.reset();
                self.hold_timer.reset();
                FsmState::Established(stream)
            }
            Ok(Message::Notification(m)) => {
                warn!(self.log, "notification received: {:#?}", m);
                self.session.lock().await.connect_retry_counter += 1;
                self.on_start().await
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    error!(self.log, "on open confirm: {:#?}", e);
                }
                FsmState::OpenConfirm(stream)
            }
            other => {
                warn!(
                    self.log,
                    "Message {:?} not expected in open confirm, ignoring",
                    other
                );
                FsmState::OpenConfirm(stream)
            }
        }
    }

    async fn on_established(&mut self, mut stream: TcpStream) -> FsmState {
        tokio::select! {
            _ = self.keepalive_timer.tick() => {
                self.send_keepalive(&mut stream).await;
                FsmState::Established(stream)
            }
            _ = self.hold_timer.tick() => {
                self.session.lock().await.connect_retry_counter += 1;
                self.on_start().await
            }
            msg = Self::recv_msg(&mut stream, &self.event_tx) => {
                match msg {
                    Ok(Message::Open(m)) => {
                        warn!(self.log,
                            "established: expected open message, \
                            received {:#?}, ignoring",
                            m);
                        FsmState::Established(stream)
                    }
                    Ok(Message::Update(m)) => {
                        self.hold_timer.reset();
                        info!(self.log, "update received: {:#?}", m);
                        //TODO apply update
                        FsmState::Established(stream)
                    }
                    Ok(Message::Notification(m)) => {
                        warn!(self.log, "notification received: {:#?}", m);
                        self.session.lock().await.connect_retry_counter += 1;
                        self.on_start().await
                    }
                    Ok(Message::KeepAlive) => {
                        self.hold_timer.reset();
                        FsmState::Established(stream)
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            error!(self.log, "recv msg {:#?}", e);
                        }
                        FsmState::Established(stream)
                    }
                }
            }
        }
    }
}
