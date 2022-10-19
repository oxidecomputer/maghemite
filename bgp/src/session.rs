use crate::messages::{
    Header, Message, MessageType, NotificationMessage, OpenMessage,
    UpdateMessage,
};
use crate::state::BgpState;
use slog::{info, warn, Logger};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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

#[derive(Debug)]
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
    // Required Attributes
    /// Track how many times a connection has been attempted.
    pub connect_retry_counter: u64,

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
        idle_hold_time: Duration,
        delay_open_time: Duration,
    ) -> Arc<Mutex<Session>> {
        Arc::new(Mutex::new(Session {
            connect_retry_counter: 0,
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
        }))
    }
}

pub enum Asn {
    TwoOctet(u16),
    FourOctet(u32),
}

pub struct SessionRunner {
    session: Arc<Mutex<Session>>,
    event_rx: Receiver<FsmEvent>,
    _event_tx: Sender<FsmEvent>,
    _bgp_state: Arc<Mutex<BgpState>>,

    /// How long to wait between connection attempts.
    pub connect_retry_timer: Interval,

    /// How often to send out keepalive messages.
    pub keepalive_timer: Interval,

    /// How long to keep a session alive between keepalive, update and/or
    /// notification messages.
    pub hold_timer: Interval,

    peer: String,
    asn: Asn,
    id: u32,

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
        peer: String,
        asn: Asn,
        id: u32,
        log: Logger,
    ) -> SessionRunner {
        SessionRunner {
            session,
            event_rx,
            _event_tx: event_tx,
            _bgp_state: bgp_state,
            peer,
            connect_retry_timer: interval(connect_retry_time),
            keepalive_timer: interval(keepalive_time),
            hold_timer: interval(hold_time),
            asn,
            id,
            log,
        }
    }

    pub async fn start(&mut self) {
        let mut next = FsmState::Idle;
        loop {
            next = match next {
                FsmState::Idle => self.idle().await,
                FsmState::Connect(stream) => self.on_connect(stream).await,
                FsmState::Active(stream) => self.on_active(stream).await,
                FsmState::OpenSent(stream) => self.on_open_sent(stream).await,
                FsmState::OpenConfirm(stream) => {
                    self.on_open_confirm(stream).await
                }
                FsmState::Established(stream) => {
                    self.on_established(stream).await
                }
            };
        }
    }

    async fn idle(&mut self) -> FsmState {
        match self.event_rx.recv().await {
            None => FsmState::Idle,
            Some(FsmEvent::ManualStart) => self.on_manual_start().await,
            x => {
                warn!(self.log, "Event {:?} not allowed in idle, ignoring", x);
                FsmState::Idle
            }
        }
    }

    async fn on_manual_start(&mut self) -> FsmState {
        self.session.lock().await.connect_retry_counter = 0;

        let listener = TcpListener::bind("0.0.0.0:179").await.unwrap();

        tokio::select! {
            _ = self.connect_retry_timer.tick() => {
                let stream = TcpStream::connect(&self.peer).await.unwrap();
                FsmState::Connect(stream)
            }
            result = listener.accept() => {
                let (stream, _) = result.unwrap();
                FsmState::Active(stream)
            }
        }
    }

    async fn recv_header(stream: &mut TcpStream) -> Header {
        loop {
            let mut buf = [0u8; 19];
            stream.read_exact(&mut buf).await.unwrap();
            match Header::from_wire(&buf) {
                Ok(h) => return h,
                Err(_) => continue,
            };
        }
    }

    async fn recv_msg(stream: &mut TcpStream) -> Message {
        loop {
            let hdr = Self::recv_header(stream).await;
            let mut msgbuf = vec![0u8; hdr.length as usize];
            stream.read_exact(&mut msgbuf).await.unwrap();

            match hdr.typ {
                MessageType::Open => match OpenMessage::from_wire(&msgbuf) {
                    Ok(m) => return m.into(),
                    Err(_) => continue,
                },
                MessageType::Update => {
                    match UpdateMessage::from_wire(&msgbuf) {
                        Ok(m) => return m.into(),
                        Err(_) => continue,
                    }
                }
                MessageType::Notification => {
                    match NotificationMessage::from_wire(&msgbuf) {
                        Ok(m) => return m.into(),
                        Err(_) => continue,
                    }
                }
                MessageType::KeepAlive => return Message::KeepAlive,
            };
        }
    }

    async fn on_connect(&mut self, mut stream: TcpStream) -> FsmState {
        self.send_open(&mut stream).await;
        FsmState::OpenSent(stream)
    }

    async fn on_active(&mut self, mut stream: TcpStream) -> FsmState {
        let msg = Self::recv_msg(&mut stream).await;
        let om =
            match msg {
                Message::Open(om) => om,
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
        let msg = Self::recv_msg(&mut stream).await;
        let om =
            match msg {
                Message::Open(om) => om,
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

    fn open_is_valid(&self, _om: OpenMessage) -> bool {
        //TODO
        true
    }

    async fn send_keepalive(&self, stream: &mut TcpStream) {
        let header = Header {
            length: 0,
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
            length: msg_buf.len() as u16,
            typ: MessageType::Notification,
        };
        let header_buf = header.to_wire();
        stream.write_all(&header_buf).await.unwrap();
        stream.write_all(&msg_buf).await.unwrap();
    }

    async fn on_open_confirm(&mut self, mut stream: TcpStream) -> FsmState {
        let msg = Self::recv_msg(&mut stream).await;
        match msg {
            Message::KeepAlive => {
                self.keepalive_timer.reset();
                self.hold_timer.reset();
                FsmState::Established(stream)
            }
            _other => todo!(),
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
                FsmState::Idle
            }
            msg = Self::recv_msg(&mut stream) => {
                match msg {
                    Message::Open(m) => {
                        warn!(self.log,
                            "established: expected open message, \
                            received {:#?}, ignoring",
                            m);
                        FsmState::Established(stream)
                    }
                    Message::Update(m) => {
                        self.hold_timer.reset();
                        info!(self.log, "update received: {:#?}", m);
                        //TODO apply update
                        FsmState::Established(stream)
                    }
                    Message::Notification(m) => {
                        warn!(self.log, "notification received: {:#?}", m);
                        FsmState::Idle
                    }
                    Message::KeepAlive => {
                        self.hold_timer.reset();
                        FsmState::Established(stream)
                    }
                }
            }
        }
    }
}
