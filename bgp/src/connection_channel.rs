// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// This file contains code for testing purposes only. Note that it's only
/// included in `lib.rs` with a `#[cfg(test)]` guard. The purpose of the
/// code in this file is to implement BgpListener and BgpConnection such that
/// the core functionality of the BGP upper-half in `session.rs` may be tested
/// rapidly using a simulated network.
use crate::{
    clock::ConnectionClock,
    connection::{
        BgpConnection, BgpConnector, BgpListener, ConnectionCreator,
        ConnectionId,
    },
    error::Error,
    log::{connection_log, connection_log_lite},
    messages::Message,
    session::{ConnectionEvent, FsmEvent, SessionEndpoint, SessionInfo},
};
use mg_common::lock;
use slog::Logger;
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{channel as mpsc_channel, Receiver, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread::spawn,
    time::Duration,
};

const UNIT_CONNECTION: &str = "connection_channel";

/// Global counter for assigning unique IDs to channel pairs
static CHANNEL_PAIR_ID: AtomicU64 = AtomicU64::new(0);

lazy_static! {
    static ref NET: Network = Network::new();
}

/// A simulated network that maps socket addresses to channels that can send
/// messages to listeners for those addresses.
pub struct Network {
    #[allow(clippy::type_complexity)]
    pub endpoints:
        Mutex<HashMap<SocketAddr, Sender<(SocketAddr, Endpoint<Message>)>>>,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{")?;
        for sockaddr in lock!(self.endpoints).iter() {
            write!(f, "{sockaddr:?}")?;
        }
        write!(f, "}}")?;
        Ok(())
    }
}

/// A listener that can listen for messages on our simulated network.
struct Listener {
    rx: Receiver<(SocketAddr, Endpoint<Message>)>,
}

impl Listener {
    fn accept(
        &self,
        timeout: Duration,
    ) -> Result<(SocketAddr, Endpoint<Message>), Error> {
        self.rx.recv_timeout(timeout).map_err(|e| match e {
            RecvTimeoutError::Timeout => Error::Timeout,
            RecvTimeoutError::Disconnected => Error::Disconnected,
        })
    }
}

// NOTE: this is not designed to be a full fidelity TCP/IP drop in. It gives
// us enough functionality to pass messages between BGP routers to test
// state machine transitions above TCP connection tracking. That's all we're
// aiming for with this.
impl Network {
    fn new() -> Self {
        Self {
            endpoints: Mutex::new(HashMap::new()),
        }
    }

    /// Bind to the specified address and return a listener.
    fn bind(&self, sa: SocketAddr) -> Listener {
        let (tx, rx) = mpsc_channel();
        lock!(self.endpoints).insert(sa, tx);
        Listener { rx }
    }

    /// Send a copy of the provided endpoint to the endpoint identified by the
    // `to` address along with our `from` address so the endpoints identified
    // by `from` and `to` can exchange messages.
    fn connect(
        &self,
        from: SocketAddr,
        to: SocketAddr,
        ep: Endpoint<Message>,
    ) -> Result<(), Error> {
        match lock!(self.endpoints).get(&to) {
            None => return Err(Error::ChannelConnect),
            Some(sender) => {
                sender
                    .send((from, ep))
                    .map_err(|e| Error::ChannelSend(e.to_string()))?;
            }
        };

        Ok(())
    }
}

/// A struct to implement BgpListener for our simulated test network.
pub struct BgpListenerChannel {
    listener: Listener,
    bind_addr: SocketAddr,
}

impl BgpListener<BgpConnectionChannel> for BgpListenerChannel {
    fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let addr = addr
            .to_socket_addrs()
            .map_err(|e| Error::InvalidAddress(e.to_string()))?
            .next()
            .ok_or(Error::InvalidAddress(
                "at least one address required".into(),
            ))?;
        let listener = NET.bind(addr);
        Ok(Self {
            listener,
            bind_addr: addr,
        })
    }

    fn accept(
        &self,
        log: Logger,
        addr_to_session: Arc<
            Mutex<BTreeMap<IpAddr, SessionEndpoint<BgpConnectionChannel>>>,
        >,
        timeout: Duration,
    ) -> Result<BgpConnectionChannel, Error> {
        let (peer, endpoint) = self.listener.accept(timeout)?;

        // For channel-based test connections, we use the bind address as the local
        // address. In a real network scenario (like TCP), we would need to get the
        // actual connection's local address to handle dual-stack correctly, but for
        // testing purposes with channels, the bind address is the connection address.
        let local = self.bind_addr;

        match lock!(addr_to_session).get(&peer.ip()) {
            Some(session_endpoint) => {
                let config = lock!(session_endpoint.config);
                Ok(BgpConnectionChannel::with_conn(
                    local,
                    peer,
                    endpoint,
                    session_endpoint.event_tx.clone(),
                    timeout,
                    log,
                    ConnectionCreator::Dispatcher,
                    &config,
                ))
            }
            None => Err(Error::UnknownPeer(peer.ip())),
        }
    }

    fn apply_policy(
        _conn: &BgpConnectionChannel,
        _min_ttl: Option<u8>,
        _md5_key: Option<String>,
    ) -> Result<(), Error> {
        // Policy application is ignored for test connections
        Ok(())
    }
}

/// A struct to implement BgpConnection for our simulated test network.
pub struct BgpConnectionChannel {
    addr: SocketAddr,
    peer: SocketAddr,
    conn_tx: Arc<Mutex<Sender<Message>>>,
    log: Logger,
    // creator of this connection, i.e. BgpListener or BgpConnector
    creator: ConnectionCreator,
    conn_id: ConnectionId,
    // Connection-level timers for keepalive, hold, and delay open
    connection_clock: ConnectionClock,
    // Parameters for spawning the recv loop (stored until start_recv_loop is called)
    // Note: No Arc needed! recv loop is started before cloning in register_conn()
    recv_loop_params: Mutex<Option<RecvLoopParamsChannel>>,
    // Track whether recv loop has been started
    recv_loop_started: std::sync::atomic::AtomicBool,
    // Unique identifier for the underlying channel pair (shared by both endpoints)
    channel_id: u64,
}

impl Clone for BgpConnectionChannel {
    fn clone(&self) -> Self {
        // Clones always have empty recv loop params since the original connection
        // should have started the recv loop before being cloned (in register_conn).
        Self {
            addr: self.addr,
            peer: self.peer,
            conn_tx: self.conn_tx.clone(),
            log: self.log.clone(),
            creator: self.creator,
            conn_id: self.conn_id,
            connection_clock: self.connection_clock.clone(),
            recv_loop_params: Mutex::new(None),
            recv_loop_started: std::sync::atomic::AtomicBool::new(true),
            channel_id: self.channel_id,
        }
    }
}

/// Parameters needed to spawn the receive loop for a channel-based BGP connection
struct RecvLoopParamsChannel {
    rx: Receiver<Message>,
    event_tx: Sender<FsmEvent<BgpConnectionChannel>>,
    timeout: Duration,
}

impl BgpConnection for BgpConnectionChannel {
    type Connector = BgpConnectorChannel;

    fn send(&self, msg: Message) -> Result<(), Error> {
        let guard = lock!(self.conn_tx);
        connection_log!(self,
            trace,
            "send {} message via channel to {} (conn_id: {}, channel_id: {})",
            msg.title(), self.peer(), self.id().short(), self.channel_id;
            "message" => msg.title(),
            "message_contents" => format!("{msg}"),
            "channel_id" => self.channel_id
        );
        if let Err(e) = guard
            .send(msg)
            .map_err(|e| Error::ChannelSend(e.to_string()))
        {
            connection_log!(self,
                error,
                "error sending message via channel to {} (conn_id: {}, channel_id: {}): {e}",
                self.peer(), self.id().short(), self.channel_id;
                "error" => format!("{e}"),
                "network_state" => format!("{}", *NET),
                "channel_id" => self.channel_id
            );
            return Err(e);
        }
        Ok(())
    }

    fn peer(&self) -> SocketAddr {
        self.peer
    }

    fn local(&self) -> SocketAddr {
        self.addr
    }

    fn conn(&self) -> (SocketAddr, SocketAddr) {
        (self.local(), self.peer())
    }

    fn creator(&self) -> ConnectionCreator {
        self.creator
    }

    fn id(&self) -> &ConnectionId {
        &self.conn_id
    }

    fn clock(&self) -> &ConnectionClock {
        &self.connection_clock
    }

    fn start_recv_loop(&self) {
        // Check if already started (idempotent)
        if self
            .recv_loop_started
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            // Already started, nothing to do
            return;
        }

        // Take the params (they should exist since we haven't started yet)
        let params = lock!(self.recv_loop_params).take();
        if let Some(params) = params {
            connection_log!(self, info,
                "spawning recv loop for {} (conn_id: {}, channel_id: {})",
                self.peer(), self.conn_id.short(), self.channel_id;
                "channel_id" => self.channel_id
            );

            let peer = self.peer;
            let event_tx = params.event_tx;
            let rx = params.rx;
            let timeout = params.timeout;
            let log = self.log.clone();
            let creator = self.creator;
            let conn_id = self.conn_id;
            let channel_id = self.channel_id;

            Self::spawn_recv_loop(
                peer, rx, event_tx, timeout, log, creator, conn_id, channel_id,
            );
        }
    }
}

impl BgpConnectionChannel {
    /// Create a new BgpConnectionChannel with an established endpoint.
    /// This is a private constructor used by BgpConnectorChannel and BgpListenerChannel.
    /// The receive loop is not started until start_recv_loop() is called.
    #[allow(clippy::too_many_arguments)]
    fn with_conn(
        addr: SocketAddr,
        peer: SocketAddr,
        conn: Endpoint<Message>,
        event_tx: Sender<FsmEvent<Self>>,
        timeout: Duration,
        log: Logger,
        creator: ConnectionCreator,
        config: &SessionInfo,
    ) -> Self {
        let conn_id = ConnectionId::new(addr, peer);
        let connection_clock = ConnectionClock::new(
            config.resolution,
            config.keepalive_time,
            config.hold_time,
            config.delay_open_time,
            conn_id,
            event_tx.clone(),
            log.clone(),
        );

        let channel_id = conn.channel_id;

        // Store the parameters for spawning the recv loop later
        let recv_loop_params = Mutex::new(Some(RecvLoopParamsChannel {
            rx: conn.rx,
            event_tx,
            timeout,
        }));

        Self {
            addr,
            peer,
            conn_tx: Arc::new(Mutex::new(conn.tx)),
            log,
            creator,
            conn_id,
            connection_clock,
            recv_loop_params,
            recv_loop_started: std::sync::atomic::AtomicBool::new(false),
            channel_id,
        }
    }

    /// Spawn the receive loop thread for this connection.
    #[allow(clippy::too_many_arguments)]
    fn spawn_recv_loop(
        peer: SocketAddr,
        rx: Receiver<Message>,
        event_tx: Sender<FsmEvent<Self>>,
        timeout: Duration,
        log: Logger,
        creator: ConnectionCreator,
        conn_id: ConnectionId,
        channel_id: u64,
    ) {
        spawn(move || loop {
            match rx.recv_timeout(timeout) {
                Ok(msg) => {
                    connection_log_lite!(log,
                        debug,
                        "recv {} msg from {peer} (conn_id: {}, channel_id: {})",
                        msg.title(), conn_id.short(), channel_id;
                        "creator" => creator.as_str(),
                        "peer" => format!("{peer}"),
                        "message" => msg.title(),
                        "message_contents" => format!("{msg}"),
                        "channel_id" => channel_id
                    );
                    if let Err(e) = event_tx.send(FsmEvent::Connection(
                        ConnectionEvent::Message { msg, conn_id },
                    )) {
                        connection_log_lite!(log,
                            error,
                            "error sending event to {peer}: {e}";
                            "creator" => creator.as_str(),
                            "peer" => format!("{peer}"),
                            "error" => format!("{e}"),
                            "channel_id" => channel_id
                        );
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Normal timeout, continue waiting for messages
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    // Peer closed connection, exit recv loop cleanly
                    connection_log_lite!(log,
                        debug,
                        "peer {peer} disconnected (conn_id: {}, channel_id: {}), terminating recv loop",
                        conn_id.short(), channel_id;
                        "creator" => creator.as_str(),
                        "peer" => format!("{peer}"),
                        "connection_id" => conn_id.short(),
                        "channel_id" => channel_id
                    );
                    break;
                }
            }
        });
    }
}

pub struct BgpConnectorChannel;

impl BgpConnector<BgpConnectionChannel> for BgpConnectorChannel {
    fn connect(
        peer: SocketAddr,
        timeout: Duration,
        log: Logger,
        event_tx: Sender<FsmEvent<BgpConnectionChannel>>,
        config: SessionInfo,
    ) -> Result<std::thread::JoinHandle<()>, Error> {
        let creator = ConnectionCreator::Connector;
        let addr = config
            .bind_addr
            .expect("source address required for channel-based connection");

        connection_log_lite!(log,
            debug,
            "connecting to {peer}";
            "creator" => creator.as_str(),
            "timeout" => timeout.as_millis()
        );

        // For the channel-based test implementation, we spawn a thread to maintain
        // consistency with the TCP implementation, even though the connection
        // is synchronous. This allows SessionRunner to track the connector thread.
        let handle = spawn(move || {
            let (local, remote) = channel();
            match NET.connect(addr, peer, remote) {
                Ok(()) => {
                    let conn = BgpConnectionChannel::with_conn(
                        addr,
                        peer,
                        local,
                        event_tx.clone(),
                        timeout,
                        log.clone(),
                        creator,
                        &config,
                    );

                    connection_log_lite!(log,
                        info,
                        "channel connection to {peer} established (conn_id: {}, channel_id: {})",
                        conn.id().short(), conn.channel_id;
                        "creator" => creator.as_str(),
                        "peer" => format!("{peer}"),
                        "local" => format!("{addr}"),
                        "connection_id" => conn.id().short(),
                        "channel_id" => conn.channel_id
                    );

                    // Send the TcpConnectionConfirmed event
                    use crate::session::SessionEvent;
                    if let Err(e) = event_tx.send(FsmEvent::Session(
                        SessionEvent::TcpConnectionConfirmed(conn),
                    )) {
                        connection_log_lite!(log,
                            error,
                            "failed to send TcpConnectionConfirmed event for {peer}: {e}";
                            "creator" => creator.as_str(),
                            "peer" => format!("{peer}"),
                            "error" => format!("{e}")
                        );
                    }
                }
                Err(e) => {
                    connection_log_lite!(log,
                        debug,
                        "connect error: {e:?}";
                        "creator" => creator.as_str(),
                        "timeout" => timeout.as_millis(),
                        "error" => format!("{e}")
                    );
                }
            }
        });

        Ok(handle)
    }
}

// BIDI

/// A combined (duplex) mpsc sender/receiver.
pub struct Endpoint<T> {
    pub rx: Receiver<T>,
    pub tx: Sender<T>,
    pub channel_id: u64,
}

impl<T> Endpoint<T> {
    fn new(rx: Receiver<T>, tx: Sender<T>, channel_id: u64) -> Self {
        Self { rx, tx, channel_id }
    }
}

/// Creates a bidirectional channel pair with both sender and receiver.
#[allow(dead_code)]
pub fn channel<T>() -> (Endpoint<T>, Endpoint<T>) {
    let (tx_a, rx_b) = mpsc_channel();
    let (tx_b, rx_a) = mpsc_channel();
    let channel_id = CHANNEL_PAIR_ID.fetch_add(1, Ordering::Relaxed);
    (
        Endpoint::new(rx_a, tx_a, channel_id),
        Endpoint::new(rx_b, tx_b, channel_id),
    )
}
