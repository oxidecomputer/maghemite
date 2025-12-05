// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// This file contains code for testing purposes only. Note that it's only
/// included in `lib.rs` with a `#[cfg(test)]` guard. The purpose of the
/// code in this file is to implement BgpListener and BgpConnection such that
/// the core functionality of the BGP upper-half in `session.rs` may be tested
/// rapidly using a simulated network.
use crate::{
    IO_TIMEOUT,
    clock::ConnectionClock,
    connection::{
        BgpConnection, BgpConnector, BgpListener, ConnectionDirection,
        ConnectionId, ThreadState,
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
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, RecvTimeoutError, Sender, channel as mpsc_channel},
    },
    thread::{JoinHandle, spawn},
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
                    IO_TIMEOUT,
                    log,
                    ConnectionDirection::Inbound,
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
    conn_rx: Arc<Mutex<Option<Receiver<Message>>>>,
    dropped: Arc<AtomicBool>,
    log: Logger,
    // direction of this connection, i.e. BgpListener or BgpConnector
    direction: ConnectionDirection,
    conn_id: ConnectionId,
    // Connection-level timers for keepalive, hold, and delay open
    connection_clock: ConnectionClock,
    // Event sender for recv loop
    event_tx: Sender<FsmEvent<BgpConnectionChannel>>,
    // Receive timeout for channel recv loop
    recv_timeout: std::time::Duration,
    // Unique identifier for the underlying channel pair (shared by both endpoints)
    channel_id: u64,
    // Typestate managing the recv loop thread lifecycle (Ready or Running)
    recv_loop_state: Mutex<ThreadState>,
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

    fn direction(&self) -> ConnectionDirection {
        self.direction
    }

    fn id(&self) -> &ConnectionId {
        &self.conn_id
    }

    fn clock(&self) -> &ConnectionClock {
        &self.connection_clock
    }

    fn start_recv_loop(self: &Arc<Self>) -> Result<(), Error> {
        let mut state = lock!(self.recv_loop_state);

        // Check if already started (idempotent via typestate)
        if state.is_running() {
            // Already started, return Ok (idempotent)
            return Ok(());
        }

        let handle = Self::spawn_recv_loop(Arc::clone(self))?;

        // Store the handle in the typestate
        state.start(handle);

        Ok(())
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
        direction: ConnectionDirection,
        config: &SessionInfo,
    ) -> Self {
        let conn_id = ConnectionId::new(addr, peer);
        let dropped = Arc::new(AtomicBool::new(false));
        let connection_clock = ConnectionClock::new(
            config.resolution,
            config.keepalive_time,
            config.hold_time,
            config.delay_open_time,
            conn_id,
            event_tx.clone(),
            dropped.clone(),
            log.clone(),
        );

        let channel_id = conn.channel_id;

        Self {
            addr,
            peer,
            conn_tx: Arc::new(Mutex::new(conn.tx)),
            conn_rx: Arc::new(Mutex::new(Some(conn.rx))),
            dropped,
            log,
            direction,
            conn_id,
            connection_clock,
            event_tx,
            recv_timeout: timeout,
            channel_id,
            recv_loop_state: Mutex::new(ThreadState::new()),
        }
    }

    /// Spawn the receive loop thread for this connection.
    fn spawn_recv_loop(self_: Arc<Self>) -> Result<JoinHandle<()>, Error> {
        // Take the receiver. This will be None after first call.
        let rx = {
            let mut conn_rx = lock!(self_.conn_rx);
            conn_rx.take()
        };

        // If no receiver, return error immediately
        let rx = rx.ok_or_else(|| {
            connection_log_lite!(self_.log,
                error,
                "failed to spawn recv loop: receiver already consumed or unavailable (channel_id: {})",
                self_.channel_id;
                "channel_id" => self_.channel_id
            );
            Error::Disconnected
        })?;

        let peer = self_.peer;
        let direction = self_.direction;
        let conn_id = self_.conn_id;
        let channel_id = self_.channel_id;
        let log = self_.log.clone();
        let timeout = self_.recv_timeout;
        let event_tx = self_.event_tx.clone();
        let dropped = self_.dropped.clone();

        // Use Builder instead of spawn().
        // This lets us catch thread spawn errors instead of panicking.
        std::thread::Builder::new()
            .spawn(move || {
                loop {
                    if dropped.load(Ordering::Relaxed) {
                        connection_log_lite!(log, info,
                            "connection dropped (peer: {peer}, conn_id: {}, channel_id: {}), terminating recv loop",
                            conn_id.short(), channel_id;
                            "direction" => direction.as_str(),
                            "peer" => format!("{peer}"),
                            "connection_id" => conn_id.short(),
                            "channel_id" => channel_id
                        );
                        break;
                    }

                    // Note: Unlike BgpConnectionTcp, this has no ParseErrors.
                    //       BgpConnectionChannel is a wrapper around Message,
                    //       which is the type representation of a fully parsed
                    //       and valid message. This means it's not possible to
                    //       exchange invalid messages as-is. To support this,
                    //       the channel would need to wrap a different type
                    //       (feasible, but of limited utility) or update the
                    //       Message type to include possibly-invalid states
                    //       (also feasible, but undesirable).
                    match rx.recv_timeout(timeout) {
                        Ok(msg) => {
                            connection_log_lite!(log,
                                debug,
                                "recv {} msg from {peer} (conn_id: {}, channel_id: {})",
                                msg.title(), conn_id.short(), channel_id;
                                "direction" => direction.as_str(),
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
                                    "direction" => direction.as_str(),
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
                                "direction" => direction.as_str(),
                                "peer" => format!("{peer}"),
                                "connection_id" => conn_id.short(),
                                "channel_id" => channel_id
                            );
                            // Notify session runner that the connection failed,
                            // unless this is a graceful shutdown
                            if !dropped.load(Ordering::Relaxed)
                                && let Err(e) = event_tx.send(FsmEvent::Connection(
                                    ConnectionEvent::TcpConnectionFails(conn_id),
                                ))
                            {
                                connection_log_lite!(log, warn,
                                    "error sending TcpConnectionFails event to {peer}: {e}";
                                    "direction" => direction.as_str(),
                                    "peer" => format!("{peer}"),
                                    "connection_id" => conn_id.short(),
                                    "channel_id" => channel_id,
                                    "error" => format!("{e}")
                                );
                            }
                            break;
                        }
                    }
                }
            })
            .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))
    }
}

impl Drop for BgpConnectionChannel {
    fn drop(&mut self) {
        connection_log!(self,
            debug,
            "dropping bgp connection for peer {} (conn_id: {}, channel_id: {})",
            self.peer(), self.id().short(), self.channel_id;
            "network_state" => format!("{}", *NET),
            "channel_id" => self.channel_id
        );
        self.dropped.store(true, Ordering::Relaxed);
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
    ) -> Result<JoinHandle<()>, Error> {
        let direction = ConnectionDirection::Outbound;
        let addr = config
            .bind_addr
            .expect("source address required for channel-based connection");

        connection_log_lite!(log,
            debug,
            "connecting to {peer}";
            "direction" => direction.as_str(),
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
                        IO_TIMEOUT,
                        log.clone(),
                        direction,
                        &config,
                    );

                    connection_log_lite!(log,
                        info,
                        "channel connection to {peer} established (conn_id: {}, channel_id: {})",
                        conn.id().short(), conn.channel_id;
                        "direction" => direction.as_str(),
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
                            "direction" => direction.as_str(),
                            "peer" => format!("{peer}"),
                            "error" => format!("{e}")
                        );
                    }
                }
                Err(e) => {
                    connection_log_lite!(log,
                        debug,
                        "connect error: {e:?}";
                        "direction" => direction.as_str(),
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
