// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// This file contains code for testing purposes only. Note that it's only
/// included in `connection/mod.rs` with a `#[cfg(test)]` guard. The purpose of the
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
    messages::{Message, MessageParseError},
    router::SessionMap,
    session::{ConnectionEvent, FsmEvent, PeerId, SessionInfo},
    unnumbered::UnnumberedManager,
};
use mg_common::lock;
use slog::{Logger, info};
use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, RecvTimeoutError, Sender, channel as mpsc_channel},
    },
    thread::{JoinHandle, spawn},
    time::{Duration, Instant},
};

const UNIT_CONNECTION: &str = "connection_channel";

/// A message or fatal parse error.
pub type MessageResult = Result<Message, MessageParseError>;

/// Global counter for assigning unique IDs to channel pairs
static CHANNEL_PAIR_ID: AtomicU64 = AtomicU64::new(0);

/// Connection attempt record for testing.
/// Tracks all outbound connection attempts made via BgpConnectorChannel.
#[derive(Debug, Clone)]
pub struct ConnectionAttempt {
    pub timestamp: Instant,
    pub local: SocketAddr,
    pub peer: SocketAddr,
    pub success: bool,
}

lazy_static! {
    static ref NET: Network = Network::new();

    /// Global tracker for connection attempts (for testing).
    /// Records all outbound connection attempts so tests can verify
    /// connection behavior (e.g., that unnumbered sessions only connect
    /// when neighbors are discovered).
    static ref CONNECTION_ATTEMPTS: Mutex<Vec<ConnectionAttempt>> = Mutex::new(Vec::new());
}

/// A simulated network that maps socket addresses to channels that can send
/// messages to listeners for those addresses.
pub struct Network {
    #[allow(clippy::type_complexity)]
    pub endpoints: Mutex<
        HashMap<SocketAddr, Sender<(SocketAddr, Endpoint<MessageResult>)>>,
    >,
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
#[derive(Debug)]
struct Listener {
    rx: Receiver<(SocketAddr, Endpoint<MessageResult>)>,
    addr: SocketAddr,
}

impl Listener {
    fn accept(
        &self,
        timeout: Duration,
    ) -> Result<(SocketAddr, Endpoint<MessageResult>), Error> {
        self.rx.recv_timeout(timeout).map_err(|e| match e {
            RecvTimeoutError::Timeout => Error::Timeout,
            RecvTimeoutError::Disconnected => Error::Disconnected,
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        NET.unbind(&self.addr);
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
        Listener { rx, addr: sa }
    }

    /// Remove a bound address from the network.
    fn unbind(&self, addr: &SocketAddr) {
        lock!(self.endpoints).remove(addr);
    }

    /// Send a copy of the provided endpoint to the endpoint identified by the
    // `to` address along with our `from` address so the endpoints identified
    // by `from` and `to` can exchange messages.
    fn connect(
        &self,
        from: SocketAddr,
        to: SocketAddr,
        ep: Endpoint<MessageResult>,
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

// =========================================================================
// Connection Attempt Tracking (for testing)
// =========================================================================

/// Get all recorded connection attempts.
pub fn get_connection_attempts() -> Vec<ConnectionAttempt> {
    lock!(CONNECTION_ATTEMPTS).clone()
}

/// Clear all recorded connection attempts.
/// Useful for test setup/cleanup.
pub fn clear_connection_attempts() {
    lock!(CONNECTION_ATTEMPTS).clear();
}

/// Get connection attempts to a specific peer address.
pub fn get_connection_attempts_to(peer: SocketAddr) -> Vec<ConnectionAttempt> {
    lock!(CONNECTION_ATTEMPTS)
        .iter()
        .filter(|attempt| attempt.peer == peer)
        .cloned()
        .collect()
}

/// Get the number of successful connection attempts to a specific peer.
pub fn count_successful_connections_to(peer: SocketAddr) -> usize {
    lock!(CONNECTION_ATTEMPTS)
        .iter()
        .filter(|attempt| attempt.peer == peer && attempt.success)
        .count()
}

/// Get the number of failed connection attempts to a specific peer.
pub fn count_failed_connections_to(peer: SocketAddr) -> usize {
    lock!(CONNECTION_ATTEMPTS)
        .iter()
        .filter(|attempt| attempt.peer == peer && !attempt.success)
        .count()
}

/// A struct to implement BgpListener for our simulated test network.
pub struct BgpListenerChannel {
    listener: Listener,
    bind_addr: SocketAddr,
    unnumbered_manager: Option<Arc<dyn UnnumberedManager>>,
}

impl BgpListenerChannel {
    /// Resolve incoming peer address to appropriate PeerId.
    fn resolve_session_key(&self, peer_addr: SocketAddr) -> PeerId {
        // Try interface-based routing for IPv6 link-local addresses
        if let Some(ref mgr) = self.unnumbered_manager
            && let SocketAddr::V6(v6_addr) = peer_addr
            && v6_addr.ip().is_unicast_link_local()
        {
            let scope_id = v6_addr.scope_id();
            if let Some(interface) = mgr.get_interface_by_scope(scope_id) {
                return PeerId::Interface(interface);
            }
        }

        // Default to IP-based routing
        PeerId::Ip(peer_addr.ip())
    }
}

impl BgpListener<BgpConnectionChannel> for BgpListenerChannel {
    fn bind<A: ToSocketAddrs>(
        addr: A,
        log: Logger,
        unnumbered_manager: Option<Arc<dyn UnnumberedManager>>,
    ) -> Result<Self, Error>
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
        info!(log, "BgpConnectionChannel Listener created"; "listener" => ?listener);
        Ok(Self {
            listener,
            bind_addr: addr,
            unnumbered_manager,
        })
    }

    fn accept(
        &self,
        log: Logger,
        sessions: Arc<Mutex<SessionMap<BgpConnectionChannel>>>,
        timeout: Duration,
    ) -> Result<BgpConnectionChannel, Error> {
        let (peer, endpoint) = self.listener.accept(timeout)?;

        let local = self.bind_addr;

        // Resolve peer address to appropriate PeerId (IP or Interface)
        let key = self.resolve_session_key(peer);

        let runner = lock!(sessions)
            .get(&key)
            .cloned()
            .ok_or_else(|| Error::UnknownPeer(key.clone()))?;

        let config = lock!(runner.session);
        Ok(BgpConnectionChannel::with_conn(
            local,
            peer,
            endpoint,
            runner.event_tx.clone(),
            IO_TIMEOUT,
            log,
            ConnectionDirection::Inbound,
            &config,
        ))
    }

    fn apply_policy(
        _conn: &BgpConnectionChannel,
        _min_ttl: Option<u8>,
        _md5_key: Option<String>,
    ) -> Result<(), Error> {
        // Policy application is ignored for test connections
        Ok(())
    }

    fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

/// A struct to implement BgpConnection for our simulated test network.
pub struct BgpConnectionChannel {
    addr: SocketAddr,
    peer: SocketAddr,
    conn_tx: Arc<Mutex<Sender<MessageResult>>>,
    conn_rx: Arc<Mutex<Option<Receiver<MessageResult>>>>,
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
            .send(Ok(msg))
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
    pub(crate) fn with_conn(
        addr: SocketAddr,
        peer: SocketAddr,
        conn: Endpoint<MessageResult>,
        event_tx: Sender<FsmEvent<Self>>,
        timeout: Duration,
        log: Logger,
        direction: ConnectionDirection,
        config: &SessionInfo,
    ) -> Self {
        let conn = Self::with_conn_without_clock_thread(
            addr, peer, conn, event_tx, timeout, log, direction, config,
        );
        conn.connection_clock.start(
            conn.event_tx.clone(),
            conn.dropped.clone(),
            conn.log.clone(),
        );
        conn
    }

    /// Construct a connection for tests that inject FSM events manually.
    /// Neither the clock thread nor the receive loop is started.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_conn_without_clock_thread(
        addr: SocketAddr,
        peer: SocketAddr,
        conn: Endpoint<MessageResult>,
        event_tx: Sender<FsmEvent<Self>>,
        timeout: Duration,
        log: Logger,
        direction: ConnectionDirection,
        config: &SessionInfo,
    ) -> Self {
        let conn_id = ConnectionId::new(addr, peer);
        let dropped = Arc::new(AtomicBool::new(false));
        let connection_clock = ConnectionClock::new_unstarted(
            config.resolution,
            config.keepalive_time,
            config.hold_time,
            config.delay_open_time,
            conn_id,
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

                    match rx.recv_timeout(timeout) {
                        Ok(Ok(msg)) => {
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
                                    warn,
                                    "error sending event to {peer}: {e}";
                                    "direction" => direction.as_str(),
                                    "peer" => format!("{peer}"),
                                    "error" => format!("{e}"),
                                    "channel_id" => channel_id
                                );
                                break;
                            }
                        }
                        Ok(Err(error)) => {
                            connection_log_lite!(log, error,
                                "recv parse error from {peer} (conn_id: {}, channel_id: {}): {error}",
                                conn_id.short(), channel_id;
                                "direction" => direction.as_str(),
                                "peer" => format!("{peer}"),
                                "connection_id" => conn_id.short(),
                                "channel_id" => channel_id,
                                "error" => format!("{error}")
                            );
                            if let Err(e) = event_tx.send(FsmEvent::Connection(
                                ConnectionEvent::ParseError { conn_id, error },
                            )) {
                                connection_log_lite!(log, warn,
                                    "error sending parse error event to {peer}: {e}";
                                    "direction" => direction.as_str(),
                                    "peer" => format!("{peer}"),
                                    "connection_id" => conn_id.short(),
                                    "channel_id" => channel_id,
                                    "error" => format!("{e}")
                                );
                            }
                            // Like TCP, a fatal parse error ends reception;
                            // the FSM owns NOTIFICATION sending and reset.
                            break;
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
                            if let Err(e) = event_tx.send(FsmEvent::Connection(
                                ConnectionEvent::TcpConnectionFails(conn_id),
                            )) {
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

            // Record connection attempt for testing
            let attempt_result = NET.connect(addr, peer, remote);
            lock!(CONNECTION_ATTEMPTS).push(ConnectionAttempt {
                timestamp: Instant::now(),
                local: addr,
                peer,
                success: attempt_result.is_ok(),
            });

            match attempt_result {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{
        ErrorCode, ErrorSubcode, MessageParseError, OpenErrorSubcode,
        OpenParseError, OpenParseErrorReason,
    };
    use crate::test::{RouteExchange, create_test_session_info};

    fn test_connection() -> (
        Arc<BgpConnectionChannel>,
        Endpoint<MessageResult>,
        Receiver<FsmEvent<BgpConnectionChannel>>,
    ) {
        let local = "192.0.2.1:179".parse().unwrap();
        let peer = "192.0.2.2:179".parse().unwrap();
        let config = create_test_session_info(
            RouteExchange::Ipv4 { nexthop: None },
            local,
            peer,
            false,
        );
        let (event_tx, event_rx) = mpsc_channel();
        let (endpoint, remote) = channel();
        let conn =
            Arc::new(BgpConnectionChannel::with_conn_without_clock_thread(
                local,
                peer,
                endpoint,
                event_tx,
                IO_TIMEOUT,
                Logger::root(slog::Discard, slog::o!()),
                ConnectionDirection::Inbound,
                &config,
            ));
        (conn, remote, event_rx)
    }

    #[test]
    fn receive_loop_stops_when_fsm_receiver_is_gone() {
        let (conn, remote, event_rx) = test_connection();
        drop(event_rx);
        remote.tx.send(Ok(Message::KeepAlive)).unwrap();
        let handle =
            BgpConnectionChannel::spawn_recv_loop(conn.clone()).unwrap();
        let (done_tx, done_rx) = mpsc_channel();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                handle.join().unwrap();
                done_tx.send(()).unwrap();
            });
            let exited = done_rx.recv_timeout(Duration::from_secs(5));
            // Release even a buggy loop before asserting, so the test cannot
            // leave a worker waiting on an open peer channel.
            drop(remote.tx);
            assert!(exited.is_ok(), "receive loop outlived the FSM receiver");
        });
    }

    #[test]
    fn disconnect_is_reported_even_if_shutdown_arrives_after_receive() {
        struct ShutdownOnDisconnect(Arc<AtomicBool>);

        impl slog::Drain for ShutdownOnDisconnect {
            type Ok = ();
            type Err = std::convert::Infallible;

            fn log(
                &self,
                record: &slog::Record<'_>,
                _: &slog::OwnedKVList,
            ) -> Result<(), Self::Err> {
                // Interpose after recv_timeout reports disconnection, without
                // a timing-dependent race or a hook in the receive loop.
                if record.msg().to_string().contains("disconnected") {
                    self.0.store(true, Ordering::Relaxed);
                }
                Ok(())
            }
        }

        let (mut conn, remote, event_rx) = test_connection();
        let dropped = conn.dropped.clone();
        Arc::get_mut(&mut conn).unwrap().log =
            Logger::root(ShutdownOnDisconnect(dropped.clone()), slog::o!());
        drop(remote.tx);
        BgpConnectionChannel::spawn_recv_loop(conn.clone())
            .unwrap()
            .join()
            .unwrap();
        assert!(dropped.load(Ordering::Relaxed));
        let events = event_rx.try_iter().collect::<Vec<_>>();
        assert!(matches!(
            events.as_slice(),
            [FsmEvent::Connection(ConnectionEvent::TcpConnectionFails(id))]
                if id == conn.id()
        ));
    }

    #[test]
    fn local_shutdown_before_receive_is_silent() {
        let (conn, remote, event_rx) = test_connection();
        conn.dropped.store(true, Ordering::Relaxed);
        drop(remote.tx);
        BgpConnectionChannel::spawn_recv_loop(conn)
            .unwrap()
            .join()
            .unwrap();
        assert!(event_rx.try_iter().next().is_none());
    }

    #[test]
    fn parse_error_is_forwarded_once_and_stops_receive_loop() {
        let (conn, remote, event_rx) = test_connection();

        conn.send(Message::KeepAlive).unwrap();
        assert_eq!(
            remote
                .rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            Message::KeepAlive,
        );
        remote.tx.send(Ok(Message::KeepAlive)).unwrap();
        remote
            .tx
            .send(Err(MessageParseError::Open(OpenParseError {
                error_code: ErrorCode::Open,
                error_subcode: ErrorSubcode::Open(
                    OpenErrorSubcode::UnsupportedVersionNumber,
                ),
                reason: OpenParseErrorReason::InvalidVersion { version: 3 },
            })))
            .unwrap();
        remote.tx.send(Ok(Message::KeepAlive)).unwrap();
        // A buggy loop that continues after the parse error will process the
        // queued message and EOF. Dropping the sender also lets that loop exit.
        drop(remote.tx);
        BgpConnectionChannel::spawn_recv_loop(conn.clone())
            .unwrap()
            .join()
            .unwrap();

        let events = event_rx.try_iter().collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            &events[0],
            FsmEvent::Connection(ConnectionEvent::Message {
                msg: Message::KeepAlive, conn_id,
            }) if conn_id == conn.id()
        ));
        assert!(matches!(
            &events[1],
            FsmEvent::Connection(ConnectionEvent::ParseError {
                conn_id,
                error: MessageParseError::Open(OpenParseError {
                    error_code: ErrorCode::Open,
                    error_subcode: ErrorSubcode::Open(
                        OpenErrorSubcode::UnsupportedVersionNumber,
                    ),
                    reason: OpenParseErrorReason::InvalidVersion { version: 3 },
                }),
            }) if conn_id == conn.id()
        ));
    }
}
