// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    DEFAULT_BGP_TTL, IO_TIMEOUT,
    clock::ConnectionClock,
    connection::{
        BgpConnection, BgpConnector, BgpListener, ConnectionDirection,
        ConnectionId, SocketOption, ThreadState,
    },
    error::Error,
    log::{connection_log, connection_log_lite},
    messages::{
        ErrorCode, ErrorSubcode, Header, HeaderErrorSubcode, HeaderParseError,
        MAX_MESSAGE_SIZE, Message, MessageParseError, MessageType,
        NotificationMessage, NotificationParseError,
        NotificationParseErrorReason, OpenErrorSubcode, OpenParseError,
        OpenParseErrorReason, RouteRefreshParseError,
        RouteRefreshParseErrorReason, notification_message_from_wire,
        open_message_from_wire, route_refresh_message_from_wire,
    },
    router::SessionMap,
    session::{ConnectionEvent, FsmEvent, PeerId, SessionEvent, SessionInfo},
    unnumbered::UnnumberedManager,
};
#[cfg(any(target_os = "linux", target_os = "illumos"))]
use libc::{IPPROTO_IP, IPPROTO_IPV6, c_void};
use mg_api_types::common::headers::Dscp;
use mg_common::lock;
use slog::{Logger, info};
use socket2::SockRef;
#[cfg(any(target_os = "linux", target_os = "illumos"))]
use std::os::fd::AsRawFd;
use std::{
    io::Read,
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    num::NonZeroU8,
    os::fd::AsFd,
    sync::atomic::AtomicBool,
    sync::{Arc, Mutex, atomic::Ordering, mpsc::Sender},
    thread::{JoinHandle, sleep},
    time::{Duration, Instant},
};

#[cfg(any(target_os = "linux", target_os = "illumos"))]
use libc::{IPPROTO_TCP, c_int};

#[cfg(target_os = "linux")]
use crate::connection::MAX_MD5SIG_KEYLEN;
#[cfg(target_os = "linux")]
use libc::{IP_MINTTL, IPV6_MINHOPCOUNT, TCP_MD5SIG, sockaddr_storage};

#[cfg(target_os = "illumos")]
use itertools::Itertools;
#[cfg(target_os = "illumos")]
use std::{collections::HashSet, net::IpAddr};

const UNIT_CONNECTION: &str = "connection_tcp";

// XXX: drop these local constants once libc 0.2.187 is released.
// rust-lang/libc#5089 adds IP_MINTTL/IPV6_MINHOPCOUNT bindings for solarish.
#[cfg(target_os = "illumos")]
const IP_MINTTL: i32 = 0x1c;
#[cfg(target_os = "illumos")]
const IPV6_MINHOPCOUNT: i32 = 0x2f;
#[cfg(target_os = "illumos")]
const TCP_MD5SIG: i32 = 0x27;
#[cfg(target_os = "illumos")]
const PFKEY_DURATION: Duration = Duration::from_secs(60 * 2);
#[cfg(target_os = "illumos")]
const PFKEY_KEEPALIVE: Duration = Duration::from_secs(60);

/// Error type for recv_msg operations.
/// Distinguishes between IO errors (connection issues) and parse errors (bad messages).
enum RecvError {
    /// IO error (connection closed, timeout, etc.) - recv loop should break
    Io(std::io::Error),
    /// Parse error (malformed message) - should send ParseError event to FSM
    Parse(MessageParseError),
    /// The recv loop is shutting down (dropped flag was set)
    Shutdown,
}

pub struct BgpListenerTcp {
    listener: TcpListener,
    unnumbered_manager: Option<Arc<dyn UnnumberedManager>>,
    bind_addr: SocketAddr,
}

impl BgpListenerTcp {
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

impl BgpListener<BgpConnectionTcp> for BgpListenerTcp {
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
        let listener = TcpListener::bind(addr)?;
        let bind_addr = listener.local_addr()?;
        set_outgoing_ttl(&listener, DEFAULT_BGP_TTL, bind_addr)?;

        info!(log, "TcpListener created"; "listener" => ?listener);
        // We set nonblocking to true on the listener because accept() can block
        // indefinitely and there isn't a portable way to do so with a timeout.
        // We would have to start using poll() to accomplish this, which is a
        // heavier lift that hasn't yet been deemed worthwhile.
        listener.set_nonblocking(true)?;

        Ok(Self {
            listener,
            unnumbered_manager,
            bind_addr,
        })
    }

    fn accept(
        &self,
        log: Logger,
        sessions: Arc<Mutex<SessionMap<BgpConnectionTcp>>>,
        timeout: Duration,
    ) -> Result<BgpConnectionTcp, Error> {
        let start = Instant::now();
        let retry_interval = Duration::from_millis(10);

        loop {
            match self.listener.accept() {
                Ok((conn, mut peer)) => {
                    // Override the nonblocking value of the parent TcpListener.
                    // Reads and Writes use a timeout via the std API, which is
                    // non-functional on nonblocking sockets.
                    if let Err(e) = conn.set_nonblocking(false) {
                        slog::error!(log,
                            "failed to set accepted connection to blocking: {e}";
                            "error" => format!("{e}")
                        );
                        return Err(e.into());
                    }

                    // Get the actual socket addresses for this accepted
                    // connection. This is critical for dual-stack scenarios
                    // where the listener may bind to an IPv6 address but accept
                    // IPv4 connections (via IPv4-mapped IPv6).
                    let ip = peer.ip().to_canonical();
                    peer.set_ip(ip);
                    let mut local = conn.local_addr()?;
                    local.set_ip(local.ip().to_canonical());

                    // Resolve peer address to appropriate PeerId (IP or Interface)
                    let key = self.resolve_session_key(peer);

                    // Look up the session runner, clone the Arc, then release
                    // the sessions lock before accessing session config.
                    let runner = lock!(sessions)
                        .get(&key)
                        .cloned()
                        .ok_or(Error::UnknownPeer(ip))?;

                    let config = lock!(runner.session);
                    return BgpConnectionTcp::with_conn(
                        local,
                        peer,
                        conn,
                        IO_TIMEOUT,
                        runner.event_tx.clone(),
                        log,
                        ConnectionDirection::Inbound,
                        &config,
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Check if we've exceeded the timeout
                    if start.elapsed() >= timeout {
                        return Err(Error::Timeout);
                    }
                    // Sleep briefly before retrying
                    sleep(retry_interval);
                    continue;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

pub struct BgpConnectorTcp;

impl BgpConnector<BgpConnectionTcp> for BgpConnectorTcp {
    fn connect(
        peer: SocketAddr,
        timeout: Duration,
        log: Logger,
        event_tx: Sender<FsmEvent<BgpConnectionTcp>>,
        config: SessionInfo,
    ) -> Result<JoinHandle<()>, Error> {
        let s = create_outbound_socket(peer, &log)?;

        // Apply MD5 authentication before connecting (Linux)
        #[cfg(target_os = "linux")]
        if let Some(key) = &config.md5_auth_key {
            let mut keyval = [0u8; MAX_MD5SIG_KEYLEN];
            let len = key.len();
            keyval[..len].copy_from_slice(key.as_bytes());
            set_md5_sig(s.as_raw_fd(), len as u16, keyval, peer).map_err(
                |e| {
                    connection_log_lite!(log,
                        warn,
                        "failed to apply MD5 auth for {peer}: {e}";
                        "direction" => ConnectionDirection::Outbound,
                        "peer" => format!("{peer}"),
                        "error" => format!("{e}")
                    );
                    e
                },
            )?;
        }

        // Setup MD5 for Illumos (initialization + SA tracking data)
        #[cfg(target_os = "illumos")]
        let md5_locals = if let Some(key) = &config.md5_auth_key {
            Some(
                setup_outbound_md5(s.as_raw_fd(), key, peer.ip(), peer, &log)
                    .map_err(|e| {
                    connection_log_lite!(log,
                        warn,
                        "failed to apply MD5 auth for {peer}: {e}";
                        "direction" => ConnectionDirection::Outbound,
                        "peer" => format!("{peer}"),
                        "error" => format!("{e}")
                    );
                    e
                })?,
            )
        } else {
            None
        };

        let handle = std::thread::Builder::new()
            .name(format!("bgp-connector-{}", peer))
            .spawn(move || {
                connection_log_lite!(log,
                    debug,
                    "starting connection attempt to {peer}";
                    "direction" => ConnectionDirection::Outbound,
                    "peer" => format!("{peer}"),
                    "timeout" => timeout.as_millis()
                );

                // Bind to source address/port if specified
                if let Some(src) = config.bind_addr {
                    let ba: socket2::SockAddr = src.into();
                    if let Err(e) = s.bind(&ba) {
                        connection_log_lite!(log,
                            warn,
                            "failed to bind to source {src} for {peer}: {e}";
                            "direction" => ConnectionDirection::Outbound,
                            "peer" => format!("{peer}"),
                            "source" => format!("{src}"),
                            "error" => format!("{e}")
                        );
                        return;
                    }
                }

                // Establish the connection (THIS IS THE BLOCKING CALL)
                let sa: socket2::SockAddr = peer.into();
                let new_conn: TcpStream = match s.connect_timeout(&sa, timeout) {
                    Ok(()) => s.into(),
                    Err(e) => {
                        connection_log_lite!(log,
                            warn,
                            "connection attempt to {peer} failed: {e}";
                            "direction" => ConnectionDirection::Outbound,
                            "peer" => format!("{peer}"),
                            "error" => format!("{e}")
                        );
                        return;
                    }
                };

                // Determine the actual source address
                let actual_source = match new_conn.local_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        connection_log_lite!(log,
                            warn,
                            "failed to get local address for {peer}: {e}";
                            "direction" => ConnectionDirection::Outbound,
                            "peer" => format!("{peer}"),
                            "error" => format!("{e}")
                        );
                        return;
                    }
                };

                // Create the connection object with the established stream.
                let conn = match BgpConnectionTcp::with_conn(
                    actual_source,
                    peer,
                    new_conn,
                    IO_TIMEOUT,
                    event_tx.clone(),
                    log.clone(),
                    ConnectionDirection::Outbound,
                    &config,
                ) {
                    Ok(conn) => conn,
                    Err(e) => {
                        connection_log_lite!(log,
                            warn,
                            "failed to create connection object for {peer}: {e}";
                            "direction" => ConnectionDirection::Outbound,
                            "peer" => format!("{peer}"),
                            "error" => format!("{e}")
                        );
                        return;
                    }
                };

                if let Some(ref key) = config.md5_auth_key
                    && let Err(e) = conn.apply_md5(key)
                {
                    connection_log_lite!(log,
                        warn,
                        "failed to apply MD5 auth for {peer}: {e}";
                        "direction" => ConnectionDirection::Outbound,
                        "peer" => format!("{peer}"),
                        "error" => format!("{e}")
                    );
                    return;
                }

                connection_log_lite!(log,
                    info,
                    "connection to {peer} established (conn_id: {})",
                    conn.id().short();
                    "direction" => ConnectionDirection::Outbound,
                    "peer" => format!("{peer}"),
                    "local" => format!("{actual_source}"),
                    "connection_id" => conn.id().short()
                );

                // Send the TcpConnectionConfirmed event
                if let Err(e) = event_tx.send(FsmEvent::Session(
                    SessionEvent::TcpConnectionConfirmed(conn),
                )) {
                    connection_log_lite!(log,
                        error,
                        "failed to send TcpConnectionConfirmed event for {peer}: {e}";
                        "direction" => ConnectionDirection::Outbound,
                        "peer" => format!("{peer}"),
                        "error" => format!("{e}")
                    );
                }
            })
            .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;

        Ok(handle)
    }
}

pub struct BgpConnectionTcp {
    id: ConnectionId,
    peer: SocketAddr,
    source: SocketAddr,
    conn: Arc<Mutex<TcpStream>>, //TODO split into tx/rx?
    #[cfg(target_os = "illumos")]
    sas: Arc<Mutex<Option<Md5Sas>>>,
    #[cfg(target_os = "illumos")]
    md5_sa_state: Mutex<ThreadState>,
    dropped: Arc<AtomicBool>,
    log: Logger,
    // direction of this connection, i.e. BgpListener or BgpConnector
    direction: ConnectionDirection,
    // Connection-level timers for keepalive, hold, and delay open
    connection_clock: ConnectionClock,
    // Event sender for the recv loop (needed for spawn_recv_loop)
    event_tx: Sender<FsmEvent<BgpConnectionTcp>>,
    // Read timeout for the recv loop
    recv_timeout: Duration,
    // Typestate managing the recv loop thread lifecycle (Ready or Running)
    recv_loop_state: Mutex<ThreadState>,
}

impl BgpConnection for BgpConnectionTcp {
    type Connector = BgpConnectorTcp;

    fn send(&self, msg: Message) -> Result<(), Error> {
        let mut guard = lock!(self.conn);
        Self::send_msg(&mut guard, &self.log, self.direction, msg)
    }

    fn peer(&self) -> SocketAddr {
        self.peer
    }

    fn local(&self) -> SocketAddr {
        self.source
    }

    fn conn(&self) -> (SocketAddr, SocketAddr) {
        (self.local(), self.peer())
    }

    fn direction(&self) -> ConnectionDirection {
        self.direction
    }

    fn id(&self) -> &ConnectionId {
        &self.id
    }

    fn clock(&self) -> &ConnectionClock {
        &self.connection_clock
    }

    fn start_recv_loop(self: &Arc<Self>) -> Result<(), Error> {
        let mut state = lock!(self.recv_loop_state);

        // Check if already started (idempotent via typestate)
        if state.is_running() {
            // Already started, return Ok (idempotent)
            connection_log!(self, debug,
                "recv_loop already started for {}", self.peer;
            );
            return Ok(());
        }

        // Spawn the recv loop with Arc clone
        connection_log!(self, info,
            "spawning recv loop for {}", self.peer;
        );
        let handle = Self::spawn_recv_loop(Arc::clone(self))?;

        // Store the handle in the typestate
        state.start(handle);

        Ok(())
    }

    fn update_socket_option(&self, option: &SocketOption) -> Result<(), Error> {
        let guard = lock!(self.conn);
        match *option {
            SocketOption::Dscp(dscp) => apply_dscp(&*guard, dscp, self.peer),
            SocketOption::MinTtl(ttl) => apply_ttl(&*guard, ttl, self.peer),
        }
    }

    fn apply_md5(&self, key: &str) -> Result<(), Error> {
        apply_md5_policy(self, Some(key))
    }
}

impl Drop for BgpConnectionTcp {
    fn drop(&mut self) {
        connection_log!(self, trace,
            "dropping connection {:?} (conn_id {})",
            self.conn(), self.id().short();
            "connection" => format!("{:?}", self.conn()),
            "connection_id" => self.id().short(),
            "dropped" => self.dropped.load(Ordering::Relaxed)
        );
        #[cfg(target_os = "illumos")]
        self.md5_sig_drop();
        self.dropped.store(true, Ordering::Relaxed);
    }
}

impl BgpConnectionTcp {
    /// Create a new BgpConnectionTcp with an established TcpStream.
    /// This is a private constructor used by BgpConnectorTcp and BgpListenerTcp.
    /// The receive loop is not started until start_recv_loop() is called.
    #[allow(clippy::too_many_arguments)]
    fn with_conn(
        source: SocketAddr,
        peer: SocketAddr,
        conn: TcpStream,
        timeout: Duration,
        event_tx: Sender<FsmEvent<Self>>,
        log: Logger,
        direction: ConnectionDirection,
        config: &SessionInfo,
    ) -> Result<Self, Error> {
        conn.set_nodelay(true)?;

        let id = ConnectionId::new(source, peer);

        let dropped = Arc::new(AtomicBool::new(false));
        let connection_clock = ConnectionClock::new(
            config.resolution,
            config.keepalive_time,
            config.hold_time,
            config.delay_open_time,
            id,
            event_tx.clone(),
            dropped.clone(),
            log.clone(),
        );

        Ok(Self {
            id,
            peer,
            source,
            conn: Arc::new(Mutex::new(conn)),
            log,
            dropped,
            #[cfg(target_os = "illumos")]
            sas: Arc::new(Mutex::new(None)),
            #[cfg(target_os = "illumos")]
            md5_sa_state: Mutex::new(ThreadState::new()),
            direction,
            connection_clock,
            event_tx,
            recv_timeout: timeout,
            recv_loop_state: Mutex::new(ThreadState::new()),
        })
    }

    /// Spawn the receive loop thread for this connection.
    fn spawn_recv_loop(conn_arc: Arc<Self>) -> Result<JoinHandle<()>, Error> {
        let peer = conn_arc.peer;
        let event_tx = conn_arc.event_tx.clone();
        let timeout = conn_arc.recv_timeout;
        let dropped = conn_arc.dropped.clone();
        let log = conn_arc.log.clone();
        let direction = conn_arc.direction;
        let conn_id = conn_arc.id;

        // Try to clone the stream before spawning the thread
        // This way we can fail fast if the connection is already broken
        let conn = lock!(conn_arc.conn).try_clone().map_err(|e| {
            connection_log_lite!(log, error,
                "failed to clone TcpStream for recv loop for {peer}";
                "direction" => direction,
                "connection_peer" => format!("{peer}"),
                "connection_id" => conn_id.short(),
                "error" => format!("{e}")
            );
            Error::Io(e)
        })?;

        // Use Builder instead of spawn().
        // This lets us catch thread spawn errors instead of panicking.
        std::thread::Builder::new()
            .name(format!("bgp-recv-{}", peer))
            .spawn(move || {
                let mut conn = conn;

                if !timeout.is_zero()
                    && let Err(e) = conn.set_read_timeout(Some(timeout))
                {
                    connection_log_lite!(log,
                        error,
                        "failed to set read timeout in recv loop for {peer} (conn_id: {}): {e}",
                        conn_id.short();
                        "direction" => direction,
                        "connection" => format!("{conn:?}"),
                        "connection_peer" => format!("{peer}"),
                        "connection_id" => conn_id.short(),
                        "error" => format!("{e}")
                    );
                    return;
                }

                let l = log.clone();
                loop {
                    if dropped.load(Ordering::Relaxed) {
                        connection_log_lite!(l, info,
                            "recv loop dropped (peer: {peer}, conn_id: {}), closing..",
                            conn_id.short();
                            "direction" => direction,
                            "connection" => format!("{conn:?}"),
                            "connection_peer" => format!("{peer}"),
                            "connection_id" => conn_id.short()
                        );
                        break;
                    }
                    match Self::recv_msg(&mut conn, dropped.clone(), &l, direction)
                    {
                        Ok(msg) => {
                            connection_log_lite!(l, trace,
                                "recv {} msg from {peer} (conn_id: {})",
                                msg.title(), conn_id.short();
                                "direction" => direction,
                                "connection" => format!("{conn:?}"),
                                "connection_peer" => format!("{peer}"),
                                "connection_id" => conn_id.short(),
                                "message" => msg.title(),
                                "message_contents" => format!("{msg}")
                            );
                            if let Err(e) = event_tx.send(FsmEvent::Connection(
                                ConnectionEvent::Message { msg, conn_id },
                            )) {
                                connection_log_lite!(l, warn,
                                    "error sending event to {peer}: {e}";
                                    "direction" => direction,
                                    "connection" => format!("{conn:?}"),
                                    "connection_peer" => format!("{peer}"),
                                    "connection_id" => conn_id.short(),
                                    "error" => format!("{e}")
                                );
                                break;
                            }
                        }
                        Err(recv_err) => {
                            match recv_err {
                                RecvError::Io(e) => {
                                    connection_log_lite!(l, info,
                                        "recv_msg IO error (peer: {peer}, conn_id: {}): {e}",
                                        conn_id.short();
                                        "direction" => direction,
                                        "connection" => format!("{conn:?}"),
                                        "connection_peer" => format!("{peer}"),
                                        "connection_id" => conn_id.short(),
                                        "error" => format!("{e}")
                                    );
                                    if let Err(e) = event_tx.send(FsmEvent::Connection(
                                        ConnectionEvent::TcpConnectionFails(conn_id),
                                    )) {
                                        connection_log_lite!(l, warn,
                                            "error sending TcpConnectionFails event to {peer}: {e}";
                                            "direction" => direction,
                                            "connection" => format!("{conn:?}"),
                                            "connection_peer" => format!("{peer}"),
                                            "connection_id" => conn_id.short(),
                                            "error" => format!("{e}")
                                        );
                                    }
                                }
                                RecvError::Shutdown => {}
                                RecvError::Parse(parse_err) => {
                                    connection_log_lite!(l, error,
                                        "recv_msg parse error (peer: {peer}, conn_id: {}): {parse_err}",
                                        conn_id.short();
                                        "direction" => direction,
                                        "connection" => format!("{conn:?}"),
                                        "connection_peer" => format!("{peer}"),
                                        "connection_id" => conn_id.short(),
                                        "error" => format!("{parse_err}")
                                    );
                                    // Notify FSM about fatal
                                    // (notification-worthy) parse errors.
                                    if let Err(e) = event_tx.send(FsmEvent::Connection(
                                        ConnectionEvent::ParseError { conn_id, error: parse_err },
                                    )) {
                                        connection_log_lite!(l, warn,
                                            "error sending parse error event to {peer}: {e}";
                                            "direction" => direction,
                                            "connection" => format!("{conn:?}"),
                                            "connection_peer" => format!("{peer}"),
                                            "connection_id" => conn_id.short(),
                                            "error" => format!("{e}")
                                        );
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
                connection_log_lite!(l, info,
                    "recv loop closed (peer: {peer}, conn_id: {})",
                    conn_id.short();
                    "direction" => direction,
                    "connection" => format!("{conn:?}"),
                    "connection_peer" => format!("{peer}"),
                    "connection_id" => conn_id.short()
                );
            })
            .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))
    }

    fn recv_header(
        stream: &mut TcpStream,
        dropped: Arc<AtomicBool>,
    ) -> Result<Header, RecvError> {
        let mut buf = [0u8; Header::WIRE_SIZE];
        let mut i = 0;
        loop {
            if dropped.load(Ordering::Relaxed) {
                return Err(RecvError::Shutdown);
            }
            match stream.read(&mut buf[i..]) {
                Ok(0) => {
                    return Err(RecvError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "peer closed connection",
                    )));
                }
                Ok(n) => i += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // This condition happens due to the read timeout that
                    // is set on the TcpStream object on connect being hit.
                    // This is a normal condition and we just jump back to
                    // the beginning of the loop, check the shutdown flag
                    // and carry on reading if there is no shutdown.
                    continue;
                }
                Err(e) => return Err(RecvError::Io(e)),
            }
            if i < Header::WIRE_SIZE {
                continue;
            }
            match Header::from_wire(&buf) {
                Ok(h) => return Ok(h),
                Err(_) => continue,
            };
        }
    }

    fn recv_msg(
        stream: &mut TcpStream,
        dropped: Arc<AtomicBool>,
        log: &Logger,
        direction: ConnectionDirection,
    ) -> Result<Message, RecvError> {
        let hdr = Self::recv_header(stream, dropped.clone())?;

        // RFC 4271 §4.1: length must be between 19 and 4096
        if usize::from(hdr.length) < Header::WIRE_SIZE {
            return Err(RecvError::Parse(MessageParseError::Header(
                HeaderParseError {
                    error_code: ErrorCode::Header,
                    error_subcode: ErrorSubcode::Header(
                        HeaderErrorSubcode::BadMessageLength,
                    ),
                    length: hdr.length,
                },
            )));
        }
        if usize::from(hdr.length) > MAX_MESSAGE_SIZE {
            return Err(RecvError::Parse(MessageParseError::Header(
                HeaderParseError {
                    error_code: ErrorCode::Header,
                    error_subcode: ErrorSubcode::Header(
                        HeaderErrorSubcode::BadMessageLength,
                    ),
                    length: hdr.length,
                },
            )));
        }

        let msg_len = usize::from(hdr.length) - Header::WIRE_SIZE;
        let mut msgbuf = vec![0u8; msg_len];
        let mut i = 0;
        while i < msg_len {
            if dropped.load(Ordering::Relaxed) {
                return Err(RecvError::Shutdown);
            }
            match stream.read(&mut msgbuf[i..]) {
                Ok(0) => {
                    return Err(RecvError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "peer closed connection",
                    )));
                }
                Ok(n) => i += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Err(RecvError::Io(e)),
            }
        }

        let msg = match hdr.typ {
            MessageType::Open => match open_message_from_wire(&msgbuf) {
                Ok(m) => m.into(),
                Err(e) => {
                    connection_log_lite!(log,
                        error,
                        "OPEN parse error: {e}";
                        "direction" => direction,
                        "connection" => format!("{stream:?}"),
                        "error" => format!("{e}")
                    );

                    let (subcode, reason) = match e {
                        Error::UnsupportedCapability(cap) => (
                            OpenErrorSubcode::UnsupportedCapability,
                            OpenParseErrorReason::Other {
                                detail: format!(
                                    "unsupported capability: {:?}",
                                    cap
                                ),
                            },
                        ),
                        Error::BadBgpIdentifier(id) => (
                            OpenErrorSubcode::BadBgpIdentifier,
                            OpenParseErrorReason::BadBgpIdentifier { id },
                        ),
                        Error::BadVersion(ver) => (
                            OpenErrorSubcode::UnsupportedVersionNumber,
                            OpenParseErrorReason::InvalidVersion {
                                version: ver,
                            },
                        ),
                        _ => (
                            OpenErrorSubcode::Unspecific,
                            OpenParseErrorReason::Other {
                                detail: e.to_string(),
                            },
                        ),
                    };

                    // Still send NOTIFICATION for OPEN errors (required by RFC)
                    if let Err(notify_err) = Self::send_notification(
                        stream,
                        log,
                        direction,
                        ErrorCode::Open,
                        ErrorSubcode::Open(subcode),
                        Vec::new(),
                    ) {
                        connection_log_lite!(log,
                            error,
                            "error sending notification: {notify_err}";
                            "direction" => direction,
                            "connection" => format!("{stream:?}"),
                            "error" => format!("{notify_err}")
                        );
                    }

                    return Err(RecvError::Parse(MessageParseError::Open(
                        OpenParseError {
                            error_code: ErrorCode::Open,
                            error_subcode: ErrorSubcode::Open(subcode),
                            reason,
                        },
                    )));
                }
            },
            MessageType::Update => {
                match crate::messages::update_message_from_wire(&msgbuf) {
                    Ok(m) => Message::from(m),
                    Err(update_err) => {
                        connection_log_lite!(log,
                            error,
                            "UPDATE parse error: {}", update_err;
                            "direction" => direction,
                            "connection" => format!("{stream:?}"),
                            "error" => format!("{update_err}")
                        );
                        return Err(RecvError::Parse(
                            MessageParseError::Update(update_err),
                        ));
                    }
                }
            }
            MessageType::Notification => {
                match notification_message_from_wire(&msgbuf) {
                    Ok(m) => m.into(),
                    Err(e) => {
                        connection_log_lite!(log,
                            error,
                            "NOTIFICATION parse error: {e}";
                            "direction" => direction,
                            "connection" => format!("{stream:?}"),
                            "error" => format!("{e}")
                        );
                        return Err(RecvError::Parse(MessageParseError::Notification(
                            NotificationParseError {
                                error_code: ErrorCode::Header,
                                error_subcode: ErrorSubcode::Header(
                                    crate::messages::HeaderErrorSubcode::BadMessageType,
                                ),
                                reason: NotificationParseErrorReason::Other {
                                    detail: e.to_string(),
                                },
                            },
                        )));
                    }
                }
            }
            MessageType::KeepAlive => {
                // RFC 4271 §4.4: KEEPALIVE must be exactly 19 bytes (16-byte header + 0-byte body)
                if !msgbuf.is_empty() {
                    connection_log_lite!(log,
                        error,
                        "KEEPALIVE parse error: message body not empty";
                        "direction" => direction,
                        "connection" => format!("{stream:?}"),
                        "body_length" => msgbuf.len()
                    );
                    return Err(RecvError::Parse(
                        MessageParseError::Notification(
                            NotificationParseError {
                                error_code: ErrorCode::Header,
                                error_subcode: ErrorSubcode::Header(
                                    HeaderErrorSubcode::BadMessageLength,
                                ),
                                reason: NotificationParseErrorReason::Other {
                                    detail: format!(
                                        "KEEPALIVE message must have zero body, got {} bytes",
                                        msgbuf.len()
                                    ),
                                },
                            },
                        ),
                    ));
                }
                return Ok(Message::KeepAlive);
            }
            MessageType::RouteRefresh => {
                match route_refresh_message_from_wire(&msgbuf) {
                    Ok(m) => m.into(),
                    Err(e) => {
                        connection_log_lite!(log,
                            error,
                            "ROUTE_REFRESH parse error: {e}";
                            "direction" => direction,
                            "connection" => format!("{stream:?}"),
                            "error" => format!("{e}")
                        );
                        return Err(RecvError::Parse(MessageParseError::RouteRefresh(
                            RouteRefreshParseError {
                                error_code: ErrorCode::Header,
                                error_subcode: ErrorSubcode::Header(
                                    crate::messages::HeaderErrorSubcode::BadMessageType,
                                ),
                                reason: RouteRefreshParseErrorReason::Other {
                                    detail: e.to_string(),
                                },
                            },
                        )));
                    }
                }
            }
        };

        Ok(msg)
    }

    fn send_msg(
        stream: &mut TcpStream,
        log: &Logger,
        direction: ConnectionDirection,
        msg: Message,
    ) -> Result<(), Error> {
        connection_log_lite!(log,
            trace,
            "sending {} msg", msg.title();
            "direction" => direction,
            "connection" => format!("{stream:?}"),
            "message" => msg.title(),
            "message_contents" => format!("{msg}")
        );
        let msg_buf = crate::messages::message_to_wire(&msg)?;
        let header = Header {
            length: (msg_buf.len() + Header::WIRE_SIZE).try_into().map_err(
                |_| {
                    Error::TooLarge(
                        "BGP message being sent is too large".into(),
                    )
                },
            )?,
            typ: MessageType::from(&msg),
        };
        let mut buf = header.to_wire().to_vec();
        buf.extend_from_slice(&msg_buf);
        connection_log_lite!(log,
            trace,
            "sending {} msg with header", msg.title();
            "connection" => format!("{stream:?}"),
            "message" => msg.title(),
            "message_contents" => format!("{buf:x?}")
        );
        stream.write_all(&buf)?;
        Ok(())
    }

    fn send_notification(
        stream: &mut TcpStream,
        log: &Logger,
        direction: ConnectionDirection,
        error_code: ErrorCode,
        error_subcode: ErrorSubcode,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        Self::send_msg(
            stream,
            log,
            direction,
            Message::Notification(NotificationMessage {
                error_code,
                error_subcode,
                data,
            }),
        )
    }

    #[cfg(target_os = "illumos")]
    fn md5_sig_drop(&self) {
        let guard = lock!(self.sas);
        if let Some(ref sas) = *guard {
            for (local, peer) in sas.associations.iter() {
                for (a, b) in sa_set(*local, *peer) {
                    if let Err(e) =
                        libnet::pf_key::tcp_md5_key_remove(a.into(), b.into())
                    {
                        connection_log!(self,
                            error,
                            "failed to drop sa {a} -> {b}: {e}";
                            "connection" => format!("{:?}", lock!(self.conn)),
                            "dropped" => self.dropped.load(Ordering::Relaxed),
                            "error" => format!("{e}")
                        );
                    }
                }
            }
        }
    }

    #[cfg(target_os = "illumos")]
    fn manage_md5_associations(
        &self,
        fd: i32,
        key: &str,
        locals: Vec<SocketAddr>,
        peer: SocketAddr,
    ) -> Result<(), Error> {
        // First set up the socket using the standalone function
        init_md5_associations(fd, key, locals.clone(), peer)?;
        // Then start SA tracking and keepalive
        self.set_md5_security_associations(key, locals, peer)?;
        Ok(())
    }

    #[cfg(target_os = "illumos")]
    fn set_md5_security_associations(
        &self,
        key: &str,
        locals: Vec<SocketAddr>,
        peer: SocketAddr,
    ) -> Result<(), Error> {
        let mut guard = lock!(self.sas);
        match &mut *guard {
            Some(sas) => {
                for local in locals.into_iter() {
                    sas.associations.insert((local, peer));
                }
            }
            None => {
                let mut sas = Md5Sas::new(key);
                for local in locals.into_iter() {
                    sas.associations.insert((local, peer));
                }
                *guard = Some(sas);
            }
        }
        drop(guard);
        self.sa_keepalive()?;
        Ok(())
    }

    #[cfg(target_os = "illumos")]
    fn sa_keepalive(&self) -> Result<(), Error> {
        use std::thread::sleep;

        let mut state = lock!(self.md5_sa_state);

        if !state.is_ready() {
            // Already running or already attempted
            connection_log!(
                self,
                debug,
                "security association keepalive loop already running";
                "connection" => format!("{:?}", self.conn()),
                "dropped" => self.dropped.load(Ordering::Relaxed)
            );
            return Ok(());
        }

        // Get one run in before returning, this helps the SAs to
        // get set up before setting up the socket.
        Self::do_sa_keepalive(&self.sas, &self.log, self.conn());

        connection_log!(
            self,
            debug,
            "spawning security association keepalive loop";
            "connection" => format!("{:?}", self.conn()),
            "dropped" => self.dropped.load(Ordering::Relaxed)
        );
        let dropped = self.dropped.clone();
        let log = self.log.clone();
        let sas = self.sas.clone();
        let conn = self.conn();
        let peer = self.peer;
        let handle = std::thread::Builder::new()
            .name(format!("bgp-md5-{}", peer))
            .spawn(move || {
                // Track when we last updated the SAs
                let mut last_update = Instant::now();

                loop {
                    // Sleep for a short duration to check shutdown flag frequently
                    sleep(IO_TIMEOUT);

                    if dropped.load(Ordering::Relaxed) {
                        break;
                    }

                    // Only update SAs if the keepalive interval has elapsed
                    if last_update.elapsed() >= PFKEY_KEEPALIVE {
                        Self::do_sa_keepalive(&sas, &log, conn);
                        last_update = Instant::now();
                    }
                }
            })?;
        state.start(handle);
        Ok(())
    }

    #[cfg(target_os = "illumos")]
    fn do_sa_keepalive(
        sas: &Arc<Mutex<Option<Md5Sas>>>,
        log: &Logger,
        conn: (SocketAddr, SocketAddr),
    ) {
        // While an API action that results in changing the authkey will
        // result in a session reset, there are other things that can change
        // out from underneath us that we need to keep tabs on. In particular
        // we may accept a connection from a client (as opposed to the client)
        // accepting a connection from us, and that will result in the
        // association set increasing according to the source port of the client.
        let guard = lock!(sas);
        if let Some(ref sas) = *guard {
            for (local, peer) in sas.associations.iter() {
                if let Err(e) = apply_md5_sa_pair(*local, *peer, &sas.key) {
                    connection_log_lite!(log,
                        error,
                        "error updating pf_key for {local} -> {peer}: {e}";
                        "connection" => format!("{conn:?}"),
                        "error" => format!("{e}")
                    );
                }
            }
        }
    }
}

/// Helper to create a socket for the peer address
fn create_outbound_socket(
    peer: SocketAddr,
    logger: &Logger,
) -> Result<socket2::Socket, Error> {
    let domain = match peer {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };

    socket2::Socket::new(domain, socket2::Type::STREAM, None).map_err(|e| {
        connection_log_lite!(logger,
            warn,
            "failed to create socket for {peer}: {e}";
            "direction" => ConnectionDirection::Outbound,
            "peer" => format!("{peer}"),
            "error" => format!("{e}")
        );
        e.into()
    })
}

/// Apply DSCP marking to a BGP TCP connection.
///
/// Sets the DSCP field in the IP header via IP_TOS (IPv4) or
/// IPV6_TCLASS (IPv6) using socket2 wrappers where available,
/// falling back to raw libc::setsockopt on illumos where socket2
/// lacks bindings.
fn apply_dscp(
    sock: &impl AsFd,
    dscp: Dscp,
    peer: SocketAddr,
) -> Result<(), Error> {
    let tos = u32::from(dscp.as_tos_byte());
    let sock = SockRef::from(sock);
    if peer.is_ipv4() {
        set_dscp_v4(&sock, tos)
    } else {
        traffic_class_v6(&sock, tos)
    }
}

/// Set IPv4 DSCP/TOS. Uses socket2 on platforms that support it,
/// raw libc on illumos.
#[cfg(not(target_os = "illumos"))]
fn set_dscp_v4(sock: &SockRef, tos: u32) -> Result<(), Error> {
    sock.set_tos_v4(tos).map_err(Error::Io)
}

#[cfg(target_os = "illumos")]
fn set_dscp_v4(sock: &SockRef, tos: u32) -> Result<(), Error> {
    unsafe {
        let fd = sock.as_raw_fd();
        if libc::setsockopt(
            fd,
            IPPROTO_IP,
            libc::IP_TOS,
            &tos as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        ) != 0
        {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Set IPv6 DSCP/Traffic Class. Uses socket2 on platforms that
/// support it, raw libc on illumos.
#[cfg(not(target_os = "illumos"))]
fn traffic_class_v6(sock: &SockRef, tos: u32) -> Result<(), Error> {
    sock.set_tclass_v6(tos).map_err(Error::Io)
}

#[cfg(target_os = "illumos")]
fn traffic_class_v6(sock: &SockRef, tos: u32) -> Result<(), Error> {
    unsafe {
        let fd = sock.as_raw_fd();
        if libc::setsockopt(
            fd,
            IPPROTO_IPV6,
            libc::IPV6_TCLASS,
            &tos as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        ) != 0
        {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

fn apply_md5_policy(
    conn: &BgpConnectionTcp,
    key: Option<&str>,
) -> Result<(), Error> {
    let Some(key) = key else {
        return Ok(());
    };

    #[cfg(target_os = "linux")]
    {
        let tcp_stream = lock!(conn.conn);
        let mut keyval = [0u8; MAX_MD5SIG_KEYLEN];
        let len = key.len();
        keyval[..len].copy_from_slice(key.as_bytes());
        set_md5_sig(tcp_stream.as_raw_fd(), len as u16, keyval, conn.peer)?;
    }

    #[cfg(target_os = "illumos")]
    {
        let tcp_stream = lock!(conn.conn);
        let local = get_md5_source_addrs(conn.peer.ip())?;
        conn.manage_md5_associations(
            tcp_stream.as_raw_fd(),
            key,
            local,
            conn.peer,
        )?;
    }

    #[cfg(not(any(target_os = "linux", target_os = "illumos")))]
    {
        let _ = (&conn, &key);
    }

    Ok(())
}

/// Apply BGP TTL policy to a TCP connection.
///
/// Sets the outgoing TTL/hop-limit to the configured `min_ttl` (if any)
/// or `DEFAULT_BGP_TTL` otherwise, and sets the incoming
/// IP_MINTTL/IPV6_MINHOPCOUNT filter to `min_ttl` (or 0 = disabled).
fn apply_ttl(
    sock: &impl AsFd,
    min_ttl: Option<NonZeroU8>,
    peer: SocketAddr,
) -> Result<(), Error> {
    let ttl = min_ttl.map(NonZeroU8::get);
    set_outgoing_ttl(sock, ttl.unwrap_or(DEFAULT_BGP_TTL), peer)?;
    set_ip_minttl(sock, ttl.unwrap_or(0), peer)
}

/// Set the outgoing TTL/hop-limit on a TCP socket.
///
/// Uses IP_TTL for IPv4 and IPV6_UNICAST_HOPS for IPv6 via socket2.
/// `TcpStream::set_ttl` would only set IP_TTL — silently a no-op on
/// IPv6 sockets — so dispatch on the peer's address family.
fn set_outgoing_ttl(
    sock: &impl AsFd,
    ttl: u8,
    peer: SocketAddr,
) -> Result<(), Error> {
    let sock = SockRef::from(sock);
    if peer.is_ipv4() {
        sock.set_ttl_v4(u32::from(ttl)).map_err(Error::Io)
    } else {
        sock.set_unicast_hops_v6(u32::from(ttl)).map_err(Error::Io)
    }
}

/// Set the incoming minimum TTL/hop-limit filter on a TCP socket.
// XXX: replace with socket2 wrappers when they become available.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "illumos")),
    allow(unused_variables)
)]
fn set_ip_minttl(
    sock: &impl AsFd,
    ttl: u8,
    peer: SocketAddr,
) -> Result<(), Error> {
    #[cfg(any(target_os = "linux", target_os = "illumos"))]
    {
        let (proto, optname) = if peer.is_ipv4() {
            (IPPROTO_IP, IP_MINTTL)
        } else {
            (IPPROTO_IPV6, IPV6_MINHOPCOUNT)
        };
        let min_ttl = ttl as u32;
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                proto,
                optname,
                &min_ttl as *const u32 as *const c_void,
                std::mem::size_of::<u32>() as u32,
            )
        };
        if rc != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct TcpMd5Sig {
    tcpm_addr: sockaddr_storage,
    tcpm_flags: u8,
    tcpm_prefixlen: u8,
    tcpm_keylen: u16,
    tcpm_ifindex: c_int,
    tcpm_key: [u8; MAX_MD5SIG_KEYLEN],
}

#[cfg(target_os = "linux")]
impl Default for TcpMd5Sig {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// Apply TCP_MD5SIG socket option to a socket
#[cfg(target_os = "linux")]
fn set_md5_sig(
    fd: i32,
    keylen: u16,
    key: [u8; MAX_MD5SIG_KEYLEN],
    peer: SocketAddr,
) -> Result<(), Error> {
    let mut sig = TcpMd5Sig {
        tcpm_keylen: keylen,
        tcpm_key: key,
        ..Default::default()
    };
    let addr = socket2::SockAddr::from(peer);
    unsafe {
        sig.tcpm_addr = *addr.as_ptr().cast::<sockaddr_storage>();
        if libc::setsockopt(
            fd,
            IPPROTO_TCP,
            TCP_MD5SIG,
            &sig as *const TcpMd5Sig as *const c_void,
            std::mem::size_of::<TcpMd5Sig>() as u32,
        ) != 0
        {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Md5 security associations (PF_KEY tracking)
#[cfg(target_os = "illumos")]
pub struct Md5Sas {
    key: String,
    associations: HashSet<(SocketAddr, SocketAddr)>,
}

#[cfg(target_os = "illumos")]
impl Md5Sas {
    fn new(key: &str) -> Self {
        Self {
            key: key.to_owned(),
            associations: HashSet::new(),
        }
    }
}

/// Select source address based on destination using routing table lookup
#[cfg(target_os = "illumos")]
fn source_address_select(dst: IpAddr) -> anyhow::Result<Vec<IpAddr>> {
    use oxnet::IpNet;

    let prefix = match dst {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let target = IpNet::new_unchecked(dst, prefix);

    let nexthop = libnet::get_route(target, None)?.gw;
    let selected_local_addrs: Vec<IpAddr> = libnet::get_ipaddrs()?
        .into_values()
        .flatten()
        .map(|x| oxnet::IpNet::new_unchecked(x.addr, x.mask as u8))
        .filter(|x| x.contains(nexthop))
        .max_set_by_key(|x| x.prefix())
        .into_iter()
        .map(|x| x.addr())
        .collect();

    Ok(selected_local_addrs)
}

/// Helper function to select and validate MD5 source addresses.
/// Eliminates duplication between inbound and outbound paths
#[cfg(target_os = "illumos")]
fn get_md5_source_addrs(peer_ip: IpAddr) -> Result<Vec<SocketAddr>, Error> {
    let sources = source_address_select(peer_ip)
        .map_err(|e| Error::InvalidAddress(e.to_string()))?;

    if sources.is_empty() {
        return Err(Error::InvalidAddress(
            "no source address available for MD5 SA setup".to_string(),
        ));
    }

    Ok(sources
        .iter()
        .map(|x| SocketAddr::new(*x, crate::BGP_PORT))
        .collect())
}

/// Zero out port field for PF_KEY SA matching (Illumos-specific)
#[cfg(target_os = "illumos")]
fn any_port(mut s: SocketAddr) -> SocketAddr {
    s.set_port(0);
    s
}

/// Generate all four bidirectional SA pairs for MD5 protection.
/// Covers both directions of traffic with both port configurations
#[cfg(target_os = "illumos")]
fn sa_set(src: SocketAddr, dst: SocketAddr) -> [(SocketAddr, SocketAddr); 4] {
    // There are two directions of traffic we have to cover with two port
    // configurations for a total of four cases.
    // * Local -> Peer
    //   * Local is TCP client Peer is server
    //   * Peer is TCP client Local is server
    // * Peer -> Local
    //   * Local is TCP client Peer is server
    //   * Peer is TCP client Local is server
    [
        (any_port(src), dst),
        (src, any_port(dst)),
        (any_port(dst), src),
        (dst, any_port(src)),
    ]
}

/// Apply or update a single MD5 SA pair (Illumos-specific PF_KEY operation)
/// This helper is used by both initial setup and periodic keepalive operations
#[cfg(target_os = "illumos")]
fn apply_md5_sa_pair(
    local: SocketAddr,
    peer: SocketAddr,
    key: &str,
) -> Result<(), Error> {
    for (a, b) in sa_set(local, peer) {
        let exists =
            libnet::pf_key::tcp_md5_key_get(a.into(), b.into()).is_ok();
        if exists {
            libnet::pf_key::tcp_md5_key_update(
                a.into(),
                b.into(),
                PFKEY_DURATION,
            )
            .map_err(|e| {
                Error::Io(std::io::Error::other(format!(
                    "failed to update pf_key {a} -> {b}: {e}"
                )))
            })?;
        } else {
            libnet::pf_key::tcp_md5_key_add(
                a.into(),
                b.into(),
                key,
                PFKEY_DURATION,
            )
            .map_err(|e| {
                Error::Io(std::io::Error::other(format!(
                    "failed to add pf_key {a} -> {b}: {e}"
                )))
            })?;
        }
    }
    Ok(())
}

/// Initialize MD5 associations for Illumos (initial setup only, no SA tracking)
/// This is called before the BgpConnectionTcp object exists, so it only sets up
/// the socket. SA tracking and keepalive are started later via instance methods.
#[cfg(target_os = "illumos")]
fn init_md5_associations(
    fd: i32,
    key: &str,
    locals: Vec<SocketAddr>,
    peer: SocketAddr,
) -> Result<(), Error> {
    // Set MD5 security associations for Illumos
    for local in locals.iter() {
        apply_md5_sa_pair(*local, peer, key)?;
    }

    let yes: c_int = 1;
    unsafe {
        if libc::setsockopt(
            fd,
            IPPROTO_TCP,
            TCP_MD5SIG,
            &yes as *const c_int as *const c_void,
            std::mem::size_of::<c_int>() as u32,
        ) != 0
        {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Setup MD5 for outbound Illumos connections: select source addresses and
/// initialize SAs.
/// Returns (key, locals) tuple for later keepalive tracking.
#[cfg(target_os = "illumos")]
fn setup_outbound_md5(
    fd: i32,
    key: &str,
    peer_ip: IpAddr,
    peer: SocketAddr,
    logger: &Logger,
) -> Result<(String, Vec<SocketAddr>), Error> {
    let sources = source_address_select(peer_ip).map_err(|e| {
        connection_log_lite!(logger,
            warn,
            "failed to select source address for {peer}: {e}";
            "direction" => ConnectionDirection::Outbound,
            "peer" => format!("{peer}"),
            "error" => format!("{e}")
        );
        Error::InvalidAddress(e.to_string())
    })?;

    if sources.is_empty() {
        connection_log_lite!(logger,
            warn,
            "no source address available for {peer}";
            "direction" => ConnectionDirection::Outbound,
            "peer" => format!("{peer}")
        );
        return Err(Error::InvalidAddress(
            "no source address available".to_string(),
        ));
    }

    let local: Vec<SocketAddr> = sources
        .iter()
        .map(|x| SocketAddr::new(*x, crate::BGP_PORT))
        .collect();

    init_md5_associations(fd, key, local.clone(), peer)?;

    Ok((key.to_string(), local))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_api_types::common::headers::Dscp;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;

    #[test]
    fn apply_dscp_sets_ip_tos() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();

        let dscp = Dscp::from_dscp_value(48).unwrap();
        apply_dscp(&stream, dscp, addr).unwrap();

        let mut readback: u32 = 0;
        let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_TOS,
                &mut readback as *mut u32 as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt failed");
        // DSCP 48 → TOS byte = 48 << 2 = 192
        assert_eq!(readback, u32::from(dscp.as_tos_byte()));
    }

    #[test]
    fn apply_dscp_sets_ipv6_tclass() {
        let listener = TcpListener::bind("[::1]:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();

        let dscp = Dscp::from_dscp_value(46).unwrap(); // EF
        apply_dscp(&stream, dscp, addr).unwrap();

        let mut readback: u32 = 0;
        let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_TCLASS,
                &mut readback as *mut u32 as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt failed");
        // DSCP 46 (EF) → TOS byte = 46 << 2 = 184
        assert_eq!(readback, u32::from(dscp.as_tos_byte()));
    }

    #[test]
    fn apply_min_ttl_sets_ipv4_ttl() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();

        apply_ttl(&stream, NonZeroU8::new(42), addr).unwrap();

        let readback = SockRef::from(&stream).ttl_v4().unwrap();
        assert_eq!(readback, 42);
    }

    #[test]
    fn apply_min_ttl_sets_ipv6_unicast_hops() {
        let listener = TcpListener::bind("[::1]:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();

        apply_ttl(&stream, NonZeroU8::new(42), addr).unwrap();

        let readback = SockRef::from(&stream).unicast_hops_v6().unwrap();
        assert_eq!(readback, 42);
    }

    // IP_MINTTL / IPV6_MINHOPCOUNT are only set on Linux and illumos.
    #[cfg(any(target_os = "linux", target_os = "illumos"))]
    #[test]
    fn apply_min_ttl_sets_ipv4_minttl_filter() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();

        apply_ttl(SockRef::from(&stream), NonZeroU8::new(200), addr).unwrap();

        let mut readback: u32 = 0;
        let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                IPPROTO_IP,
                IP_MINTTL,
                &mut readback as *mut u32 as *mut c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt failed");
        assert_eq!(readback, 200);
    }

    #[cfg(any(target_os = "linux", target_os = "illumos"))]
    #[test]
    fn apply_min_ttl_sets_ipv6_minhopcount_filter() {
        let listener = TcpListener::bind("[::1]:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();

        apply_ttl(SockRef::from(&stream), NonZeroU8::new(200), addr).unwrap();

        let mut readback: u32 = 0;
        let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                IPPROTO_IPV6,
                IPV6_MINHOPCOUNT,
                &mut readback as *mut u32 as *mut c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt failed");
        assert_eq!(readback, 200);
    }
}
