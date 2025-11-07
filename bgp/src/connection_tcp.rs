// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    clock::ConnectionClock,
    connection::{
        BgpConnection, BgpConnector, BgpListener, ConnectionDirection,
        ConnectionId, RecvLoopState,
    },
    error::Error,
    log::{connection_log, connection_log_lite},
    messages::{
        ErrorCode, ErrorSubcode, Header, Message, MessageType,
        NotificationMessage, OpenMessage, RouteRefreshMessage, UpdateMessage,
    },
    session::{
        ConnectionEvent, FsmEvent, SessionEndpoint, SessionEvent, SessionInfo,
    },
};
use mg_common::lock;
use slog::Logger;
use std::{
    collections::BTreeMap,
    io::Read,
    io::Write,
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::atomic::AtomicBool,
    sync::{Arc, Mutex, atomic::Ordering, mpsc::Sender},
    thread::{JoinHandle, sleep, spawn},
    time::{Duration, Instant},
};

const UNIT_CONNECTION: &str = "connection_tcp";

#[cfg(target_os = "linux")]
use crate::connection::MAX_MD5SIG_KEYLEN;
#[cfg(target_os = "linux")]
use libc::{IP_MINTTL, TCP_MD5SIG, sockaddr_storage};
#[cfg(target_os = "illumos")]
use {
    itertools::Itertools,
    std::{collections::HashSet, time::Instant},
};
#[cfg(any(target_os = "linux", target_os = "illumos"))]
use {
    libc::{IPPROTO_IP, IPPROTO_IPV6, IPPROTO_TCP, c_int, c_void},
    std::os::fd::AsRawFd,
};

#[cfg(target_os = "illumos")]
const IP_MINTTL: i32 = 0x1c;
#[cfg(target_os = "illumos")]
const TCP_MD5SIG: i32 = 0x27;
#[cfg(target_os = "illumos")]
const PFKEY_DURATION: Duration = Duration::from_secs(60 * 2);
#[cfg(target_os = "illumos")]
const PFKEY_KEEPALIVE: Duration = Duration::from_secs(60);

pub struct BgpListenerTcp {
    listener: TcpListener,
}

/// Md5 security associations.
#[cfg(target_os = "illumos")]
pub struct Md5Sas {
    key: String,
    associations: HashSet<(SocketAddr, SocketAddr)>,
    create_time: Instant,
}

#[cfg(target_os = "illumos")]
impl Md5Sas {
    fn new(key: &str) -> Self {
        Self {
            key: key.to_owned(),
            associations: HashSet::new(),
            create_time: Instant::now(),
        }
    }
}

impl BgpListener<BgpConnectionTcp> for BgpListenerTcp {
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
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener })
    }

    fn accept(
        &self,
        log: Logger,
        addr_to_session: Arc<
            Mutex<BTreeMap<IpAddr, SessionEndpoint<BgpConnectionTcp>>>,
        >,
        timeout: Duration,
    ) -> Result<BgpConnectionTcp, Error> {
        let start = Instant::now();
        let retry_interval = Duration::from_millis(10);

        loop {
            match self.listener.accept() {
                Ok((conn, mut peer)) => {
                    // Get the actual socket addresses for this accepted
                    // connection. This is critical for dual-stack scenarios
                    // where the listener may bind to an IPv6 address but accept
                    // IPv4 connections (via IPv4-mapped IPv6).
                    let ip = peer.ip().to_canonical();
                    peer.set_ip(ip);
                    let mut local = conn.local_addr()?;
                    local.set_ip(local.ip().to_canonical());

                    // Check if we have a session for this peer
                    match lock!(addr_to_session).get(&ip) {
                        Some(session_endpoint) => {
                            let config = lock!(session_endpoint.config);
                            return BgpConnectionTcp::with_conn(
                                local,
                                peer,
                                conn,
                                timeout,
                                session_endpoint.event_tx.clone(),
                                log,
                                ConnectionDirection::Inbound,
                                &config,
                            );
                        }
                        None => return Err(Error::UnknownPeer(ip)),
                    }
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

    fn apply_policy(
        conn: &BgpConnectionTcp,
        min_ttl: Option<u8>,
        md5_key: Option<String>,
    ) -> Result<(), Error> {
        let tcp_stream = lock!(conn.conn);

        if let Some(ttl) = min_ttl {
            apply_min_ttl(&tcp_stream, ttl, conn.peer)?;
        }

        if let Some(ref key) = md5_key {
            #[cfg(target_os = "linux")]
            {
                let mut keyval = [0u8; MAX_MD5SIG_KEYLEN];
                let len = key.len();
                keyval[..len].copy_from_slice(key.as_bytes());
                set_md5_sig(
                    tcp_stream.as_raw_fd(),
                    len as u16,
                    keyval,
                    conn.peer,
                )?;
            }

            #[cfg(target_os = "illumos")]
            {
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
                // MD5 authentication not supported on this platform
                let _ = key; // Suppress unused variable warning
            }
        }

        Ok(())
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
        // Spawn a background thread to perform the connection attempt
        let handle = spawn(move || {
            connection_log_lite!(log,
                debug,
                "starting connection attempt to {peer}";
                "direction" => ConnectionDirection::Outbound,
                "peer" => format!("{peer}"),
                "timeout" => timeout.as_millis()
            );

            let s = match peer {
                SocketAddr::V4(_) => match socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::STREAM,
                    None,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        connection_log_lite!(log,
                            warn,
                            "failed to create IPv4 socket for {peer}: {e}";
                            "direction" => ConnectionDirection::Outbound,
                            "peer" => format!("{peer}"),
                            "error" => format!("{e}")
                        );
                        return;
                    }
                },
                SocketAddr::V6(_) => match socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::STREAM,
                    None,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        connection_log_lite!(log,
                            warn,
                            "failed to create IPv6 socket for {peer}: {e}";
                            "direction" => ConnectionDirection::Outbound,
                            "peer" => format!("{peer}"),
                            "error" => format!("{e}")
                        );
                        return;
                    }
                },
            };

            // Apply MD5 authentication before connecting
            #[cfg(target_os = "linux")]
            if let Some(key) = &config.md5_auth_key {
                let mut keyval = [0u8; MAX_MD5SIG_KEYLEN];
                let len = key.len();
                keyval[..len].copy_from_slice(key.as_bytes());
                if let Err(e) =
                    set_md5_sig(s.as_raw_fd(), len as u16, keyval, peer)
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
            }

            #[cfg(target_os = "illumos")]
            if let Some(key) = &config.md5_auth_key {
                let sources = match source_address_select(peer.ip()) {
                    Ok(s) => s,
                    Err(e) => {
                        connection_log_lite!(log,
                            warn,
                            "failed to select source address for {peer}: {e}";
                            "direction" => ConnectionDirection::Outbound,
                            "peer" => format!("{peer}"),
                            "error" => format!("{e}")
                        );
                        return;
                    }
                };
                if sources.is_empty() {
                    connection_log_lite!(log,
                        warn,
                        "no source address available for {peer}";
                        "direction" => ConnectionDirection::Outbound,
                        "peer" => format!("{peer}")
                    );
                    return;
                }
                let local: Vec<SocketAddr> = sources
                    .iter()
                    .map(|x| SocketAddr::new(*x, crate::BGP_PORT))
                    .collect();
                if let Err(e) =
                    init_md5_associations(s.as_raw_fd(), key, local, peer)
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
            }

            // Bind to source address if specified
            if let Some(source_addr) = config.bind_addr {
                let mut src = source_addr;
                // clear source port, we only want to set the source ip
                src.set_port(0);
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

            // Apply TTL if specified
            if let Some(ttl) = config.min_ttl
                && let Err(e) = apply_min_ttl(&new_conn, ttl, peer)
            {
                connection_log_lite!(log,
                    warn,
                    "failed to apply min TTL for {peer}: {e}";
                    "direction" => ConnectionDirection::Outbound,
                    "peer" => format!("{peer}"),
                    "error" => format!("{e}")
                );
                return;
            }

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

            // Create the connection object with the established stream
            let conn = match BgpConnectionTcp::with_conn(
                actual_source,
                peer,
                new_conn,
                timeout,
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

            // Start SA tracking and keepalive for Illumos MD5
            #[cfg(target_os = "illumos")]
            if let Some(key) = &config.md5_auth_key {
                let sources = match source_address_select(peer.ip()) {
                    Ok(s) => s,
                    Err(e) => {
                        connection_log_lite!(log,
                            warn,
                            "failed to select source address for SA tracking for {peer}: {e}";
                            "direction" => ConnectionDirection::Outbound,
                            "peer" => format!("{peer}"),
                            "error" => format!("{e}")
                        );
                        return;
                    }
                };
                if !sources.is_empty() {
                    let local: Vec<SocketAddr> = sources
                        .iter()
                        .map(|x| SocketAddr::new(*x, crate::BGP_PORT))
                        .collect();
                    if let Err(e) =
                        conn.set_md5_security_associations(key, local, peer)
                    {
                        connection_log_lite!(log,
                            warn,
                            "failed to start SA tracking for {peer}: {e}";
                            "direction" => ConnectionDirection::Outbound,
                            "peer" => format!("{peer}"),
                            "error" => format!("{e}")
                        );
                        return;
                    }
                }
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
        });

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
    sa_keepalive_running: Arc<AtomicBool>,
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
    recv_loop_state: Mutex<RecvLoopState>,
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
}

impl Drop for BgpConnectionTcp {
    fn drop(&mut self) {
        // Only set dropped flag if this is the last reference.
        // This prevents the recv loop from closing prematurely when intermediate
        // clones are dropped during FSM state transitions (e.g., collision resolution).
        if Arc::strong_count(&self.dropped) == 1 {
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
        let id = ConnectionId::new(source, peer);

        let dropped = Arc::new(AtomicBool::new(false));
        let connection_clock = ConnectionClock::new(
            config.resolution,
            config.keepalive_time,
            config.hold_time,
            config.delay_open_time,
            id,
            event_tx.clone(),
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
            sa_keepalive_running: Arc::new(AtomicBool::new(false)),
            #[cfg(target_os = "illumos")]
            sas: Arc::new(Mutex::new(None)),
            direction,
            connection_clock,
            event_tx,
            recv_timeout: timeout,
            recv_loop_state: Mutex::new(RecvLoopState::new()),
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
                        Err(e) => {
                            connection_log_lite!(l, info,
                                "recv_msg error (peer: {peer}, conn_id: {}): {e}",
                                conn_id.short();
                                "direction" => direction,
                                "connection" => format!("{conn:?}"),
                                "connection_peer" => format!("{peer}"),
                                "connection_id" => conn_id.short(),
                                "error" => format!("{e}")
                            );
                            // Break the loop on connection errors to prevent zombie threads
                            // that continue trying to read from closed connections
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
    ) -> std::io::Result<Header> {
        let mut buf = [0u8; Header::WIRE_SIZE];
        let mut i = 0;
        loop {
            if dropped.load(Ordering::Relaxed) {
                return Err(std::io::Error::other("shutting down"));
            }
            let n = match stream.read(&mut buf[i..]) {
                Ok(n) => Ok(n),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        // This condition happens due to the read timeout that
                        // is set on the TcpStream object on connect being hit.
                        // This is a normal condition and we just jump back to
                        // the beginning of the loop, check the shutdown flag
                        // and carry on reading if there is no shutdown.
                        continue;
                    } else {
                        Err(e)
                    }
                }
            }?;
            // Check for EOF (peer closed connection)
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed connection",
                ));
            }
            i += n;
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
    ) -> std::io::Result<Message> {
        use crate::messages::OpenErrorSubcode;
        let hdr = Self::recv_header(stream, dropped.clone())?;

        let mut msgbuf = vec![0u8; usize::from(hdr.length) - Header::WIRE_SIZE];
        stream.read_exact(&mut msgbuf)?;

        let msg = match hdr.typ {
            MessageType::Open => match OpenMessage::from_wire(&msgbuf) {
                Ok(m) => m.into(),
                Err(e) => {
                    connection_log_lite!(log,
                        error,
                        "open message error: {e}";
                        "direction" => direction,
                        "connection" => format!("{stream:?}"),
                        "error" => format!("{e}")
                    );

                    let subcode = match e {
                        Error::UnsupportedCapability(_) => {
                            OpenErrorSubcode::UnsupportedCapability
                        }
                        _ => OpenErrorSubcode::Unspecific,
                    };

                    if let Err(e) = Self::send_notification(
                        stream,
                        log,
                        direction,
                        ErrorCode::Open,
                        ErrorSubcode::Open(subcode),
                        Vec::new(),
                    ) {
                        connection_log_lite!(log,
                            error,
                            "error sending notification: {e}";
                            "direction" => direction,
                            "connection" => format!("{stream:?}"),
                            "error" => format!("{e}")
                        );
                    }
                    return Err(std::io::Error::other("open message error"));
                }
            },
            MessageType::Update => match UpdateMessage::from_wire(&msgbuf) {
                Ok(m) => m.into(),
                Err(_) => {
                    return Err(std::io::Error::other("update message error"));
                }
            },
            MessageType::Notification => {
                match NotificationMessage::from_wire(&msgbuf) {
                    Ok(m) => m.into(),
                    Err(_) => {
                        return Err(std::io::Error::other(
                            "notification message error",
                        ));
                    }
                }
            }
            MessageType::KeepAlive => return Ok(Message::KeepAlive),
            MessageType::RouteRefresh => {
                match RouteRefreshMessage::from_wire(&msgbuf) {
                    Ok(m) => m.into(),
                    Err(_) => {
                        return Err(std::io::Error::other(
                            "route refresh message error",
                        ));
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
        let msg_buf = msg.to_wire()?;
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
        self.sa_keepalive();
        Ok(())
    }

    #[cfg(target_os = "illumos")]
    fn sa_keepalive(&self) {
        use std::thread::sleep;

        let running = self
            .sa_keepalive_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Acquire)
            .is_err();
        if running {
            connection_log!(
                self,
                debug,
                "security association keepalive loop already running";
                "connection" => format!("{:?}", self.conn()),
                "dropped" => self.dropped.load(Ordering::Relaxed)
            );
            return;
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
        spawn(move || {
            loop {
                sleep(PFKEY_KEEPALIVE);
                if dropped.load(Ordering::Relaxed) {
                    break;
                }
                Self::do_sa_keepalive(&sas, &log, conn);
            }
        });
    }

    #[cfg(target_os = "illumos")]
    fn do_sa_keepalive(
        sas: &Arc<Mutex<Option<Md5Sas>>>,
        log: &Logger,
        conn: (SocketAddr, SocketAddr),
    ) {
        use std::ops::{Add, Sub};

        // While an API action that results in changing the authkey will
        // result in a session reset, there are other things that can change
        // out from underneath us that we need to keep tabs on. In particular
        // we may accept a connection from a client (as opposed to the client)
        // accepting a connection from us, and that will result in the
        // association set increasing according to the source port of the client.
        let guard = lock!(sas);
        if let Some(ref sas) = *guard {
            for (local, peer) in sas.associations.iter() {
                for (a, b) in sa_set(*local, *peer) {
                    let update =
                        libnet::pf_key::tcp_md5_key_get(a.into(), b.into())
                            .is_ok();
                    let valid_time =
                        Instant::now().sub(sas.create_time).add(PFKEY_DURATION);
                    if update {
                        if let Err(e) = libnet::pf_key::tcp_md5_key_update(
                            a.into(),
                            b.into(),
                            valid_time,
                        ) {
                            connection_log_lite!(log,
                                error,
                                "error updating pf_key {a} -> {b}: {e}";
                                "connection" => format!("{conn:?}"),
                                "error" => format!("{e}")
                            );
                        }
                    } else if let Err(e) = libnet::pf_key::tcp_md5_key_add(
                        a.into(),
                        b.into(),
                        sas.key.as_str(),
                        valid_time,
                    ) {
                        connection_log_lite!(log,
                            error,
                            "error adding pf_key {a} -> {b}: {e}";
                            "connection" => format!("{conn:?}"),
                            "error" => format!("{e}")
                        );
                    }
                }
            }
        }
    }
}

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
    let x = socket2::SockAddr::from(peer);
    let x = x.as_storage();
    sig.tcpm_addr = x;
    unsafe {
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

/// Helper function to select and validate MD5 source addresses
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

#[cfg(target_os = "illumos")]
fn any_port(mut s: SocketAddr) -> SocketAddr {
    s.set_port(0);
    s
}

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

/// Apply min TTL setting to a TCP connection
#[allow(unused_variables)]
fn apply_min_ttl(
    conn: &TcpStream,
    ttl: u8,
    peer: SocketAddr,
) -> Result<(), Error> {
    conn.set_ttl(ttl.into())?;
    #[cfg(any(target_os = "linux", target_os = "illumos"))]
    {
        let fd = conn.as_raw_fd();
        let min_ttl = ttl as u32;
        unsafe {
            if peer.is_ipv4()
                && libc::setsockopt(
                    fd,
                    IPPROTO_IP,
                    IP_MINTTL,
                    &min_ttl as *const u32 as *const c_void,
                    std::mem::size_of::<u32>() as u32,
                ) != 0
            {
                return Err(Error::Io(std::io::Error::last_os_error()));
            }
            if peer.is_ipv6()
                && libc::setsockopt(
                    fd,
                    IPPROTO_IPV6,
                    IP_MINTTL,
                    &min_ttl as *const u32 as *const c_void,
                    std::mem::size_of::<u32>() as u32,
                ) != 0
            {
                return Err(Error::Io(std::io::Error::last_os_error()));
            }
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
        for (a, b) in sa_set(*local, peer) {
            // Check if SA already exists before attempting to add
            let exists =
                libnet::pf_key::tcp_md5_key_get(a.into(), b.into()).is_ok();
            if exists {
                // Update existing SA with extended duration
                if let Err(e) = libnet::pf_key::tcp_md5_key_update(
                    a.into(),
                    b.into(),
                    PFKEY_DURATION,
                ) {
                    return Err(Error::Io(std::io::Error::other(format!(
                        "failed to update pf_key {a} -> {b}: {e}"
                    ))));
                }
            } else {
                // Add new SA
                if let Err(e) = libnet::pf_key::tcp_md5_key_add(
                    a.into(),
                    b.into(),
                    key,
                    PFKEY_DURATION,
                ) {
                    return Err(Error::Io(std::io::Error::other(format!(
                        "failed to add pf_key {a} -> {b}: {e}"
                    ))));
                }
            }
        }
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
