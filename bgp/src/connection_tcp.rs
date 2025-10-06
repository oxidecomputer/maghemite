// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::clock::ConnectionClock;
use crate::connection::{
    BgpConnection, BgpConnector, BgpListener, ConnectionCreator, ConnectionId,
    MAX_MD5SIG_KEYLEN,
};
use crate::error::Error;
use crate::log::{connection_log, connection_log_lite};
use crate::messages::{
    ErrorCode, ErrorSubcode, Header, Message, MessageType, NotificationMessage,
    OpenMessage, RouteRefreshMessage, UpdateMessage,
};
use crate::session::{ConnectionEvent, FsmEvent, SessionEndpoint, SessionInfo};
use crossbeam_channel::Sender;
use libc::{c_int, sockaddr_storage};
use mg_common::lock;
use slog::Logger;
use std::collections::BTreeMap;
use std::io::Read;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use std::time::Duration;
#[cfg(any(target_os = "linux", target_os = "illumos"))]
use {crate::log::connection_log, std::os::fd::AsRawFd};

const UNIT_CONNECTION: &str = "connection_tcp";

#[cfg(target_os = "illumos")]
use itertools::Itertools;
#[cfg(any(target_os = "linux", target_os = "illumos"))]
use libc::{c_void, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_TCP};
#[cfg(target_os = "linux")]
use libc::{IP_MINTTL, TCP_MD5SIG};
#[cfg(target_os = "illumos")]
use slog::debug;
#[cfg(target_os = "illumos")]
use std::collections::HashSet;
#[cfg(target_os = "illumos")]
use std::time::Instant;

#[cfg(target_os = "illumos")]
const IP_MINTTL: i32 = 0x1c;
#[cfg(target_os = "illumos")]
const TCP_MD5SIG: i32 = 0x27;
#[cfg(target_os = "illumos")]
const PFKEY_DURATION: Duration = Duration::from_secs(60 * 2);
#[cfg(target_os = "illumos")]
const PFKEY_KEEPALIVE: Duration = Duration::from_secs(60);

pub struct BgpListenerTcp {
    addr: SocketAddr,
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
        Ok(Self { listener, addr })
    }

    fn accept(
        &self,
        log: Logger,
        addr_to_session: Arc<
            Mutex<BTreeMap<IpAddr, SessionEndpoint<BgpConnectionTcp>>>,
        >,
        timeout: Duration,
    ) -> Result<BgpConnectionTcp, Error> {
        let (conn, mut peer) = self.listener.accept().map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                Error::Timeout
            } else {
                e.into()
            }
        })?;

        let ip = peer.ip().to_canonical();
        peer.set_ip(ip);

        // Check if we have a session for this peer
        match lock!(addr_to_session).get(&ip) {
            Some(session_endpoint) => {
                let config = lock!(session_endpoint.config);
                BgpConnectionTcp::with_conn(
                    self.addr,
                    peer,
                    conn,
                    timeout,
                    session_endpoint.event_tx.clone(),
                    log,
                    ConnectionCreator::Dispatcher,
                    &config,
                )
            }
            None => Err(Error::UnknownPeer(ip)),
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
            // Apply MD5 authentication to the accepted connection
            #[cfg(target_os = "linux")]
            {
                let mut keyval = [0u8; MAX_MD5SIG_KEYLEN];
                let len = key.len();
                keyval[..len].copy_from_slice(key.as_bytes());
                set_md5_sig_fd(
                    tcp_stream.as_raw_fd(),
                    len as u16,
                    keyval,
                    conn.peer,
                )?;
            }

            #[cfg(target_os = "illumos")]
            {
                let sources = match source_address_select(conn.peer.ip()) {
                    Ok(s) => s,
                    Err(e) => return Err(Error::InvalidAddress(e.to_string())),
                };
                if !sources.is_empty() {
                    let local: Vec<SocketAddr> = sources
                        .iter()
                        .map(|x| SocketAddr::new(*x, crate::BGP_PORT))
                        .collect();
                    set_md5_sig_fd(
                        tcp_stream.as_raw_fd(),
                        key,
                        local,
                        conn.peer,
                    )?;
                }
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
    #[allow(clippy::too_many_arguments)]
    fn connect(
        peer: SocketAddr,
        timeout: Duration,
        min_ttl: Option<u8>,
        _md5_key: Option<String>, // TODO: Fix MD5 implementation for macOS
        log: Logger,
        event_tx: Sender<FsmEvent<BgpConnectionTcp>>,
        config: &SessionInfo,
    ) -> Result<BgpConnectionTcp, Error> {
        let s = match peer {
            SocketAddr::V4(_) => socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                None,
            )?,
            SocketAddr::V6(_) => socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                None,
            )?,
        };

        // Apply MD5 authentication before connecting
        #[cfg(target_os = "linux")]
        if let Some(key) = &_md5_key {
            let mut keyval = [0u8; MAX_MD5SIG_KEYLEN];
            let len = key.len();
            keyval[..len].copy_from_slice(key.as_bytes());
            if let Err(e) =
                set_md5_sig_fd(s.as_raw_fd(), len as u16, keyval, peer)
            {
                return Err(e);
            }
        }

        #[cfg(target_os = "illumos")]
        if let Some(key) = &_md5_key {
            let sources = match source_address_select(peer.ip()) {
                Ok(s) => s,
                Err(e) => return Err(Error::InvalidAddress(e.to_string())),
            };
            if sources.is_empty() {
                return Err(Error::InvalidAddress(String::from(
                    "no source address",
                )));
            }
            let local: Vec<SocketAddr> = sources
                .iter()
                .map(|x| SocketAddr::new(*x, crate::BGP_PORT))
                .collect();
            if let Err(e) = set_md5_sig_fd(s.as_raw_fd(), key, local, peer) {
                return Err(e);
            }
        }

        // Bind to source address if specified
        if let Some(source_addr) = config.bind_addr {
            let mut src = source_addr;
            // clear source port, we only want to set the source ip
            src.set_port(0);
            let ba: socket2::SockAddr = src.into();
            s.bind(&ba)?;
        }

        // Establish the connection
        let sa: socket2::SockAddr = peer.into();
        let new_conn: TcpStream = match s.connect_timeout(&sa, timeout) {
            Ok(()) => s.into(),
            Err(e) => return Err(Error::Io(e)),
        };

        // Apply TTL if specified
        if let Some(ttl) = min_ttl {
            apply_min_ttl(&new_conn, ttl, peer)?;
        }

        // Determine the actual source address
        let actual_source = new_conn.local_addr()?;

        // Create the connection object with the established stream
        BgpConnectionTcp::with_conn(
            actual_source,
            peer,
            new_conn,
            timeout,
            event_tx,
            log,
            ConnectionCreator::Connector,
            config,
        )
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
    // creator of this connection, i.e. BgpListener or BgpConnector
    creator: ConnectionCreator,
    // Connection-level timers for keepalive, hold, and delay open
    connection_clock: ConnectionClock,
    // Parameters for spawning the recv loop (stored until start_recv_loop is called)
    // Note: No Arc needed! recv loop is started before cloning in register_conn()
    recv_loop_params: Mutex<Option<RecvLoopParams>>,
    // Track whether recv loop has been started
    recv_loop_started: AtomicBool,
}

impl Clone for BgpConnectionTcp {
    fn clone(&self) -> Self {
        // Clones always have empty recv loop params since the original connection
        // should have started the recv loop before being cloned (in register_conn).
        Self {
            id: self.id,
            peer: self.peer,
            source: self.source,
            conn: self.conn.clone(),
            #[cfg(target_os = "illumos")]
            sas: self.sas.clone(),
            #[cfg(target_os = "illumos")]
            sa_keepalive_running: self.sa_keepalive_running.clone(),
            dropped: self.dropped.clone(),
            log: self.log.clone(),
            creator: self.creator,
            connection_clock: self.connection_clock.clone(),
            recv_loop_params: Mutex::new(None),
            recv_loop_started: AtomicBool::new(true),
        }
    }
}

/// Parameters needed to spawn the receive loop for a BGP connection
struct RecvLoopParams {
    event_tx: Sender<FsmEvent<BgpConnectionTcp>>,
    timeout: Duration,
}

impl BgpConnection for BgpConnectionTcp {
    type Connector = BgpConnectorTcp;

    fn send(&self, msg: Message) -> Result<(), Error> {
        let mut guard = lock!(self.conn);
        Self::send_msg(&mut guard, &self.log, self.creator.as_str(), msg)
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

    fn creator(&self) -> ConnectionCreator {
        self.creator
    }

    fn id(&self) -> &ConnectionId {
        &self.id
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
                "spawning recv loop for {}", self.peer;
            );

            let peer = self.peer;
            let event_tx = params.event_tx;
            let timeout = params.timeout;
            let dropped = self.dropped.clone();
            let log = self.log.clone();
            let creator = self.creator;
            let conn_id = self.id;

            // Clone the TcpStream for the recv thread
            if let Ok(conn) = lock!(self.conn).try_clone() {
                Self::spawn_recv_loop(
                    peer, event_tx, conn, timeout, dropped, log, creator,
                    conn_id,
                );
            }
        }
    }
}

impl Drop for BgpConnectionTcp {
    fn drop(&mut self) {
        #[cfg(target_os = "illumos")]
        self.md5_sig_drop();
        connection_log!(self, trace,
            "dropping connection {:?} (conn_id {})",
            self.conn(), self.id().short();
            "connection" => format!("{:?}", self.conn()),
            "connection_id" => self.id().short(),
            "dropped" => self.dropped.load(std::sync::atomic::Ordering::Relaxed)
        );
        // Only set dropped flag if this is the last reference.
        // This prevents the recv loop from closing prematurely when intermediate
        // clones are dropped during FSM state transitions (e.g., collision resolution).
        if Arc::strong_count(&self.dropped) == 1 {
            self.dropped
                .store(true, std::sync::atomic::Ordering::Relaxed);
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
        creator: ConnectionCreator,
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

        // Store the parameters for spawning the recv loop later
        let recv_loop_params =
            Mutex::new(Some(RecvLoopParams { event_tx, timeout }));

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
            creator,
            connection_clock,
            recv_loop_params,
            recv_loop_started: AtomicBool::new(false),
        })
    }

    /// Spawn the receive loop thread for this connection.
    #[allow(clippy::too_many_arguments)]
    fn spawn_recv_loop(
        peer: SocketAddr,
        event_tx: Sender<FsmEvent<Self>>,
        mut conn: TcpStream,
        timeout: Duration,
        dropped: Arc<AtomicBool>,
        log: Logger,
        creator: ConnectionCreator,
        conn_id: ConnectionId,
    ) {
        if !timeout.is_zero() {
            if let Err(e) = conn.set_read_timeout(Some(timeout)) {
                connection_log_lite!(log,
                    error,
                    "failed to set read timeout in recv loop for {peer} (conn_id: {}): {e}",
                    conn_id.short();
                    "creator" => creator.as_str(),
                    "connection" => format!("{conn:?}"),
                    "connection_peer" => format!("{peer}"),
                    "connection_id" => conn_id.short(),
                    "error" => format!("{e}")
                );
                return;
            }
        }

        let l = log.clone();

        spawn(move || {
            loop {
                if dropped.load(std::sync::atomic::Ordering::Relaxed) {
                    connection_log_lite!(l, info,
                        "recv loop dropped (peer: {peer}, conn_id: {}), closing..",
                        conn_id.short();
                        "creator" => creator.as_str(),
                        "connection" => format!("{conn:?}"),
                        "connection_peer" => format!("{peer}"),
                        "connection_id" => conn_id.short()
                    );
                    break;
                }
                match Self::recv_msg(
                    &mut conn,
                    dropped.clone(),
                    &l,
                    creator.as_str(),
                ) {
                    Ok(msg) => {
                        connection_log_lite!(l, trace,
                            "recv {} msg from {peer} (conn_id: {})",
                            msg.title(), conn_id.short();
                            "creator" => creator.as_str(),
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
                                "creator" => creator.as_str(),
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
                            "creator" => creator.as_str(),
                            "connection" => format!("{conn:?}"),
                            "connection_peer" => format!("{peer}"),
                            "connection_id" => conn_id.short(),
                            "error" => format!("{e}")
                        );
                    }
                }
            }
            connection_log_lite!(l, info,
                "recv loop closed (peer: {peer}, conn_id: {})",
                conn_id.short();
                "creator" => creator.as_str(),
                "connection" => format!("{conn:?}"),
                "connection_peer" => format!("{peer}"),
                "connection_id" => conn_id.short()
            );
        });
    }

    fn recv_header(
        stream: &mut TcpStream,
        dropped: Arc<AtomicBool>,
    ) -> std::io::Result<Header> {
        let mut buf = [0u8; Header::WIRE_SIZE];
        let mut i = 0;
        loop {
            if dropped.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "shutting down",
                ));
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
        creator: &str,
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
                        "creator" => creator,
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
                        UNIT_CONNECTION,
                        ErrorCode::Open,
                        ErrorSubcode::Open(subcode),
                        Vec::new(),
                    ) {
                        connection_log_lite!(log,
                            error,
                            "error sending notification: {e}";
                            "creator" => creator,
                            "connection" => format!("{stream:?}"),
                            "error" => format!("{e}")
                        );
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "open message error",
                    ));
                }
            },
            MessageType::Update => match UpdateMessage::from_wire(&msgbuf) {
                Ok(m) => m.into(),
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "update message error",
                    ))
                }
            },
            MessageType::Notification => {
                match NotificationMessage::from_wire(&msgbuf) {
                    Ok(m) => m.into(),
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "notification message error",
                        ))
                    }
                }
            }
            MessageType::KeepAlive => return Ok(Message::KeepAlive),
            MessageType::RouteRefresh => {
                match RouteRefreshMessage::from_wire(&msgbuf) {
                    Ok(m) => m.into(),
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "route refresh message error",
                        ))
                    }
                }
            }
        };

        Ok(msg)
    }

    fn send_msg(
        stream: &mut TcpStream,
        _log: &Logger,
        _creator: &str,
        msg: Message,
    ) -> Result<(), Error> {
        // connection_log_lite!(log,
        //     trace,
        //     "sending {} msg", msg.title();
        //     "creator" => creator,
        //     "connection" => format!("{stream:?}"),
        //     "message" => msg.title(),
        //     "message_contents" => format!("{msg}")
        // );
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
        // connection_log_lite!(log,
        //     trace,
        //     "sending {} msg with header", msg.title();
        //     "connection" => format!("{stream:?}"),
        //     "message" => msg.title(),
        //     "message_contents" => format!("{buf:x?}")
        // );
        stream.write_all(&buf)?;
        Ok(())
    }

    fn send_notification(
        stream: &mut TcpStream,
        log: &Logger,
        creator: &str,
        error_code: ErrorCode,
        error_subcode: ErrorSubcode,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        Self::send_msg(
            stream,
            log,
            creator,
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
                            "dropped" => self.dropped.load(std::sync::atomic::Ordering::Relaxed),
                            "error" => format!("{e}")
                        );
                    }
                }
            }
        }
    }

    #[cfg(target_os = "illumos")]
    fn set_md5_sig_fd(
        &self,
        fd: i32,
        key: &str,
        locals: Vec<SocketAddr>,
        peer: SocketAddr,
    ) -> Result<(), Error> {
        self.set_md5_security_associations(key, locals, peer)?;

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
        use std::{sync::atomic::Ordering, thread::sleep};

        let running = self
            .sa_keepalive_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Acquire)
            .is_err();
        if running {
            connection_log!(self,
                debug,
                "security association keepalive loop already running";
                "connection" => format!("{:?}", lock!(self.conn)),
                "dropped" => self.dropped.load(std::sync::atomic::Ordering::Relaxed)
            );
            return;
        }

        // Get one run in before returning, this helps the SAs to
        // get set up before setting up the socket.
        Self::do_sa_keepalive(&self.sas, &self.log);

        connection_log!(self,
            debug,
            // space after loop is needed... because macros?
            "spawning security association keepalive loop ";
            "connection" => format!("{:?}", lock!(self.conn)),
            "dropped" => self.dropped.load(std::sync::atomic::Ordering::Relaxed)
        );
        let dropped = self.dropped.clone();
        let log = self.log.clone();
        let sas = self.sas.clone();
        spawn(move || loop {
            sleep(PFKEY_KEEPALIVE);
            if dropped.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            Self::do_sa_keepalive(&sas, &log);
        });
    }

    #[cfg(target_os = "illumos")]
    fn do_sa_keepalive(sas: &Arc<Mutex<Option<Md5Sas>>>, log: &Logger) {
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
                            connection_log!(self,
                                error,
                                "error updating pf_key {a} -> {b}: {e}";
                                "connection" => format!("{:?}", lock!(self.conn)),
                                "dropped" => self.dropped.load(std::sync::atomic::Ordering::Relaxed),
                                "error" => format!("{e}")
                            );
                        }
                    } else if let Err(e) = libnet::pf_key::tcp_md5_key_add(
                        a.into(),
                        b.into(),
                        sas.key.as_str(),
                        valid_time,
                    ) {
                        connection_log!(self,
                            error,
                            "error adding pf_key {a} -> {b}: {e}";
                            "connection" => format!("{:?}", lock!(self.conn)),
                            "dropped" => self.dropped.load(std::sync::atomic::Ordering::Relaxed),
                            "error" => format!("{e}")
                        );
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn set_md5_sig_fd(
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

#[repr(C)]
struct TcpMd5Sig {
    tcpm_addr: sockaddr_storage,
    tcpm_flags: u8,
    tcpm_prefixlen: u8,
    tcpm_keylen: u16,
    tcpm_ifindex: c_int,
    tcpm_key: [u8; MAX_MD5SIG_KEYLEN],
}

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

/// Apply MD5 signature to socket for Illumos
#[cfg(target_os = "illumos")]
fn set_md5_sig_fd(
    fd: i32,
    key: &str,
    locals: Vec<SocketAddr>,
    peer: SocketAddr,
) -> Result<(), Error> {
    // Set MD5 security associations for Illumos
    for local in locals.iter() {
        for (a, b) in sa_set(*local, peer) {
            let valid_time = std::time::Instant::now().add(PFKEY_DURATION);
            if let Err(e) = libnet::pf_key::tcp_md5_key_add(
                a.into(),
                b.into(),
                key,
                valid_time,
            ) {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to add pf_key {a} -> {b}: {e}"),
                )));
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
