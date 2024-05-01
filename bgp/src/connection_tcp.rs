// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::connection::{BgpConnection, BgpListener, MAX_MD5SIG_KEYLEN};
use crate::error::Error;
use crate::messages::{
    ErrorCode, ErrorSubcode, Header, Message, MessageType, NotificationMessage,
    OpenMessage, RouteRefreshMessage, UpdateMessage,
};
use crate::session::FsmEvent;
use crate::to_canonical;
use libc::{c_int, sockaddr_storage};
#[cfg(any(target_os = "linux", target_os = "illumos"))]
use libc::{c_void, IPPROTO_IP, IPPROTO_IPV6};
#[cfg(target_os = "linux")]
use libc::{IPPROTO_TCP, IP_MINTTL, TCP_MD5SIG};

use mg_common::lock;
use slog::{error, trace, warn, Logger};
use std::collections::BTreeMap;
use std::io::Read;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use std::time::Duration;

#[cfg(target_os = "illumos")]
const IP_MINTTL: i32 = 0x1c;

pub struct BgpListenerTcp {
    addr: SocketAddr,
    listener: TcpListener,
}

#[derive(Clone)]
pub struct BgpConnectionTcp {
    peer: SocketAddr,
    conn: Arc<Mutex<Option<TcpStream>>>, //TODO split into tx/rx?
    dropped: Arc<AtomicBool>,
    log: Logger,
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
        Ok(Self { listener, addr })
    }

    fn accept(
        &self,
        log: Logger,
        addr_to_session: Arc<
            Mutex<BTreeMap<IpAddr, Sender<FsmEvent<BgpConnectionTcp>>>>,
        >,
        _timeout: Duration, //TODO implement
    ) -> Result<BgpConnectionTcp, Error> {
        let (conn, mut peer) = self.listener.accept()?;

        let ip = to_canonical(peer.ip());
        peer.set_ip(ip);

        match lock!(addr_to_session).get(&ip) {
            Some(event_tx) => Ok(BgpConnectionTcp::with_conn(
                self.addr,
                peer,
                conn,
                event_tx.clone(),
                log,
            )?),
            None => Err(Error::UnknownPeer(ip)),
        }
    }
}

impl BgpConnection for BgpConnectionTcp {
    fn new(_source: Option<SocketAddr>, peer: SocketAddr, log: Logger) -> Self {
        let conn = Arc::new(Mutex::new(None));
        Self {
            peer,
            conn,
            log,
            dropped: Arc::new(AtomicBool::new(false)),
        }
    }

    #[allow(unused_variables)]
    fn connect(
        &self,
        event_tx: Sender<FsmEvent<Self>>,
        timeout: Duration,
        min_ttl: Option<u8>,
        md5_key: Option<String>,
    ) -> Result<(), Error> {
        let s = match self.peer {
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

        #[cfg(target_os = "linux")]
        if let Some(key) = md5_key {
            slog::info!(self.log, "setting md5 key: {:?}", key);
            let mut keyval = [0u8; MAX_MD5SIG_KEYLEN];
            let len = key.len();
            keyval[..len].copy_from_slice(key.as_bytes());
            if let Err(e) =
                set_md5_sig_fd(s.as_raw_fd(), len as u16, keyval, self.peer)
            {
                error!(self.log, "set md5 key for tcp conn failed: {e}");
                return Err(e);
            }
        }

        let sa: socket2::SockAddr = self.peer.into();
        match s.connect_timeout(&sa, timeout) {
            Ok(()) => {
                let new_conn: TcpStream = s.into();
                lock!(self.conn).replace(new_conn.try_clone()?);
                if let Some(ttl) = min_ttl {
                    self.set_min_ttl(ttl)?;
                }
                Self::recv(
                    self.peer,
                    event_tx.clone(),
                    new_conn,
                    timeout,
                    self.dropped.clone(),
                    self.log.clone(),
                )?;
                event_tx.send(FsmEvent::TcpConnectionConfirmed).map_err(
                    |e| {
                        Error::InternalCommunication(format!(
                            "fsm-send: tcp connection confirmed: {e}"
                        ))
                    },
                )?;
                Ok(())
            }
            Err(e) => {
                error!(self.log, "connect error: {e}");
                Err(Error::Io(e))
            }
        }
    }

    fn send(&self, msg: Message) -> Result<(), Error> {
        let mut guard = lock!(self.conn);
        match *guard {
            Some(ref mut stream) => Self::send_msg(stream, &self.log, msg),
            None => Err(Error::NotConnected),
        }
    }

    fn peer(&self) -> SocketAddr {
        self.peer
    }

    fn local(&self) -> Option<SocketAddr> {
        let result = match lock!(self.conn).as_ref() {
            Some(conn) => conn.local_addr(),
            None => return None,
        };

        let sockaddr = match result {
            Ok(sa) => sa,
            Err(e) => {
                warn!(
                    self.log,
                    "failed to get local address for TCP connection: {e}"
                );
                return None;
            }
        };
        Some(sockaddr)
    }

    #[allow(unused_variables)]
    fn set_min_ttl(&self, ttl: u8) -> Result<(), Error> {
        let conn = self.conn.lock().unwrap();
        match conn.as_ref() {
            None => Err(Error::NotConnected),
            Some(conn) => {
                conn.set_ttl(ttl.into())?;
                let fd = conn.as_raw_fd();
                let min_ttl = ttl as u32;
                #[cfg(any(target_os = "linux", target_os = "illumos"))]
                unsafe {
                    if self.peer().is_ipv4()
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
                    if self.peer().is_ipv6()
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
                Ok(())
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn set_md5_sig(
        &self,
        keylen: u16,
        key: [u8; MAX_MD5SIG_KEYLEN],
    ) -> Result<(), Error> {
        slog::info!(self.log, "setting md5 auth for {}", self.peer);
        let conn = self.conn.lock().unwrap();
        let fd = match conn.as_ref() {
            None => return Err(Error::NotConnected),
            Some(c) => c.as_raw_fd(),
        };

        set_md5_sig_fd(fd, keylen, key, self.peer)
    }

    #[cfg(target_os = "illumos")]
    fn set_md5_sig(
        &self,
        _keylen: u16,
        _key: [u8; MAX_MD5SIG_KEYLEN],
    ) -> Result<(), Error> {
        todo!();
    }

    #[cfg(target_os = "macos")]
    fn set_md5_sig(
        &self,
        _keylen: u16,
        _key: [u8; MAX_MD5SIG_KEYLEN],
    ) -> Result<(), Error> {
        todo!();
    }
}

impl Drop for BgpConnectionTcp {
    fn drop(&mut self) {
        self.dropped
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl BgpConnectionTcp {
    fn with_conn(
        _source: SocketAddr,
        peer: SocketAddr,
        conn: TcpStream,
        event_tx: Sender<FsmEvent<Self>>,
        log: Logger,
    ) -> Result<Self, Error> {
        let dropped = Arc::new(AtomicBool::new(false));
        //TODO timeout as param
        Self::recv(
            peer,
            event_tx,
            conn.try_clone()?,
            Duration::from_millis(100),
            dropped.clone(),
            log.clone(),
        )?;
        Ok(Self {
            peer,
            conn: Arc::new(Mutex::new(Some(conn))),
            log,
            dropped,
        })
    }

    fn recv(
        peer: SocketAddr,
        event_tx: Sender<FsmEvent<Self>>,
        mut conn: TcpStream,
        timeout: Duration,
        dropped: Arc<AtomicBool>,
        log: Logger,
    ) -> Result<(), Error> {
        if !timeout.is_zero() {
            conn.set_read_timeout(Some(timeout))?;
        }

        slog::info!(log, "spawning recv loop");

        spawn(move || loop {
            if dropped.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            match Self::recv_msg(&mut conn, dropped.clone(), &log) {
                Ok(msg) => {
                    trace!(log, "[{peer}] recv: {msg:#?}");
                    if let Err(e) = event_tx.send(FsmEvent::Message(msg)) {
                        warn!(
                            log,
                            "[{peer}] connection: error sending event {e}"
                        );
                        break;
                    }
                }
                Err(_e) => {
                    //TODO log?
                }
            }
        });

        Ok(())
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
    ) -> std::io::Result<Message> {
        use crate::messages::OpenErrorSubcode;
        let hdr = Self::recv_header(stream, dropped.clone())?;

        let mut msgbuf = vec![0u8; usize::from(hdr.length) - Header::WIRE_SIZE];
        stream.read_exact(&mut msgbuf)?;

        let msg = match hdr.typ {
            MessageType::Open => match OpenMessage::from_wire(&msgbuf) {
                Ok(m) => m.into(),
                Err(e) => {
                    error!(log, "open message error: {e}");

                    let subcode = match e {
                        Error::UnsupportedCapability(_) => {
                            OpenErrorSubcode::UnsupportedCapability
                        }
                        _ => OpenErrorSubcode::Unspecific,
                    };

                    if let Err(e) = Self::send_notification(
                        stream,
                        log,
                        ErrorCode::Open,
                        ErrorSubcode::Open(subcode),
                        Vec::new(),
                    ) {
                        warn!(log, "send notification: {e}");
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
        log: &Logger,
        msg: Message,
    ) -> Result<(), Error> {
        trace!(log, "sending {:#?}", msg);
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
        trace!(log, "sending {:x?}", buf);
        stream.write_all(&buf)?;
        Ok(())
    }

    fn send_notification(
        stream: &mut TcpStream,
        log: &Logger,
        error_code: ErrorCode,
        error_subcode: ErrorSubcode,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        Self::send_msg(
            stream,
            log,
            Message::Notification(NotificationMessage {
                error_code,
                error_subcode,
                data,
            }),
        )
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
