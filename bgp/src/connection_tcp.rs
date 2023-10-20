use crate::connection::{BgpConnection, BgpListener};
use crate::error::Error;
use crate::messages::{
    ErrorCode, ErrorSubcode, Header, Message, MessageType, NotificationMessage,
    OpenMessage, UpdateMessage,
};
use crate::session::FsmEvent;
use mg_common::lock;
use slog::{debug, error, warn, Logger};
use std::collections::BTreeMap;
use std::io::Read;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use std::time::Duration;

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
        let (conn, peer) = self.listener.accept()?;
        match lock!(addr_to_session).get(&peer.ip()) {
            Some(event_tx) => Ok(BgpConnectionTcp::with_conn(
                self.addr,
                peer,
                conn,
                event_tx.clone(),
                log,
            )?),
            None => Err(Error::UnknownPeer),
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

    fn connect(
        &self,
        event_tx: Sender<FsmEvent<Self>>,
        timeout: Duration,
    ) -> Result<(), Error> {
        match TcpStream::connect_timeout(&self.peer, timeout) {
            Ok(new_conn) => {
                lock!(self.conn).replace(new_conn.try_clone()?);
                Self::recv(
                    self.peer,
                    event_tx.clone(),
                    new_conn,
                    timeout,
                    self.dropped.clone(),
                    self.log.clone(),
                );
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
        );
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
    ) {
        if !timeout.is_zero() {
            // Unwrap is OK here as this function only returns an error when a
            // zero timeout is supplied.
            conn.set_read_timeout(Some(timeout))
                .unwrap_or_else(|_| panic!("set read timeout failed"));
        }

        slog::info!(log, "spawning recv loop");

        spawn(move || loop {
            if dropped.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            match Self::recv_msg(&mut conn, dropped.clone(), &log) {
                Ok(msg) => {
                    debug!(log, "[{peer}] recv: {msg:#?}");
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
        };

        Ok(msg)
    }

    fn send_msg(
        stream: &mut TcpStream,
        log: &Logger,
        msg: Message,
    ) -> Result<(), Error> {
        debug!(log, "sending {:#?}", msg);
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
        debug!(log, "sending {:x?}", buf);
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
