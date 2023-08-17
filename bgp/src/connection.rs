use crate::error::Error;
use crate::messages::{Header, Message, MessageType};
use crate::session::FsmEvent;
use slog::{error, Logger};
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use std::time::Duration;

pub trait BgpListener<Cnx: BgpConnection> {
    fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, Error>
    where
        Self: Sized;

    fn accept(
        &self,
        log: Logger,
        event_tx: Sender<FsmEvent<Cnx>>,
        timeout: Duration,
    ) -> Result<Cnx, Error>;
}

pub struct BgpListenerTcp {
    addr: SocketAddr,
    listener: TcpListener,
}

impl BgpListener<BgpConnectionTcp> for BgpListenerTcp {
    fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let addr = addr.to_socket_addrs().unwrap().next().unwrap();
        let listener = TcpListener::bind(addr)?;
        Ok(Self { listener, addr })
    }

    fn accept(
        &self,
        log: Logger,
        _event_tx: Sender<FsmEvent<BgpConnectionTcp>>, //TODO plumb
        _timeout: Duration,                            //TODO implement
    ) -> Result<BgpConnectionTcp, Error> {
        let (conn, sa) = self.listener.accept()?;
        Ok(BgpConnectionTcp::with_conn(self.addr, sa, conn, log))
    }
}

pub trait BgpConnection: Send {
    fn new(source: Option<SocketAddr>, peer: SocketAddr, log: Logger) -> Self
    where
        Self: Sized;

    fn connect(&self, event_tx: Sender<FsmEvent<Self>>, timeout: Duration)
    where
        Self: Sized;

    fn send(&self, msg: Message) -> Result<(), Error>;
    fn peer(&self) -> SocketAddr;
}

pub struct BgpConnectionTcp {
    #[allow(dead_code)]
    source: Option<SocketAddr>,
    peer: SocketAddr,
    conn: Arc<Mutex<Option<TcpStream>>>,
    log: Logger,
}

impl BgpConnection for BgpConnectionTcp {
    fn new(source: Option<SocketAddr>, peer: SocketAddr, log: Logger) -> Self {
        let conn = Arc::new(Mutex::new(None));
        Self {
            source,
            peer,
            conn,
            log,
        }
    }

    //TODO: this is dumb - should just to synchronously since we have a timeout
    //anyway.
    fn connect(&self, event_tx: Sender<FsmEvent<Self>>, timeout: Duration) {
        let peer = self.peer;
        let conn = self.conn.clone();
        let log = self.log.clone();
        spawn(move || match TcpStream::connect_timeout(&peer, timeout) {
            Ok(new_conn) => {
                conn.lock().unwrap().replace(new_conn);
                Self::recv(event_tx.clone(), timeout, log.clone());
                event_tx.send(FsmEvent::TcpConnectionConfirmed).unwrap();
            }
            Err(e) => {
                error!(log, "connect error: {e}");
            }
        });
    }

    fn send(&self, msg: Message) -> Result<(), Error> {
        let msg_buf = msg.to_wire()?;
        let header = Header {
            length: msg_buf.len() as u16 + 19,
            typ: MessageType::from(&msg),
        };
        let mut buf = header.to_wire().to_vec();
        buf.extend_from_slice(&msg_buf);
        let mut guard = self.conn.lock().unwrap();
        match *guard {
            Some(ref mut ch) => {
                ch.write_all(&buf)?;
            }
            None => {
                return Err(Error::NotConnected);
            }
        }
        Ok(())
    }

    fn peer(&self) -> SocketAddr {
        self.peer
    }
}

impl BgpConnectionTcp {
    fn with_conn(
        source: SocketAddr,
        peer: SocketAddr,
        conn: TcpStream,
        log: Logger,
    ) -> Self {
        Self {
            source: Some(source),
            peer,
            conn: Arc::new(Mutex::new(Some(conn))),
            log,
        }
    }

    fn recv(
        _event_tx: Sender<FsmEvent<Self>>,
        _timeout: Duration,
        _log: Logger,
    ) {
        todo!();
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::messages::Message;
    use slog::debug;
    use std::collections::HashMap;
    use std::sync::mpsc::RecvTimeoutError;
    use std::sync::Mutex;

    lazy_static! {
        static ref NET: Network = Network::new();
    }

    pub struct Network {
        #[allow(clippy::type_complexity)]
        endpoints:
            Mutex<HashMap<SocketAddr, Sender<(SocketAddr, Endpoint<Message>)>>>,
    }

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

        fn bind(&self, sa: SocketAddr) -> Listener {
            let (tx, rx) = std::sync::mpsc::channel();
            self.endpoints.lock().unwrap().insert(sa, tx);
            Listener { rx }
        }

        fn connect(
            &self,
            from: SocketAddr,
            to: SocketAddr,
            ep: Endpoint<Message>,
        ) -> Result<(), Error> {
            match self.endpoints.lock().unwrap().get(&to) {
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

    pub struct BgpListenerChannel {
        listener: Listener,
        addr: SocketAddr,
    }

    impl BgpListener<BgpConnectionChannel> for BgpListenerChannel {
        fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, Error>
        where
            Self: Sized,
        {
            let addr = addr.to_socket_addrs().unwrap().next().unwrap();
            let listener = NET.bind(addr);
            Ok(Self { listener, addr })
        }

        fn accept(
            &self,
            log: Logger,
            event_tx: Sender<FsmEvent<BgpConnectionChannel>>,
            timeout: Duration,
        ) -> Result<BgpConnectionChannel, Error> {
            let (peer, endpoint) = self.listener.accept(timeout)?;
            Ok(BgpConnectionChannel::with_conn(
                self.addr, peer, endpoint, event_tx, log,
            ))
        }
    }

    pub struct BgpConnectionChannel {
        addr: SocketAddr,
        peer: SocketAddr,
        conn_tx: Arc<Mutex<Option<Sender<Message>>>>,
        log: Logger,
    }

    impl BgpConnection for BgpConnectionChannel {
        fn new(
            addr: Option<SocketAddr>,
            peer: SocketAddr,
            log: Logger,
        ) -> Self {
            Self {
                addr: addr.unwrap(),
                peer,
                conn_tx: Arc::new(Mutex::new(None)),
                log,
            }
        }

        fn connect(&self, event_tx: Sender<FsmEvent<Self>>, timeout: Duration) {
            debug!(self.log, "[{}] connecting", self.peer);
            let (local, remote) = channel();
            match NET.connect(self.addr, self.peer, remote) {
                Ok(()) => {
                    self.conn_tx.lock().unwrap().replace(local.tx);
                    Self::recv(
                        self.peer,
                        local.rx,
                        event_tx.clone(),
                        timeout,
                        self.log.clone(),
                    );
                    event_tx.send(FsmEvent::TcpConnectionConfirmed).unwrap();
                }
                Err(e) => {
                    error!(self.log, "connect: {e}");
                }
            }
        }

        fn send(&self, msg: Message) -> Result<(), Error> {
            let guard = self.conn_tx.lock().unwrap();
            match *guard {
                Some(ref ch) => {
                    ch.send(msg)
                        .map_err(|e| Error::ChannelSend(e.to_string()))?;
                }
                None => {
                    return Err(Error::NotConnected);
                }
            }
            Ok(())
        }

        fn peer(&self) -> SocketAddr {
            self.peer
        }
    }

    impl BgpConnectionChannel {
        fn with_conn(
            addr: SocketAddr,
            peer: SocketAddr,
            conn: Endpoint<Message>,
            event_tx: Sender<FsmEvent<Self>>,
            log: Logger,
        ) -> Self {
            //TODO timeout as param
            Self::recv(
                peer,
                conn.rx,
                event_tx,
                Duration::from_millis(100),
                log.clone(),
            );
            Self {
                addr,
                peer,
                conn_tx: Arc::new(Mutex::new(Some(conn.tx))),
                log,
            }
        }

        fn recv(
            peer: SocketAddr,
            rx: Receiver<Message>,
            event_tx: Sender<FsmEvent<Self>>,
            _timeout: Duration, //TODO shutdown detection
            log: Logger,
        ) {
            spawn(move || loop {
                match rx.recv() {
                    Ok(msg) => {
                        debug!(log, "[{peer}] recv: {msg:#?}");
                        event_tx.send(FsmEvent::Message(msg)).unwrap();
                    }
                    Err(_e) => {
                        //TODO this goes a bit nuts .... sort out why
                        //error!(log, "recv: {e}");
                    }
                }
            });
        }
    }

    // BIDI

    use std::sync::mpsc::{self, Receiver, Sender};

    /// A combined mpsc sender/receiver.
    pub struct Endpoint<T> {
        pub rx: Receiver<T>,
        pub tx: Sender<T>,
    }

    impl<T> Endpoint<T> {
        fn new(rx: Receiver<T>, tx: Sender<T>) -> Self {
            Self { rx, tx }
        }
    }

    /// Analsgous to std::sync::mpsc::channel for bidirectional endpoints.
    #[allow(dead_code)]
    pub fn channel<T>() -> (Endpoint<T>, Endpoint<T>) {
        let (tx_a, rx_b) = mpsc::channel();
        let (tx_b, rx_a) = mpsc::channel();
        (Endpoint::new(rx_a, tx_a), Endpoint::new(rx_b, tx_b))
    }
}
