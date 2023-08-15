use crate::error::Error;
use crate::messages::Message;
use crate::session::FsmEvent;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use std::time::Duration;

pub trait BgpListener<Cnx: BgpConnection> {
    fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, Error>
    where
        Self: Sized;

    fn accept(&self) -> Result<Cnx, Error>;
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
        Ok(Self {
            listener: TcpListener::bind(addr)?,
            addr,
        })
    }

    fn accept(&self) -> Result<BgpConnectionTcp, Error> {
        let (conn, sa) = self.listener.accept()?;
        Ok(BgpConnectionTcp::with_conn(self.addr, sa, conn))
    }
}

pub trait BgpConnection: Send {
    fn new(source: Option<SocketAddr>, peer: SocketAddr) -> Self
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
}

impl BgpConnection for BgpConnectionTcp {
    fn new(source: Option<SocketAddr>, peer: SocketAddr) -> Self {
        let conn = Arc::new(Mutex::new(None));
        Self { source, peer, conn }
    }

    fn connect(&self, event_tx: Sender<FsmEvent<Self>>, timeout: Duration) {
        let peer = self.peer;
        let conn = self.conn.clone();
        spawn(move || {
            match TcpStream::connect_timeout(&peer, timeout) {
                Ok(new_conn) => {
                    conn.lock().unwrap().replace(new_conn);
                    event_tx.send(FsmEvent::TcpConnectionConfirmed).unwrap();
                }
                Err(_e) => {
                    //TODO log
                }
            }
        });
    }

    fn send(&self, _msg: Message) -> Result<(), Error> {
        todo!();
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
    ) -> Self {
        Self {
            source: Some(source),
            peer,
            conn: Arc::new(Mutex::new(Some(conn))),
        }
    }
}

/*
struct DropSleep(Duration);

impl Drop for DropSleep {
    fn drop(&mut self) {
        sleep(self.0);
    }
}

impl ConnectionTcp {
    fn accept(
        resolution: Duration,
        shutdown: Arc<AtomicBool>,
        peer: SocketAddr,
        conn: Arc<Mutex<Option<TcpStream>>>,
        event_tx: Sender<FsmEvent>,
    ) {
        spawn(move || loop {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            let _d = DropSleep(resolution);
            let listener = match TcpListener::bind(peer) {
                Ok(l) => l,
                Err(_e) => {
                    //TODO log
                    continue;
                }
            };
            match listener.accept() {
                Ok((new_conn, _peer)) => {
                    //TODO check that the peer is expected one
                    conn.lock().unwrap().replace(new_conn);
                    event_tx.send(FsmEvent::TcpConnectionConfirmed).unwrap();
                    break;
                }
                Err(_e) => {
                    //TODO log
                    continue;
                }
            };
        });
    }
}
*/

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::messages::Message;
    use std::collections::HashMap;
    use std::sync::Mutex;

    lazy_static! {
        static ref NET: Network = Network::new();
    }

    pub struct Network {
        #[allow(clippy::type_complexity)]
        endpoints: Mutex<HashMap<
            SocketAddr,
            Sender<(SocketAddr, Endpoint<Message>)>
        >>,
    }

    struct Listener {
        rx: Receiver<(SocketAddr, Endpoint<Message>)>,
    }

    impl Listener {
        fn accept(&self)
        -> Result<(SocketAddr, Endpoint<Message>), std::sync::mpsc::RecvError> {
            self.rx.recv()
        }
    }

    impl Network {
        fn new() -> Self {
            Self{endpoints: Mutex::new(HashMap::new())}
        }

        fn bind(&self, sa: SocketAddr) -> Listener {
            let (tx, rx) = std::sync::mpsc::channel();
            self.endpoints.lock().unwrap().insert(sa, tx);
            Listener{rx}
        }

        fn connect(
            &self,
            from: SocketAddr,
            to: SocketAddr,
            ep: Endpoint<Message>,
        ) -> Result<(), Error> {

            match self.endpoints.lock().unwrap().get(&from) {
                None => return Err(Error::ChannelConnect),
                Some(sender) => {
                    sender.send((to, ep))
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
            Ok(Self{listener, addr})
        }

        fn accept(&self) -> Result<BgpConnectionChannel, Error> {
            let (peer, endpoint) = self.listener.accept()?;
            Ok(BgpConnectionChannel::with_conn(
                    peer,
                    self.addr,
                    endpoint,
            ))
        }
    }

    pub struct BgpConnectionChannel {
        addr: SocketAddr,
        peer: SocketAddr,
        conn: Arc<Mutex<Option<Endpoint<Message>>>>,
    }

    impl BgpConnection for BgpConnectionChannel {
        fn new(addr: Option<SocketAddr>, peer: SocketAddr) -> Self {
            Self {
                addr: addr.unwrap(),
                peer,
                conn: Arc::new(Mutex::new(None)),
            }
        }

        fn connect(
            &self,
            event_tx: Sender<FsmEvent<Self>>,
            _timeout: Duration,
        ) {
            let (local, remote) = channel();
            match NET.connect(
                self.addr,
                self.peer,
                remote,
            ) {
                Ok(_) => {
                    self.conn.lock().unwrap().replace(local);
                    event_tx.send(FsmEvent::TcpConnectionConfirmed).unwrap();
                }
                Err(_e) => {
                    //TODO log
                }
            }

            todo!();
        }

        fn send(&self, _msg: Message) -> Result<(), Error> {
            todo!();
        }

        fn peer(&self) -> SocketAddr {
            todo!();
        }
    }

    impl BgpConnectionChannel {
        fn with_conn(
            addr: SocketAddr,
            peer: SocketAddr,
            conn: Endpoint<Message>, 
        ) -> Self {
            Self {
                addr,
                peer,
                conn: Arc::new(Mutex::new(Some(conn))),
            }
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
