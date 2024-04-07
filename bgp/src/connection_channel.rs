// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// This file contains code for testing purposes only. Note that it's only
/// included in `lib.rs` with a `#[cfg(test)]` guard. The purpose of the
/// code in this file is to implement BgpListener and BgpConnection such that
/// the core functionality of the BGP upper-half in `session.rs` may be tested
/// rapidly using a simulated network.
use crate::connection::{BgpConnection, BgpListener};
use crate::error::Error;
use crate::messages::Message;
use crate::session::FsmEvent;
use mg_common::lock;
use slog::debug;
use slog::error;
use slog::Logger;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use std::time::Duration;

lazy_static! {
    static ref NET: Network = Network::new();
}

/// A simulated network that maps socket addresses to channels that can send
/// messages to listeners for those addresses.
pub struct Network {
    #[allow(clippy::type_complexity)]
    endpoints:
        Mutex<HashMap<SocketAddr, Sender<(SocketAddr, Endpoint<Message>)>>>,
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
        let (tx, rx) = std::sync::mpsc::channel();
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
    addr: SocketAddr,
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
        Ok(Self { listener, addr })
    }

    fn accept(
        &self,
        log: Logger,
        addr_to_session: Arc<
            Mutex<BTreeMap<IpAddr, Sender<FsmEvent<BgpConnectionChannel>>>>,
        >,
        timeout: Duration,
    ) -> Result<BgpConnectionChannel, Error> {
        let (peer, endpoint) = self.listener.accept(timeout)?;
        match lock!(addr_to_session).get(&peer.ip()) {
            Some(event_tx) => Ok(BgpConnectionChannel::with_conn(
                self.addr,
                peer,
                endpoint,
                event_tx.clone(),
                log,
            )),
            None => Err(Error::UnknownPeer(peer.ip())),
        }
    }
}

/// A struct to implement BgpConnection for our simulated test network.
#[derive(Clone)]
pub struct BgpConnectionChannel {
    addr: SocketAddr,
    peer: SocketAddr,
    conn_tx: Arc<Mutex<Option<Sender<Message>>>>,
    log: Logger,
}

impl BgpConnection for BgpConnectionChannel {
    fn new(addr: Option<SocketAddr>, peer: SocketAddr, log: Logger) -> Self {
        Self {
            addr: addr
                .expect("source address required for channel-based connection"),
            peer,
            conn_tx: Arc::new(Mutex::new(None)),
            log,
        }
    }

    fn connect(
        &self,
        event_tx: Sender<FsmEvent<Self>>,
        timeout: Duration,
        _ttl_sec: bool,
    ) -> Result<(), Error> {
        debug!(self.log, "[{}] connecting", self.peer);
        let (local, remote) = channel();
        match NET.connect(self.addr, self.peer, remote) {
            Ok(()) => {
                lock!(self.conn_tx).replace(local.tx);
                Self::recv(
                    self.peer,
                    local.rx,
                    event_tx.clone(),
                    timeout,
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
                error!(self.log, "connect: {e:?}");
                Err(e)
            }
        }
    }

    fn send(&self, msg: Message) -> Result<(), Error> {
        let guard = lock!(self.conn_tx);
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

    fn local(&self) -> Option<SocketAddr> {
        Some(self.addr)
    }

    fn set_min_ttl(&self, _ttl: u8) -> Result<(), Error> {
        Ok(())
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
        slog::info!(log, "spawning recv loop");
        spawn(move || loop {
            match rx.recv() {
                Ok(msg) => {
                    debug!(log, "[{peer}] recv: {msg:#?}");
                    if let Err(e) = event_tx.send(FsmEvent::Message(msg)) {
                        error!(
                            log,
                            "[{peer}] failed to send fsm message to sm: {e}"
                        );
                    }
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

/// A combined (duplex) mpsc sender/receiver.
pub struct Endpoint<T> {
    pub rx: Receiver<T>,
    pub tx: Sender<T>,
}

impl<T> Endpoint<T> {
    fn new(rx: Receiver<T>, tx: Sender<T>) -> Self {
        Self { rx, tx }
    }
}

/// Analagous to std::sync::mpsc::channel for bidirectional endpoints.
#[allow(dead_code)]
pub fn channel<T>() -> (Endpoint<T>, Endpoint<T>) {
    let (tx_a, rx_b) = mpsc::channel();
    let (tx_b, rx_a) = mpsc::channel();
    (Endpoint::new(rx_a, tx_a), Endpoint::new(rx_b, tx_b))
}
