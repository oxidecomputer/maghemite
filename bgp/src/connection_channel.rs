// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// This file contains code for testing purposes only. Note that it's only
/// included in `lib.rs` with a `#[cfg(test)]` guard. The purpose of the
/// code in this file is to implement BgpListener and BgpConnection such that
/// the core functionality of the BGP upper-half in `session.rs` may be tested
/// rapidly using a simulated network.
use crate::clock::ConnectionClock;
use crate::connection::{
    BgpConnection, BgpConnector, BgpListener, ConnectionCreator, ConnectionId,
};
use crate::error::Error;
use crate::log::{connection_log, connection_log_lite};
use crate::messages::Message;
use crate::session::{ConnectionEvent, FsmEvent, SessionEndpoint, SessionInfo};
use crossbeam_channel::{unbounded, RecvTimeoutError};
use mg_common::lock;
use slog::Logger;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use std::time::Duration;

const UNIT_CONNECTION: &str = "connection_channel";

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
        let (tx, rx) = unbounded();
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
            Mutex<BTreeMap<IpAddr, SessionEndpoint<BgpConnectionChannel>>>,
        >,
        timeout: Duration,
    ) -> Result<BgpConnectionChannel, Error> {
        let (peer, endpoint) = self.listener.accept(timeout)?;
        match lock!(addr_to_session).get(&peer.ip()) {
            Some(session_endpoint) => {
                let config = lock!(session_endpoint.config);
                Ok(BgpConnectionChannel::with_conn(
                    self.addr,
                    peer,
                    endpoint,
                    session_endpoint.event_tx.clone(),
                    timeout,
                    log,
                    ConnectionCreator::Dispatcher,
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
    log: Logger,
    // creator of this connection, i.e. BgpListener or BgpConnector
    creator: ConnectionCreator,
    conn_id: ConnectionId,
    // Connection-level timers for keepalive, hold, and delay open
    connection_clock: ConnectionClock,
    // Parameters for spawning the recv loop (stored until start_recv_loop is called)
    // Note: No Arc needed! recv loop is started before cloning in register_conn()
    recv_loop_params: Mutex<Option<RecvLoopParamsChannel>>,
    // Track whether recv loop has been started
    recv_loop_started: std::sync::atomic::AtomicBool,
}

impl Clone for BgpConnectionChannel {
    fn clone(&self) -> Self {
        // Clones always have empty recv loop params since the original connection
        // should have started the recv loop before being cloned (in register_conn).
        Self {
            addr: self.addr,
            peer: self.peer,
            conn_tx: self.conn_tx.clone(),
            log: self.log.clone(),
            creator: self.creator,
            conn_id: self.conn_id,
            connection_clock: self.connection_clock.clone(),
            recv_loop_params: Mutex::new(None),
            recv_loop_started: std::sync::atomic::AtomicBool::new(true),
        }
    }
}

/// Parameters needed to spawn the receive loop for a channel-based BGP connection
struct RecvLoopParamsChannel {
    rx: Receiver<Message>,
    event_tx: Sender<FsmEvent<BgpConnectionChannel>>,
    timeout: Duration,
}

impl BgpConnection for BgpConnectionChannel {
    type Connector = BgpConnectorChannel;

    fn send(&self, msg: Message) -> Result<(), Error> {
        let guard = lock!(self.conn_tx);
        connection_log!(self,
            trace,
            "send {} message via channel to {}", msg.title(), self.peer();
            "message" => msg.title(),
            "message_contents" => format!("{msg}")
        );
        if let Err(e) = guard
            .send(msg)
            .map_err(|e| Error::ChannelSend(e.to_string()))
        {
            connection_log!(self,
                error,
                "error sending message via channel to {}: {e}", self.peer();
                "error" => format!("{e}"),
                "network_state" => format!("{}", *NET)
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

    fn creator(&self) -> ConnectionCreator {
        self.creator
    }

    fn id(&self) -> &ConnectionId {
        &self.conn_id
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
                "spawning recv loop for {} (conn_id: {})",
                self.peer(), self.conn_id.short();
            );

            let peer = self.peer;
            let event_tx = params.event_tx;
            let rx = params.rx;
            let timeout = params.timeout;
            let log = self.log.clone();
            let creator = self.creator;
            let conn_id = self.conn_id;

            Self::spawn_recv_loop(
                peer, rx, event_tx, timeout, log, creator, conn_id,
            );
        }
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
        creator: ConnectionCreator,
        config: &SessionInfo,
    ) -> Self {
        let conn_id = ConnectionId::new(addr, peer);
        let connection_clock = ConnectionClock::new(
            config.resolution,
            config.keepalive_time,
            config.hold_time,
            config.delay_open_time,
            conn_id,
            event_tx.clone(),
            log.clone(),
        );

        // Store the parameters for spawning the recv loop later
        let recv_loop_params = Mutex::new(Some(RecvLoopParamsChannel {
            rx: conn.rx,
            event_tx,
            timeout,
        }));

        Self {
            addr,
            peer,
            conn_tx: Arc::new(Mutex::new(conn.tx)),
            log,
            creator,
            conn_id,
            connection_clock,
            recv_loop_params,
            recv_loop_started: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Spawn the receive loop thread for this connection.
    fn spawn_recv_loop(
        peer: SocketAddr,
        rx: Receiver<Message>,
        event_tx: Sender<FsmEvent<Self>>,
        timeout: Duration,
        log: Logger,
        creator: ConnectionCreator,
        conn_id: ConnectionId,
    ) {
        spawn(move || loop {
            match rx.recv_timeout(timeout) {
                Ok(msg) => {
                    connection_log_lite!(log,
                        debug,
                        "recv {} msg from {peer} (conn_id: {})",
                        msg.title(), conn_id.short();
                        "creator" => creator.as_str(),
                        "peer" => format!("{peer}"),
                        "message" => msg.title(),
                        "message_contents" => format!("{msg}")
                    );
                    if let Err(e) = event_tx.send(FsmEvent::Connection(
                        ConnectionEvent::Message { msg, conn_id },
                    )) {
                        connection_log_lite!(log,
                            error,
                            "error sending event to {peer}: {e}";
                            "creator" => creator.as_str(),
                            "peer" => format!("{peer}"),
                            "error" => format!("{e}")
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

pub struct BgpConnectorChannel;

impl BgpConnector<BgpConnectionChannel> for BgpConnectorChannel {
    #[allow(clippy::too_many_arguments)]
    fn connect(
        peer: SocketAddr,
        timeout: Duration,
        _min_ttl: Option<u8>, // Ignored for test connections
        _md5_key: Option<String>, // Ignored for test connections
        log: Logger,
        event_tx: Sender<FsmEvent<BgpConnectionChannel>>,
        config: &SessionInfo,
    ) -> Result<BgpConnectionChannel, Error> {
        let creator = ConnectionCreator::Connector;
        let addr = config
            .bind_addr
            .expect("source address required for channel-based connection");

        connection_log_lite!(log,
            debug,
            "connecting to {peer}";
            "creator" => creator.as_str(),
            "timeout" => timeout.as_millis()
        );

        let (local, remote) = channel();
        match NET.connect(addr, peer, remote) {
            Ok(()) => Ok(BgpConnectionChannel::with_conn(
                addr, peer, local, event_tx, timeout, log, creator, config,
            )),
            Err(e) => {
                connection_log_lite!(log,
                    error,
                    "connect error: {e:?}";
                    "creator" => creator.as_str(),
                    "timeout" => timeout.as_millis(),
                    "error" => format!("{e}")
                );
                Err(e)
            }
        }
    }
}

// BIDI

use crossbeam_channel::{Receiver, Sender};

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

/// Analagous to crossbeam_channel::unbounded for bidirectional endpoints.
#[allow(dead_code)]
pub fn channel<T>() -> (Endpoint<T>, Endpoint<T>) {
    let (tx_a, rx_b) = unbounded();
    let (tx_b, rx_a) = unbounded();
    (Endpoint::new(rx_a, tx_a), Endpoint::new(rx_b, tx_b))
}
