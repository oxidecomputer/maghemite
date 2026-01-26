// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    clock::ConnectionClock,
    error::Error,
    messages::Message,
    session::{FsmEvent, PeerId, SessionEndpoint, SessionInfo},
    unnumbered::UnnumberedManager,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::{
    collections::BTreeMap,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex, mpsc::Sender},
    thread::JoinHandle,
    time::Duration,
};
use uuid::Uuid;

#[cfg(target_os = "linux")]
pub const MAX_MD5SIG_KEYLEN: usize = libc::TCP_MD5SIG_MAXKEYLEN;

#[cfg(target_os = "illumos")]
pub const MAX_MD5SIG_KEYLEN: usize = 80;

#[cfg(target_os = "macos")]
pub const MAX_MD5SIG_KEYLEN: usize = 80;

/// Creator of a BGP connection
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum ConnectionDirection {
    /// Connection was created by the dispatcher (listener)
    Inbound,
    /// Connection was created by the connector
    Outbound,
}

impl ConnectionDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionDirection::Inbound => "inbound",
            ConnectionDirection::Outbound => "outbound",
        }
    }
}

impl std::fmt::Display for ConnectionDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl slog::Value for ConnectionDirection {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str(key, &self.to_string())
    }
}

/// Unique identifier for a BGP connection instance
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub struct ConnectionId {
    /// Unique identifier for this connection instance
    uuid: Uuid,
    /// Local socket address for this connection
    local: SocketAddr,
    /// Remote socket address for this connection
    remote: SocketAddr,
}

impl ConnectionId {
    /// Create a new ConnectionId
    pub fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            local,
            remote,
        }
    }

    /// Get a short, human-readable identifier for this connection
    pub fn short(&self) -> String {
        self.uuid.to_string()[0..8].to_string()
    }

    /// Get the local socket address
    pub fn local(&self) -> SocketAddr {
        self.local
    }

    /// Get the remote socket address
    pub fn remote(&self) -> SocketAddr {
        self.remote
    }
}

/// Implementors of this trait listen to and accept inbound BGP connections.
pub trait BgpListener<Cnx: BgpConnection> {
    /// Bind to an address and listen for connections.
    ///
    /// # Arguments
    /// * `addr` - The address to bind to
    /// * `unnumbered_manager` - Optional unnumbered manager for resolving scope_id -> interface
    fn bind<A: ToSocketAddrs>(
        addr: A,
        unnumbered_manager: Option<Arc<dyn UnnumberedManager>>,
    ) -> Result<Self, Error>
    where
        Self: Sized;

    /// Accept a connection. This Listener is non-blocking, so the timeout
    /// is used as a sleep between accept attempts. This function may be called
    /// multiple times, returning a new connection each time. Policy application
    /// is handled by the Dispatcher after the peer_to_session lookup.
    fn accept(
        &self,
        log: Logger,
        peer_to_session: Arc<Mutex<BTreeMap<PeerId, SessionEndpoint<Cnx>>>>,
        timeout: Duration,
    ) -> Result<Cnx, Error>;

    /// Apply policy to an established connection. This is called by the
    /// Dispatcher after accept() returns and session lookup is completed.
    fn apply_policy(
        conn: &Cnx,
        min_ttl: Option<u8>,
        md5_key: Option<String>,
    ) -> Result<(), Error>;
}

/// Implementors of this trait initiate outbound BGP connections to peers.
/// A BgpConnector applies all policy (TTL, MD5) before informing the FSM of a
/// successful connection attempt. Connection failures are silent.
pub trait BgpConnector<Cnx: BgpConnection> {
    /// Initiate an outbound connection attempt to a peer.
    /// On success, hands off the BgpConnection to the FSM via event_tx.
    /// On failure, logs the error but does not send an event.
    /// Returns a handle to the connection attempt, allowing the caller to track
    /// and manage it.
    fn connect(
        peer: SocketAddr,
        timeout: Duration,
        log: Logger,
        event_tx: Sender<FsmEvent<Cnx>>,
        config: SessionInfo,
    ) -> Result<JoinHandle<()>, Error>
    where
        Self: Sized;
}

/// Implementors of this trait represent a valid, established Connection to a
/// BGP peer. They are generalized across transport mechanisms (currently TCP
/// or Channels), but could later allow for additional transports to be
/// supported (e.g. QUIC). BGP Messages are sent through the `send` method.
/// Received BGP messages are propagated to consumers via the channel sender
/// `event_tx` as an FsmEvent::Message.
///
/// A BgpConnection always represents a valid, established connection.
/// Connection establishment (including policy application) is handled by the
/// BgpConnector and BgpListener traits for outbound and inbound connections
/// respectively.
///
/// The receive loop is not started automatically when the connection is
/// created. It must be explicitly started by calling `start_recv_loop()`.
/// This allows the SessionRunner to complete connection registration before
/// any messages can be received, preventing race conditions.
pub trait BgpConnection: Send + Sync + Sized {
    /// The type of connector used to establish outbound connections for this
    /// connection type.
    type Connector: BgpConnector<Self>;

    /// Send a message over this established connection.
    fn send(&self, msg: Message) -> Result<(), Error>;

    /// Return the socket address of the peer for this connection.
    fn peer(&self) -> SocketAddr;

    /// Return the local socket address for this connection.
    fn local(&self) -> SocketAddr;

    /// Return the local/remote sockaddr pair for this connection.
    fn conn(&self) -> (SocketAddr, SocketAddr);

    /// Return the direction (inbound or outbound) of this connection.
    fn direction(&self) -> ConnectionDirection;

    /// Return the unique identifier for this connection.
    fn id(&self) -> &ConnectionId;

    /// Return the connection-level clock for this connection.
    fn clock(&self) -> &ConnectionClock;

    /// Start the receive loop for this connection. This method is idempotent.
    /// Returns Ok(()) upon successful start of recv loop, else Err.
    fn start_recv_loop(self: &Arc<Self>) -> Result<(), Error>;
}

pub use mg_common::thread::{ManagedThread, ThreadState};
