// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::clock::ConnectionClock;
use crate::error::Error;
use crate::messages::Message;
use crate::session::{FsmEvent, SessionEndpoint, SessionInfo};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::cmp::{Ord, Ordering, PartialOrd};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;
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
pub enum ConnectionCreator {
    /// Connection was created by the dispatcher (listener)
    Dispatcher,
    /// Connection was created by the connector
    Connector,
}

impl ConnectionCreator {
    /// Get the string representation of the creator
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionCreator::Dispatcher => "dispatcher",
            ConnectionCreator::Connector => "connector",
        }
    }
}

impl std::fmt::Display for ConnectionCreator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Unique identifier for a BGP connection instance
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
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

impl PartialOrd for ConnectionId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ConnectionId {
    fn cmp(&self, other: &Self) -> Ordering {
        // Order by UUID first (most unique), then by local/remote addresses
        self.uuid
            .cmp(&other.uuid)
            .then_with(|| self.local.cmp(&other.local))
            .then_with(|| self.remote.cmp(&other.remote))
    }
}

/// Implementors of this trait listen to and accept inbound BGP connections.
pub trait BgpListener<Cnx: BgpConnection> {
    /// Bind to an address and listen for connections.
    fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, Error>
    where
        Self: Sized;

    /// Accept a connection. This Listener is non-blocking, so the timeout
    /// is used as a sleep between accept attempts. This function may be called
    /// multiple times, returning a new connection each time. Policy application
    /// is handled by the Dispatcher after the addr_to_session lookup.
    fn accept(
        &self,
        log: Logger,
        addr_to_session: Arc<Mutex<BTreeMap<IpAddr, SessionEndpoint<Cnx>>>>,
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
/// BgpConnector spawns a background thread to establish the connection and
/// applies all policy (TTL, MD5) before sending a SessionEvent::TcpConnectionConfirmed
/// on the event channel. Connection failures are silent - the ConnectRetryTimer
/// will handle retries.
pub trait BgpConnector<Cnx: BgpConnection> {
    /// Initiate an outbound connection attempt to a peer in a background thread.
    /// On success, sends SessionEvent::TcpConnectionConfirmed via event_tx.
    /// On failure, logs the error but does not send an event (FSM retry logic handles it).
    /// Returns Err only if the thread spawn itself fails.
    #[allow(clippy::too_many_arguments)]
    fn connect(
        peer: SocketAddr,
        timeout: Duration,
        log: Logger,
        event_tx: Sender<FsmEvent<Cnx>>,
        config: SessionInfo,
    ) -> Result<(), Error>
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
pub trait BgpConnection: Send + Clone {
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

    /// Return the ConnectionCreator indicating what component created this connection.
    fn creator(&self) -> ConnectionCreator;

    /// Return the unique identifier for this connection.
    fn id(&self) -> &ConnectionId;

    /// Return the connection-level clock for this connection.
    fn clock(&self) -> &ConnectionClock;

    /// Start the receive loop for this connection. This spawns a background
    /// thread that will receive messages and send them to the SessionRunner.
    /// This method is idempotent - calling it multiple times has no effect
    /// after the first call.
    fn start_recv_loop(&self);
}
