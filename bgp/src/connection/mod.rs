// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
pub mod channel;
pub mod tcp;
#[cfg(test)]
mod test;

use crate::{
    clock::ConnectionClock,
    messages::Message,
    router::SessionMap,
    session::{FsmEvent, PeerId, SessionInfo},
    unnumbered::UnnumberedManager,
};
use slog::Logger;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex, mpsc::Sender},
    thread::JoinHandle,
    time::Duration,
};

pub(crate) use mg_api_types::bgp::session::{
    ConnectionDirection, ConnectionId,
};

#[cfg(target_os = "linux")]
pub const MAX_MD5SIG_KEYLEN: usize = libc::TCP_MD5SIG_MAXKEYLEN;

#[cfg(target_os = "illumos")]
pub const MAX_MD5SIG_KEYLEN: usize = 80;

#[cfg(target_os = "macos")]
pub const MAX_MD5SIG_KEYLEN: usize = 80;

/// Failure to resolve, bind, or configure a listener.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum ListenerBindError {
    #[error("failed to resolve listen address")]
    AddressResolution(#[source] std::io::Error),
    #[error("listen address resolved to no addresses")]
    NoAddress,
    #[error("failed to initialize listener")]
    ListenerSetup(#[from] std::io::Error),
}

/// Failure to accept a connection from a BgpListener.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum ListenerAcceptError {
    #[error("timed out waiting for an inbound connection")]
    Timeout,
    #[error("connection attempt from unknown peer: {0}")]
    UnknownPeer(PeerId),
    #[error("failed to configure accepted connection")]
    NewConnectionSetup(#[source] std::io::Error),
    #[error("failed to accept connection")]
    Listener(#[source] std::io::Error),
}

/// Failure to configure TCP MD5 authentication.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum Md5Error {
    #[error("failed to query route to peer")]
    RouteQuery(#[source] anyhow::Error),
    #[error("failed to query local IP addresses")]
    LocalAddressQuery(#[source] anyhow::Error),
    #[error("no local source address available for MD5 authentication")]
    NoMatchingSourceAddress,
    #[error("failed to set up MD5 authentication")]
    AuthenticationSetup(#[from] std::io::Error),
}

/// Failure to apply connection policy.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum ConnectionPolicyError {
    #[error("failed to configure minimum TTL")]
    MinTtl(#[source] std::io::Error),
    #[error(transparent)]
    Md5(#[from] Md5Error),
}

/// Failure to start an outbound connection attempt.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum ConnectError {
    #[error("failed to initialize outbound connection")]
    ConnectionSetup(#[source] std::io::Error),
    #[error(transparent)]
    Md5(#[from] Md5Error),
    #[error("failed to spawn connector thread")]
    ThreadSpawn(#[source] std::io::Error),
}

/// Failure to encode or transmit a message on an established connection.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum SendError {
    #[error("failed to encode BGP message")]
    Encode(#[source] Box<crate::error::Error>),
    #[error("BGP message length {0} exceeds the wire limit")]
    TooLarge(usize),
    #[error("failed to write BGP message")]
    Write(#[from] std::io::Error),
}

/// Failure to start a BgpConnection's recv loop.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum StartRecvLoopError {
    #[error("failed to acquire connection reader")]
    AcquireReader(#[source] std::io::Error),
    #[error("failed to spawn receive thread")]
    ThreadSpawn(#[source] std::io::Error),
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
        log: Logger,
        unnumbered_manager: Option<Arc<dyn UnnumberedManager>>,
    ) -> Result<Self, ListenerBindError>
    where
        Self: Sized;

    /// Accept a connection. This Listener is non-blocking, so the timeout
    /// is used as a sleep between accept attempts. This function may be called
    /// multiple times, returning a new connection each time. Policy application
    /// is handled by the Dispatcher after the session lookup.
    fn accept(
        &self,
        log: Logger,
        sessions: Arc<Mutex<SessionMap<Cnx>>>,
        timeout: Duration,
    ) -> Result<Cnx, ListenerAcceptError>;

    /// Apply policy to an established connection. This is called by the
    /// Dispatcher after accept() returns and session lookup is completed.
    fn apply_policy(
        conn: &Cnx,
        min_ttl: Option<u8>,
        md5_key: Option<String>,
    ) -> Result<(), ConnectionPolicyError>;

    /// `SocketAddr` the listener is receiving connections on
    fn bind_addr(&self) -> SocketAddr;
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
    ) -> Result<JoinHandle<()>, ConnectError>
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
    fn send(&self, msg: Message) -> Result<(), SendError>;

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
    fn start_recv_loop(self: &Arc<Self>) -> Result<(), StartRecvLoopError>;
}

pub use mg_common::thread::{ManagedThread, ThreadState};
