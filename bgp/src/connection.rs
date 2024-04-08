// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::error::Error;
use crate::messages::Message;
use crate::session::FsmEvent;
use rdb::Md5Key;
use slog::Logger;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(not(target_os = "illumos"))]
pub const MAX_MD5SIG_KEYLEN: usize = libc::TCP_MD5SIG_MAXKEYLEN;

#[cfg(target_os = "illumos")]
pub const MAX_MD5SIG_KEYLEN: usize = 80;

/// Implementors of this trait listen to and accept BGP connections.
pub trait BgpListener<Cnx: BgpConnection> {
    /// Bind to an address and listen for connections.
    fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, Error>
    where
        Self: Sized;

    /// Accept a connection. If no connections are currently available this
    /// function will block. This function may be called multiple times,
    /// returning a new connection each time.
    fn accept(
        &self,
        log: Logger,
        addr_to_session: Arc<Mutex<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>>,
        timeout: Duration,
    ) -> Result<Cnx, Error>;
}

/// Implementors of this trait connect to BGP peers and sending/receiving
/// messages. Messages are sent through the `send` method. Received messages
/// are propagated to consumers via the channel sender `event_tx` as FsmEvent
/// messages.
pub trait BgpConnection: Send + Clone {
    /// Create a new BGP connection to the specified peer. If a source address
    /// is provided, that address will be used. Otherwise, the underlying
    /// platform is free to choose a source address.
    fn new(source: Option<SocketAddr>, peer: SocketAddr, log: Logger) -> Self
    where
        Self: Sized;

    /// Try to connect to a peer. On success messages from the peer a
    /// propagated through `event_tx`.
    fn connect(
        &self,
        event_tx: Sender<FsmEvent<Self>>,
        timeout: Duration,
        ttl_sec: bool,
        md5_key: Option<Md5Key>,
    ) -> Result<(), Error>
    where
        Self: Sized;

    /// Send a message over this connection. If the connection is not
    /// established a `Error::NotConnected` will be returned.
    fn send(&self, msg: Message) -> Result<(), Error>;

    /// Return the socket address of the peer for this connection.
    fn peer(&self) -> SocketAddr;

    // Return the local address being used for the connection.
    fn local(&self) -> Option<SocketAddr>;

    fn set_min_ttl(&self, ttl: u8) -> Result<(), Error>;

    fn set_md5_sig(
        &self,
        keylen: u16,
        key: [u8; MAX_MD5SIG_KEYLEN],
    ) -> Result<(), Error>;
}
