// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;

mod single_hop_egress_src_port;
mod sm;
mod dispatcher;

pub use dispatcher::ListenerShutdownHandle;

/// Errors from attempting to add a new BFD peer.
#[derive(Debug, thiserror::Error)]
pub enum AddPeerError {
    #[error("BFD peer {0} already exists")]
    PeerExists(IpAddr),

    #[error("failed to bind to {addr}")]
    Bind {
        addr: SocketAddr,
        #[source]
        err: io::Error,
    },

    #[error("failed to set socket to nonblocking")]
    SetSocketNonBlocking(#[source] io::Error),

    #[error("failed to convert std socket to tokio socket")]
    StdToTokio(#[source] io::Error),
}
