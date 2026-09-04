// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This module implements the ddm router prefix exchange mechanisms. These
//! mechanisms are responsible for announcing and withdrawing prefix sets to
//! and from peers.
//!
//! The module has a set of request initiators and request handlers for
//! announcing, withdrawing, and synchronizing routes with a given peer.
//! Communication between peers is over HTTP(s) requests.
//!
//! This module only contains basic mechanisms for prefix information exchange
//! with peers. How those mechanisms are used in the overall state machine
//! model of a ddm router is defined in the state machine implementation in
//! [`crate::sm`].
//!
//! The wire types (`Update`, `UnderlayUpdate`, `TunnelUpdate`,
//! `MulticastUpdate`, and their versioned counterparts) live in the
//! [`ddm_protocol`] crate. The runtime helpers that drive the HTTP exchange
//! protocol and program forwarding state live in the `runtime` submodule and
//! are illumos-only, since they call into `crate::sys` to install routes.

use thiserror::Error;

#[cfg(any(test, all(feature = "backend", target_os = "illumos")))]
mod paging;

#[cfg(any(test, all(feature = "backend", target_os = "illumos")))]
mod reconcile;

#[cfg(all(feature = "backend", target_os = "illumos"))]
mod runtime;

#[cfg(all(feature = "backend", target_os = "illumos"))]
pub(crate) use reconcile::reconcile_multicast_withdrawals;

#[cfg(all(feature = "backend", target_os = "illumos"))]
pub(crate) use runtime::{
    ExchangeHandle, UpdateMode, announce_multicast, announce_tunnel,
    announce_underlay, do_pull_v2, do_pull_v3, do_pull_v4, handler, pull,
    withdraw_multicast, withdraw_tunnel, withdraw_underlay,
};

#[derive(Error, Debug)]
pub enum ExchangeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("hyper client error: {0}")]
    HyperClient(#[from] hyper_util::client::legacy::Error),

    #[error("timeout error: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("peer returned status {0}")]
    Status(hyper::StatusCode),

    #[error("json error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    /// A single multicast path vector exceeds the exchange body limit, so no
    /// approach to batching can make it sendable.
    #[error("multicast vector for {group} is {size} bytes, limit is {limit}")]
    MulticastVectorTooLarge {
        group: std::net::IpAddr,
        size: usize,
        limit: usize,
    },

    /// A peer's pull response exceeded the bound on the client's read.
    #[error("pull response exceeds the {limit} byte limit")]
    ResponseTooLarge { limit: usize },

    /// A peer handed back a continuation token on every page, meaning that a
    /// single pull never reached the end of its snapshot.
    #[error("pull did not terminate within {limit} pages")]
    PullTooManyPages { limit: usize },

    /// A continuation token could not be encoded for the next page.
    #[error("could not construct a pull page token: {0}")]
    PageToken(String),

    /// An exchange request URI could not be constructed.
    #[error("invalid exchange request URI: {0}")]
    InvalidUri(String),
}

impl ExchangeError {
    /// Whether a failed exchange operation should expire the peer session.
    ///
    /// Expiry is a liveness response, so it applies when a failure suggests
    /// the peer is unreachable or unhealthy. Two cases are deterministic
    /// instead, where retrying the same payload against a fresh session
    /// changes nothing.
    ///
    /// A `400 Bad Request` from the push endpoint means Dropshot rejected the
    /// request body before the handler ran, since the handlers themselves
    /// surface every failure as a `500`. Other 4xx responses, such as `404 Not
    /// Found` or `405 Method Not Allowed`, can indicate an endpoint or
    /// protocol mismatch and still expire the peer.
    ///
    /// A size limit is reached locally, before anything reaches the wire.
    ///
    /// Dropping the update is safe for multicast because the peer's periodic
    /// V4 pull reads our full advertisable multicast set and reconciles
    /// against it, repairing both a missing announcement and a missed
    /// withdrawal. Callers should use this exception only for multicast
    /// updates. Underlay and tunnel updates have no equivalent full
    /// reconciliation path.
    pub fn expires_peer(&self) -> bool {
        match self {
            Self::Status(status) => *status != hyper::StatusCode::BAD_REQUEST,
            Self::MulticastVectorTooLarge { .. }
            | Self::ResponseTooLarge { .. } => false,
            Self::Io(_)
            | Self::Hyper(_)
            | Self::HyperClient(_)
            | Self::Timeout(_)
            | Self::PullTooManyPages { .. }
            | Self::PageToken(_)
            | Self::InvalidUri(_)
            | Self::SerdeJson(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ExchangeError;

    #[test]
    fn deterministic_size_errors_do_not_expire_peers() {
        assert!(
            !ExchangeError::MulticastVectorTooLarge {
                group: "ff04::1".parse().unwrap(),
                size: 16,
                limit: 8,
            }
            .expires_peer()
        );
        assert!(!ExchangeError::ResponseTooLarge { limit: 8 }.expires_peer());
    }

    #[test]
    fn transport_and_protocol_errors_expire_peers() {
        assert!(
            ExchangeError::Io(std::io::Error::other("connection lost"))
                .expires_peer()
        );
        assert!(ExchangeError::PullTooManyPages { limit: 64 }.expires_peer());
    }
}
