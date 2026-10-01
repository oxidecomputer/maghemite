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
//! The wire types ([`Update`], [`UnderlayUpdate`], [`TunnelUpdate`], and
//! their versioned counterparts) are platform-agnostic and stay in this
//! module. The runtime helpers that drive the HTTP exchange protocol and
//! program forwarding state live in the [`runtime`] submodule and are
//! illumos-only, since they call into [`crate::sys`] to install routes.

use crate::discovery::Version;
use hyper::StatusCode;
use thiserror::Error;

#[cfg(all(feature = "backend", target_os = "illumos"))]
mod runtime;

#[cfg(all(feature = "backend", target_os = "illumos"))]
pub(crate) use runtime::{
    announce_tunnel, announce_underlay, do_pull, handler, pull,
    withdraw_tunnel, withdraw_underlay,
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

    #[error("json error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("http status: {0}")]
    Status(StatusCode),
}

/// The version to retry a failed pull or push at. A 404 means the peer does
/// not serve this version, so fall back to v2. Any other error is transient and is
/// retried at the same version, so that a blip does not pin the peer to v2
/// until restart.
pub fn retry_version(version: Version, err: &ExchangeError) -> Version {
    match err {
        ExchangeError::Status(StatusCode::NOT_FOUND) => Version::V2,
        _ => version,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn retry_version_falls_back_to_v2_only_on_404() {
        let not_found = ExchangeError::Status(StatusCode::NOT_FOUND);
        assert_eq!(retry_version(Version::V4, &not_found), Version::V2);
        assert_eq!(retry_version(Version::V2, &not_found), Version::V2);

        let server_error =
            ExchangeError::Status(StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(retry_version(Version::V4, &server_error), Version::V4);

        let json = serde_json::from_str::<u8>("x").unwrap_err().into();
        assert_eq!(retry_version(Version::V4, &json), Version::V4);
    }
}
