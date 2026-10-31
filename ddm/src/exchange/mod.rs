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
//! Wire types live in [`ddm_protocol`]. The `runtime` submodule handles HTTP
//! exchange and route programming (requiring illumos for `crate::sys`).

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

    #[error("unexpected http status: {0}")]
    Status(hyper::StatusCode),

    #[error("json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

impl ExchangeError {
    pub(crate) fn is_transient(&self) -> bool {
        match self {
            Self::Io(_)
            | Self::Hyper(_)
            | Self::HyperClient(_)
            | Self::Timeout(_) => true,
            Self::Status(status) => {
                status.is_server_error()
                    || *status == hyper::StatusCode::REQUEST_TIMEOUT
                    || *status == hyper::StatusCode::TOO_MANY_REQUESTS
            }
            Self::SerdeJson(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use hyper::StatusCode;

    use super::ExchangeError;

    #[test]
    fn transient_statuses_are_retried() {
        for status in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert!(ExchangeError::Status(status).is_transient(), "{status}");
        }
    }

    #[test]
    fn persistent_statuses_are_not_retried() {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::METHOD_NOT_ALLOWED,
            StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::MOVED_PERMANENTLY,
        ] {
            assert!(!ExchangeError::Status(status).is_transient(), "{status}");
        }
    }

    #[test]
    fn decode_errors_are_not_transient() {
        let e = serde_json::from_str::<u32>("not json").unwrap_err();
        assert!(!ExchangeError::SerdeJson(e).is_transient());
    }

    #[test]
    fn io_errors_are_retried() {
        let e = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(ExchangeError::Io(e).is_transient());
    }
}
