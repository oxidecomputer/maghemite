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
mod reconcile;

#[cfg(all(feature = "backend", target_os = "illumos"))]
mod runtime;

#[cfg(all(feature = "backend", target_os = "illumos"))]
pub(crate) use reconcile::reconcile_multicast_withdrawals;

#[cfg(all(feature = "backend", target_os = "illumos"))]
pub(crate) use runtime::{
    ExchangeHandle, UpdateMode, announce_multicast, announce_tunnel,
    announce_underlay, do_pull_v4, handler, pull, withdraw_multicast,
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

    #[error("peer returned status {0}")]
    Status(hyper::StatusCode),

    #[error("json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}
