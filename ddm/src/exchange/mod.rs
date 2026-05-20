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

use ddm_api_types::exchange::{PathVector, PathVectorV2};
use ddm_api_types::net::TunnelOrigin;
use mg_common::net::TunnelOriginV2;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

#[cfg(all(feature = "backend", target_os = "illumos"))]
mod runtime;

#[cfg(all(feature = "backend", target_os = "illumos"))]
pub(crate) use runtime::{
    announce_tunnel, announce_underlay, do_pull, handler, pull,
    withdraw_tunnel, withdraw_underlay,
};

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 1. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV1 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UpdateV1 {
    pub announce: HashSet<PathVector>,
    pub withdraw: HashSet<PathVector>,
}

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 2. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV2 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UpdateV2 {
    pub underlay: Option<UnderlayUpdateV2>,
    pub tunnel: Option<TunnelUpdateV2>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct Update {
    pub underlay: Option<UnderlayUpdate>,
    pub tunnel: Option<TunnelUpdate>,
}

impl From<UpdateV1> for Update {
    fn from(value: UpdateV1) -> Self {
        Update {
            tunnel: None,
            underlay: Some(UnderlayUpdate {
                announce: value.announce,
                withdraw: value.withdraw,
            }),
        }
    }
}

impl From<UpdateV2> for Update {
    fn from(value: UpdateV2) -> Self {
        Update {
            tunnel: value.tunnel.map(TunnelUpdate::from),
            underlay: value.underlay.map(UnderlayUpdate::from),
        }
    }
}

impl From<Update> for UpdateV1 {
    fn from(value: Update) -> Self {
        let (announce, withdraw) = match value.underlay {
            Some(underlay) => (underlay.announce, underlay.withdraw),
            None => (HashSet::new(), HashSet::new()),
        };
        UpdateV1 { announce, withdraw }
    }
}

impl From<Update> for UpdateV2 {
    fn from(value: Update) -> Self {
        UpdateV2 {
            tunnel: value.tunnel.map(TunnelUpdateV2::from),
            underlay: value.underlay.map(UnderlayUpdateV2::from),
        }
    }
}

impl From<UnderlayUpdate> for Update {
    fn from(u: UnderlayUpdate) -> Self {
        Update {
            underlay: Some(u),
            tunnel: None,
        }
    }
}

impl From<TunnelUpdate> for Update {
    fn from(t: TunnelUpdate) -> Self {
        Update {
            underlay: None,
            tunnel: Some(t),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct PullResponse {
    pub underlay: Option<HashSet<PathVector>>,
    pub tunnel: Option<HashSet<TunnelOrigin>>,
}

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 2. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV2 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct PullResponseV2 {
    pub underlay: Option<HashSet<PathVectorV2>>,
    pub tunnel: Option<HashSet<TunnelOriginV2>>,
}

impl From<PullResponseV2> for PullResponse {
    fn from(value: PullResponseV2) -> Self {
        PullResponse {
            underlay: value
                .underlay
                .map(|x| x.into_iter().map(PathVector::from).collect()),
            tunnel: value
                .tunnel
                .map(|x| x.into_iter().map(TunnelOrigin::from).collect()),
        }
    }
}

impl From<HashSet<PathVector>> for PullResponse {
    fn from(value: HashSet<PathVector>) -> Self {
        PullResponse {
            underlay: Some(value),
            tunnel: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UnderlayUpdate {
    pub announce: HashSet<PathVector>,
    pub withdraw: HashSet<PathVector>,
}

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 2. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV2 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UnderlayUpdateV2 {
    pub announce: HashSet<PathVectorV2>,
    pub withdraw: HashSet<PathVectorV2>,
}

impl From<UnderlayUpdate> for UnderlayUpdateV2 {
    fn from(value: UnderlayUpdate) -> Self {
        UnderlayUpdateV2 {
            announce: value
                .announce
                .into_iter()
                .map(PathVectorV2::from)
                .collect(),
            withdraw: value
                .withdraw
                .into_iter()
                .map(PathVectorV2::from)
                .collect(),
        }
    }
}

impl From<UnderlayUpdateV2> for UnderlayUpdate {
    fn from(value: UnderlayUpdateV2) -> Self {
        UnderlayUpdate {
            announce: value
                .announce
                .into_iter()
                .map(PathVector::from)
                .collect(),
            withdraw: value
                .withdraw
                .into_iter()
                .map(PathVector::from)
                .collect(),
        }
    }
}

impl UnderlayUpdate {
    pub fn announce(prefixes: HashSet<PathVector>) -> Self {
        Self {
            announce: prefixes,
            ..Default::default()
        }
    }
    pub fn withdraw(prefixes: HashSet<PathVector>) -> Self {
        Self {
            withdraw: prefixes,
            ..Default::default()
        }
    }
    pub fn with_path_element(&self, element: String) -> Self {
        Self {
            announce: self
                .announce
                .iter()
                .map(|x| {
                    let mut pv = x.clone();
                    pv.path.push(element.clone());
                    pv
                })
                .collect(),
            withdraw: self
                .withdraw
                .iter()
                .map(|x| {
                    let mut pv = x.clone();
                    pv.path.push(element.clone());
                    pv
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct TunnelUpdate {
    pub announce: HashSet<TunnelOrigin>,
    pub withdraw: HashSet<TunnelOrigin>,
}

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 2. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV2 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct TunnelUpdateV2 {
    pub announce: HashSet<TunnelOriginV2>,
    pub withdraw: HashSet<TunnelOriginV2>,
}

impl From<TunnelUpdateV2> for TunnelUpdate {
    fn from(value: TunnelUpdateV2) -> Self {
        TunnelUpdate {
            announce: value
                .announce
                .into_iter()
                .map(TunnelOrigin::from)
                .collect(),
            withdraw: value
                .withdraw
                .into_iter()
                .map(TunnelOrigin::from)
                .collect(),
        }
    }
}

impl From<TunnelUpdate> for TunnelUpdateV2 {
    fn from(value: TunnelUpdate) -> Self {
        TunnelUpdateV2 {
            announce: value
                .announce
                .into_iter()
                .map(TunnelOriginV2::from)
                .collect(),
            withdraw: value
                .withdraw
                .into_iter()
                .map(TunnelOriginV2::from)
                .collect(),
        }
    }
}

impl TunnelUpdate {
    pub fn announce(prefixes: HashSet<TunnelOrigin>) -> Self {
        Self {
            announce: prefixes,
            ..Default::default()
        }
    }
    pub fn withdraw(prefixes: HashSet<TunnelOrigin>) -> Self {
        Self {
            withdraw: prefixes,
            ..Default::default()
        }
    }
}

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
}
