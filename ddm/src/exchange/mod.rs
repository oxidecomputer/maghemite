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

use ddm_api_types::exchange::PathVector;
use ddm_api_types::net::TunnelOrigin;
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

mod ddm_v2;

pub use ddm_v2::*;

#[cfg(all(feature = "backend", target_os = "illumos"))]
mod runtime;

#[cfg(all(feature = "backend", target_os = "illumos"))]
pub(crate) use runtime::{
    announce_tunnel, announce_underlay, do_pull, handler, pull,
    withdraw_tunnel, withdraw_underlay,
};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct Update {
    pub underlay: Option<UnderlayUpdate>,
    pub tunnel: Option<TunnelUpdate>,
}

impl From<UpdateV2> for Update {
    fn from(value: UpdateV2) -> Self {
        Update {
            tunnel: value.tunnel.map(TunnelUpdate::from),
            underlay: value.underlay.map(UnderlayUpdate::from),
        }
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

impl From<PathVectorV2> for PathVector {
    fn from(value: PathVectorV2) -> Self {
        PathVector {
            destination: Ipv6Net::new_unchecked(
                value.destination.addr,
                value.destination.len,
            ),
            path: value.path,
        }
    }
}

impl From<PathVector> for PathVectorV2 {
    fn from(value: PathVector) -> Self {
        PathVectorV2 {
            destination: Ipv6Prefix {
                addr: value.destination.addr(),
                len: value.destination.width(),
            },
            path: value.path,
        }
    }
}

impl From<TunnelOriginV2> for TunnelOrigin {
    fn from(value: TunnelOriginV2) -> Self {
        // TunnelOriginV2 is the DDMv2 wire shape, frozen by protocol
        // contract. If this destructure stops compiling, the V2
        // contract has been violated upstream — there is no
        // #[serde(skip)] escape valve for a wire-format type.
        let TunnelOriginV2 {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        } = value;
        TunnelOrigin {
            overlay_prefix: overlay_prefix.into(),
            boundary_addr,
            vni,
            metric,
        }
    }
}

impl From<TunnelOrigin> for TunnelOriginV2 {
    fn from(value: TunnelOrigin) -> Self {
        // Compile barrier: adding a TunnelOrigin (latest API) field
        // fails to bind here, forcing a decision about whether the new
        // field is representable in the V2 wire form.
        let TunnelOrigin {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        } = value;
        TunnelOriginV2 {
            overlay_prefix: overlay_prefix.into(),
            boundary_addr,
            vni,
            metric,
        }
    }
}

impl From<Ipv4Net> for Ipv4Prefix {
    fn from(value: Ipv4Net) -> Self {
        Ipv4Prefix {
            addr: value.addr(),
            len: value.width(),
        }
    }
}

impl From<Ipv4Prefix> for Ipv4Net {
    fn from(value: Ipv4Prefix) -> Self {
        Ipv4Net::new_unchecked(value.addr, value.len)
    }
}

impl From<Ipv6Net> for Ipv6Prefix {
    fn from(value: Ipv6Net) -> Self {
        Ipv6Prefix {
            addr: value.addr(),
            len: value.width(),
        }
    }
}

impl From<Ipv6Prefix> for Ipv6Net {
    fn from(value: Ipv6Prefix) -> Self {
        Ipv6Net::new_unchecked(value.addr, value.len)
    }
}

impl From<IpNet> for IpPrefix {
    fn from(value: IpNet) -> Self {
        match value {
            IpNet::V4(x) => IpPrefix::V4(x.into()),
            IpNet::V6(x) => IpPrefix::V6(x.into()),
        }
    }
}
impl From<IpPrefix> for IpNet {
    fn from(value: IpPrefix) -> Self {
        match value {
            IpPrefix::V4(x) => IpNet::V4(x.into()),
            IpPrefix::V6(x) => IpNet::V6(x.into()),
        }
    }
}
