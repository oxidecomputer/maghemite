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
//! The wire types ([`Update`], [`UnderlayUpdate`], [`TunnelUpdate`],
//! [`MulticastUpdate`], and their versioned counterparts) are
//! platform-agnostic and stay in this module. The runtime helpers that drive
//! the HTTP exchange protocol and program forwarding state live in the
//! [`runtime`] submodule and are illumos-only, since they call into
//! [`crate::sys`] to install routes.

use ddm_types::exchange::{
    MulticastPathHop, MulticastPathVector, PathVector, PathVectorV2,
};
use mg_common::net::{TunnelOrigin, TunnelOriginV2};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

#[cfg(all(feature = "illumos", target_os = "illumos"))]
mod runtime;

#[cfg(all(feature = "illumos", target_os = "illumos"))]
pub(crate) use runtime::{
    announce_multicast, announce_tunnel, announce_underlay, do_pull_v4,
    handler, pull, withdraw_multicast, withdraw_tunnel, withdraw_underlay,
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

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 3. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV3 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UpdateV3 {
    pub underlay: Option<UnderlayUpdate>,
    pub tunnel: Option<TunnelUpdate>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct Update {
    pub underlay: Option<UnderlayUpdate>,
    pub tunnel: Option<TunnelUpdate>,
    pub multicast: Option<MulticastUpdate>,
}

impl From<UpdateV1> for Update {
    fn from(value: UpdateV1) -> Self {
        Update {
            tunnel: None,
            underlay: Some(UnderlayUpdate {
                announce: value.announce,
                withdraw: value.withdraw,
            }),
            multicast: None,
        }
    }
}

impl From<UpdateV2> for Update {
    fn from(value: UpdateV2) -> Self {
        Update {
            tunnel: value.tunnel.map(TunnelUpdate::from),
            underlay: value.underlay.map(UnderlayUpdate::from),
            // V2 protocol doesn't support multicast
            multicast: None,
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

impl From<UpdateV3> for Update {
    fn from(value: UpdateV3) -> Self {
        Update {
            underlay: value.underlay,
            tunnel: value.tunnel,
            multicast: None,
        }
    }
}

impl From<Update> for UpdateV3 {
    fn from(value: Update) -> Self {
        UpdateV3 {
            underlay: value.underlay,
            tunnel: value.tunnel,
        }
    }
}

impl From<UnderlayUpdate> for Update {
    fn from(u: UnderlayUpdate) -> Self {
        Update {
            underlay: Some(u),
            tunnel: None,
            multicast: None,
        }
    }
}

impl From<TunnelUpdate> for Update {
    fn from(t: TunnelUpdate) -> Self {
        Update {
            underlay: None,
            tunnel: Some(t),
            multicast: None,
        }
    }
}

impl From<MulticastUpdate> for Update {
    fn from(m: MulticastUpdate) -> Self {
        Update {
            underlay: None,
            tunnel: None,
            multicast: Some(m),
        }
    }
}

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 3. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV3 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct PullResponseV3 {
    pub underlay: Option<HashSet<PathVector>>,
    pub tunnel: Option<HashSet<TunnelOrigin>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct PullResponse {
    pub underlay: Option<HashSet<PathVector>>,
    pub tunnel: Option<HashSet<TunnelOrigin>>,
    pub multicast: Option<HashSet<MulticastPathVector>>,
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
            // V2 protocol doesn't support multicast
            multicast: None,
        }
    }
}

impl From<PullResponseV3> for PullResponse {
    fn from(value: PullResponseV3) -> Self {
        PullResponse {
            underlay: value.underlay,
            tunnel: value.tunnel,
            multicast: None,
        }
    }
}

impl From<HashSet<PathVector>> for PullResponse {
    fn from(value: HashSet<PathVector>) -> Self {
        PullResponse {
            underlay: Some(value),
            tunnel: None,
            multicast: None,
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

/// Multicast group subscription updates.
///
/// Each entry carries a [`MulticastPathVector`] containing a
/// [`MulticastOrigin`] (overlay group + ff04::/64 underlay mapping)
/// and the path vector for loop detection.
///
/// [`MulticastOrigin`]: mg_common::net::MulticastOrigin
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct MulticastUpdate {
    pub announce: HashSet<MulticastPathVector>,
    pub withdraw: HashSet<MulticastPathVector>,
}

impl MulticastUpdate {
    pub fn announce(groups: HashSet<MulticastPathVector>) -> Self {
        Self {
            announce: groups,
            ..Default::default()
        }
    }
    pub fn withdraw(groups: HashSet<MulticastPathVector>) -> Self {
        Self {
            withdraw: groups,
            ..Default::default()
        }
    }

    /// Add a hop to all path vectors in this update.
    pub fn with_hop(&self, hop: MulticastPathHop) -> Self {
        Self {
            announce: self
                .announce
                .iter()
                .map(|pv| pv.with_hop(hop.clone()))
                .collect(),
            withdraw: self
                .withdraw
                .iter()
                .map(|pv| pv.with_hop(hop.clone()))
                .collect(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ddm_types::exchange::MulticastPathHop;
    use mg_common::net::{MulticastOrigin, UnderlayMulticastIpv6, Vni};
    use std::net::Ipv6Addr;

    fn sample_multicast_update() -> MulticastUpdate {
        let origin = MulticastOrigin {
            overlay_group: "233.252.0.1".parse().unwrap(),
            underlay_group: UnderlayMulticastIpv6::new(
                "ff04::1".parse().unwrap(),
            )
            .unwrap(),
            vni: Vni::try_from(77u32).unwrap(),
            metric: 0,
            source: None,
        };
        let pv = MulticastPathVector {
            origin,
            path: vec![MulticastPathHop::new(
                "router-1".into(),
                Ipv6Addr::LOCALHOST,
            )],
        };
        MulticastUpdate::announce([pv].into_iter().collect())
    }

    #[test]
    fn v4_update_round_trips() {
        let update = Update {
            underlay: None,
            tunnel: None,
            multicast: Some(sample_multicast_update()),
        };
        let json = serde_json::to_string(&update).unwrap();
        let back: Update = serde_json::from_str(&json).unwrap();
        assert!(back.multicast.is_some());
        assert_eq!(back.multicast.unwrap().announce.len(), 1,);
    }

    #[test]
    fn v4_update_deserializes_as_v3_drops_multicast() {
        let update = Update {
            underlay: None,
            tunnel: None,
            multicast: Some(sample_multicast_update()),
        };
        let json = serde_json::to_string(&update).unwrap();
        // A V3 peer would deserialize this as UpdateV3, silently
        // dropping the unknown multicast field.
        let v3: UpdateV3 = serde_json::from_str(&json).unwrap();
        assert!(v3.underlay.is_none());
        assert!(v3.tunnel.is_none());
    }

    #[test]
    fn v3_update_deserializes_as_v4_multicast_none() {
        let v3 = UpdateV3 {
            underlay: None,
            tunnel: None,
        };
        let json = serde_json::to_string(&v3).unwrap();
        // A V4 peer receiving a V3 update gets multicast: None.
        let update: Update = serde_json::from_str(&json).unwrap();
        assert!(update.multicast.is_none());
    }

    #[test]
    fn v4_pull_response_round_trips() {
        let origin = MulticastOrigin {
            overlay_group: "ff0e::1".parse().unwrap(),
            underlay_group: UnderlayMulticastIpv6::new(
                "ff04::2".parse().unwrap(),
            )
            .unwrap(),
            vni: Vni::try_from(77u32).unwrap(),
            metric: 0,
            source: None,
        };
        let pv = MulticastPathVector {
            origin,
            path: vec![],
        };
        let resp = PullResponse {
            underlay: None,
            tunnel: None,
            multicast: Some([pv].into_iter().collect()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: PullResponse = serde_json::from_str(&json).unwrap();
        assert!(back.multicast.is_some());
    }

    #[test]
    fn v4_pull_response_deserializes_as_v3() {
        let origin = MulticastOrigin {
            overlay_group: "233.252.0.1".parse().unwrap(),
            underlay_group: UnderlayMulticastIpv6::new(
                "ff04::1".parse().unwrap(),
            )
            .unwrap(),
            vni: Vni::try_from(77u32).unwrap(),
            metric: 0,
            source: None,
        };
        let pv = MulticastPathVector {
            origin,
            path: vec![],
        };
        let resp = PullResponse {
            underlay: None,
            tunnel: None,
            multicast: Some([pv].into_iter().collect()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        // V3 peer drops the multicast field.
        let v3: PullResponseV3 = serde_json::from_str(&json).unwrap();
        assert!(v3.underlay.is_none());
        assert!(v3.tunnel.is_none());
    }

    #[test]
    fn v3_pull_response_deserializes_as_v4() {
        let v3 = PullResponseV3 {
            underlay: None,
            tunnel: None,
        };
        let json = serde_json::to_string(&v3).unwrap();
        let resp: PullResponse = serde_json::from_str(&json).unwrap();
        assert!(resp.multicast.is_none());
    }

    #[test]
    fn from_conversions_strip_multicast() {
        let update = Update {
            underlay: None,
            tunnel: None,
            multicast: Some(sample_multicast_update()),
        };
        let v3 = UpdateV3::from(update);
        let back = Update::from(v3);
        assert!(back.multicast.is_none());
    }
}
