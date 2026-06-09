// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Database types changed in API version 3 (MULTICAST_SUPPORT).
//!
//! Adds `MulticastRoute` for routes learned via DDM and extends
//! `PeerInfo` with an optional discovery interface name.

use std::net::Ipv6Addr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use ddm_protocol::v4::MulticastPathHop;

use super::net::MulticastOrigin;
use crate::v1::db::RouterKind;
use crate::v2::db::PeerStatus;

/// A multicast route learned via DDM.
///
/// Carries a `MulticastOrigin` (overlay group + ff04::/64 underlay
/// mapping) and the path vector from the originating subscriber
/// through intermediate transit routers.
// The path enables loop detection and (in multi-rack topologies)
// replication optimizations (RFD 488) in the future.
//
// Equality and hashing consider only `origin` and `nexthop`, so the path
// is not part of a route's identity. Updating a stored route's path
// therefore requires replacing the existing entry (e.g. `HashSet::replace`).
// `HashSet::insert` leaves the stored path unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MulticastRoute {
    /// The multicast group origin information.
    pub origin: MulticastOrigin,

    /// Underlay nexthop address (DDM peer that advertised this route).
    /// Used to associate the route with a peer for expiration.
    pub nexthop: Ipv6Addr,

    /// Path vector from the originating subscriber outward.
    /// Each hop records the router that redistributed this
    /// subscription announcement. Used for loop detection on pull
    /// and for future replication optimization in multi-rack
    /// topologies.
    #[serde(default)]
    pub path: Vec<MulticastPathHop>,
}

impl MulticastRoute {
    /// Identity used for equality and hashing: which group, from which peer.
    /// Excludes `path`, so equality and hashing both key on the same fields
    /// and cannot drift as the struct grows.
    fn identity(&self) -> (&MulticastOrigin, &Ipv6Addr) {
        (&self.origin, &self.nexthop)
    }
}

impl PartialEq for MulticastRoute {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl Eq for MulticastRoute {}

impl std::hash::Hash for MulticastRoute {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity().hash(state);
    }
}

impl From<MulticastRoute> for MulticastOrigin {
    fn from(x: MulticastRoute) -> Self {
        x.origin
    }
}

/// Peer information with an optional interface name.
///
// Adds the `if_name` field to identify which underlay interface the peer
// was discovered on.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PeerInfo {
    pub status: PeerStatus,
    pub addr: Ipv6Addr,
    pub host: String,
    pub kind: RouterKind,
    /// Interface name the peer was discovered on (e.g., "tfportrear0_0").
    #[serde(default)]
    pub if_name: Option<String>,
}

/// Down-convert v3 `PeerInfo` to v2 `PeerInfo` by dropping `if_name`.
impl From<PeerInfo> for crate::v2::db::PeerInfo {
    fn from(p: PeerInfo) -> Self {
        Self {
            status: p.status,
            addr: p.addr,
            host: p.host,
            kind: p.kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(overlay: &str) -> MulticastOrigin {
        serde_json::from_value(serde_json::json!({
            "overlay_group": overlay,
            "underlay_group": "ff04::1",
            "vni": 77,
            "metric": 0
        }))
        .unwrap()
    }

    // The path is excluded from a route's identity, so two routes sharing an
    // origin and nexthop but carrying different paths are equal.
    // `HashSet::replace` relies on this to refresh a stored route's path.
    #[test]
    fn route_identity_excludes_path() {
        let base = MulticastRoute {
            origin: origin("233.252.0.1"),
            nexthop: Ipv6Addr::LOCALHOST,
            path: vec![MulticastPathHop::new(
                "router-1".into(),
                Ipv6Addr::LOCALHOST,
            )],
        };
        let mut other = base.clone();
        other.path = vec![
            MulticastPathHop::new("router-1".into(), Ipv6Addr::LOCALHOST),
            MulticastPathHop::new("router-2".into(), Ipv6Addr::LOCALHOST),
        ];
        assert_eq!(base, other);
    }

    #[test]
    fn route_identity_keys_on_origin_and_nexthop() {
        let base = MulticastRoute {
            origin: origin("233.252.0.1"),
            nexthop: Ipv6Addr::LOCALHOST,
            path: vec![],
        };
        let other_origin = MulticastRoute {
            origin: origin("233.252.0.2"),
            nexthop: Ipv6Addr::LOCALHOST,
            path: vec![],
        };
        let other_nexthop = MulticastRoute {
            origin: origin("233.252.0.1"),
            nexthop: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            path: vec![],
        };
        assert_ne!(base, other_origin);
        assert_ne!(base, other_nexthop);
    }
}
