// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::exchange::MulticastPathHop;
use super::net::MulticastOrigin;
use crate::v1::db::RouterKind;
use crate::v2;
use crate::v2::db::PeerStatus;

/// A multicast route learned via DDM.
///
/// Carries a `MulticastOrigin` (overlay group + ff04::/64 underlay
/// mapping) and the path vector from the originating subscriber
/// through intermediate transit routers.
// Identity excludes path. Use `HashSet::replace` to refresh a stored path;
// `HashSet::insert` retains the existing entry.
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

/// Peer information with an optional interface name.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PeerInfo {
    pub status: PeerStatus,
    pub addr: Ipv6Addr,
    pub host: String,
    pub kind: RouterKind,
    /// Interface name the peer was discovered on (e.g., "tfportrear0_0").
    #[serde(default)]
    pub if_name: Option<String>,
}

/// Downconvert a MULTICAST_SUPPORT `PeerInfo` to PEER_DURATIONS by dropping
/// the `if_name`.
impl From<PeerInfo> for v2::db::PeerInfo {
    fn from(p: PeerInfo) -> Self {
        Self {
            status: p.status,
            addr: p.addr,
            host: p.host,
            kind: p.kind,
        }
    }
}
