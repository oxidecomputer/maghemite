// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;

use mg_common::net::MulticastOrigin;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v2::exchange::MulticastPathHop;

/// A multicast route learned via DDM.
///
/// Carries a MulticastOrigin (overlay group + ff04::/64 underlay
/// mapping) and the path vector from the originating subscriber
/// through intermediate transit routers.
// The path enables loop detection and (in multi-rack topologies)
// replication optimizations (RFD 488) in the future.
//
// Equality and hashing consider only `origin` and `nexthop` so that
// a route update with a longer path replaces the existing entry in
// hash-based collections.
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

impl PartialEq for MulticastRoute {
    fn eq(&self, other: &Self) -> bool {
        self.origin == other.origin && self.nexthop == other.nexthop
    }
}

impl Eq for MulticastRoute {}

impl std::hash::Hash for MulticastRoute {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.origin.hash(state);
        self.nexthop.hash(state);
    }
}

impl From<MulticastRoute> for MulticastOrigin {
    fn from(x: MulticastRoute) -> Self {
        x.origin
    }
}
