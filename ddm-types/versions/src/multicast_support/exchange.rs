// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

/// A single hop in the multicast path, carrying metadata needed for
/// replication optimization.
// Unlike unicast paths which only need hostnames, multicast hops carry
// additional information for computing optimal replication points
// (RFD 488).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct MulticastPathHop {
    /// Router identifier (hostname).
    pub router_id: String,

    /// The underlay address of this router (for replication targeting).
    pub underlay_addr: Ipv6Addr,

    /// Number of downstream subscribers reachable via this hop.
    /// Used for load-aware replication decisions in multi-rack
    /// topologies.
    #[serde(default)]
    pub downstream_subscriber_count: u32,
}

impl MulticastPathHop {
    /// Create a hop with the given router identity and a zero subscriber
    /// count. The count will be populated once transit routers track
    /// downstream subscriber counts for load-aware replication (RFD 488).
    pub fn new(router_id: String, underlay_addr: Ipv6Addr) -> Self {
        Self {
            router_id,
            underlay_addr,
            downstream_subscriber_count: 0,
        }
    }
}

/// Multicast group subscription announcement propagating through DDM.
///
/// Contains a MulticastOrigin (overlay group + ff04::/64 underlay
/// mapping) and the path from the original subscriber outward.
// Currently, this is used for loop detection: if our router_id appears in the
// path, the announcement has already traversed us and is dropped. The path
// structure also carries topology information for future replication
// optimizations (RFD 488).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct MulticastPathVector {
    /// The multicast group origin information.
    pub origin: mg_common::net::MulticastOrigin,

    /// The path from the original subscriber to the current router.
    /// Ordered from subscriber outward (subscriber router first).
    pub path: Vec<MulticastPathHop>,
}

impl MulticastPathVector {
    /// Append a hop to this path vector.
    pub fn with_hop(&self, hop: MulticastPathHop) -> Self {
        let mut path = self.path.clone();
        path.push(hop);
        Self {
            origin: self.origin.clone(),
            path,
        }
    }
}
