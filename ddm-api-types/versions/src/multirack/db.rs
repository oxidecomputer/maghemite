// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;

use crate::v1;
use crate::v1::net::TunnelOrigin;
use crate::v5;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A tunnel route imported from a peer.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelRoute {
    pub origin: TunnelOrigin,

    /// The routers the route was advertised through, starting with its
    /// originator and ending with the peer it was learned from.
    pub path: Vec<String>,

    /// The address of the peer the route was learned from.
    pub nexthop: Ipv6Addr,
}

impl From<TunnelRoute> for v1::db::TunnelRoute {
    fn from(value: TunnelRoute) -> Self {
        // compilation barrier. a new field must be considered here.
        let TunnelRoute {
            origin,
            path: _,
            nexthop,
        } = value;
        Self { origin, nexthop }
    }
}

/// Counters for the routing session on one address object. The imported
/// counts are the routes currently imported from this session's peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PeerStats {
    pub solicitations_sent: u64,
    pub solicitations_received: u64,
    pub advertisements_sent: u64,
    pub advertisements_received: u64,
    pub peer_expirations: u64,
    pub peer_address_changes: u64,
    pub peer_established: u64,
    pub updates_sent: u64,
    pub updates_received: u64,
    pub update_send_fail: u64,
    pub imported_underlay_prefixes: u64,
    pub imported_bootstrap_prefixes: u64,
    pub imported_tunnel_endpoints: u64,
}

impl From<PeerStats> for v5::db::PeerStats {
    fn from(value: PeerStats) -> Self {
        // compilation barrier. a new counter must be considered here.
        let PeerStats {
            solicitations_sent,
            solicitations_received,
            advertisements_sent,
            advertisements_received,
            peer_expirations,
            peer_address_changes,
            peer_established,
            updates_sent,
            updates_received,
            update_send_fail,
            imported_underlay_prefixes,
            imported_bootstrap_prefixes: _,
            imported_tunnel_endpoints,
        } = value;
        Self {
            solicitations_sent,
            solicitations_received,
            advertisements_sent,
            advertisements_received,
            peer_expirations,
            peer_address_changes,
            peer_established,
            updates_sent,
            updates_received,
            update_send_fail,
            imported_underlay_prefixes,
            imported_tunnel_endpoints,
        }
    }
}
