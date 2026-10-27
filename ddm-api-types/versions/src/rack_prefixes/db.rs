// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;

use crate::v1::db::RouterKind;
use crate::v2::db::PeerStatus;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The routing session on one address object, and its peer if one has been
/// discovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PeerInfo {
    pub status: PeerStatus,
    pub peer: Option<Peer>,
}

/// A discovered DDM peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Peer {
    pub addr: Ipv6Addr,
    pub host: String,
    pub kind: RouterKind,
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
    pub imported_tunnel_endpoints: u64,
    pub imported_rack_prefixes: u64,
}
