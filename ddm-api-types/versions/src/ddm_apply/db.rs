// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v1::db::RouterKind;
use crate::v2::db::PeerStatus;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

/// Information about a DDM interface and its FSM state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InterfaceInfo {
    pub name: String,
    pub addr: Ipv6Addr,
    pub status: PeerStatus,
    pub peer: Option<PeerIdentity>,
    pub stats: InterfaceStats,
}

/// Information about a DDM peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PeerIdentity {
    pub addr: Ipv6Addr,
    pub hostname: String,
    pub kind: RouterKind,
}

/// Statistics about a DDM interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InterfaceStats {
    pub solicitations_sent: u64,
    pub solicitations_received: u64,
    pub advertisements_sent: u64,
    pub advertisements_received: u64,
    pub peer_expirations: u64,
    pub peer_address_changes: u64,
    pub peer_established: u64,
    pub updates_sent: u64,
    pub updates_received: u64,
    pub imported_underlay_prefixes: u64,
    pub imported_tunnel_endpoints: u64,
    pub update_send_fail: u64,
}
