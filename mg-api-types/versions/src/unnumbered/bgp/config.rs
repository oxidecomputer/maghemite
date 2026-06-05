// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::v4::bgp::config::BgpPeerParameters;
use crate::v4::bgp::config::NeighborResetOp;

/// Unified neighbor selector supporting both numbered and unnumbered peers.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NeighborSelector {
    pub asn: u32,
    /// Peer identifier as a string.
    ///
    /// - For numbered peers: IP address (e.g., "192.0.2.1" or "2001:db8::1")
    /// - For unnumbered peers: Interface name (e.g., "eth0" or "cxgbe0")
    ///
    /// Server parses as IP address first; if parsing fails, treats as
    /// interface name. Uses PeerId::from_str() for type-safe conversion.
    pub peer: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct UnnumberedNeighborSelector {
    pub asn: u32,
    pub interface: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct UnnumberedNeighborResetRequest {
    pub asn: u32,
    pub interface: String,
    pub op: NeighborResetOp,
}

/// Unnumbered neighbor configuration for v4-v6 API (lacks src_addr/src_port).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct UnnumberedNeighbor {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub interface: String,
    pub act_as_a_default_ipv6_router: u16,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}
