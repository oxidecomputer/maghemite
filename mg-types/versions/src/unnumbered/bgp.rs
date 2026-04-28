// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

use bgp_types_versions::v2::session::{FsmEventRecord, MessageHistory};
use bgp_types_versions::v4::messages::Afi;
use rdb_types_versions::v1::peer::PeerId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v2::bgp::{FsmEventBuffer, MessageDirection};
use crate::v4::bgp::{BgpPeerParameters, NeighborResetOp};

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

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExportedSelector {
    /// ASN of the router to get exported prefixes from.
    pub asn: u32,
    /// Optional peer filter using PeerId enum
    pub peer: Option<PeerId>,
    /// Optional address family filter (None = all negotiated families)
    pub afi: Option<Afi>,
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

/// Unified message history request supporting both numbered and unnumbered
/// peers
#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct MessageHistoryRequest {
    /// ASN of the BGP router
    pub asn: u32,

    /// Optional peer filter using PeerId enum
    /// JSON format: {"ip": "192.0.2.1"} or {"interface": "eth0"}
    pub peer: Option<PeerId>,

    /// Optional direction filter - if None, returns both sent and received
    pub direction: Option<MessageDirection>,
}

/// Unified message history response with string keys from PeerId Display
/// Keys will be "192.0.2.1" or "eth0" format
#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponse {
    pub by_peer: HashMap<String, MessageHistory>,
}

/// Unified FSM history request supporting both numbered and unnumbered peers
#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct FsmHistoryRequest {
    /// ASN of the BGP router
    pub asn: u32,

    /// Optional peer filter using PeerId enum
    /// JSON format: {"ip": "192.0.2.1"} or {"interface": "eth0"}
    pub peer: Option<PeerId>,

    /// Which buffer to retrieve - if None, returns major buffer
    pub buffer: Option<FsmEventBuffer>,
}

/// Unified FSM history response with string keys from PeerId Display
/// Keys will be "192.0.2.1" or "eth0" format
#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct FsmHistoryResponse {
    /// Events organized by peer identifier
    /// Each peer's value contains only the events from the requested buffer
    pub by_peer: HashMap<String, Vec<FsmEventRecord>>,
}

/// Unnumbered neighbor configuration for v4-v6 API (lacks src_addr/src_port).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[schemars(rename = "UnnumberedNeighbor")]
pub struct UnnumberedNeighbor {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub interface: String,
    pub act_as_a_default_ipv6_router: u16,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}
