// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::v1::bgp::peer::PeerId;
use crate::v2::bgp::history::FsmEventBuffer;
use crate::v2::bgp::history::MessageDirection;
use crate::v2::bgp::session::FsmEventRecord;
use crate::v4::bgp::messages::Afi;
use crate::v4::bgp::session::MessageHistory;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExportedSelector {
    /// ASN of the router to get exported prefixes from.
    pub asn: u32,
    /// Optional peer filter using PeerId enum
    pub peer: Option<PeerId>,
    /// Optional address family filter (None = all negotiated families)
    pub afi: Option<Afi>,
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
