// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

use bgp::session::{MessageHistoryEntry, PeerId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v2::bgp::MessageDirection;

/// Which message buffer to retrieve.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MessageBuffer {
    /// All messages including KeepAlives.
    All,
    /// Major messages only (excludes KeepAlives).
    Major,
}

/// Message history request with buffer selection
/// (VERSION_SPRING_CLEANING+).
#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct MessageHistoryRequest {
    pub asn: u32,
    pub peer: Option<PeerId>,
    pub direction: Option<MessageDirection>,
    /// Which buffer to retrieve — if None, returns major buffer.
    pub buffer: Option<MessageBuffer>,
}

/// Message history response with flat list of entries per peer
/// (VERSION_SPRING_CLEANING+).
///
/// Each entry carries its own direction, unlike the sent/received
/// split used by older API versions.
#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponse {
    pub by_peer: HashMap<String, Vec<MessageHistoryEntry>>,
}
