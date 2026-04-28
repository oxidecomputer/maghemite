// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Session-related types published since the initial admin API version.
//!
//! Includes the v1 wire-shape `MessageHistory` / `MessageHistoryEntry` used by
//! the `/bgp/message-history` endpoint at v1. These shapes lack the
//! `connection_id` field added in v2.

use std::collections::VecDeque;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1::messages::Message;

// V1 API compatibility type for message history entry (IPv4-only with v1 Message)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "MessageHistoryEntry")]
pub struct MessageHistoryEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub message: Message,
}

// V1 API compatibility type for message history collection
#[derive(Default, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "MessageHistory")]
pub struct MessageHistory {
    pub received: VecDeque<MessageHistoryEntry>,
    pub sent: VecDeque<MessageHistoryEntry>,
}
