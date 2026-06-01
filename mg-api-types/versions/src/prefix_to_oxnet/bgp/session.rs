// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::collections::VecDeque;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::messages::Message;
use crate::v2::bgp::session::ConnectionId;
use crate::v4;
use crate::v5;

pub use crate::v4::bgp::session::MAX_MESSAGE_HISTORY;

/// A message history entry is a BGP message with an associated timestamp and connection ID
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistoryEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub message: Message,
    pub connection_id: ConnectionId,
}

/// Message history for a BGP session
#[derive(Default, Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistory {
    pub received: VecDeque<MessageHistoryEntry>,
    pub sent: VecDeque<MessageHistoryEntry>,
}

/// Unified message history response with string keys from PeerId Display
#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponse {
    pub by_peer: HashMap<String, MessageHistory>,
}

// ---------------------------------------------------------------------------
// Downgrade conversions: v10 → v4
// ---------------------------------------------------------------------------

impl From<MessageHistoryEntry> for v4::bgp::session::MessageHistoryEntry {
    fn from(entry: MessageHistoryEntry) -> Self {
        let MessageHistoryEntry { timestamp, message, connection_id } = entry;
        Self { timestamp, message: v4::bgp::messages::Message::from(message), connection_id }
    }
}

impl From<MessageHistory> for v4::bgp::session::MessageHistory {
    fn from(history: MessageHistory) -> Self {
        let MessageHistory { received, sent } = history;
        Self {
            received: received
                .into_iter()
                .map(v4::bgp::session::MessageHistoryEntry::from)
                .collect(),
            sent: sent
                .into_iter()
                .map(v4::bgp::session::MessageHistoryEntry::from)
                .collect(),
        }
    }
}

impl From<MessageHistoryResponse> for v5::bgp::session::MessageHistoryResponse {
    fn from(r: MessageHistoryResponse) -> Self {
        Self {
            by_peer: r
                .by_peer
                .into_iter()
                .map(|(k, v)| (k, v4::bgp::session::MessageHistory::from(v)))
                .collect(),
        }
    }
}
