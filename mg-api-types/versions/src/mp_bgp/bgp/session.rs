// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Session-history wire shapes introduced in the MP_BGP (v4) admin API
//! version.
//!
//! At v4, the `Message` enum (and its `UpdateMessage` payload) changed
//! shape to carry MP_REACH/UNREACH path attributes; that change is the
//! first version in which the current `MessageHistory` /
//! `MessageHistoryEntry` wire shape was introduced. The `ConnectionId`
//! field carried on each entry was added earlier, in v2, and is
//! re-used here via a fixed `crate::v2::bgp::session::ConnectionId`
//! identifier.

use std::collections::VecDeque;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::messages::Message;
use crate::v1;
use crate::v2;
use crate::v2::bgp::session::ConnectionId;

/// Maximum number of historical messages retained per direction in
/// `MessageHistory`.
pub const MAX_MESSAGE_HISTORY: usize = 1024;

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

// ----------------------------------------------------------------------------
// Cross-version downgrade: v4 session-history shapes → v2 (history-module)
// shapes. The v2 history shapes carry a v2-local `Message`/`UpdateMessage`
// whose `withdrawn`/`nlri` carry the V4/V6 rdb prefix enum; the per-message
// conversion lives next to the v4 `Message` definition in
// `crate::v4::bgp::messages`.
// ----------------------------------------------------------------------------

impl From<MessageHistoryEntry> for v2::bgp::history::MessageHistoryEntry {
    fn from(entry: MessageHistoryEntry) -> Self {
        let MessageHistoryEntry {
            timestamp,
            message,
            connection_id,
        } = entry;
        Self {
            timestamp,
            message: v2::bgp::history::Message::from(message),
            connection_id,
        }
    }
}

impl From<MessageHistory> for v2::bgp::history::MessageHistory {
    fn from(history: MessageHistory) -> Self {
        let MessageHistory { received, sent } = history;
        Self {
            received: received
                .into_iter()
                .map(v2::bgp::history::MessageHistoryEntry::from)
                .collect(),
            sent: sent
                .into_iter()
                .map(v2::bgp::history::MessageHistoryEntry::from)
                .collect(),
        }
    }
}

// ----------------------------------------------------------------------------
// Cross-version downgrade: v4 session-history shapes → v1 (no
// connection_id, v1 `Message` enum). The v1 shapes are pre-IPV6_BASIC
// and lack the `connection_id` field added at v2.
// ----------------------------------------------------------------------------

impl From<MessageHistoryEntry> for v1::bgp::session::MessageHistoryEntry {
    fn from(entry: MessageHistoryEntry) -> Self {
        // Compile barrier: a latest MessageHistoryEntry field addition
        // will fail to bind here, forcing a deliberate decision about
        // how (or whether) to surface it on the v1 form.
        let MessageHistoryEntry {
            timestamp,
            message,
            // v1 has no connection_id concept (added in v2 alongside
            // multi-connection FSM history).
            connection_id: _,
        } = entry;
        Self {
            timestamp,
            message: v1::bgp::messages::Message::from(message),
        }
    }
}

impl From<MessageHistory> for v1::bgp::session::MessageHistory {
    fn from(history: MessageHistory) -> Self {
        let MessageHistory { received, sent } = history;
        Self {
            received: received
                .into_iter()
                .map(v1::bgp::session::MessageHistoryEntry::from)
                .collect(),
            sent: sent
                .into_iter()
                .map(v1::bgp::session::MessageHistoryEntry::from)
                .collect(),
        }
    }
}
