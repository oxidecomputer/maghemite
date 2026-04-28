// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Display, helper, and cross-version conversion impls for the versioned BGP
//! session-history types.

use std::fmt::{self, Display, Formatter};
use std::net::SocketAddr;

use uuid::Uuid;

use crate::v1::session::{
    MessageHistory as MessageHistoryV1,
    MessageHistoryEntry as MessageHistoryEntryV1,
};
use crate::v2::session::{
    ConnectionDirection, ConnectionId, FsmStateKind, MessageHistory,
    MessageHistoryEntry,
};
use crate::v4::messages::Message;

use crate::v2::session::MAX_MESSAGE_HISTORY;

impl ConnectionDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionDirection::Inbound => "inbound",
            ConnectionDirection::Outbound => "outbound",
        }
    }
}

impl Display for ConnectionDirection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl slog::Value for ConnectionDirection {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str(key, &self.to_string())
    }
}

impl ConnectionId {
    /// Create a new ConnectionId
    pub fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            local,
            remote,
        }
    }

    /// Get a short, human-readable identifier for this connection
    pub fn short(&self) -> String {
        self.uuid.to_string()[0..8].to_string()
    }

    /// Get the local socket address
    pub fn local(&self) -> SocketAddr {
        self.local
    }

    /// Get the remote socket address
    pub fn remote(&self) -> SocketAddr {
        self.remote
    }
}

impl FsmStateKind {
    pub fn as_str(&self) -> &str {
        match self {
            FsmStateKind::Idle => "idle",
            FsmStateKind::Connect => "connect",
            FsmStateKind::Active => "active",
            FsmStateKind::OpenSent => "open sent",
            FsmStateKind::OpenConfirm => "open confirm",
            FsmStateKind::ConnectionCollision => "connection collision",
            FsmStateKind::SessionSetup => "session setup",
            FsmStateKind::Established => "established",
        }
    }
}

impl Display for FsmStateKind {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl MessageHistoryEntry {
    pub fn new(
        timestamp: chrono::DateTime<chrono::Utc>,
        message: Message,
        connection_id: ConnectionId,
    ) -> Self {
        Self {
            timestamp,
            message,
            connection_id,
        }
    }

    pub fn timestamp(&self) -> chrono::DateTime<chrono::Utc> {
        self.timestamp
    }

    pub fn message(&self) -> &Message {
        &self.message
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }
}

impl MessageHistory {
    pub fn receive(&mut self, msg: Message, connection_id: ConnectionId) {
        if self.received.len() >= MAX_MESSAGE_HISTORY {
            self.received.pop_back();
        }
        self.received.push_front(MessageHistoryEntry {
            message: msg,
            timestamp: chrono::Utc::now(),
            connection_id,
        });
    }

    pub fn send(&mut self, msg: Message, connection_id: ConnectionId) {
        if self.sent.len() >= MAX_MESSAGE_HISTORY {
            self.sent.pop_back();
        }
        self.sent.push_front(MessageHistoryEntry {
            message: msg,
            timestamp: chrono::Utc::now(),
            connection_id,
        });
    }
}

// ----------------------------------------------------------------------------
// Cross-version conversions: v2 (latest) → v1 (compat shapes).
// ----------------------------------------------------------------------------

impl From<MessageHistoryEntry> for MessageHistoryEntryV1 {
    fn from(entry: MessageHistoryEntry) -> Self {
        Self {
            timestamp: entry.timestamp,
            message: crate::v1::messages::Message::from(entry.message),
        }
    }
}

impl From<MessageHistory> for MessageHistoryV1 {
    fn from(history: MessageHistory) -> Self {
        Self {
            received: history
                .received
                .into_iter()
                .map(MessageHistoryEntryV1::from)
                .collect(),
            sent: history
                .sent
                .into_iter()
                .map(MessageHistoryEntryV1::from)
                .collect(),
        }
    }
}
