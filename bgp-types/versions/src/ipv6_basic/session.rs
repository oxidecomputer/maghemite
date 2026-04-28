// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Session-related types added in the IPV6_BASIC (v2) admin API version:
//! `ConnectionId`, `ConnectionDirection`, the latest `FsmStateKind`,
//! the v2 `MessageHistory` / `MessageHistoryEntry` (carrying a `ConnectionId`),
//! and the FSM event record types.

use std::collections::VecDeque;
use std::net::SocketAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::v4::messages::Message;

/// Maximum number of historical messages retained per direction in
/// `MessageHistory`.
pub const MAX_MESSAGE_HISTORY: usize = 1024;

/// Creator of a BGP connection
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum ConnectionDirection {
    /// Connection was created by the dispatcher (listener)
    Inbound,
    /// Connection was created by the connector
    Outbound,
}

/// Unique identifier for a BGP connection instance
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub struct ConnectionId {
    /// Unique identifier for this connection instance
    pub(crate) uuid: Uuid,
    /// Local socket address for this connection
    pub(crate) local: SocketAddr,
    /// Remote socket address for this connection
    pub(crate) remote: SocketAddr,
}

/// Simplified representation of a BGP state without having to carry a
/// connection.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema,
)]
pub enum FsmStateKind {
    /// Initial state. Refuse all incomming BGP connections. No resources
    /// allocated to peer.
    Idle,

    /// Waiting for the TCP connection to be completed.
    Connect,

    /// Trying to acquire peer by listening for and accepting a TCP connection.
    Active,

    /// Waiting for open message from peer.
    OpenSent,

    /// Waiting for keepalive or notification from peer.
    OpenConfirm,

    /// Handler for Connection Collisions (RFC 4271 6.8)
    ConnectionCollision,

    /// Sync up with peers.
    SessionSetup,

    /// Able to exchange update, notification and keepliave messages with peers.
    Established,
}

/// A message history entry is a BGP message with an associated timestamp and connection ID
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistoryEntry {
    pub(crate) timestamp: chrono::DateTime<chrono::Utc>,
    pub(crate) message: Message,
    pub(crate) connection_id: ConnectionId,
}

/// Message history for a BGP session
#[derive(Default, Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistory {
    pub received: VecDeque<MessageHistoryEntry>,
    pub sent: VecDeque<MessageHistoryEntry>,
}

/// Category of FSM event for filtering and display purposes
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum FsmEventCategory {
    Admin,
    Connection,
    Session,
    StateTransition,
}

/// Serializable record of an FSM event with full context
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FsmEventRecord {
    /// UTC timestamp when event occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// High-level event category
    pub event_category: FsmEventCategory,

    /// Specific event type as string (e.g., "ManualStart", "HoldTimerExpires")
    pub event_type: String,

    /// FSM state at time of event
    pub current_state: FsmStateKind,

    /// Previous state if this caused a transition
    pub previous_state: Option<FsmStateKind>,

    /// Connection ID if event is connection-specific
    pub connection_id: Option<ConnectionId>,

    /// Additional event details (e.g., "Received OPEN", "Admin command")
    pub details: Option<String>,
}
