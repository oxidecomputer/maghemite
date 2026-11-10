// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::collections::VecDeque;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::messages::Afi;
use super::messages::Message;
use super::peer::PeerId;
use crate::v2::bgp::history::MessageDirection;
use crate::v2::bgp::session::ConnectionId;
use crate::v13::bgp::history::HistoryBufferSelector;
use crate::{v2, v5, v11, v13};

/// Simplified representation of a BGP state without having to carry a
/// connection.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
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

/// Category of FSM event for filtering and display purposes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExportedSelector {
    /// ASN of the router to get exported prefixes from.
    pub asn: u32,
    /// Optional peer filter using PeerId enum
    pub peer: Option<PeerId>,
    /// Optional address family filter (None = all negotiated families)
    pub afi: Option<Afi>,
}

/// Unified FSM history response with string keys from PeerId Display
/// Keys will be "192.0.2.1" or "eth0" format
#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct FsmHistoryResponse {
    /// Events organized by peer identifier
    /// Each peer's value contains only the events from the requested buffer
    pub by_peer: HashMap<String, Vec<FsmEventRecord>>,
}

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
/// Keys will be "192.0.2.1" or "eth0" format
#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponse {
    pub by_peer: HashMap<String, MessageHistory>,
}

/// Unified message history request supporting both numbered and unnumbered
/// peers
#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct MessageHistoryRequest {
    /// ASN of the BGP router
    pub asn: u32,

    /// Optional peer filter using PeerId enum
    pub peer: Option<PeerId>,

    /// Optional direction filter - if None, returns both sent and received
    pub direction: Option<MessageDirection>,

    /// Which buffer to retrieve - if None, returns major buffer
    pub buffer: Option<HistoryBufferSelector>,
}

/// Unified FSM history request supporting both numbered and unnumbered peers
#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct FsmHistoryRequest {
    /// ASN of the BGP router
    pub asn: u32,

    /// Optional peer filter using PeerId enum
    pub peer: Option<PeerId>,

    /// Which buffer to retrieve - if None, returns major buffer
    pub buffer: Option<HistoryBufferSelector>,
}

impl From<FsmStateKind> for v2::bgp::session::FsmStateKind {
    fn from(new: FsmStateKind) -> Self {
        match new {
            FsmStateKind::Idle => Self::Idle,
            FsmStateKind::Connect => Self::Connect,
            FsmStateKind::Active => Self::Active,
            FsmStateKind::OpenSent => Self::OpenSent,
            FsmStateKind::OpenConfirm => Self::OpenConfirm,
            FsmStateKind::ConnectionCollision => Self::ConnectionCollision,
            FsmStateKind::SessionSetup => Self::SessionSetup,
            FsmStateKind::Established => Self::Established,
        }
    }
}

impl From<FsmEventCategory> for v2::bgp::session::FsmEventCategory {
    fn from(new: FsmEventCategory) -> Self {
        match new {
            FsmEventCategory::Admin => Self::Admin,
            FsmEventCategory::Connection => Self::Connection,
            FsmEventCategory::Session => Self::Session,
            FsmEventCategory::StateTransition => Self::StateTransition,
        }
    }
}

impl From<FsmEventRecord> for v2::bgp::session::FsmEventRecord {
    fn from(new: FsmEventRecord) -> Self {
        let FsmEventRecord {
            timestamp,
            event_category,
            event_type,
            current_state,
            previous_state,
            connection_id,
            details,
        } = new;
        Self {
            timestamp,
            event_category: event_category.into(),
            event_type,
            current_state: current_state.into(),
            previous_state: previous_state.map(Into::into),
            connection_id,
            details,
        }
    }
}

impl From<v5::bgp::session::ExportedSelector> for ExportedSelector {
    fn from(old: v5::bgp::session::ExportedSelector) -> Self {
        let v5::bgp::session::ExportedSelector { asn, peer, afi } = old;
        Self {
            asn,
            peer: peer.map(Into::into),
            afi: afi.map(Into::into),
        }
    }
}

impl From<FsmHistoryResponse> for v5::bgp::session::FsmHistoryResponse {
    fn from(new: FsmHistoryResponse) -> Self {
        let FsmHistoryResponse { by_peer } = new;
        Self {
            by_peer: by_peer
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
                .collect(),
        }
    }
}

impl From<MessageHistoryEntry> for v11::bgp::session::MessageHistoryEntry {
    fn from(new: MessageHistoryEntry) -> Self {
        let MessageHistoryEntry {
            timestamp,
            message,
            connection_id,
        } = new;
        Self {
            timestamp,
            message: message.into(),
            connection_id,
        }
    }
}

impl From<MessageHistory> for v11::bgp::session::MessageHistory {
    fn from(new: MessageHistory) -> Self {
        let MessageHistory { received, sent } = new;
        Self {
            received: received.into_iter().map(Into::into).collect(),
            sent: sent.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<MessageHistoryResponse>
    for v11::bgp::session::MessageHistoryResponse
{
    fn from(new: MessageHistoryResponse) -> Self {
        let MessageHistoryResponse { by_peer } = new;
        Self {
            by_peer: by_peer.into_iter().map(|(k, v)| (k, v.into())).collect(),
        }
    }
}

impl From<v13::bgp::session::MessageHistoryRequest> for MessageHistoryRequest {
    fn from(old: v13::bgp::session::MessageHistoryRequest) -> Self {
        let v13::bgp::session::MessageHistoryRequest {
            asn,
            peer,
            direction,
            buffer,
        } = old;
        Self {
            asn,
            peer: peer.map(Into::into),
            direction,
            buffer,
        }
    }
}

impl From<v13::bgp::session::FsmHistoryRequest> for FsmHistoryRequest {
    fn from(old: v13::bgp::session::FsmHistoryRequest) -> Self {
        let v13::bgp::session::FsmHistoryRequest { asn, peer, buffer } = old;
        Self {
            asn,
            peer: peer.map(Into::into),
            buffer,
        }
    }
}
