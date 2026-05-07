// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use bgp::connection::ConnectionId;
use bgp::messages::{
    NotificationMessage, OpenMessage, PathAttributeV1, RouteRefreshMessage,
};
use bgp::session::{
    FsmEventRecord, MessageHistory as LiveMessageHistory,
    MessageHistoryEntry as LiveMessageHistoryEntry,
};
use rdb::Prefix as RdbPrefix;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MessageDirection {
    Sent,
    Received,
}

#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct MessageHistoryRequest {
    /// ASN of the BGP router
    pub asn: u32,
    /// Optional peer filter - if None, returns history for all peers
    pub peer: Option<IpAddr>,
    /// Optional direction filter - if None, returns both sent and received
    pub direction: Option<MessageDirection>,
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponse {
    pub by_peer: HashMap<IpAddr, MessageHistory>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FsmEventBuffer {
    /// All FSM events (high frequency, includes all timers)
    All,
    /// Major events only (state transitions, admin, new connections)
    Major,
}

#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct FsmHistoryRequest {
    /// ASN of the BGP router
    pub asn: u32,
    /// Optional peer filter - if None, returns history for all peers
    pub peer: Option<IpAddr>,
    /// Which buffer to retrieve - if None, returns major buffer
    pub buffer: Option<FsmEventBuffer>,
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct FsmHistoryResponse {
    /// Events organized by peer address Each peer's value contains only
    /// the events from the requested buffer
    pub by_peer: HashMap<IpAddr, Vec<FsmEventRecord>>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistory {
    pub received: VecDeque<MessageHistoryEntry>,
    pub sent: VecDeque<MessageHistoryEntry>,
}

impl From<LiveMessageHistory> for MessageHistory {
    fn from(history: LiveMessageHistory) -> Self {
        Self {
            received: history
                .received
                .into_iter()
                .map(MessageHistoryEntry::from)
                .collect(),
            sent: history
                .sent
                .into_iter()
                .map(MessageHistoryEntry::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistoryEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub message: Message,
    pub connection_id: ConnectionId,
}

impl From<LiveMessageHistoryEntry> for MessageHistoryEntry {
    fn from(entry: LiveMessageHistoryEntry) -> Self {
        Self {
            timestamp: entry.timestamp,
            message: Message::from(entry.message),
            connection_id: entry.connection_id,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Message {
    Open(OpenMessage),
    Update(UpdateMessage),
    Notification(NotificationMessage),
    KeepAlive,
    RouteRefresh(RouteRefreshMessage),
}

impl From<bgp::messages::Message> for Message {
    fn from(msg: bgp::messages::Message) -> Self {
        match msg {
            bgp::messages::Message::Open(open) => Self::Open(open),
            bgp::messages::Message::Update(update) => {
                Self::Update(UpdateMessage::from(update))
            }
            bgp::messages::Message::Notification(notif) => {
                Self::Notification(notif)
            }
            bgp::messages::Message::KeepAlive => Self::KeepAlive,
            bgp::messages::Message::RouteRefresh(rr) => Self::RouteRefresh(rr),
        }
    }
}

#[derive(
    Debug, PartialEq, Eq, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct UpdateMessage {
    pub withdrawn: Vec<RdbPrefix>,
    pub path_attributes: Vec<PathAttributeV1>,
    pub nlri: Vec<RdbPrefix>,
}

impl From<bgp::messages::UpdateMessage> for UpdateMessage {
    fn from(msg: bgp::messages::UpdateMessage) -> Self {
        // The latest UpdateMessage carries IPv4-only NLRI in its body; IPv6
        // NLRI lives in MP_REACH/UNREACH path attributes, which v2 does not
        // surface. Converting v4 prefixes back into the V4/V6 enum gives the
        // pre-MP-BGP wire shape.
        Self {
            withdrawn: msg.withdrawn.into_iter().map(RdbPrefix::V4).collect(),
            path_attributes: msg
                .path_attributes
                .into_iter()
                .filter_map(Option::<PathAttributeV1>::from)
                .collect(),
            nlri: msg.nlri.into_iter().map(RdbPrefix::V4).collect(),
        }
    }
}
