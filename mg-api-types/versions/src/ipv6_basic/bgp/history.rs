// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::v1::bgp::config::PeerTimers;
use crate::v1::bgp::messages::NotificationMessage;
use crate::v1::bgp::messages::OpenMessage;
use crate::v1::bgp::messages::PathAttribute;
use crate::v1::bgp::messages::RouteRefreshMessage;
use crate::v1::rdb::prefix::Prefix;
use crate::v1::rdb::prefix::Prefix6;
use crate::v2;
use crate::v2::bgp::session::ConnectionId;
use crate::v2::bgp::session::FsmEventRecord;
use crate::v2::bgp::session::FsmStateKind;
use crate::v4;

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

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[schemars(rename = "PeerInfo")]
pub struct PeerInfo {
    pub state: FsmStateKind,
    pub asn: Option<u32>,
    pub duration_millis: u64,
    pub timers: PeerTimers,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Origin6 {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix6>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistory {
    pub received: VecDeque<MessageHistoryEntry>,
    pub sent: VecDeque<MessageHistoryEntry>,
}

impl From<v2::bgp::session::MessageHistory> for MessageHistory {
    fn from(history: v2::bgp::session::MessageHistory) -> Self {
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

impl From<v2::bgp::session::MessageHistoryEntry> for MessageHistoryEntry {
    fn from(entry: v2::bgp::session::MessageHistoryEntry) -> Self {
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

impl From<v4::bgp::messages::Message> for Message {
    fn from(msg: v4::bgp::messages::Message) -> Self {
        match msg {
            v4::bgp::messages::Message::Open(open) => Self::Open(open),
            v4::bgp::messages::Message::Update(update) => {
                Self::Update(UpdateMessage::from(update))
            }
            v4::bgp::messages::Message::Notification(notif) => {
                Self::Notification(notif)
            }
            v4::bgp::messages::Message::KeepAlive => Self::KeepAlive,
            v4::bgp::messages::Message::RouteRefresh(rr) => {
                Self::RouteRefresh(rr)
            }
        }
    }
}

#[derive(
    Debug, PartialEq, Eq, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct UpdateMessage {
    pub withdrawn: Vec<Prefix>,
    pub path_attributes: Vec<PathAttribute>,
    pub nlri: Vec<Prefix>,
}

impl From<v4::bgp::messages::UpdateMessage> for UpdateMessage {
    fn from(msg: v4::bgp::messages::UpdateMessage) -> Self {
        // The latest UpdateMessage carries IPv4-only NLRI in its body; IPv6
        // NLRI lives in MP_REACH/UNREACH path attributes, which v2 does not
        // surface. Converting v4 prefixes back into the V4/V6 enum gives the
        // pre-MP-BGP wire shape.
        Self {
            withdrawn: msg.withdrawn.into_iter().map(Prefix::V4).collect(),
            path_attributes: msg
                .path_attributes
                .into_iter()
                .filter_map(Option::<PathAttribute>::from)
                .collect(),
            nlri: msg.nlri.into_iter().map(Prefix::V4).collect(),
        }
    }
}

impl From<PeerInfo> for crate::v1::bgp::config::PeerInfo {
    fn from(info: PeerInfo) -> Self {
        let PeerInfo {
            state,
            asn,
            duration_millis,
            timers,
        } = info;
        Self {
            state: crate::v1::bgp::config::FsmStateKind::from(state),
            asn,
            duration_millis,
            timers,
        }
    }
}
