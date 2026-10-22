// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::Deserialize;

use super::history::HistoryBufferSelector;
use crate::v1::bgp::peer::PeerId;
use crate::v2::bgp::history::MessageDirection;
use crate::v5;

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

// ---------------------------------------------------------------------------
// Upgrade conversions: v5 → v13
// ---------------------------------------------------------------------------

/// Earlier versions had a single message buffer that included keepalives, so
/// they keep receiving the `all` buffer.
impl From<v5::bgp::session::MessageHistoryRequest> for MessageHistoryRequest {
    fn from(rq: v5::bgp::session::MessageHistoryRequest) -> Self {
        let v5::bgp::session::MessageHistoryRequest {
            asn,
            peer,
            direction,
        } = rq;
        Self {
            asn,
            peer,
            direction,
            buffer: Some(HistoryBufferSelector::All),
        }
    }
}

impl From<v5::bgp::session::FsmHistoryRequest> for FsmHistoryRequest {
    fn from(rq: v5::bgp::session::FsmHistoryRequest) -> Self {
        let v5::bgp::session::FsmHistoryRequest { asn, peer, buffer } = rq;
        Self {
            asn,
            peer,
            buffer: buffer.map(HistoryBufferSelector::from),
        }
    }
}
