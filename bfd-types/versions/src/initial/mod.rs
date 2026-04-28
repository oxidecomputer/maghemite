// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use num_enum::TryFromPrimitive;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub struct BfdPeerConfig {
    /// Address of the peer to add.
    pub peer: IpAddr,
    /// Address to listen on for control messages from the peer.
    pub listen: IpAddr,
    /// Acceptable time between control messages in microseconds.
    pub required_rx: u64,
    /// Detection threshold for connectivity as a multipler to required_rx
    pub detection_threshold: u8,
    /// Mode is single-hop (RFC 5881) or multi-hop (RFC 5883).
    pub mode: SessionMode,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub enum SessionMode {
    SingleHop,
    MultiHop,
}

/// The possible peer states. See the `State` trait implementations `Down`,
/// `Init`, and `Up` for detailed semantics. Data representation is u8 as this
/// enum is used as a part of the BFD wire protocol.
#[derive(
    Default,
    PartialEq,
    Debug,
    Copy,
    Clone,
    TryFromPrimitive,
    JsonSchema,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
pub enum BfdPeerState {
    /// A stable down state. Non-responsive to incoming messages.
    AdminDown = 0,

    /// The initial state.
    #[default]
    Down = 1,

    /// The peer has detected a remote peer in the down state.
    Init = 2,

    /// The peer has detected a remote peer in the up or init state while in the
    /// init state.
    Up = 3,
}

impl BfdPeerState {
    /// A helper function to transition between enum and wire representations
    /// for peer states.
    pub fn wire_format(&self) -> u8 {
        (*self as u8) << 6
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BfdPeerInfo {
    pub config: BfdPeerConfig,
    pub state: BfdPeerState,
}
