// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{v1, v12};
use num_enum::TryFromPrimitive;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::num::NonZeroU8;

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    SingleHop,
    MultiHop,
}

impl From<v1::bfd::SessionMode> for SessionMode {
    fn from(old: v1::bfd::SessionMode) -> Self {
        match old {
            v1::bfd::SessionMode::SingleHop => Self::SingleHop,
            v1::bfd::SessionMode::MultiHop => Self::MultiHop,
        }
    }
}

impl From<SessionMode> for v1::bfd::SessionMode {
    fn from(new: SessionMode) -> Self {
        match new {
            SessionMode::SingleHop => Self::SingleHop,
            SessionMode::MultiHop => Self::MultiHop,
        }
    }
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
#[serde(rename_all = "snake_case")]
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

impl From<BfdPeerState> for v1::bfd::BfdPeerState {
    fn from(new: BfdPeerState) -> Self {
        match new {
            BfdPeerState::AdminDown => Self::AdminDown,
            BfdPeerState::Down => Self::Down,
            BfdPeerState::Init => Self::Init,
            BfdPeerState::Up => Self::Up,
        }
    }
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub struct BfdPeerConfig {
    /// Address of the peer to add.
    pub peer: IpAddr,
    /// Address to listen on for control messages from the peer.
    pub listen: IpAddr,
    /// Acceptable time between control messages in microseconds.
    pub required_rx: u64,
    /// Detection threshold for connectivity as a multipler to required_rx
    pub detection_threshold: NonZeroU8,
    /// Mode is single-hop (RFC 5881) or multi-hop (RFC 5883).
    pub mode: SessionMode,
}

impl From<v12::bfd::BfdPeerConfig> for BfdPeerConfig {
    fn from(old: v12::bfd::BfdPeerConfig) -> Self {
        let v12::bfd::BfdPeerConfig {
            peer,
            listen,
            required_rx,
            detection_threshold,
            mode,
        } = old;
        Self {
            peer,
            listen,
            required_rx,
            detection_threshold,
            mode: mode.into(),
        }
    }
}

impl From<BfdPeerConfig> for v12::bfd::BfdPeerConfig {
    fn from(new: BfdPeerConfig) -> Self {
        let BfdPeerConfig {
            peer,
            listen,
            required_rx,
            detection_threshold,
            mode,
        } = new;
        Self {
            peer,
            listen,
            required_rx,
            detection_threshold,
            mode: mode.into(),
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BfdPeerInfo {
    pub config: BfdPeerConfig,
    pub state: BfdPeerState,
}

impl From<BfdPeerInfo> for v12::bfd::BfdPeerInfo {
    fn from(new: BfdPeerInfo) -> Self {
        let BfdPeerInfo { config, state } = new;
        Self {
            config: config.into(),
            state: state.into(),
        }
    }
}
