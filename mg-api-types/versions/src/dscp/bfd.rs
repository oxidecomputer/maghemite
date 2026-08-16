// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::num::NonZeroU8;

use crate::v1;
use crate::v13::common::headers::Dscp;

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
    pub mode: v1::bfd::SessionMode,
    /// DSCP value for BFD UDP packets (0-63). Defaults to CS6 (48) when None.
    #[serde(default)]
    pub dscp: Option<Dscp>,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BfdPeerInfo {
    pub config: BfdPeerConfig,
    pub state: v1::bfd::BfdPeerState,
}

impl From<crate::v12::bfd::BfdPeerConfig> for BfdPeerConfig {
    fn from(v12: crate::v12::bfd::BfdPeerConfig) -> Self {
        let crate::v12::bfd::BfdPeerConfig {
            peer,
            listen,
            required_rx,
            detection_threshold,
            mode,
        } = v12;
        Self {
            peer,
            listen,
            required_rx,
            detection_threshold,
            mode,
            dscp: None,
        }
    }
}

impl From<BfdPeerConfig> for crate::v12::bfd::BfdPeerConfig {
    fn from(v13: BfdPeerConfig) -> Self {
        let BfdPeerConfig {
            peer,
            listen,
            required_rx,
            detection_threshold,
            mode,
            dscp: _,
        } = v13;
        Self {
            peer,
            listen,
            required_rx,
            detection_threshold,
            mode,
        }
    }
}

impl From<crate::v12::bfd::BfdPeerInfo> for BfdPeerInfo {
    fn from(v12: crate::v12::bfd::BfdPeerInfo) -> Self {
        let crate::v12::bfd::BfdPeerInfo { config, state } = v12;
        Self {
            config: config.into(),
            state,
        }
    }
}

impl From<BfdPeerInfo> for crate::v12::bfd::BfdPeerInfo {
    fn from(v13: BfdPeerInfo) -> Self {
        let BfdPeerInfo { config, state } = v13;
        Self {
            config: config.into(),
            state,
        }
    }
}
