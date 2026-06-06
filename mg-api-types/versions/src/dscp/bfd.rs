// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::v1;
use crate::v11::common::headers::Dscp;

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

impl From<v1::bfd::BfdPeerConfig> for BfdPeerConfig {
    fn from(v1: v1::bfd::BfdPeerConfig) -> Self {
        let v1::bfd::BfdPeerConfig {
            peer,
            listen,
            required_rx,
            detection_threshold,
            mode,
        } = v1;
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

impl From<BfdPeerConfig> for v1::bfd::BfdPeerConfig {
    fn from(v10: BfdPeerConfig) -> Self {
        let BfdPeerConfig {
            peer,
            listen,
            required_rx,
            detection_threshold,
            mode,
            dscp: _,
        } = v10;
        Self {
            peer,
            listen,
            required_rx,
            detection_threshold,
            mode,
        }
    }
}

impl From<v1::bfd::BfdPeerInfo> for crate::v11::bfd::BfdPeerInfo {
    fn from(v1: v1::bfd::BfdPeerInfo) -> Self {
        let v1::bfd::BfdPeerInfo { config, state } = v1;
        Self {
            config: config.into(),
            state,
        }
    }
}

impl From<crate::v11::bfd::BfdPeerInfo> for v1::bfd::BfdPeerInfo {
    fn from(v10: crate::v11::bfd::BfdPeerInfo) -> Self {
        let crate::v11::bfd::BfdPeerInfo { config, state } = v10;
        Self {
            config: config.into(),
            state,
        }
    }
}
