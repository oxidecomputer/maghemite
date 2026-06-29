// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::impls::bfd::error::BfdRequestError;
use crate::v1::bfd as v1;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::num::NonZeroU8;

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
    pub mode: v1::SessionMode,
}

impl From<BfdPeerConfig> for v1::BfdPeerConfig {
    fn from(value: BfdPeerConfig) -> Self {
        Self {
            peer: value.peer,
            listen: value.listen,
            required_rx: value.required_rx,
            detection_threshold: value.detection_threshold.get(),
            mode: value.mode,
        }
    }
}

impl TryFrom<v1::BfdPeerConfig> for BfdPeerConfig {
    type Error = BfdRequestError;

    fn try_from(value: v1::BfdPeerConfig) -> Result<Self, Self::Error> {
        let detection_threshold = NonZeroU8::new(value.detection_threshold)
            .ok_or(BfdRequestError::DetectionThresholdZero)?;

        Ok(Self {
            peer: value.peer,
            listen: value.listen,
            required_rx: value.required_rx,
            detection_threshold,
            mode: value.mode,
        })
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BfdPeerInfo {
    pub config: BfdPeerConfig,
    pub state: v1::BfdPeerState,
}

impl From<BfdPeerInfo> for v1::BfdPeerInfo {
    fn from(value: BfdPeerInfo) -> Self {
        Self {
            config: value.config.into(),
            state: value.state,
        }
    }
}
