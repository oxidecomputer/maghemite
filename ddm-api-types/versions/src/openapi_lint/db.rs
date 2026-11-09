// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;
use std::time::Duration;

use crate::v1::db::RouterKind;
use crate::v2;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Status of a DDM peer, including how long the peer has been in its
/// current state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "duration", rename_all = "snake_case")]
pub enum PeerStatus {
    Init(Duration),
    Solicit(Duration),
    Exchange(Duration),
    Expired(Duration),
}

impl From<PeerStatus> for v2::db::PeerStatus {
    fn from(new: PeerStatus) -> Self {
        match new {
            PeerStatus::Init(d) => Self::Init(d),
            PeerStatus::Solicit(d) => Self::Solicit(d),
            PeerStatus::Exchange(d) => Self::Exchange(d),
            PeerStatus::Expired(d) => Self::Expired(d),
        }
    }
}

/// Information about a DDM peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PeerInfo {
    pub status: PeerStatus,
    pub addr: Ipv6Addr,
    pub host: String,
    pub kind: RouterKind,
}

impl From<PeerInfo> for v2::db::PeerInfo {
    fn from(new: PeerInfo) -> Self {
        let PeerInfo {
            status,
            addr,
            host,
            kind,
        } = new;
        Self {
            status: status.into(),
            addr,
            host,
            kind,
        }
    }
}
