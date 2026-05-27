// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;
use std::time::Duration;

use crate::v1::db::RouterKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Status of a DDM peer, including how long the peer has been in its
/// current state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "duration")]
pub enum PeerStatus {
    Init(Duration),
    Solicit(Duration),
    Exchange(Duration),
    Expired(Duration),
}

/// Information about a DDM peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PeerInfo {
    pub status: PeerStatus,
    pub addr: Ipv6Addr,
    pub host: String,
    pub kind: RouterKind,
}

// Response backwards-compat: convert v2 PeerInfo to v1 PeerInfo.
impl From<PeerInfo> for crate::v1::db::PeerInfo {
    fn from(value: PeerInfo) -> Self {
        Self {
            status: match value.status {
                PeerStatus::Init(_) | PeerStatus::Solicit(_) => {
                    crate::v1::db::PeerStatus::NoContact
                }
                PeerStatus::Exchange(_) => crate::v1::db::PeerStatus::Active,
                PeerStatus::Expired(_) => crate::v1::db::PeerStatus::Expired,
            },
            addr: value.addr,
            host: value.host,
            kind: value.kind,
        }
    }
}
