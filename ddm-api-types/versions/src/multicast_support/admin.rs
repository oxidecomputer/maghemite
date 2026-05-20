// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Admin request types added in version 2 (MULTICAST_SUPPORT).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::db::PeerInfo;

/// Body for `PUT /peer`. Sets `info` at the slot keyed by `if_index`
/// (interface index) in the in-memory peer map.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct PutPeerRequest {
    pub if_index: u32,
    pub info: PeerInfo,
}
