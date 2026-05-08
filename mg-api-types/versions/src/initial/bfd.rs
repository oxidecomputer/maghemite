// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Request to remove a peer from the daemon.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct DeleteBfdPeerPathParams {
    /// Address of the peer to remove.
    pub addr: IpAddr,
}
