// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use oxnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

// This was a re-export of the DDMv3 wire type. It is defined here so the
// admin API and the exchange protocol can change independently; its schema is
// identical to the one the re-export published. Doc comments would add
// descriptions to that schema, so this note is a plain comment.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelOrigin {
    pub overlay_prefix: IpNet,
    pub boundary_addr: Ipv6Addr,
    pub vni: u32,
    #[serde(default)]
    pub metric: u64,
}
