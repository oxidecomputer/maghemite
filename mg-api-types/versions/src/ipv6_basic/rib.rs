// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use rdb_types_versions::v1::{AddressFamily, ProtocolFilter};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RibQuery {
    /// Filter by address family (None means all families)
    #[serde(default)]
    pub address_family: Option<AddressFamily>,
    /// Filter by protocol (optional)
    pub protocol: Option<ProtocolFilter>,
}
