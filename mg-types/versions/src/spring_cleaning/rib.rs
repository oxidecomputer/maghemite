// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{BTreeMap, BTreeSet};

use rdb::Path as RdbPath;
use rdb::types::{AddressFamily, ProtocolFilter};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// RIB query with prefix filtering (VERSION_SPRING_CLEANING+).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RibQuery {
    #[serde(default)]
    pub address_family: Option<AddressFamily>,
    pub protocol: Option<ProtocolFilter>,
    /// Exact-match prefix filter (e.g. "10.0.0.0/24").
    #[serde(default)]
    pub prefix: Option<String>,
}

/// Rib for VERSION_SPRING_CLEANING+.
///
/// Uses current rdb::Path (with origin/internal/peer_ip fields).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct Rib(pub BTreeMap<String, BTreeSet<RdbPath>>);
