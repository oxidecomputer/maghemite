// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU8;

use rdb_types_versions::v1::path::Path;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// V1 Rib with v1::path::Path.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct Rib(pub BTreeMap<String, BTreeSet<Path>>);

// `From<rdb::db::Rib> for Rib` lives in the `mg-types` facade crate
// (`mg-types/src/rib.rs`) to keep `mg-types-versions` from depending on
// the `rdb` business-logic crate (see RFD 619 leaf-crate rule).

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct BestpathFanoutRequest {
    /// Maximum number of equal-cost paths for ECMP forwarding
    pub fanout: NonZeroU8,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct BestpathFanoutResponse {
    /// Current maximum number of equal-cost paths for ECMP forwarding
    pub fanout: NonZeroU8,
}

pub type GetRibResult = BTreeMap<String, BTreeSet<Path>>;
