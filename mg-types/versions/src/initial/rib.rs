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

impl From<rdb::db::Rib> for Rib {
    fn from(value: rdb::db::Rib) -> Self {
        Rib(value
            .into_iter()
            .map(|(k, v)| {
                let paths_v1: BTreeSet<Path> =
                    v.into_iter().map(Path::from).collect();
                (k.to_string(), paths_v1)
            })
            .collect())
    }
}

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
