// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU8;

use rdb::PathV1;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// V1 Rib with PathV1.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct Rib(pub BTreeMap<String, BTreeSet<PathV1>>);

impl From<rdb::db::Rib> for Rib {
    fn from(value: rdb::db::Rib) -> Self {
        Rib(
            value
                .into_iter()
                .map(|(k, v)| {
                    let paths_v1: BTreeSet<PathV1> =
                        v.into_iter().map(PathV1::from).collect();
                    (k.to_string(), paths_v1)
                })
                .collect(),
        )
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

pub type GetRibResult = BTreeMap<String, BTreeSet<rdb::Path>>;
