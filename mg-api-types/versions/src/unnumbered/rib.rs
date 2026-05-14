// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{BTreeMap, BTreeSet};

use super::rdb::path::Path;
use crate::v1;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct Rib(pub BTreeMap<String, BTreeSet<Path>>);

pub type GetRibResult = BTreeMap<String, BTreeSet<Path>>;

/// Downgrade a v5 `GetRibResult` to its v1 shape by mapping each `Path`
/// through `From<v5::path::Path> for v1::path::Path`. Used by the
/// pre-UNNUMBERED `static_list_v{4,6}_routes` shims.
pub fn get_rib_result_into_v1(value: GetRibResult) -> v1::rib::GetRibResult {
    value
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
        .collect()
}

impl From<Rib> for v1::rib::Rib {
    fn from(value: Rib) -> Self {
        let Rib(inner) = value;
        v1::rib::Rib(
            inner
                .into_iter()
                .map(|(k, v)| {
                    let paths_v1: BTreeSet<v1::rdb::path::Path> =
                        v.into_iter().map(v1::rdb::path::Path::from).collect();
                    (k, paths_v1)
                })
                .collect(),
        )
    }
}
