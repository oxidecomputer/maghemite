// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{BTreeMap, BTreeSet};

use rdb_types_versions::v5::path::Path as RdbPath;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct Rib(pub BTreeMap<String, BTreeSet<RdbPath>>);

pub type GetRibResult = BTreeMap<String, BTreeSet<RdbPath>>;

/// Downgrade a v5 `GetRibResult` to its v1 shape by mapping each `Path`
/// through `From<v5::path::Path> for v1::path::Path`. Used by the
/// pre-UNNUMBERED `static_list_v{4,6}_routes` shims.
pub fn get_rib_result_into_v1(
    value: GetRibResult,
) -> crate::v1::rib::GetRibResult {
    value
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
        .collect()
}
