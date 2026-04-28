// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v1::prefix::Prefix;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Legacy import/export policy type for v1/v2 API compatibility.
///
/// This type uses mixed IPv4/IPv6 prefixes and is used at the API boundary.
/// For internal use, convert to typed variants via
/// `ImportExportPolicy4::from(...)` / `ImportExportPolicy6::from(...)`.
#[derive(
    Default, Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq,
)]
pub enum ImportExportPolicy {
    #[default]
    NoFiltering,
    Allow(BTreeSet<Prefix>),
}
