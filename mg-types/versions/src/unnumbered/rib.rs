// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{BTreeMap, BTreeSet};

use rdb::PathV2;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Rib for VERSION_UNNUMBERED..VERSION_SPRING_CLEANING.
///
/// Uses PathV2 (without origin/internal/peer_ip fields added in
/// SPRING_CLEANING).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct Rib(pub BTreeMap<String, BTreeSet<PathV2>>);
