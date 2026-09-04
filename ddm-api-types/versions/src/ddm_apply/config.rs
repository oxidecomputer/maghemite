// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ApplyRequest {
    /// The complete set of interface names DDM should peer over. Each
    /// interface must carry an IPv6 link-local address. Interfaces not in
    /// this set are torn down and their routes withdrawn.
    pub ddm_interfaces: BTreeSet<String>,
}
