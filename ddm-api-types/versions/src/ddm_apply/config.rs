// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ApplyRequest {
    /// The complete set of dynamically managed interface names DDM should
    /// peer over. Dynamic interfaces not in this set are torn down and their
    /// routes withdrawn. Interfaces supplied on the ddmd command line are
    /// static and unaffected by this request.
    pub ddm_interfaces: BTreeSet<String>,
}
