// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v5;

/// A multicast route with the interface on which its peer was discovered.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct ImportedMulticastRoute {
    /// The imported multicast route.
    pub route: v5::db::MulticastRoute,
    /// Local interface on which the advertising peer was discovered.
    pub if_name: String,
}

impl From<ImportedMulticastRoute> for v5::db::MulticastRoute {
    fn from(imported: ImportedMulticastRoute) -> Self {
        imported.route
    }
}
