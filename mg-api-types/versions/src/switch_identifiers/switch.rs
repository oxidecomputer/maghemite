// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::Serialize;

/// Identifiers for a switch.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct SwitchIdentifiers {
    /// The slot number of the switch being managed.
    ///
    /// MGS uses u16 for this internally.
    pub slot: Option<u16>,
}
