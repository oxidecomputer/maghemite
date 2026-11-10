// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub(crate) mod error;

use crate::latest::bfd::BfdPeerState;

impl BfdPeerState {
    /// A helper function to transition between enum and wire representations
    /// for peer states.
    pub fn wire_format(&self) -> u8 {
        (*self as u8) << 6
    }
}
