// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::atomic::AtomicU64;

#[derive(Default)]
pub struct MgLowerStats {
    pub routes_blocked_by_link_state: AtomicU64,
}
