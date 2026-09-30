// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Duration;

use crate::latest::unnumbered::DiscoveredRouter;

impl DiscoveredRouter {
    /// Time remaining until this entry expires if no further Router
    /// Advertisement is received. Zero means expiry is imminent; an
    /// already-expired entry is never reported as a discovered router.
    pub fn time_until_expiration(&self) -> Duration {
        self.effective_reachable_time
            .saturating_sub(self.time_since_last_rx)
    }
}
