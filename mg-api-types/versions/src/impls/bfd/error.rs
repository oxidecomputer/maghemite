// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// Errors converting from older API request versions.
#[derive(Debug, thiserror::Error)]
pub enum BfdRequestError {
    #[error("detection threshold must be nonzero")]
    DetectionThresholdZero,
}
