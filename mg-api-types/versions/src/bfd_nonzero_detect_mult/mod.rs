// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `BFD_NONZER_DETECT_MULT` of the Maghemite Admin API.
//!
//! Changes `BfdPeerConfig::detection_threshold` from `u8` to `NonZeroU8`. (Per
//! RFC 5880, detection multipliers must be nonzero.)

pub mod bfd;
