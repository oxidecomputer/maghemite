// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types from API version 2 (PEER_DURATIONS) that changed in version 3
//! (MULTICAST_SUPPORT).
//!
//! Tracks how long each DDM peer has been in its current state and exposes
//! that through the `/peers` endpoint with duration information.

pub mod db;
