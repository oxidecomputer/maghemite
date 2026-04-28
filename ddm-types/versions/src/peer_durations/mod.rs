// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `PEER_DURATIONS` of the DDM Admin API.
//!
//! Tracks how long each DDM peer has been in its current state and exposes
//! that through the `/peers` endpoint with duration information.

pub mod db;
