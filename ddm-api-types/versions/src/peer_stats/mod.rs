// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `PEER_STATS` of the DDM Admin API.
//!
//! Exposes the counters of each routing session, and keys `/peers` by
//! address object name so sessions without a discovered peer are visible.

pub mod admin;
pub mod db;
