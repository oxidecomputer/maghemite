// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types added in version 3 (MULTICAST_SUPPORT).
//!
//! Adds multicast group origination, route distribution, and per-peer
//! discovery interface name tracking.

pub mod db;
pub mod exchange;
pub mod net;
