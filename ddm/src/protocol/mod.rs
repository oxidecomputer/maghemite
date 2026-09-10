// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Pure protocol logic: events in, actions out. Nothing in this module
//! performs I/O, spawns threads, reads the clock, or is gated on a target
//! platform, so all of it is reachable from `cargo test` on any host.

pub mod rib;
