// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Version `MULTICAST_SUPPORT` of the Maghemite Admin API.
//!
//! Added MRIB (Multicast Routing Information Base) support with static
//! multicast route management, RPF verification, and query endpoints.

pub mod mrib;
