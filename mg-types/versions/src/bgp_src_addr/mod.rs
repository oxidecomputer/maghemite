// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `BGP_SRC_ADDR` of the Maghemite Admin API.
//!
//! Adds optional `src_addr` / `src_port` fields to BGP peer parameters so
//! operators can pin the local endpoint of outbound TCP connections.

pub mod bgp;
