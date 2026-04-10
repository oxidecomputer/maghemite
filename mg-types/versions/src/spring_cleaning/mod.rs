// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `SPRING_CLEANING` of the Maghemite Admin API.
//!
//! Adds DSCP support on neighbors, per-AFI peer counters, prefix
//! filtering on RIB queries, message history buffer selection, and
//! generalized static route nexthops (IpAddr + optional interface).

pub mod bgp;
pub mod rib;
pub mod static_routes;
