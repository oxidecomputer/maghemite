// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `IPV6_BASIC` of the Maghemite Admin API.
//!
//! Added IPv6 static routes, RIB query filtering, and richer message/FSM
//! history endpoints.

pub mod bgp;
pub mod rib;
pub mod static_routes;
