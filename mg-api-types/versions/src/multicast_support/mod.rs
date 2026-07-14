// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Version `MULTICAST_SUPPORT` of the Maghemite Admin API.
//!
//! Adds MRIB (Multicast Routing Information Base) endpoints for static
//! multicast route management and query of imported and selected multicast
//! routes. Introduces the supporting wire types (validated unicast and
//! multicast addresses, the underlay group within `ff04::/64`, multicast
//! route keys, and route entries).

pub mod mrib;
