// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `UNNUMBERED` of the Maghemite Admin API.
//!
//! Added unnumbered BGP neighbor support, unified neighbor selectors using
//! PeerId, NDP management endpoints, and updated RIB/history types to support
//! both numbered and unnumbered peers.

pub mod bgp;
pub mod ndp;
pub mod rib;
