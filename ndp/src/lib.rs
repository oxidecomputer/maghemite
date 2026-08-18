//! Neighbor discovery protocol support crate

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

mod packet;
mod router_discovery;
mod util;

pub use packet::Icmp6RouterAdvertisement;
pub use router_discovery::*;
