// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `UNIFY_BGP_NEIGHBORS` of the Maghemite Admin API.
//!
//! Collapses the numbered and unnumbered BGP neighbor types and endpoints
//! into a single `PeerId`-identified `Neighbor`, with an explicit `port` and
//! the former `BgpPeerParameters` fields inlined.

pub mod bgp;
