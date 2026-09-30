// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `UNNUMBERED_REFACTOR` of the Maghemite Admin API.
//!
//! Moves unnumbered/NDP endpoints under `/bgp/unnumbered/...` and renames
//! interface runtime state from the NDP-thread-specific API shape to router
//! discovery runtime state.

pub mod unnumbered;
