// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `MULTI_ROUTER` of the Maghemite Admin API.
//!
//! Introduces named router instances (VRF-like), each with its own RIB and
//! its own tunnel endpoint (TEP) address, and a declarative reconciler
//! endpoint (`PUT /routers`) that applies the full desired router list at
//! once.

pub mod router;
