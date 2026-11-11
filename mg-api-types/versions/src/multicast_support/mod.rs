// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `MULTICAST_SUPPORT` of the Maghemite Admin API.
//!
//! This introduces the MRIB (Multicast Routing Information Base) types. See
//! [`mrib`] for the validated addresses, route keys, and routes.
//!
//! This version adds MRIB endpoints for static multicast route management and
//! for querying imported and selected multicast routes.

pub mod mrib;
