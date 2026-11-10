// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `OPENAPI_LINT` of the Maghemite Admin API.
//!
//! Makes the API pass openapi-lint: enum variants are serialized as
//! snake_case, and enums that mix unit and data-carrying variants use serde
//! adjacent tagging.

pub mod bfd;
pub mod bgp;
pub mod rdb;
pub mod rib;
