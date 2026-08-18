// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Facade for the latest versions of the Maghemite admin API types.
//!
//! Each submodule wildcard-re-exports from the corresponding
//! `mg_api_types_versions::latest::<domain>` module. Business logic
//! that does not need to distinguish API versions should depend on this
//! crate and reach types as `mg_api_types::<domain>::Type`; only code
//! that performs cross-version conversions (e.g. ledger migrations,
//! progenitor `replace` shims) should depend on `mg-api-types-versions`
//! directly.
//!
//! For the versioned definitions and the rules governing how new
//! versions are added, see `mg-api-types-versions` and [RFD 619].
//!
//! [RFD 619]: https://rfd.shared.oxide.computer/rfd/619

pub mod bfd;
pub mod bgp;
pub mod rdb;
pub mod rib;
pub mod static_routes;
pub mod switch;
pub mod unnumbered;
