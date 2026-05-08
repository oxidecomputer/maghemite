// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod bfd;
pub mod bgp;
pub mod ndp;
pub mod rib;
pub mod static_routes;
pub mod switch;

// Flat re-exports of routing-database types (formerly the `rdb-types`
// facade). Consumers reach `Prefix4`, `AddressFamily`, etc. via
// `mg_api_types::*`; the progenitor `replace = {}` block in
// `mg-admin-client` depends on these top-level paths.
pub use mg_api_types_versions::latest::rdb::neighbor::*;
pub use mg_api_types_versions::latest::rdb::path::*;
pub use mg_api_types_versions::latest::rdb::peer::*;
pub use mg_api_types_versions::latest::rdb::policy::*;
pub use mg_api_types_versions::latest::rdb::prefix::*;
pub use mg_api_types_versions::latest::rdb::router::*;
pub use mg_api_types_versions::latest::rdb::{AddressFamily, ProtocolFilter};
