// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub use mg_api_types_versions::latest::rdb::*;

// Flatten high-traffic submodule types into the facade for ergonomic
// access by business logic. The versioned `latest::rdb` module keeps
// these under their semantic submodules so re-exports there stay
// grouped by version (RFD 619, "Versions crates re-export the latest
// versions of each type"); flattening lives here instead of in
// `latest` so `mg_api_types::rdb::Prefix` etc. remain callable without
// muddying the version-grouped block.
pub use mg_api_types_versions::latest::rdb::neighbor::{
    BgpNeighborInfo, BgpNeighborParameters, BgpUnnumberedNeighborInfo,
};
pub use mg_api_types_versions::latest::rdb::path::{BgpPathProperties, Path};
pub use mg_api_types_versions::latest::rdb::prefix::{Prefix, Prefix4, Prefix6};
pub use mg_api_types_versions::latest::rdb::router::BgpRouterInfo;
