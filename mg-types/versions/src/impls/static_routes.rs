// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// This module intentionally left empty. The previous
// `From<latest::static_routes::StaticRouteN> for rdb::StaticRouteKey`
// impls were removed because they forced `mg-types-versions` to depend on
// the `rdb` business-logic crate, violating RFD 619's leaf-crate rule for
// `*-types-versions` crates. The conversions now live as free functions in
// `mgd/src/static_admin.rs`.
