// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Conversions from `rdb::db::Rib` (a business-logic type) into the
// versioned `Rib` shapes live in the `mg-types` facade crate (see
// `mg-types/src/rib.rs`). Keeping them out of `mg-types-versions`
// preserves the leaf-crate property required by RFD 619.
