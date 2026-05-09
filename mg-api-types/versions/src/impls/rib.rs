// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Cross-version conversions from the runtime `latest::rdb::Rib` shape
// into the versioned admin-API `Rib` shapes. Both source and target
// types live in this crate, so the orphan rule is satisfied without
// pulling `rdb` in as a dependency.

use std::collections::BTreeSet;

use crate::{latest, v1};

impl From<latest::rdb::Rib> for latest::rib::Rib {
    fn from(value: latest::rdb::Rib) -> Self {
        latest::rib::Rib(
            value.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        )
    }
}

impl From<latest::rdb::Rib> for v1::rib::Rib {
    fn from(value: latest::rdb::Rib) -> Self {
        v1::rib::Rib(
            value
                .into_iter()
                .map(|(k, v)| {
                    let paths_v1: BTreeSet<v1::rdb::path::Path> =
                        v.into_iter().map(v1::rdb::path::Path::from).collect();
                    (k.to_string(), paths_v1)
                })
                .collect(),
        )
    }
}
