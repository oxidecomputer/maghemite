// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Cross-version downgrade from the latest published RIB shape to v1.

use std::collections::BTreeSet;

use crate::{latest, v1};

impl From<latest::rib::Rib> for v1::rib::Rib {
    fn from(value: latest::rib::Rib) -> Self {
        let latest::rib::Rib(inner) = value;
        v1::rib::Rib(
            inner
                .into_iter()
                .map(|(k, v)| {
                    let paths_v1: BTreeSet<v1::rdb::path::Path> =
                        v.into_iter().map(v1::rdb::path::Path::from).collect();
                    (k, paths_v1)
                })
                .collect(),
        )
    }
}
