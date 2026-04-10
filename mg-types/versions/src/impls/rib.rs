// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{latest, v5};

impl From<rdb::db::Rib> for latest::rib::Rib {
    fn from(value: rdb::db::Rib) -> Self {
        latest::rib::Rib(
            value.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        )
    }
}

impl From<rdb::db::Rib> for v5::rib::Rib {
    fn from(value: rdb::db::Rib) -> Self {
        v5::rib::Rib(
            value
                .into_iter()
                .map(|(k, v)| {
                    let paths: std::collections::BTreeSet<rdb::PathV2> =
                        v.into_iter().map(rdb::PathV2::from).collect();
                    (k.to_string(), paths)
                })
                .collect(),
        )
    }
}
