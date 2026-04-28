// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub use mg_types_versions::latest::rib::*;

use std::collections::{BTreeMap, BTreeSet};

use mg_types_versions::latest;
use mg_types_versions::v1;
use rdb::types::ProtocolFilter;
use rdb::{Path as RdbPath, Prefix};
use rdb_types_versions::v1::path::Path as PathV1;

// `rdb::db::Rib` -> versioned `Rib` conversions live here as free
// functions. The orphan rule prevents an `impl From<rdb::db::Rib> for
// vN::rib::Rib` in this crate (both types are foreign), and putting the
// impl in `mg-types-versions` would force that leaf crate to depend on
// `rdb` (forbidden by RFD 619).
pub fn rib_latest_from_rdb(value: rdb::db::Rib) -> latest::rib::Rib {
    latest::rib::Rib(
        value.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
    )
}

pub fn rib_v1_from_rdb(value: rdb::db::Rib) -> v1::rib::Rib {
    v1::rib::Rib(
        value
            .into_iter()
            .map(|(k, v)| {
                let paths_v1: BTreeSet<PathV1> =
                    v.into_iter().map(PathV1::from).collect();
                (k.to_string(), paths_v1)
            })
            .collect(),
    )
}

pub fn filter_rib_by_protocol(
    rib: BTreeMap<Prefix, BTreeSet<RdbPath>>,
    protocol_filter: Option<ProtocolFilter>,
) -> BTreeMap<Prefix, BTreeSet<RdbPath>> {
    match protocol_filter {
        None => rib,
        Some(filter) => {
            let mut filtered = BTreeMap::new();

            for (prefix, paths) in rib {
                let filtered_paths: BTreeSet<RdbPath> = paths
                    .into_iter()
                    .filter(|path| match filter {
                        ProtocolFilter::Bgp => path.bgp.is_some(),
                        ProtocolFilter::Static => path.bgp.is_none(),
                    })
                    .collect();

                if !filtered_paths.is_empty() {
                    filtered.insert(prefix, filtered_paths);
                }
            }

            filtered
        }
    }
}
