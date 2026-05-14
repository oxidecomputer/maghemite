// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Runtime routing-information-base type aliases used by `rdb`.
//!
//! These are convenience aliases — not part of any published API schema.
//! The published wire-shaped RIB is `mg_api_types::rib::Rib`; the
//! [`RibExt::into_latest_api_rib`] method converts to it.

use mg_api_types::rdb::path::Path;
use mg_api_types::rdb::prefix::{Prefix, Prefix4, Prefix6};
use mg_api_types::rdb::rib::ProtocolFilter;
use std::collections::{BTreeMap, BTreeSet};

/// Runtime IPv4+IPv6 routing-information-base shape.
pub type Rib = BTreeMap<Prefix, BTreeSet<Path>>;
/// Runtime IPv4-only RIB.
pub type Rib4 = BTreeMap<Prefix4, BTreeSet<Path>>;
/// Runtime IPv6-only RIB.
pub type Rib6 = BTreeMap<Prefix6, BTreeSet<Path>>;

/// Extension methods on [`Rib`] that don't fit on the underlying `BTreeMap`.
///
/// Lives next to the type alias so the conversion impls stay in sync with
/// `Rib`'s shape, even though the orphan rule would let mg-api-types-versions
/// take a structural `BTreeMap<...>` arg too.
pub trait RibExt {
    /// Drop paths whose protocol does not match `protocol_filter`. `None`
    /// is a pass-through.
    fn filter_by_protocol(
        self,
        protocol_filter: Option<ProtocolFilter>,
    ) -> Self;

    /// Convert to the published latest-API RIB shape (`String`-keyed,
    /// `BTreeSet<latest::Path>`-valued).
    fn into_latest_api_rib(self) -> mg_api_types::rib::Rib;
}

impl RibExt for Rib {
    fn filter_by_protocol(
        self,
        protocol_filter: Option<ProtocolFilter>,
    ) -> Self {
        let Some(filter) = protocol_filter else {
            return self;
        };
        let mut filtered: Rib = BTreeMap::new();
        for (prefix, paths) in self {
            let filtered_paths: BTreeSet<_> = paths
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

    fn into_latest_api_rib(self) -> mg_api_types::rib::Rib {
        mg_api_types::rib::Rib(
            self.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        )
    }
}
