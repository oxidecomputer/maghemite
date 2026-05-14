// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v1::rdb::prefix::Prefix;
use crate::v1::rdb::prefix::Prefix4;
use crate::v1::rdb::prefix::Prefix6;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Import/Export policy for IPv4 prefixes only.
#[derive(
    Default, Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq,
)]
pub enum ImportExportPolicy4 {
    #[default]
    NoFiltering,
    Allow(BTreeSet<Prefix4>),
}

/// Import/Export policy for IPv6 prefixes only.
#[derive(
    Default, Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq,
)]
pub enum ImportExportPolicy6 {
    #[default]
    NoFiltering,
    Allow(BTreeSet<Prefix6>),
}

impl crate::v1::bgp::policy::ImportExportPolicy {
    /// Combine v4-introduced per-AF policies back into the v1 mixed-AF
    /// policy. Used by prior-version (v1) endpoints to project the
    /// current per-AF configuration onto the legacy wire shape.
    ///
    /// - If both are `NoFiltering`, returns `NoFiltering`
    /// - Otherwise, unions the allowed prefixes from both into a single set
    pub fn from_per_af_policies(
        v4: &ImportExportPolicy4,
        v6: &ImportExportPolicy6,
    ) -> Self {
        use crate::v1::bgp::policy::ImportExportPolicy as V1;
        match (v4, v6) {
            (
                ImportExportPolicy4::NoFiltering,
                ImportExportPolicy6::NoFiltering,
            ) => V1::NoFiltering,
            (
                ImportExportPolicy4::Allow(v4_prefixes),
                ImportExportPolicy6::NoFiltering,
            ) => {
                let prefixes: BTreeSet<Prefix> =
                    v4_prefixes.iter().map(|p| Prefix::V4(*p)).collect();
                V1::Allow(prefixes)
            }
            (
                ImportExportPolicy4::NoFiltering,
                ImportExportPolicy6::Allow(v6_prefixes),
            ) => {
                let prefixes: BTreeSet<Prefix> =
                    v6_prefixes.iter().map(|p| Prefix::V6(*p)).collect();
                V1::Allow(prefixes)
            }
            (
                ImportExportPolicy4::Allow(v4_prefixes),
                ImportExportPolicy6::Allow(v6_prefixes),
            ) => {
                let mut prefixes: BTreeSet<Prefix> =
                    v4_prefixes.iter().map(|p| Prefix::V4(*p)).collect();
                prefixes.extend(v6_prefixes.iter().map(|p| Prefix::V6(*p)));
                V1::Allow(prefixes)
            }
        }
    }
}

impl From<crate::v1::bgp::policy::ImportExportPolicy> for ImportExportPolicy4 {
    fn from(value: crate::v1::bgp::policy::ImportExportPolicy) -> Self {
        match value {
            crate::v1::bgp::policy::ImportExportPolicy::NoFiltering => {
                ImportExportPolicy4::NoFiltering
            }
            crate::v1::bgp::policy::ImportExportPolicy::Allow(prefixes) => {
                let v4_prefixes: BTreeSet<Prefix4> = prefixes
                    .iter()
                    .filter_map(|p| match p {
                        Prefix::V4(p4) => Some(*p4),
                        Prefix::V6(_) => None,
                    })
                    .collect();
                if v4_prefixes.is_empty() {
                    // Policy had prefixes but none were V4 - treat as no filtering for V4
                    ImportExportPolicy4::NoFiltering
                } else {
                    ImportExportPolicy4::Allow(v4_prefixes)
                }
            }
        }
    }
}

impl From<crate::v1::bgp::policy::ImportExportPolicy> for ImportExportPolicy6 {
    fn from(value: crate::v1::bgp::policy::ImportExportPolicy) -> Self {
        match value {
            crate::v1::bgp::policy::ImportExportPolicy::NoFiltering => {
                ImportExportPolicy6::NoFiltering
            }
            crate::v1::bgp::policy::ImportExportPolicy::Allow(prefixes) => {
                let v6_prefixes: BTreeSet<Prefix6> = prefixes
                    .iter()
                    .filter_map(|p| match p {
                        Prefix::V4(_) => None,
                        Prefix::V6(p6) => Some(*p6),
                    })
                    .collect();
                if v6_prefixes.is_empty() {
                    // Policy had prefixes but none were V6 - treat as no filtering for V6
                    ImportExportPolicy6::NoFiltering
                } else {
                    ImportExportPolicy6::Allow(v6_prefixes)
                }
            }
        }
    }
}
