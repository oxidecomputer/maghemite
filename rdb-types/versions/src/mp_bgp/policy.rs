// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v1::prefix::{Prefix, Prefix4, Prefix6};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
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

/// Address-family-specific import/export policy wrapper for internal use.
/// This is distinct from the API-facing `ImportExportPolicy` type.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ImportExportPolicy {
    V4(ImportExportPolicy4),
    V6(ImportExportPolicy6),
}

impl From<crate::v1::policy::ImportExportPolicy> for ImportExportPolicy4 {
    fn from(value: crate::v1::policy::ImportExportPolicy) -> Self {
        match value {
            crate::v1::policy::ImportExportPolicy::NoFiltering => {
                ImportExportPolicy4::NoFiltering
            }
            crate::v1::policy::ImportExportPolicy::Allow(prefixes) => {
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

impl From<crate::v1::policy::ImportExportPolicy> for ImportExportPolicy6 {
    fn from(value: crate::v1::policy::ImportExportPolicy) -> Self {
        match value {
            crate::v1::policy::ImportExportPolicy::NoFiltering => {
                ImportExportPolicy6::NoFiltering
            }
            crate::v1::policy::ImportExportPolicy::Allow(prefixes) => {
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
