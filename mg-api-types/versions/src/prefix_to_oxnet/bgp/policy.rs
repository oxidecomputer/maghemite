// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v4;
use oxnet::{Ipv4Net, Ipv6Net};
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
    Allow(BTreeSet<Ipv4Net>),
}

/// Import/Export policy for IPv6 prefixes only.
#[derive(
    Default, Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq,
)]
pub enum ImportExportPolicy6 {
    #[default]
    NoFiltering,
    Allow(BTreeSet<Ipv6Net>),
}

impl From<v4::bgp::policy::ImportExportPolicy4> for ImportExportPolicy4 {
    fn from(old: v4::bgp::policy::ImportExportPolicy4) -> Self {
        match old {
            v4::bgp::policy::ImportExportPolicy4::NoFiltering => {
                Self::NoFiltering
            }
            v4::bgp::policy::ImportExportPolicy4::Allow(prefixes) => {
                Self::Allow(prefixes.into_iter().map(Into::into).collect())
            }
        }
    }
}

impl From<v4::bgp::policy::ImportExportPolicy6> for ImportExportPolicy6 {
    fn from(old: v4::bgp::policy::ImportExportPolicy6) -> Self {
        match old {
            v4::bgp::policy::ImportExportPolicy6::NoFiltering => {
                Self::NoFiltering
            }
            v4::bgp::policy::ImportExportPolicy6::Allow(prefixes) => {
                Self::Allow(prefixes.into_iter().map(Into::into).collect())
            }
        }
    }
}

impl From<ImportExportPolicy4> for v4::bgp::policy::ImportExportPolicy4 {
    fn from(new: ImportExportPolicy4) -> Self {
        match new {
            ImportExportPolicy4::NoFiltering => Self::NoFiltering,
            ImportExportPolicy4::Allow(nets) => {
                Self::Allow(nets.into_iter().map(Into::into).collect())
            }
        }
    }
}

impl From<ImportExportPolicy6> for v4::bgp::policy::ImportExportPolicy6 {
    fn from(new: ImportExportPolicy6) -> Self {
        match new {
            ImportExportPolicy6::NoFiltering => Self::NoFiltering,
            ImportExportPolicy6::Allow(nets) => {
                Self::Allow(nets.into_iter().map(Into::into).collect())
            }
        }
    }
}
