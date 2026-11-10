// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{BTreeMap, BTreeSet};

use super::rdb::path::Path;
use super::rdb::rib::AddressFamily;
use super::rdb::rib::ProtocolFilter;
use crate::{v2, v5};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct Rib(pub BTreeMap<String, BTreeSet<Path>>);

pub type GetRibResult = BTreeMap<String, BTreeSet<Path>>;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RibQuery {
    /// Filter by address family (None means all families)
    #[serde(default)]
    pub address_family: Option<AddressFamily>,
    /// Filter by protocol (optional)
    pub protocol: Option<ProtocolFilter>,
}

pub fn get_rib_result_into_v5(value: GetRibResult) -> v5::rib::GetRibResult {
    value
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
        .collect()
}

impl From<Rib> for v5::rib::Rib {
    fn from(new: Rib) -> Self {
        let Rib(inner) = new;
        Self(get_rib_result_into_v5(inner))
    }
}

impl From<v2::rib::RibQuery> for RibQuery {
    fn from(old: v2::rib::RibQuery) -> Self {
        let v2::rib::RibQuery {
            address_family,
            protocol,
        } = old;
        Self {
            address_family: address_family.map(Into::into),
            protocol: protocol.map(Into::into),
        }
    }
}
