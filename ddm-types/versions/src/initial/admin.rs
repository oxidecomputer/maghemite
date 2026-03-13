// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{BTreeMap, HashSet};
use std::net::Ipv6Addr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::exchange::PathVector;

pub type PrefixMap = BTreeMap<Ipv6Addr, HashSet<PathVector>>;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ExpirePathParams {
    pub addr: Ipv6Addr,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct EnableStatsRequest {
    pub sled_id: Uuid,
    pub rack_id: Uuid,
}
