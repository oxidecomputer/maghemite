// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    JsonSchema,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
)]
pub struct Path {
    pub nexthop: IpAddr,
    pub shutdown: bool,
    pub rib_priority: u8,
    pub bgp: Option<BgpPathProperties>,
    pub vlan_id: Option<u16>,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    JsonSchema,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
)]
pub struct BgpPathProperties {
    pub origin_as: u32,
    pub id: u32,
    pub peer: IpAddr,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub as_path: Vec<u32>,
    pub stale: Option<DateTime<Utc>>,
}
