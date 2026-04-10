// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv4Addr;

use rdb::{Prefix4, StaticRouteKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddStaticRoute4Request {
    pub routes: StaticRoute4List,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteStaticRoute4Request {
    pub routes: StaticRoute4List,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StaticRoute4List {
    pub list: Vec<StaticRoute4>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StaticRoute4 {
    pub prefix: Prefix4,
    pub nexthop: Ipv4Addr,
    pub vlan_id: Option<u16>,
    pub rib_priority: u8,
}

impl From<StaticRoute4> for StaticRouteKey {
    fn from(val: StaticRoute4) -> Self {
        StaticRouteKey {
            prefix: val.prefix.into(),
            nexthop: val.nexthop.into(),
            nexthop_interface: None,
            vlan_id: val.vlan_id,
            rib_priority: val.rib_priority,
        }
    }
}
