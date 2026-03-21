// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;

use rdb::Prefix6;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddStaticRoute6Request {
    pub routes: StaticRoute6List,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteStaticRoute6Request {
    pub routes: StaticRoute6List,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StaticRoute6List {
    pub list: Vec<StaticRoute6>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StaticRoute6 {
    pub prefix: Prefix6,
    pub nexthop: Ipv6Addr,
    pub vlan_id: Option<u16>,
    pub rib_priority: u8,
}
