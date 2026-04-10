// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::IpAddr;

use rdb::{Prefix4, Prefix6};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// IPv4 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
    pub nexthop: IpAddr,
    pub nexthop_interface: Option<String>,
    pub vlan_id: Option<u16>,
    pub rib_priority: u8,
}

// IPv6 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
    pub nexthop: IpAddr,
    pub nexthop_interface: Option<String>,
    pub vlan_id: Option<u16>,
    pub rib_priority: u8,
}
