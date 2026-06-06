// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::{IpAddr, Ipv6Addr};

use crate::v1;
use crate::v2;
use crate::v10;
use oxnet::{Ipv4Net, Ipv6Net};
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

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct StaticRoute4 {
    pub prefix: Ipv4Net,
    pub nexthop: IpAddr,
    pub vlan_id: Option<u16>,
    pub rib_priority: u8,
}

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

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct StaticRoute6 {
    pub prefix: Ipv6Net,
    pub nexthop: Ipv6Addr,
    pub vlan_id: Option<u16>,
    pub rib_priority: u8,
}

// ---------------------------------------------------------------------------
// Upgrade conversions: v1/v2/v10 → v11
// ---------------------------------------------------------------------------

impl From<v10::static_routes::StaticRoute4> for StaticRoute4 {
    fn from(old: v10::static_routes::StaticRoute4) -> Self {
        let v10::static_routes::StaticRoute4 {
            prefix,
            nexthop,
            vlan_id,
            rib_priority,
        } = old;
        Self {
            prefix: prefix.into(),
            nexthop,
            vlan_id,
            rib_priority,
        }
    }
}

impl From<v10::static_routes::StaticRoute4List> for StaticRoute4List {
    fn from(old: v10::static_routes::StaticRoute4List) -> Self {
        Self {
            list: old.list.into_iter().map(StaticRoute4::from).collect(),
        }
    }
}

impl From<v10::static_routes::AddStaticRoute4Request>
    for AddStaticRoute4Request
{
    fn from(old: v10::static_routes::AddStaticRoute4Request) -> Self {
        Self {
            routes: StaticRoute4List::from(old.routes),
        }
    }
}

impl From<v10::static_routes::DeleteStaticRoute4Request>
    for DeleteStaticRoute4Request
{
    fn from(old: v10::static_routes::DeleteStaticRoute4Request) -> Self {
        Self {
            routes: StaticRoute4List::from(old.routes),
        }
    }
}

impl From<v1::static_routes::StaticRoute4> for StaticRoute4 {
    fn from(old: v1::static_routes::StaticRoute4) -> Self {
        let v1::static_routes::StaticRoute4 {
            prefix,
            nexthop,
            vlan_id,
            rib_priority,
        } = old;
        Self {
            prefix: prefix.into(),
            nexthop: IpAddr::V4(nexthop),
            vlan_id,
            rib_priority,
        }
    }
}

impl From<v1::static_routes::StaticRoute4List> for StaticRoute4List {
    fn from(old: v1::static_routes::StaticRoute4List) -> Self {
        Self {
            list: old.list.into_iter().map(StaticRoute4::from).collect(),
        }
    }
}

impl From<v1::static_routes::AddStaticRoute4Request>
    for AddStaticRoute4Request
{
    fn from(old: v1::static_routes::AddStaticRoute4Request) -> Self {
        Self {
            routes: StaticRoute4List::from(old.routes),
        }
    }
}

impl From<v1::static_routes::DeleteStaticRoute4Request>
    for DeleteStaticRoute4Request
{
    fn from(old: v1::static_routes::DeleteStaticRoute4Request) -> Self {
        Self {
            routes: StaticRoute4List::from(old.routes),
        }
    }
}

impl From<v2::static_routes::StaticRoute6> for StaticRoute6 {
    fn from(old: v2::static_routes::StaticRoute6) -> Self {
        let v2::static_routes::StaticRoute6 {
            prefix,
            nexthop,
            vlan_id,
            rib_priority,
        } = old;
        Self {
            prefix: prefix.into(),
            nexthop,
            vlan_id,
            rib_priority,
        }
    }
}

impl From<v2::static_routes::StaticRoute6List> for StaticRoute6List {
    fn from(old: v2::static_routes::StaticRoute6List) -> Self {
        Self {
            list: old.list.into_iter().map(StaticRoute6::from).collect(),
        }
    }
}

impl From<v2::static_routes::AddStaticRoute6Request>
    for AddStaticRoute6Request
{
    fn from(old: v2::static_routes::AddStaticRoute6Request) -> Self {
        Self {
            routes: StaticRoute6List::from(old.routes),
        }
    }
}

impl From<v2::static_routes::DeleteStaticRoute6Request>
    for DeleteStaticRoute6Request
{
    fn from(old: v2::static_routes::DeleteStaticRoute6Request) -> Self {
        Self {
            routes: StaticRoute6List::from(old.routes),
        }
    }
}
