// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v1::rdb::prefix::Prefix4;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
    pub vlan_id: Option<u16>,
    pub rib_priority: u8,
}

impl From<crate::v1::static_routes::AddStaticRoute4Request>
    for AddStaticRoute4Request
{
    fn from(value: crate::v1::static_routes::AddStaticRoute4Request) -> Self {
        AddStaticRoute4Request {
            routes: value.routes.into(),
        }
    }
}

impl From<crate::v1::static_routes::DeleteStaticRoute4Request>
    for DeleteStaticRoute4Request
{
    fn from(
        value: crate::v1::static_routes::DeleteStaticRoute4Request,
    ) -> Self {
        DeleteStaticRoute4Request {
            routes: value.routes.into(),
        }
    }
}

impl From<crate::v1::static_routes::StaticRoute4List> for StaticRoute4List {
    fn from(value: crate::v1::static_routes::StaticRoute4List) -> Self {
        StaticRoute4List {
            list: value.list.into_iter().map(StaticRoute4::from).collect(),
        }
    }
}

impl From<crate::v1::static_routes::StaticRoute4> for StaticRoute4 {
    fn from(value: crate::v1::static_routes::StaticRoute4) -> Self {
        Self {
            prefix: value.prefix,
            nexthop: IpAddr::V4(value.nexthop),
            vlan_id: value.vlan_id,
            rib_priority: value.rib_priority,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1;
    use std::net::Ipv4Addr;

    fn v1_route() -> v1::static_routes::StaticRoute4 {
        v1::static_routes::StaticRoute4 {
            prefix: v1::rdb::prefix::Prefix4 {
                value: Ipv4Addr::new(192, 168, 0, 0),
                length: 16,
            },
            nexthop: Ipv4Addr::new(10, 0, 0, 1),
            vlan_id: Some(100),
            rib_priority: 50,
        }
    }

    #[test]
    fn v1_static_route4_converts_to_latest() {
        let v1 = v1_route();
        let latest = StaticRoute4::from(v1);
        assert_eq!(latest.prefix.value, Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(latest.prefix.length, 16);
        assert_eq!(latest.nexthop, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(latest.vlan_id, Some(100));
        assert_eq!(latest.rib_priority, 50);
    }

    #[test]
    fn v1_add_request_converts_to_latest() {
        let req = v1::static_routes::AddStaticRoute4Request {
            routes: v1::static_routes::StaticRoute4List {
                list: vec![v1_route()],
            },
        };
        let latest = AddStaticRoute4Request::from(req);
        assert_eq!(latest.routes.list.len(), 1);
        assert_eq!(
            latest.routes.list[0].nexthop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );
    }

    #[test]
    fn v1_delete_request_converts_to_latest() {
        let req = v1::static_routes::DeleteStaticRoute4Request {
            routes: v1::static_routes::StaticRoute4List {
                list: vec![v1_route()],
            },
        };
        let latest = DeleteStaticRoute4Request::from(req);
        assert_eq!(latest.routes.list.len(), 1);
        assert_eq!(
            latest.routes.list[0].nexthop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );
    }

    // Old (v1) clients send `nexthop` as a bare IPv4 string. Make sure such
    // a body still deserializes against the v1 type and converts to latest
    // — this is the wire contract for the version shim.
    #[test]
    fn v1_wire_payload_deserializes_then_converts() {
        let body = r#"{
            "routes": {
                "list": [{
                    "prefix": { "value": "192.168.0.0", "length": 16 },
                    "nexthop": "10.0.0.1",
                    "vlan_id": 100,
                    "rib_priority": 50
                }]
            }
        }"#;
        let v1_req: v1::static_routes::AddStaticRoute4Request =
            serde_json::from_str(body).expect("v1 body parses");
        let latest = AddStaticRoute4Request::from(v1_req);
        assert_eq!(
            latest.routes.list[0].nexthop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );
    }
}
