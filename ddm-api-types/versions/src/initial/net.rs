// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;

use oxnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelOrigin {
    pub overlay_prefix: IpNet,
    pub boundary_addr: Ipv6Addr,
    pub vni: u32,
    #[serde(default)]
    pub metric: u64,
}

impl From<TunnelOrigin> for ddm_protocol::v4::TunnelOrigin {
    fn from(value: TunnelOrigin) -> Self {
        let TunnelOrigin {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        } = value;
        Self {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
            router_id: None,
        }
    }
}

impl From<ddm_protocol::v4::TunnelOrigin> for TunnelOrigin {
    fn from(value: ddm_protocol::v4::TunnelOrigin) -> Self {
        // router_id is dropped: this version cannot represent it.
        let ddm_protocol::v4::TunnelOrigin {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
            router_id: _,
        } = value;
        Self {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        }
    }
}
