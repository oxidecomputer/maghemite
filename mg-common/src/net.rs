use oxnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

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

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelOriginV2 {
    pub overlay_prefix: IpNet,
    pub boundary_addr: Ipv6Addr,
    pub vni: u32,
    #[serde(default)]
    pub metric: u64,
}

impl From<TunnelOriginV2> for TunnelOrigin {
    fn from(value: TunnelOriginV2) -> Self {
        TunnelOrigin {
            overlay_prefix: value.overlay_prefix,
            boundary_addr: value.boundary_addr,
            vni: value.vni,
            metric: value.metric,
        }
    }
}

impl From<TunnelOrigin> for TunnelOriginV2 {
    fn from(value: TunnelOrigin) -> Self {
        TunnelOriginV2 {
            overlay_prefix: value.overlay_prefix,
            boundary_addr: value.boundary_addr,
            vni: value.vni,
            metric: value.metric,
        }
    }
}
