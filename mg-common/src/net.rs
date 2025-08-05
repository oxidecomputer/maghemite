use oxnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

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

pub fn zero_ipv4_addr_host_bits(ip: Ipv4Addr, length: u8) -> Ipv4Addr {
    let mask = match length {
        0 => 0,
        _ => (!0u32) << (32 - length),
    };

    Ipv4Addr::from_bits(ip.to_bits() & mask)
}

pub fn zero_ipv6_addr_host_bits(ip: Ipv6Addr, length: u8) -> Ipv6Addr {
    let mask = match length {
        0 => 0,
        _ => (!0u128) << (128 - length),
    };

    Ipv6Addr::from_bits(ip.to_bits() & mask)
}
