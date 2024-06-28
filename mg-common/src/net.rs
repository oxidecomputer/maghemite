use oxnet::{IpNet, Ipv4Net, Ipv6Net};
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
    pub overlay_prefix: IpPrefix,
    pub boundary_addr: Ipv6Addr,
    pub vni: u32,
    #[serde(default)]
    pub metric: u64,
}

impl From<TunnelOriginV2> for TunnelOrigin {
    fn from(value: TunnelOriginV2) -> Self {
        TunnelOrigin {
            overlay_prefix: match value.overlay_prefix {
                IpPrefix::V4(x) => {
                    IpNet::V4(Ipv4Net::new_unchecked(x.addr, x.len))
                }
                IpPrefix::V6(x) => {
                    IpNet::V6(Ipv6Net::new_unchecked(x.addr, x.len))
                }
            },
            boundary_addr: value.boundary_addr,
            vni: value.vni,
            metric: value.metric,
        }
    }
}

impl From<TunnelOrigin> for TunnelOriginV2 {
    fn from(value: TunnelOrigin) -> Self {
        TunnelOriginV2 {
            overlay_prefix: match value.overlay_prefix {
                IpNet::V4(x) => IpPrefix::V4(Ipv4Prefix {
                    addr: x.addr(),
                    len: x.width(),
                }),
                IpNet::V6(x) => IpPrefix::V6(Ipv6Prefix {
                    addr: x.addr(),
                    len: x.width(),
                }),
            },
            boundary_addr: value.boundary_addr,
            vni: value.vni,
            metric: value.metric,
        }
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct Ipv6Prefix {
    pub addr: Ipv6Addr,
    pub len: u8,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct Ipv4Prefix {
    pub addr: Ipv4Addr,
    pub len: u8,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum IpPrefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}
