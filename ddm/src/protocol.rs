use std::collections::HashSet;
use std::net::IpAddr;
use std::net::Ipv6Addr;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::net::Ipv6Prefix;
use crate::sys;

#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema,
)]
pub enum RouterKind {
    Server,
    Transit,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Hail {
    pub sender: String,
    pub router_kind: RouterKind,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Response {
    pub sender: String,
    pub origin: String,
    pub router_kind: RouterKind,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Advertise {
    /// The next hop address for the enclosed prefixes
    pub nexthop: Ipv6Addr,

    /// Prefixes being advertised
    pub prefixes: HashSet<Ipv6Prefix>,
}

impl From<Advertise> for Vec<sys::Route> {
    fn from(a: Advertise) -> Vec<sys::Route> {
        a.prefixes
            .iter()
            .map(|pfx| sys::Route {
                dest: IpAddr::V6(pfx.addr),
                prefix_len: pfx.mask,
                gw: IpAddr::V6(a.nexthop),
                egress_port: 0,
            })
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Solicit {
    /// The source address of the peer asking for advertisements.
    pub src: Ipv6Addr,
}
