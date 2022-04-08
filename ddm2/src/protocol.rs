use std::collections::HashSet;
use std::net::Ipv6Addr;

use schemars::JsonSchema;
use serde::{Serialize, Deserialize};
use crate::net::Ipv6Prefix;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema)]
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
    pub prefixes: HashSet::<Ipv6Prefix>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Solicit {
    /// The source address of the peer asking for advertisements.
    pub src: Ipv6Addr,
}
