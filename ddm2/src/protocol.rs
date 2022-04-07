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
pub struct Ping {
    pub sender: String,
    // TODO: include the serial of the last ddm messages received,
    // .     this way if the peer notices we are behind, it can resend us
    // .     any information we may have missed. This woudl allow us to
    // .     automatically converge on the most up to date state through
    // .     the ping messages. This would preclude the need for the sync
    // .     messages.
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Pong {
    pub sender: String,
    pub origin: String,
    pub kind: RouterKind,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Advertise {
    pub origin: String,
    pub nexthop: Ipv6Addr,
    pub prefixes: HashSet::<Ipv6Prefix>,
    pub serial: u64,
}
