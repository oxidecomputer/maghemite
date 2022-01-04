use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::Ipv6Addr;

use serde::{Serialize, Deserialize};
use schemars::JsonSchema;

use crate::net::Ipv6Prefix;

/// The DDM multicast address used for bootstrapping ff02::dd;
pub const RDP_MCAST_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0,0,0,0,0,0, 0xdd);
pub const PEERING_PORT: u16 = 0x1dd0;
pub const PREFIX_EXCHANGE_PORT: u16 = 0x1dd1;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema)]
pub enum RouterKind {
    Server,
    Transit,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PeerMessage {
    Ping(PeerPing),
    Pong(PeerPong),
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PeerPing {
    pub sender: String,
    // TODO: include the serial of the last ddm messages received,
    // .     this way if the peer notices we are behind, it can resend us
    // .     any information we may have missed. This woudl allow us to
    // .     automatically converge on the most up to date state through
    // .     the ping messages. This would preclude the need for the sync
    // .     messages.
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PeerPong {
    pub sender: String,
    pub origin: String,
    pub kind: RouterKind,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub enum DdmMessage {
    Prefix(DdmPrefix),
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DdmPrefix {
    pub origin: String,
    pub prefixes: HashSet::<Ipv6Prefix>,
    pub serial: u64,
}

impl Hash for DdmPrefix {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.origin.hash(state);
    }
}
