use crate::net::Ipv6Prefix;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use serde::{Serialize, Deserialize};
use schemars::JsonSchema;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema)]
pub enum RouterKind {
    Server,
    Transit,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeerMessage {
    Ping(PeerPing),
    Pong(PeerPong),
}

#[derive(Debug, PartialEq, Eq)]
pub struct PeerPing {
    pub sender: String,
    // TODO: include the serial of the last ddm messages received,
    // .     this way if the peer notices we are behind, it can resend us
    // .     any information we may have missed. This woudl allow us to
    // .     automatically converge on the most up to date state through
    // .     the ping messages. This would preclude the need for the sync
    // .     messages.
}

#[derive(Debug, PartialEq, Eq)]
pub struct PeerPong {
    pub sender: String,
    pub origin: String,
    pub kind: RouterKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
