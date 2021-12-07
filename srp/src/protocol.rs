use crate::net::Ipv6Prefix;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
    // TODO: include the serial of the last prefix and srp messages received,
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
pub enum SrpMessage {
    Prefix(SrpPrefix),
    Link(SrpLink),
    SyncRequest(SrpSyncRequest),
    SyncResponse(SrpSyncResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrpPrefix {
    pub origin: String,
    pub prefixes: HashSet::<Ipv6Prefix>,
    pub serial: u64,
}

impl Hash for SrpPrefix {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.origin.hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrpLink {
    pub origin: String,
    pub neighbor: String,
    pub capacity: u64,
    pub egress_rate: u64,
    pub ingress_rate: u64,
    pub serial: u64,
}

impl Hash for SrpLink {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.origin.hash(state);
        self.neighbor.hash(state);
    }
}

/// An SrpSyncRequest is used in the event that a router is restarted and
/// does not have any initial state. The router sends out an SrpSyncRequest
/// to any of it's peers. The peer will respond with all the prefixes and
/// link state in the network. This is similar to BGP graceful restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrpSyncRequest { }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrpSyncResponse {
    pub prefixes: HashSet<SrpPrefix>,
    pub link_state:  HashSet<SrpLink>,
}