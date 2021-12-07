use crate::net::Ipv6Prefix;
use std::collections::HashSet;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrpPrefix {
    pub origin: String,
    pub prefixes: HashSet::<Ipv6Prefix>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrpLink {
    pub origin: String,
    pub neighbor: String,
    pub capacity: u64,
    pub egress_rate: u64,
    pub ingress_rate: u64,
}