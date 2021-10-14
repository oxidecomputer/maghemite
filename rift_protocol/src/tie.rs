// Copyright 2021 Oxide Computer Company

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use serde::{Serialize, Deserialize};
use schemars::JsonSchema;
use crate::{
    Header,
    Level,
    NodeCapabilities,
    SystemId,
    LinkId,
    TIENumber,
    SequenceNumber,
    Lifetime,
    Metric,
    InterfaceIndex,
    OuterSecurityKeyId,
    Bandwidth,
    PodId,
    Seconds,
    IPv4Address,
    IPv6Address,
    PrefixLength,
    RouteTag,
    PrefixTransactionId,
};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TIEPacket {
    pub header: Header,
    pub tie_header: TIEHeader,
    pub element: TIEElement,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TIEHeader {
    pub id: TIEId,
    pub seq: SequenceNumber,
    pub origination_time: Option<Timestamp>,
    pub origination_lifetime: Option<Lifetime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TIEId {
    pub direction: TIEDirection,
    pub originator: SystemId,
    pub number: TIENumber,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[repr(u8)]
pub enum TIEDirection {
    Illegal,
    South,
    North,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[repr(u8)]
pub enum TIEElement {
    Node(NodeTIE),
    Prefixes(PrefixTIE),
    PositiveDisaggregationPrefixes(PrefixTIE),
    NegativeDisaggregationPrefixes(PrefixTIE),
    External(PrefixTIE),
    PositiveExternalDisaggregationPrefixes(PrefixTIE),
    KeyValues(KeyValueTIE),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NodeTIE {
    pub level: Level,
    pub neighbors: HashMap<SystemId, NeighborTIE>,
    pub capabilities: NodeCapabilities,
    pub flags: Option<NodeFlags>,
    pub pod: Option<PodId>,
    pub startup_time: Option<Seconds>,
    pub miscabled_links: Option<HashSet<LinkId>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PrefixTIE {
    pub prefixes: HashMap<IPPrefix, PrefixAttributes>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct KeyValueTIE {
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Timestamp {
    pub sec: u64,
    pub nsec: u32,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NodeFlags {
    pub overload: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NeighborTIE {
    pub level: Level,
    pub cost: Option<Metric>,
    pub link_ids: Option<HashSet<LinkIdPair>>,
    pub bandwidth: Option<Bandwidth>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LinkIdPair {
    pub local_id: LinkId,
    pub remote_id: LinkId,
    pub local_if_index: Option<InterfaceIndex>,
    pub local_if_name: Option<String>,
    pub outer_security_key: Option<OuterSecurityKeyId>,
    pub bfd_up: Option<bool>,
    pub address_families: Option<HashSet<AddressFamily>>,
}

impl PartialEq for LinkIdPair {
    fn eq(&self, other: &Self) -> bool {
        self.local_id == other.local_id && self.remote_id == self.remote_id
    }
}

impl Eq for LinkIdPair {}

impl Hash for LinkIdPair {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.local_id.hash(state);
        self.remote_id.hash(state);
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Hash, Eq)]
#[repr(u8)]
pub enum AddressFamily {
    Illegal = 0,
    Min = 1,
    IPv4 = 2,
    IPv6 = 3,
    Max = 4,
}


#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Hash, Eq)]
#[repr(u8)]
pub enum IPPrefix {
    IPv4(IPv4Prefix),
    IPv6(IPv6Prefix),
}

#[derive(Debug,Clone, Serialize, Deserialize, JsonSchema, PartialEq, Hash, Eq)]
pub struct IPv4Prefix {
    pub address: IPv4Address,
    pub prefixlen: PrefixLength,
}

#[derive(Debug,Clone, Serialize, Deserialize, JsonSchema, PartialEq, Hash, Eq)]
pub struct IPv6Prefix {
    pub address: IPv6Address,
    pub prefixlen: PrefixLength,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PrefixAttributes {
    pub metric: Metric,
    pub tags: Option<HashSet<RouteTag>>,
    pub monotonic_clock: Option<PrefixSequence>,
    pub loopback: Option<bool>,
    pub directly_attached: Option<bool>,
    pub from_link: Option<LinkId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PrefixSequence {
    pub timestamp: Timestamp,
    pub transaction_id: Option<PrefixTransactionId>,
}
