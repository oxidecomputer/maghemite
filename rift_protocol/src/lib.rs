// Copyright 2021 Oxide Computer Company

use serde::{Serialize, Deserialize};
use schemars::JsonSchema;

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct LinkInfo {
    pub name: String,
    pub local_id: u64,
    pub flood_port: u16,
    pub mtu: u16,
    pub bandwidth: u64,
    pub neighbor: Neighbor,
    pub node_capabilities: NodeCapabilities,
    pub link_capabilities: LinkCapabilities,
    pub hold_time: u16,
    pub label: u32,
    pub not_ztp: bool,
    pub repeater: bool,
    pub backoff: bool,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Neighbor {
    pub originator: u64,
    pub remote_id: u32,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct NodeCapabilities {
    pub protocol_minor_version: u16,
    pub flood_reduction: bool,
    pub hierarchy_indication: HierarchyIndication,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LinkCapabilities {
    pub bfd: bool,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum HierarchyIndication {
    Leaf,
    ToF,
}
