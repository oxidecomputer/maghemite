// Copyright 2021 Oxide Computer Company

use serde::{Serialize, Deserialize};
use schemars::JsonSchema;
use crate::{
    Header,
    NodeCapabilities,
    LinkCapabilities,
    SystemId,
    LinkId,
    net::Ipv6Prefix,
};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LIEPacket {
    pub header: Header,
    pub name: String,
    pub local_id: u32,
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
    
    // NOTE begin non-standard items
    pub underlay_init: Option<UnderlayInit>,
}

impl Default for LIEPacket {
    fn default() -> LIEPacket {
        LIEPacket{
            header: Header::default(),
            name: "".to_string(),
            local_id: 0,
            flood_port: 0,
            mtu: 0,
            bandwidth: 0,
            neighbor: Neighbor::default(),
            node_capabilities: NodeCapabilities{
                protocol_minor_version: 0,
                flood_reduction: None,
                hierarchy_indication: None,
            },
            link_capabilities: LinkCapabilities{
                bfd: false,
            },
            hold_time: 0,
            label: 0,
            not_ztp: true,
            repeater: false,
            backoff: false,
            underlay_init: None,
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Neighbor {
    pub originator: SystemId,
    pub remote_id: LinkId,
}

impl Default for Neighbor {
    fn default() -> Neighbor {
        Neighbor{
            originator: 0,
            remote_id: 0,
        }
    }
}


// NOTE: This is not a standard Rift protocol item.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct UnderlayInit {
    pub prefix: Ipv6Prefix,
}
