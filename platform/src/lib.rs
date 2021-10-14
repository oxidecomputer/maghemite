// Copyright 2021 Oxide Computer Company

pub mod error;

use std::net;
use std::hash::{Hash, Hasher};
use error::Error;
use icmpv6::RDPMessage;
use tokio::sync::mpsc::{Sender, Receiver};
use std::net::Ipv6Addr;
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use rift_protocol::lie::LIEPacket;
use rift_protocol::tie::TIEPacket;

pub struct TIEPacketTx {
    pub packet: TIEPacket,
    pub dest: Ipv6Addr,
    pub local_ifx: i32,
}

pub trait Platform {
    // Local platform state
    fn get_links(&self) -> Result<Vec<LinkStatus>, Error>;
    fn get_link_status(&self, link_name: impl AsRef<str>) -> Result<LinkStatus, Error>;
    fn get_interface_v6ll(&self, interface: impl AsRef<str>) -> Result<Option<IpIfAddr>, Error>;

    // IPv6 RDP
    fn solicit_rift_routers(&self, interface: Option<IpIfAddr>) -> Result<(), Error>;
    fn advertise_rift_router(&self, interface: Option<IpIfAddr>) -> Result<(), Error>;
    fn get_rdp_channel(&self, interface: Option<IpIfAddr>) -> Result<Receiver<RDPMessage>, Error>;

    // RIFT Link Element Exchange (LIE)
    fn get_link_channel(&self, local: Ipv6Addr, peer: Ipv6Addr, local_ifx: i32) 
    -> Result<(Sender<LIEPacket>, Receiver<LIEPacket>), Error>;

    // RIFT Topology Element Exchange (TIE)
    fn get_topology_channel(&self) -> Result<(Sender<TIEPacketTx>, Receiver<TIEPacket>), Error>;
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct IpIfAddr {
    pub addr: Ipv6Addr,
    pub if_index: i32,
}

impl Eq for IpIfAddr {}
impl Hash for IpIfAddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.if_index.hash(state);
        self.addr.hash(state);
    }
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum LinkState {
    Unknown,
    Down,
    Up,
}

#[derive(Debug)]
pub struct LinkStatus {
    pub name: String,
    pub state: LinkState,
}

#[derive(Clone, Debug)]
pub struct NeighborRouter {
    pub addr: net::Ipv6Addr,
    pub local_link: String,
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
