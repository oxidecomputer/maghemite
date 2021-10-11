// Copyright 2021 Oxide Computer Company

pub mod error;

use std::net;
use error::Error;
use icmpv6::RDPMessage;
//use std::sync::mpsc::{Sender, Receiver};
use tokio::sync::mpsc::{Sender, Receiver};
use std::net::Ipv6Addr;
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use rift_protocol::lie::LIEPacket;

pub trait Platform {
    fn get_links(&self) -> Result<Vec<LinkStatus>, Error>;
    fn get_link_status(&self, link_name: impl AsRef<str>) -> Result<LinkStatus, Error>;
    fn get_interface_v6ll(&self, interface: impl AsRef<str>) -> Result<Option<IpIfAddr>, Error>;


    fn solicit_rift_routers(&self, interface: Option<IpIfAddr>) -> Result<(), Error>;
    fn advertise_rift_router(&self, interface: Option<IpIfAddr>) -> Result<(), Error>;
    fn get_rdp_channel(&self, interface: Option<IpIfAddr>) -> Result<Receiver<RDPMessage>, Error>;
    fn get_link_channel(&self, local: Ipv6Addr, peer: Ipv6Addr) -> Result<
        (Sender<LIEPacket>, Receiver<LIEPacket>),
        Error
    >;
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct IpIfAddr {
    pub addr: Ipv6Addr,
    pub if_index: i32,
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
