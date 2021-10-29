// Copyright 2021 Oxide Computer Company

pub mod error;

use std::net;
use std::hash::{Hash, Hasher};
use error::Error;
use icmpv6::RDPMessage;
use tokio::sync::mpsc::{Sender, Receiver};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use rift_protocol::lie::LIEPacket;
use rift_protocol::tie::TIEPacket;
use std::net::{
    IpAddr,
    Ipv6Addr,
};

pub struct TIEPacketTx {
    pub packet: TIEPacket,
    pub dest: Ipv6Addr,
    pub local_ifx: i32,
}

pub trait Platform {

    // Local platform state

    /// Get a list of the links on the platform and their carrier status
    fn get_links(&self) -> Result<Vec<LinkStatus>, Error>;

    /// Get the current carrier status for the named link
    fn get_link_status(&self, link_name: impl AsRef<str>)
    -> Result<LinkStatus, Error>;

    /// Get the ipv6 link local address for the named interface
    fn get_interface_v6ll(&self, interface: impl AsRef<str>)
    -> Result<Option<IpIfAddr>, Error>;

    /// Ensure that the provide address is present for the named interface
    fn ensure_address_present(
        &self,
        interface: impl AsRef<str>,
        addr: IpAddr,
        mask: u8,
    ) -> Result<(), Error>;


    fn get_routes(&self) -> Result<Vec::<Route>, Error>;
    fn set_route(&self, route: Route) -> Result<(), Error>;
    fn clear_route(&self, route: Route) -> Result<(), Error>;

    // IPv6 RDP

    /// Send out an IPv6 router solicitation on the specified interface to the
    /// RIFT router multicast address ff02::a1f7
    fn solicit_rift_routers(&self, interface: Option<IpIfAddr>)
    -> Result<(), Error>;

    /// Send out an IPv6 router advertisement on the specified interface to the
    /// RIFT router multicast address ff02::a1f7
    fn advertise_rift_router(&self, interface: Option<IpIfAddr>)
    -> Result<(), Error>;

    /// Get a reciever for IPv6 router discovery messages (solicitations and
    /// advertisements) for the given interface listening on the RIFT router
    /// multicast address ff02::a1f7
    fn get_rdp_channel(&self, interface: Option<IpIfAddr>)
    -> Result<Receiver<RDPMessage>, Error>;

    // RIFT Link Element Exchange (LIE)

    /// Get a sender and reciever for RIFT Link Element Exchange (LIE) packets
    /// on the spcified interface using the specified link local address.
    fn get_link_channel(&self, local: Ipv6Addr, peer: Ipv6Addr, local_ifx: i32) 
    -> Result<(Sender<LIEPacket>, Receiver<LIEPacket>), Error>;

    // RIFT Topology Element Exchange (TIE)

    /// Get a sender and reciever for RIFT Topology Element Exchange (TIE)
    /// packets.
    fn get_topology_channel(&self)
    -> Result<(Sender<TIEPacketTx>, Receiver<TIEPacket>), Error>;
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub enum Route {
    Gateway(GatewayRoute),
    Link(LinkRoute),
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub struct GatewayRoute {
    pub dest: IpAddr,
    pub mask: u32,
    pub gw: IpAddr,
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub struct LinkRoute {
    pub dest: IpAddr,
    pub mask: u32,
    pub if_index: i32,
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
