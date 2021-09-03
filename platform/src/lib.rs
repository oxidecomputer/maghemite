// Copyright 2021 Oxide Computer Company

pub mod error;

use std::net;
use error::Error;
use icmpv6::RDPMessage;
use std::sync::mpsc::{Sender, Receiver};
use std::net::Ipv6Addr;

pub trait Platform {
    fn solicit_rift_routers(&self) -> Result<(), Error>;
    fn advertise_rift_router(&self) -> Result<(), Error>;
    fn get_rdp_channel(&self) -> Result<Receiver<RDPMessage>, Error>;
    fn get_link_channel(&self, peer: Ipv6Addr) -> Result<
        (Sender<rift_protocol::LinkInfo>, Receiver<rift_protocol::LinkInfo>),
        Error
    >;
}

#[derive(Debug)]
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
