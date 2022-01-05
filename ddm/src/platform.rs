use std::io::Result;

use tokio::sync::mpsc::{Sender, Receiver};
use icmpv6::RDPMessage;
use async_trait::async_trait;

use crate::protocol::{DdmMessage, PeerMessage};
use crate::port::Port;
use crate::router::Route;

pub trait Capabilities {
    fn discovery() -> bool;
}

#[async_trait]
pub trait Ports {
    async fn ports(&self) -> Result<Vec<Port>>;
}

#[async_trait]
pub trait Rdp {
    async fn rdp_channel(&self, p: Port)
    -> Result<(Sender<RDPMessage>, Receiver<RDPMessage>)>;
}

#[async_trait]
pub trait Ddm {
    async fn peer_channel(&self, p: Port)
    -> Result<(Sender<PeerMessage>, Receiver<PeerMessage>)>;

    async fn ddm_channel(&self, p: Port)
    -> Result<(Sender<DdmMessage>, Receiver<DdmMessage>)>;
}

#[async_trait]
pub trait Router {
    async fn get_routes(&self) -> Result<Vec<Route>>;
    async fn set_route(&self, r: Route) -> Result<()>;
    async fn delete_route(&self, r: Route) -> Result<()>;
}

pub trait Full:
    Capabilities +
    Ports +
    Rdp +
    Ddm +
    Router +
    Sync +
    Send +
    Clone +
    'static
{}

impl<T: 
    Capabilities +
    Ports +
    Rdp +
    Ddm +
    Router +
    Sync +
    Send +
    Clone +
    'static
> Full for T {}
