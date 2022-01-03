use std::io::Result;

use tokio::sync::mpsc::{Sender, Receiver};

use crate::protocol::{DdmMessage, PeerMessage};
use crate::rdp::RdpMessage;
use crate::port::Port;
use crate::router::Route;

pub trait Ports {
    fn ports(&self) -> Result<Vec<Port>>;
}

pub trait Rdp {
    fn rdp_channel(&self, p: Port)
    -> Result<(Sender<RdpMessage>, Receiver<RdpMessage>)>;
}

pub trait Ddm {
    fn peer_channel(&self, p: Port)
    -> Result<(Sender<PeerMessage>, Receiver<PeerMessage>)>;

    fn ddm_channel(&self, p: Port)
    -> Result<(Sender<DdmMessage>, Receiver<DdmMessage>)>;
}

pub trait Router {
    fn get_routes(&self) -> Result<Vec<Route>>;
    fn set_route(&self, r: Route) -> Result<()>;
    fn delete_route(&self, r: Route) -> Result<()>;
}

pub trait Full:
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
    Ports +
    Rdp +
    Ddm +
    Router +
    Sync +
    Send +
    Clone +
    'static
> Full for T {}
