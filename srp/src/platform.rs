use std::io::Result;

use tokio::sync::mpsc::{Sender, Receiver};

use crate::protocol::{SrpMessage, PeerMessage};
use crate::rdp::RdpMessage;
use crate::port::Port;
use crate::flowstat::PortStats;
use crate::router::Route;

pub trait Ports {
    fn ports(&self) -> Result<Vec<Port>>;
}

pub trait FlowStat {
    fn stats(&self, p: Port) -> Result<PortStats>;
}

pub trait Rdp {
    fn rdp_channel(&self, p: Port)
    -> Result<(Sender<RdpMessage>, Receiver<RdpMessage>)>;
}

pub trait Srp {
    fn peer_channel(&self, p: Port)
    -> Result<(Sender<PeerMessage>, Receiver<PeerMessage>)>;

    fn arc_channel(&self, p: Port)
    -> Result<(Sender<SrpMessage>, Receiver<SrpMessage>)>;
}

pub trait Router {
    fn get_routes(&self) -> Result<Vec<Route>>;
    fn set_route(&self, r: Route) -> Result<()>;
    fn delete_route(&self, r: Route) -> Result<()>;
}

pub trait Full: Ports + FlowStat + Rdp + Srp + Router {}
impl<T: Ports + FlowStat + Rdp + Srp + Router> Full for T {}