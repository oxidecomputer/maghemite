use crate::port::Port;
use std::io::Result;
use icmpv6::RDPMessage;
use async_trait::async_trait;
use tokio::sync::mpsc::{Receiver};
use crate::protocol::{Ping, Pong, PingPong};
use crate::router::Route;

pub trait Capabilities {
    fn discovery() -> bool;
}

pub trait Ports {
    fn ports(&self) -> Result<Vec<Port>>;
}

#[async_trait]
pub trait Rdp {
    async fn send(m: RDPMessage) -> Result<()>;
    async fn recv() -> Result<Receiver<RDPMessage>>;
}

#[async_trait]
pub trait Ddm {
    async fn ping(m: Ping) -> Result<Pong>;
    async fn pingpong(m: PingPong) -> Result<()>;
}

pub trait Router {
    fn get_routes(&self) -> Result<Vec<Route>>;
    fn set_route(&self, r: Route) -> Result<()>;
    fn delete_route(&self, r: Route) -> Result<()>;
}
