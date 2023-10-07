use crate::error::Error;
use crate::messages::Message;
use crate::session::FsmEvent;
use slog::Logger;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub trait BgpListener<Cnx: BgpConnection> {
    fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, Error>
    where
        Self: Sized;

    fn accept(
        &self,
        log: Logger,
        addr_to_session: Arc<Mutex<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>>,
        timeout: Duration,
    ) -> Result<Cnx, Error>;
}

pub trait BgpConnection: Send + Clone {
    fn new(source: Option<SocketAddr>, peer: SocketAddr, log: Logger) -> Self
    where
        Self: Sized;

    fn connect(
        &self,
        event_tx: Sender<FsmEvent<Self>>,
        timeout: Duration,
    ) -> Result<(), Error>
    where
        Self: Sized;

    fn send(&self, msg: Message) -> Result<(), Error>;
    fn peer(&self) -> SocketAddr;
}
