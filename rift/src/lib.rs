// Copyright 2021 Oxide Computer Company

mod error;
mod admin;
mod rdp;
mod link;

use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use platform::Platform;
use slog::info;
use std::sync::mpsc::{Sender, Receiver, channel};
use link::LinkSM;

/// The RIFT multicast address used for bootstrapping ff02::a1f7.
pub const RDP_MADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0,0,0,0,0,0, 0xa1f7);
pub const LINKINFO_PORT: u16 = 914;
pub const TOPOLOY_INFO_PORT: u16 = 915;

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Peer {
    pub remote_addr: Ipv6Addr,
    pub advertisement: icmpv6::RouterAdvertisement,
}

impl Hash for Peer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.remote_addr.hash(state);
    }
}

impl PartialEq for Peer {
    fn eq(&self, other: &Self) -> bool {
        self.remote_addr == other.remote_addr
    }
}
impl Eq for Peer {}

pub struct Rift<P: Platform + std::marker::Send + 'static> {
    platform: Arc::<Mutex::<P>>,
    peers: Arc::<Mutex::<HashSet::<Peer>>>,
    links: Arc::<Mutex::<HashSet::<LinkSM>>>,
    log: slog::Logger,
}

impl<P: Platform + std::marker::Send> Rift<P> {
    pub fn new(
        platform: Arc::<Mutex::<P>>, 
        log: slog::Logger,
    ) -> Self {
        Rift{
            platform: platform, 
            peers: Arc::new(Mutex::new(HashSet::new())),
            links: Arc::new(Mutex::new(HashSet::new())),
            log: log,
        }
    }

    pub fn run(&mut self) -> Result<(), error::Error> {

        let (peer_tx, peer_rx): (Sender<Peer>, Receiver<Peer>) = channel();

        info!(self.log, "starting link handler");
        self.link_handler(peer_rx)?;

        info!(self.log, "starting rdp handler");
        self.rdp_handler(peer_tx)?;

        info!(self.log, "starting adm handler");
        self.admin_handler();

        info!(self.log, "entering router loop");
        self.router_loop()

    }

    fn router_loop(&self) -> Result<(), error::Error> {

        loop {
            let p = self.platform.lock().unwrap();
            (*p).solicit_rift_routers()?;
            (*p).advertise_rift_router()?;
            std::thread::sleep(
                std::time::Duration::from_secs(5),
            );
        }

        #[allow(unreachable_code)]
        Err(error::Error::Runtime("early exit".to_string()))
    }

}
