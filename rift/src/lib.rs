// Copyright 2021 Oxide Computer Company

mod error;
mod admin;
mod topology;
pub mod config;
pub mod link;

use std::time::SystemTime;
use crate::error::Error;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use tokio::time::sleep;
use std::time::{Duration};
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use platform::{Platform, IpIfAddr};
use slog::{trace, info};
use link::LinkSM;
use rift_protocol::lie::{LIEPacket, Neighbor};

/// The RIFT multicast address used for bootstrapping ff02::a1f7.
pub const RDP_MADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0,0,0,0,0,0, 0xa1f7);
pub const LINKINFO_PORT: u16 = 914;
pub const TOPOLOGYINFO_PORT: u16 = 915;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Peer {
    pub remote_addr: Ipv6Addr,
    pub advertisement: icmpv6::RouterAdvertisement,
    pub lie: Option<LIEPacket>,
    pub neighbor: Option<Neighbor>,
    pub last_seen: u128,
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

impl Peer {
    fn is_expired(&self) -> Result<bool, Error> {
        let delta = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Err(e) => return runtime_error!("system time: {}", e),
            Ok(n) => n.as_millis() - self.last_seen,
        };
        Ok(delta >= self.advertisement.reachable_time.into())
    }
}

#[derive(Debug, Clone)]
enum PeerEvent {
    Up((Peer, IpIfAddr)),
    Down((Peer, IpIfAddr)),
}

pub struct Rift<P: Platform + std::marker::Send + 'static> {
    platform: Arc::<Mutex::<P>>,
    links: Arc::<Mutex::<HashSet::<LinkSM>>>,
    log: slog::Logger,
    config: config::Config,
}

impl<P: Platform + std::marker::Send + std::marker::Sync> Rift<P> {

    pub fn new(
        platform: Arc::<Mutex::<P>>, 
        log: slog::Logger,
        config: config::Config,
    ) -> Self {
        Rift{
            platform: platform, 
            links: Arc::new(Mutex::new(HashSet::new())),
            log: log,
            config: config,
        }
    }

    pub async fn run(&mut self) -> Result<(), error::Error> {

        // start admin interface
        info!(self.log, "starting adm handler");
        self.admin_handler();

        // collect link status from the platform
        let links = {
            let p = self.platform .lock().await;
            p.get_links()?
        };

        let (peer_event_tx, peer_event_rx) = broadcast::channel(32);

        // start topology thread
        topology::tie_entry(
            self.log.clone(),
            self.platform.clone(),
            self.links.clone(),
            self.config,
            peer_event_rx,
        ).await;

        // start link state machines
        for l in links.iter() {
            let mut sm = link::LinkSM::new(
                self.log.clone(), 
                l.name.clone(),
                l.state,
                self.config,
            );
            sm.run(
                self.platform.clone(),
                peer_event_tx.clone(),
            ).await;
            let mut lsms = self.links.lock().await;
            lsms.insert(sm);
        }

        self.router_loop().await?;

        Ok(())

    }

    async fn router_loop(&self) -> Result<(), error::Error> {

        loop {
            sleep(Duration::from_secs(10)).await;
            trace!(self.log, "router loop");
        }

        #[allow(unreachable_code)]
        Err(error::Error::Runtime("early exit".to_string()))
    }

}
