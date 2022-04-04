// DDM Peering

// TODO(you are here)
//
// - Plumb in dropshot server
// - Generate clients
// - Implement 3-way peering handshake
// - Implement keepalives

use std::io::Result;
use std::net::Ipv6Addr;
use std::time::Duration;

use tokio::{ spawn, time::sleep };
use slog::Logger;

pub struct PeerSession {
    log: Logger,
    ifnum: i32,
    addr: Ipv6Addr,
    interval: u64,
    expire: u64,
}

impl PeerSession {
    pub fn new(
        log: Logger,
        ifnum: i32,
        addr: Ipv6Addr,
        interval: u64,
        expire: u64,
    ) -> Self {
        PeerSession{ log, ifnum, addr, interval, expire }
    }

    pub async fn start(&self) -> Result<()> {

        //
        // establish initial peering relationship
        //
        
        Self::ping(&self.log, self.ifnum, self.addr).await?;
        Self::pingpong(&self.log, self.ifnum, self.addr).await?;

        //
        // keep the peering session alive on a background task
        //

        let log = self.log.clone();
        let ifnum = self.ifnum;
        let addr = self.addr;
        let interval = self.interval;
        let expire = self.expire;
        spawn(async move { 
            Self::keepalive(log, ifnum, addr, interval, expire);
        });

        Ok(())
    }

    async fn keepalive(
        log: Logger,
        ifnum: i32,
        addr: Ipv6Addr,
        interval: u64,
        expire: u64,
    ) -> Result<()> {
        loop {
            Self::ping(&log, ifnum, addr);
            sleep(Duration::from_millis(interval)).await;
        }
    }

    async fn ping(log: &Logger, ifnum: i32, addr: Ipv6Addr) -> Result<()> {
        todo!();
    }

    async fn pingpong(log: &Logger, ifnum: i32, addr: Ipv6Addr) -> Result<()> {
        todo!();
    }
}


