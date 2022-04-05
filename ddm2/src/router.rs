// DDM Router Implementation

use std::net::Ipv6Addr;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use slog::{self, warn, Logger};

use tokio::{sync::Mutex, spawn, time::sleep};
use libnet::get_ipaddr_info;
use icmpv6::{ICMPv6Packet, RouterSolicitation};

use crate::rdp;

pub struct Router { 
    config: Config,
    state: Arc::<Mutex::<RouterState>>,
    log: Logger,
}

struct RouterState {
    /// Interface numbers for the IP interfaces this router will peer over. The
    /// NeighboringRouter entry value for each interface index is populated when
    /// a neighbor on that interface is discovered.
    interfaces: BTreeMap::<i32, Option::<NeighboringRouter>>,
}

/// User provided router configuration information
pub struct Config {
    /// Interfaces the router will peer over. These are illumos address object
    /// names e.g. "cxgbe0/v6"
    pub interfaces: Vec<String>,

    /// How many milliseconds to wait between neighbor solicitations during
    /// discovery.
    pub discovery_interval: u64
}

impl Default for Config {
    fn default() -> Self {
        Config {
            interfaces: Vec::new(),
            discovery_interval: 1000,
        }
    }
}

impl Router {
    pub fn new(log: Logger, config: Config) -> Result<Self, String> {

        let mut interfaces = BTreeMap::new();
        for name in &config.interfaces {
            let ifnum = get_ipaddr_info(&name)
                .map_err(|e| e.to_string())?
                .index;
            interfaces.insert(ifnum, None);
        }
        let state = Arc::new(Mutex::new(RouterState{ interfaces }));
        Ok(Router{ log, config, state })
    }

    pub async fn neighbors(&self) -> BTreeMap<i32, Option::<NeighboringRouter>> {
        self.state.lock().await.interfaces.clone()
    }

    pub async fn run(&self) -> Result<(), String> {
        self.start_discovery().await;
        Ok(())
    }

    async fn start_discovery(&self) {
        // Get a copy of they interface keys. We cannot hold onto the lock as
        // the threads that are spawned below need to acquire the lock
        // individually to update the router state when a peer is discovered.
        
        let s = self.state.lock().await;
        let ifnums: Vec<i32> = s
            .interfaces
            .keys()
            .map(|k| *k)
            .collect();
        drop(s);

        for i in ifnums {
            let state = self.state.clone();
            let interval = self.config.discovery_interval;
            let log = self.log.clone();
            spawn(async move { 
                Self::discover_neighboring_router(
                    i, state, interval, log).await; 
            });
        }
    }

    async fn discover_neighboring_router(
        ifnum: i32,
        state: Arc::<Mutex::<RouterState>>,
        interval: u64,
        log: Logger,
    ) {
        loop {
            match discover_neighboring_router(ifnum, interval, log.clone()).await {
                Ok(addr) => {
                    state.lock().await.interfaces.insert(
                        ifnum,
                        Some(NeighboringRouter{ addr }),
                    );
                }
                Err(_) => {
                    // log
                }
            }
        }
    }

}

async fn discover_neighboring_router(
    ifnum: i32,
    interval: u64,
    log: Logger,
) -> Result<Ipv6Addr, String> {

    //
    // Start a solicitor.
    //
    let mut solicitor = Solicitor::new(log.clone(), ifnum, interval); 
    solicitor.start();

    //
    // Handle advertisements.
    //

    let receiver = rdp::Receiver::new(log.clone(), ifnum as u32)
        .map_err(|e| e.to_string())?;

    loop {
        match receiver.recv().await {
            Ok((src, ICMPv6Packet::RouterSolicitation(_))) => return Ok(src),
            Ok(_) => continue,
            Err(_err) => {
                // log
            }
        }
    }
}

async fn solicit_ddm_router(ifnum: i32) -> Result<(), String>{
    let msg = ICMPv6Packet::RouterSolicitation(
        RouterSolicitation::new(None)
    );
    let dst = rdp::DDM_RDP_MADDR;
    rdp::send(msg.clone(), dst, ifnum as u32)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// A solicitor that solicits in the background and stops soliciting when
/// droppd.
struct Solicitor {
    ifnum: i32,
    task: Option<tokio::task::JoinHandle<()>>,
    interval: u64,
    log: Logger,
}

impl Solicitor {
    fn new(log: Logger, ifnum: i32, interval: u64) -> Self {
        Solicitor { ifnum, interval, task: None, log }
    }

    fn start(&mut self) {
        let ifnum = self.ifnum;
        let interval = self.interval;
        let log = self.log.clone();
         self.task = Some(spawn(async move { 
            loop { 
                match solicit_ddm_router(ifnum).await {
                    Ok(_) => {},
                    Err(e) => {
                        warn!(log, "solicit failed: {}", e);
                    }
                }
                sleep(Duration::from_millis(interval)).await;
            } 
        }));
    }
}

impl Drop for Solicitor {
    fn drop(&mut self) {
        match self.task {
            Some(ref t) => t.abort(),
            None => {}
        }
    }
}

#[derive(Clone, Copy)]
pub struct NeighboringRouter {
    pub addr: Ipv6Addr
}

#[cfg(test)]
mod tests {

    use std::time::Duration;
    use std::net::IpAddr;

    use anyhow::Result;
    use util::test::testlab_x2;
    use tokio::time::sleep;
    use super::*;

    #[tokio::test]
    async fn rs_discover() -> Result<()> {

        //
        // set up testlab interfaces
        //
        
        let interfaces = testlab_x2("disc1")?;
        let if1 = format!("{}/v6", interfaces[0].name.clone());
        let if2 = format!("{}/v6", interfaces[1].name.clone());

        //
        // set up routers
        //

        let discovery_interval = 100;
        let c1 = Config{ interfaces: vec![if1], discovery_interval };
        let c2 = Config{ interfaces: vec![if2], discovery_interval };

        let log = util::test::logger();
        let r1 = Router::new(log.clone(), c1).expect("new router 1");
        let r2 = Router::new(log.clone(), c2).expect("new router 1");

        //
        // run the routers
        //
        
        println!("running routers");
        r1.run().await.expect("run router 1");
        r2.run().await.expect("run router 2");
        println!("routers running");

        //
        // wait for discovery
        //
        
        println!("sleeping");
        sleep(Duration::from_secs(1)).await;
        println!("done sleeping");

        //
        // assert expected discovery state
        //

        println!("get n1");
        let n1 = r1.neighbors().await
            .get(&interfaces[0].addr.info.index)
            .expect("get n1")
            .expect("n1 is some");

        println!("get n1");
        let n2 = r2.neighbors().await
            .get(&interfaces[1].addr.info.index)
            .expect("get n2")
            .expect("n2 is some");

        println!("got n1/n2");

        assert_eq!(
            IpAddr::V6(n1.addr),
            interfaces[1].addr.info.addr,
        );

        assert_eq!(
            IpAddr::V6(n2.addr),
            interfaces[0].addr.info.addr,
        );

        Ok(())
    }
}
