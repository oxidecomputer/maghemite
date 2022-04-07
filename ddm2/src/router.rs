// DDM Router Implementation

use std::net::{IpAddr, Ipv6Addr};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use std::convert::TryFrom;

use tokio::{sync::Mutex, spawn, time::sleep};
use libnet::{IpInfo, get_ipaddr_info};
use icmpv6::{ICMPv6Packet, RouterSolicitation};
use slog::{self, error, warn, Logger};

use crate::rdp;
use crate::peer;
use crate::rpx;
use crate::net::Ipv6Prefix;

pub struct Router { 
    config: Config,
    state: Arc::<Mutex::<RouterState>>,
    log: Logger,
}

pub(crate) struct RouterState {
    /// Interface numbers for the IP interfaces this router will peer over. The
    /// NeighboringRouter entry value for each interface index is populated when
    /// a neighbor on that interface is discovered.
    pub(crate) interfaces: BTreeMap::<Interface, Option::<NeighboringRouter>>,

    /// A set of prefixes that have been advertised to this router, indexed by
    /// nexthop
    pub(crate) remote_prefixes: BTreeMap::<Ipv6Addr, HashSet::<Ipv6Prefix>>,

    /// A set of prefixes that this router is advertising.
    pub(crate) local_prefixes: HashSet::<Ipv6Prefix>,
}

impl Default for RouterState {
    fn default() -> Self {
        RouterState {
            interfaces: BTreeMap::new(),
            remote_prefixes: BTreeMap::new(),
            local_prefixes: HashSet::new(),
        }
    }
}


/// User provided router configuration information
#[derive(Clone)]
pub struct Config {
    /// Router name
    pub name: String,

    /// Interfaces the router will peer over. These are illumos address object
    /// names e.g. "cxgbe0/v6"
    pub interfaces: Vec<String>,

    /// How many milliseconds to wait between neighbor solicitations during
    /// discovery.
    pub discovery_interval: u64,

    /// How many milliseconds to wait between peer pings.
    pub peer_interval: u64,

    /// How many milliseconds to wait until expiring a peer.
    pub peer_expire: u64,

    /// What port to use when contacting peers.
    pub peer_port: u16,

    /// What port to use for router prefix exchange
    pub rpx_port: u16,

    /// What address to listen on for router prefix exchange messages
    pub rpx_addr: Ipv6Addr,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            name: String::new(),
            interfaces: Vec::new(),
            discovery_interval: 100,
            peer_interval: 50,
            peer_expire: 3000,
            peer_port: 0x1dd0,
            rpx_port: 0x1dd1,
            rpx_addr: Ipv6Addr::UNSPECIFIED,
        }
    }
}

impl Router {
    pub fn new(log: Logger, config: Config) -> Result<Self, String> {

        let mut interfaces = BTreeMap::new();
        for name in &config.interfaces {
            let info = get_ipaddr_info(&name).map_err(|e| e.to_string())?;
            interfaces.insert(info.try_into()? , None);
        }
        let state = Arc::new(Mutex::new(
            RouterState{interfaces, ..Default::default()}
        ));
        Ok(Router{ log, config, state })
    }

    pub async fn neighbors(&self) 
    -> BTreeMap<Interface, Option::<NeighboringRouter>> {
        self.state.lock().await.interfaces.clone()
    }

    pub async fn peer_status(&self) -> BTreeMap<Interface, Option::<peer::Status>> {

        let mut result = BTreeMap::new();
        for (k,v) in self.state.lock().await.interfaces.clone() {
            let status = match v {
                Some(rtr) => Some(rtr.session.status().await),
                None => None
            };
            result.insert(k, status);
        }
        
        result
    }

    pub async fn run(&self) -> Result<(), String> {
        self.start_discovery().await;
        rpx::start_server(
            self.config.rpx_addr, 
            self.config.rpx_port,
            self.state.clone(),
        )?;
        Ok(())
    }

    async fn start_discovery(&self) {
        // Get a copy of they interface keys. We cannot hold onto the lock as
        // the threads that are spawned below need to acquire the lock
        // individually to update the router state when a peer is discovered.
        
        let s = self.state.lock().await;
        let interfaces : Vec<Interface> = s
            .interfaces
            .keys()
            .map(|k| *k)
            .collect();
        drop(s);

        for i in interfaces {
            let state = self.state.clone();
            let config = self.config.clone();
            let log = self.log.clone();
            spawn(async move { 
                Self::discover_neighboring_router(i, state, config, log).await;
            });
        }
    }

    async fn discover_neighboring_router(
        interface: Interface,
        state: Arc::<Mutex::<RouterState>>,
        config: Config,
        log: Logger,
    ) {
        loop {
            match discover_neighboring_router(
                interface.ifnum, config.discovery_interval, log.clone()).await {
                Ok(addr) => {
                    let mut session = peer::Session::new(
                        log.clone(),
                        interface.ifnum,
                        addr,
                        config.peer_interval,
                        config.peer_expire,
                        config.name.clone(),
                        interface.ll_addr,
                        config.peer_port,
                    );
                    match session.start().await {
                        Ok(_) => {},
                        Err(e) => {
                            error!(log,
                                "start peer session on {:?}: {}", interface, e);
                            sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    state.lock().await.interfaces.insert(
                        interface,
                        Some(NeighboringRouter{
                            addr,
                            session,
                        }),
                    );
                    return;
                }
                Err(e) => {
                    sleep(Duration::from_millis(100)).await;
                    error!(log, "discovery error on {:?}: {}", interface, e);
                }
            }
        }
    }

    pub async fn advertise(&self, prefixes: HashSet::<Ipv6Prefix>)
    -> Result<(), String>{

        let interfaces = self.state.lock().await.interfaces.clone();
        for (_, rtr) in interfaces {

            let rtr = match rtr {
                Some(rtr) => rtr,
                None => continue,
            };

            // only advertise to active peers
            match rtr.session.status().await {
                peer::Status::Active => {}
                _ => continue,
            }

            rpx::advertise(&prefixes, rtr.addr).await?;

        }

        todo!();
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

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Interface {
    ifnum: i32,
    ll_addr: Ipv6Addr,
}

impl TryFrom<&IpInfo> for Interface {
    type Error = String;

    fn try_from(info: &IpInfo) -> Result<Self, Self::Error> {
        let ll_addr = match info.addr {
            IpAddr::V6(addr) => addr,
            _ => return Err("expected ipv6 addr".into()),
        };
        Ok(Interface{ll_addr, ifnum: info.index})
    }
}

impl TryFrom<IpInfo> for Interface {
    type Error = String;

    fn try_from(info: IpInfo) -> Result<Self, Self::Error> {
        Interface::try_from(&info)
    }
}

#[derive(Clone)]
pub struct NeighboringRouter {
    pub addr: Ipv6Addr,
    pub session: peer::Session,
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
    async fn rs_discover_and_peer() -> Result<()> {

        //
        // set up testlab interfaces
        //
        
        let interfaces = testlab_x2("disc1")?;
        let if1 = format!("{}/v6", interfaces[0].name.clone());
        let if2 = format!("{}/v6", interfaces[1].name.clone());

        //
        // set up routers
        //

        let c1 = Config{
            name: "r1".into(),
            interfaces: vec![if1],
            ..Default::default()
        };

        let c2 = Config{
            name: "r2".into(),
            interfaces: vec![if2],
            ..Default::default()
        };

        let log = util::test::logger();
        let r1 = Router::new(log.clone(), c1).expect("new router 1");
        let r2 = Router::new(log.clone(), c2).expect("new router 2");

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
        sleep(Duration::from_secs(2)).await;
        println!("done sleeping");

        //
        // assert expected discovery state
        //

        println!("get n1");
        let n1 = r1.neighbors().await;
        let ifx1: Interface = (&interfaces[0].addr.info).try_into().unwrap();
        let n1 = n1.get(&ifx1)
            .expect("get n1").as_ref()
            .expect("n1 is some");

        println!("get n1");
        let n2 = r2.neighbors().await;
        let ifx2: Interface = (&interfaces[1].addr.info).try_into().unwrap();
        let n2 = n2.get(&ifx2)
            .expect("get n2").as_ref()
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

        //
        // assert expected peer state
        //

        let p1 = r1.peer_status().await;
        assert_eq!(p1.len(), 1);
        assert_eq!(p1.get(&ifx1), Some(&Some(peer::Status::Active)));

        //
        // drop a peer and test expiration
        //

        drop(r2);
        sleep(Duration::from_secs(5)).await;

        let p1 = r1.peer_status().await;
        assert_eq!(p1.len(), 1);
        assert_eq!(p1.get(&ifx1), Some(&Some(peer::Status::Expired)));


        Ok(())
    }
}
