// DDM Router Implementation

use std::net::{IpAddr, Ipv6Addr};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use std::convert::TryFrom;

use tokio::{sync::Mutex, spawn, time::sleep};
use libnet::{IpInfo, get_ipaddr_info};
use icmpv6::{ICMPv6Packet, RouterSolicitation};
use slog::{self, trace, error, warn, Logger};

use crate::rdp;
use crate::peer;
use crate::rpx;
use crate::net::Ipv6Prefix;
use crate::protocol::RouterKind;

#[derive(Clone)]
pub struct Router { 
    pub config: Config,
    pub(crate) state: Arc::<Mutex::<RouterState>>,
    pub(crate) log: Logger,
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

    /// The kind of router this is.
    pub router_kind: RouterKind,
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
            router_kind: RouterKind::Server,
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

    /// Get the status for a peer with the specified address
    pub async fn peer_status_for(&self, addr: Ipv6Addr) -> Option<(Interface, peer::Status)> {

        for (ifx, nbr) in self.state.lock().await.interfaces.clone() {
            match nbr {
                Some(nbr) => {
                    if nbr.addr == addr {
                        return Some((ifx, nbr.session.status().await));
                    }
                    continue
                }
                None => return None,
            }
        }
        None
    }

    pub async fn run(&self) -> Result<(), String> {
        self.start_rpx().await?;
        self.start_discovery().await;
        self.initial_solicit().await;
        Ok(())
    }

    pub async fn start_rpx(&self) -> Result<(), String> {

        let s = self.state.lock().await;
        let interfaces : Vec<Interface> = s
            .interfaces
            .keys()
            .map(|k| *k)
            .collect();
        drop(s);

        for i in interfaces {
            rpx::start_server(
                i.ll_addr,
                self.config.rpx_port,
                self.clone(),
            )?;
        }

        Ok(())
    }

    /// for each interface, wait until the peering session is active and then
    /// solicit all the routes from that peer.
    async fn initial_solicit(&self) {

        trace!(self.log, "initial solicit: cloning ifxs");
        let interfaces = self.state.lock().await.interfaces.clone();
        trace!(self.log, "initial solicit: cloned ifxs");
        for (ifx, _) in interfaces {
            let rtr = self.clone();
            spawn(async move { loop {
                // get an updated copy of the neighbor
                let nbr = rtr.state.lock().await.interfaces.get(&ifx).unwrap().clone();
                match nbr {
                    Some(ref nbr) => match nbr.session.status().await {
                        peer::Status::Active => {
                            trace!(rtr.log, "soliciting {} on {:?}", nbr.addr, ifx);
                            match rtr.solicit(ifx, nbr.addr).await {
                                Ok(_) => return,
                                Err(e) => {
                                    warn!(rtr.log, "solicit failed: {}", e);
                                }
                            }
                        }
                        _ => { 
                            trace!(rtr.log, "initial_solicit: peer not active on {:?}", ifx);
                        }
                    }
                    None => { 
                        trace!(rtr.log, "initial_solicit: no peer on {:?}", ifx);
                    }
                };
                sleep(Duration::from_millis(rtr.config.peer_interval)).await;
            }});
        }

    }

    pub async fn add_remote_prefixes(&self, nexthop: Ipv6Addr, prefixes: HashSet::<Ipv6Prefix>) {
        let mut router_state = self.state.lock().await;
        match router_state.remote_prefixes.get_mut(&nexthop) {
            Some(ref mut set) => {
                set.extend(prefixes.iter());
            }
            None => {
                router_state.remote_prefixes.insert(nexthop, prefixes.clone());
            }
        }
    }

    async fn solicit(&self, ifx: Interface, dst: Ipv6Addr) 
    -> Result<(), String> {

        let advertisement = rpx::solicit(
            ifx.ll_addr,
            ifx.ifnum,
            dst,
            self.config.rpx_port,
        ).await?;

        self.add_remote_prefixes(
            advertisement.nexthop,
            advertisement.prefixes,
        ).await;

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
                        config.router_kind,
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

        // get exclusive access to internal state
        let mut state = self.state.lock().await;

        // add the provided prefixes to our local prefixes
        state.local_prefixes.extend(prefixes.iter());

        // clone out the current interfaces so we can drop our lock on internal
        // state
        let interfaces = state.interfaces.clone();
        drop(state);

        // advertise the given prefixes to our peers
        for (ifx, rtr) in interfaces {

            let rtr = match rtr {
                Some(rtr) => rtr,
                None => continue,
            };

            // only advertise to active peers
            match rtr.session.status().await {
                peer::Status::Active => {}
                _ => continue,
            }

            rpx::advertise(
                ifx.ll_addr,
                prefixes.clone(),
                ifx.ifnum,
                rtr.addr,
                self.config.rpx_port,
            ).await?;

        }

        Ok(())
    }

    pub async fn nexthops(&self, prefix: Ipv6Prefix) -> HashSet::<Ipv6Addr> {

        let mut result = HashSet::new();
        let remotes = self.state.lock().await.remote_prefixes.clone();
        for (nexthop, prefixes) in remotes {
            if prefixes.contains(&prefix) {
                result.insert(nexthop);
            }
        }

        result
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
    pub ifnum: i32,
    pub ll_addr: Ipv6Addr,
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
    use std::str::FromStr;

    use anyhow::Result;
    use util::test::testlab_x2;
    use tokio::time::sleep;
    use super::*;

    /// Discover Peer Exchange
    #[tokio::test]
    async fn rs_dpx() -> Result<()> {

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
            peer_interval: 50,
            peer_expire: 10000,
            ..Default::default()
        };

        let c2 = Config{
            name: "r2".into(),
            interfaces: vec![if2],
            peer_interval: 50,
            peer_expire: 10000,
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
        // advertise some routes
        //

        let pfx1 = Ipv6Prefix::from_str("fd00:1::/64").expect("parse prefix a1");
        let mut a1 = HashSet::new();
        a1.insert(pfx1);
        r1.advertise(a1).await.expect("advertise from r1");

        let pfx2 = Ipv6Prefix::from_str("fd00:2::/64").expect("parse prefix a2");
        let mut a2 = HashSet::new();
        a2.insert(pfx2);
        r2.advertise(a2).await.expect("advertise from a2");

        //
        // wait for discovery
        //
        
        println!("sleeping");
        sleep(Duration::from_secs(5)).await;
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

        let p2 = r2.peer_status().await;
        assert_eq!(p2.len(), 1);
        assert_eq!(p2.get(&ifx2), Some(&Some(peer::Status::Active)));

        //
        // assert expected prefix state
        //
        
        sleep(Duration::from_secs(5)).await;

        // router1 should have router2's link-local address as a nexthop for
        // fd00:2::/64
        let nexthops = r1.nexthops(pfx2).await;
        println!("{:?}", nexthops);
        assert!(nexthops.contains(&ifx2.ll_addr));

        // router2 should have router1's link-local address as a nexthop for
        // fd00:1::/64
        let nexthops = r2.nexthops(pfx1).await;
        println!("{:?}", nexthops);
        assert!(nexthops.contains(&ifx1.ll_addr));

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
