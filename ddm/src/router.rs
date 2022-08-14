//! This file contains the DDM Router implementation. This implementation is
//! responsible for the DDM control plane, and not the data plane. The
//! responsibility of the control plane is to
//!
//!   1. Discover neighboring routers.
//!   2. Peer with neighboring routers.
//!   3. Exchange routing information with neighboring routers.
//!
//! The responsibility of the data plane is to decide what route to use when
//! multiple routes for the same destination are present. This is done either in
//! the operating system kernel or on a switch ASIC and is not implemented here.
//! Here we are only concered with the 3 responsiblities above.
//!
//! The DDM router implementation is mostly event driven. The router responds to
//! discovery solicitations by attempting to peer with a soliciting neighbor.
//! Hailing messages result in reflection responses that let peering routers
//! know this router is a viable peer for route exchange. Reception of
//! advertisements results in the update of routing tables and in the case of
//! transit routers, distribution of advertisements to other peers.
//!
//! Each of the responsibilities above, discovery, peering and routing prefix
//! exchange - are implemented in their own files and have block comments at the
//! top that describe their functionality.
//!
//! The router is intrinsically asynchronous as it is primarily event driven.
//! Because of this several tasks are spawned by the router to manage
//! interactions with other routers and admin API users. A common design element
//! used throughout the router is to save the join handles associated with these
//! tasks in structures with a drop implementation that will abort the thread
//! when dropped. This is to prevent situations like a peering session being
//! kept alive by a peer that has been dropped by a router.
//!
//! A router is configured with a set of interfaces that it expects to peer
//! over. When starting up there is an initial solicit routine that will wait
//! for active peering sessions to be established on each of these interfaces
//! and then solicit each neighboring router for all routes it currently has.
//! This allows a newly peered router to synchronize with the rest of the
//! network. After that initial solicitation takes place, normal real-time route
//! prefix exchange takes place between routers.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;

use icmpv6::ICMPv6Packet;
use libnet::get_ipaddr_info;
use libnet::IpInfo;
use slog::debug;
use slog::error;
use slog::info;
use slog::trace;
use slog::warn;
use slog::Logger;
use slog::{self};
use tokio::spawn;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::net::Ipv6Prefix;
use crate::peer;
use crate::protocol::Advertise;
use crate::protocol::RouterKind;
use crate::rdp;
use crate::rpx;
use crate::sys;

pub struct Router {
    pub config: Config,
    pub(crate) state: Arc<Mutex<RouterState>>,
    pub(crate) log: Logger,
    threadpile: Vec<JoinHandle<()>>,
}

impl Drop for Router {
    fn drop(&mut self) {
        warn!(self.log, "dropping threadpile[{}]", self.threadpile.len());
        for t in &self.threadpile {
            t.abort();
        }
    }
}

#[derive(Default)]
pub struct RouterState {
    /// Interface numbers for the IP interfaces this router will peer over. The
    /// NeighboringRouter entry value for each interface index is populated when
    /// a neighbor on that interface is discovered.
    pub interfaces: BTreeMap<Interface, Option<NeighboringRouter>>,

    /// A set of prefixes that have been advertised to this router, indexed by
    /// nexthop
    pub remote_prefixes: BTreeMap<Ipv6Addr, HashSet<Ipv6Prefix>>,

    /// A set of prefixes that this router is advertising.
    pub local_prefixes: HashSet<Ipv6Prefix>,
}

impl RouterState {
    /// Get the status for a peer with the specified address
    pub async fn peer_status_for(
        &self,
        addr: Ipv6Addr,
    ) -> Option<(Interface, peer::Status)> {
        for (ifx, nbr) in self.interfaces.clone() {
            match nbr {
                Some(nbr) => {
                    if nbr.addr == addr {
                        return Some((ifx, nbr.session.status().await));
                    }
                    continue;
                }
                None => continue,
            }
        }
        None
    }

    /// Get this router's active peers.
    pub async fn active_peers(&self) -> BTreeMap<Interface, NeighboringRouter> {
        let mut result = BTreeMap::new();

        for (ifx, nbr) in self.interfaces.clone() {
            match nbr {
                Some(nbr) => match nbr.session.status().await {
                    peer::Status::Active => {
                        result.insert(ifx, nbr);
                    }
                    _ => continue,
                },
                None => continue,
            }
        }

        result
    }
}

/// User provided router configuration information
#[derive(Debug, Clone)]
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

    /// Only run the upper half of the router. This results in the router
    /// implementing the DDM protocol to discover, peer and exchange routes with
    /// other DDM routers. But it will not actually manage routes on the
    /// underlying system.
    pub upper_half_only: bool,

    /// If this value is populated the router will manage routes through a
    /// Dendrite dpd endpoint rather than the underlying illumos system.
    pub dpd: Option<DpdConfig>,
}

#[derive(Debug, Clone)]
pub struct DpdConfig {
    /// Hostname protod can be contacted at.
    pub host: String,

    /// Port number protod can be contacted on.
    pub port: u16,
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
            upper_half_only: false,
            dpd: None,
        }
    }
}

impl Router {
    pub fn new(log: Logger, config: Config) -> Result<Self, String> {
        let mut interfaces = BTreeMap::new();
        for name in &config.interfaces {
            let info = get_ipaddr_info(&name).map_err(|e| e.to_string())?;
            interfaces.insert(info.try_into()?, None);
        }
        let state = Arc::new(Mutex::new(RouterState {
            interfaces,
            ..Default::default()
        }));
        Ok(Router {
            log,
            config,
            state,
            threadpile: Vec::new(),
        })
    }

    pub async fn neighbors(
        &self,
    ) -> BTreeMap<Interface, Option<NeighboringRouter>> {
        self.state.lock().await.interfaces.clone()
    }

    pub async fn peer_status(
        &self,
    ) -> BTreeMap<Interface, Option<peer::Status>> {
        let mut result = BTreeMap::new();
        for (k, v) in self.state.lock().await.interfaces.clone() {
            let status = match v {
                Some(rtr) => Some(rtr.session.status().await),
                None => None,
            };
            result.insert(k, status);
        }

        result
    }

    pub async fn run(&mut self) -> Result<(), String> {
        self.start_rpx().await?;
        self.start_discovery().await;
        self.initial_solicit().await;
        Ok(())
    }

    pub async fn start_rpx(&mut self) -> Result<(), String> {
        trace!(self.log, "starting rpx");

        let s = self.state.lock().await;
        let interfaces: Vec<Interface> =
            s.interfaces.keys().map(|k| *k).collect();
        drop(s);

        for i in interfaces {
            let t = rpx::start_server(
                self.log.clone(),
                i.ll_addr,
                self.config.rpx_port,
                self.state.clone(),
                self.config.clone(),
            )?;
            self.threadpile.push(t);
        }

        trace!(self.log, "rpx started");

        Ok(())
    }

    /// for each interface, wait until the peering session is active and then
    /// solicit all the routes from that peer.
    async fn initial_solicit(&mut self) {
        trace!(self.log, "starting initial solicit");

        trace!(self.log, "initial solicit: cloning ifxs");
        let interfaces = self.state.lock().await.interfaces.clone();
        trace!(self.log, "initial solicit: cloned ifxs");
        for (ifx, _) in interfaces {
            debug!(self.log, "begin solicit for {:?}", ifx);
            let rtr = self.state.clone();
            let log = self.log.clone();
            let config = self.config.clone();
            let state = self.state.clone();
            let t = spawn(async move {
                loop {
                    // get an updated copy of the neighbor
                    let nbr =
                        rtr.lock().await.interfaces.get(&ifx).unwrap().clone();
                    match nbr {
                        Some(ref nbr) => match nbr.session.status().await {
                            peer::Status::Active => {
                                trace!(
                                    log,
                                    "soliciting {} on {:?}",
                                    nbr.addr,
                                    ifx
                                );
                                match Self::solicit(
                                    config.clone(),
                                    state.clone(),
                                    ifx,
                                    nbr.addr,
                                    &log,
                                )
                                .await
                                {
                                    Ok(_) => {
                                        debug!(
                                            log,
                                            "initial solicit complete for {:?}",
                                            ifx,
                                        );
                                        return;
                                    }
                                    Err(e) => {
                                        warn!(log, "solicit failed: {}", e);
                                    }
                                }
                            }
                            _ => {
                                trace!(
                                    log,
                                    "initial_solicit: peer not active on {:?}",
                                    ifx,
                                );
                            }
                        },
                        None => {
                            trace!(
                                log,
                                "initial_solicit: no peer on {:?}",
                                ifx
                            );
                        }
                    };
                    sleep(Duration::from_millis(config.peer_interval)).await;
                }
            });
            self.threadpile.push(t);
        }
        trace!(self.log, "initial solicit started");
    }

    pub async fn add_remote_prefixes(
        state: &Arc<Mutex<RouterState>>,
        nexthop: Ipv6Addr,
        prefixes: HashSet<Ipv6Prefix>,
    ) {
        let mut router_state = state.lock().await;
        match router_state.remote_prefixes.get_mut(&nexthop) {
            Some(ref mut set) => {
                set.extend(prefixes.iter());
            }
            None => {
                router_state
                    .remote_prefixes
                    .insert(nexthop, prefixes.clone());
            }
        }
    }

    pub async fn distribute(
        state: &Arc<Mutex<RouterState>>,
        adv: &Advertise,
        config: &Config,
        log: &Logger,
    ) {
        let s = state.lock().await;
        let active_peers = s.active_peers().await;
        drop(s);

        warn!(log, "DISTRIBUTE({})", active_peers.len());

        for (ifx, nbr) in active_peers {
            // dont redistribute to the source
            if adv.nexthop == nbr.addr {
                continue;
            }

            let mut adv = adv.clone();

            // update the next hop to be this interface e.g. distance vector
            // routing
            adv.nexthop = ifx.ll_addr;

            warn!(log, "DIST: {:?} -> {:?}", adv, nbr.addr);

            match rpx::advertise(
                adv.nexthop,
                adv.prefixes.clone(),
                ifx.ifnum,
                nbr.addr,
                config.rpx_port,
            )
            .await
            {
                Ok(_) => {}
                Err(e) => error!(log, "distribute advertisement: {}", e),
            }
        }
    }

    async fn solicit(
        config: Config,
        state: Arc<Mutex<RouterState>>,
        ifx: Interface,
        dst: Ipv6Addr,
        log: &Logger,
    ) -> Result<(), String> {
        let advertisement =
            rpx::solicit(ifx.ll_addr, ifx.ifnum, dst, config.rpx_port).await?;

        Self::add_remote_prefixes(
            &state,
            advertisement.nexthop,
            advertisement.prefixes.clone(),
        )
        .await;

        if config.router_kind == RouterKind::Transit {
            warn!(log, "DISTRIBUTE");
            Router::distribute(&state, &advertisement, &config, &log).await;
        }

        // for upper half only we're done
        if config.upper_half_only {
            return Ok(());
        }

        // add routes to the underlying system
        sys::add_routes(&log, &config, advertisement.into())
    }

    async fn start_discovery(&mut self) {
        // Get a copy of they interface keys. We cannot hold onto the lock as
        // the threads that are spawned below need to acquire the lock
        // individually to update the router state when a peer is discovered.

        trace!(self.log, "starting discovery");

        let s = self.state.lock().await;
        let interfaces: Vec<Interface> =
            s.interfaces.keys().map(|k| *k).collect();
        drop(s);

        for i in interfaces {
            let state = self.state.clone();
            let config = self.config.clone();
            let log = self.log.clone();
            let t = spawn(async move {
                Self::discover_neighboring_router(i, state, config, log).await;
            });
            self.threadpile.push(t);
        }

        trace!(self.log, "discovery started");
    }

    async fn discover_neighboring_router(
        interface: Interface,
        state: Arc<Mutex<RouterState>>,
        config: Config,
        log: Logger,
    ) {
        //
        // Start a solicitor.
        //
        let mut solicitor = rdp::Solicitor::new(
            log.clone(),
            interface.ifnum,
            config.discovery_interval,
        );
        solicitor.start();

        loop {
            match discover_neighboring_router(interface.ifnum, log.clone())
                .await
            {
                Ok(addr) => {
                    info!(log, "discovered neighbor {}", addr);
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
                        Ok(_) => {
                            info!(log, "started peering session for {}", addr);
                        }
                        Err(e) => {
                            error!(
                                log,
                                "start peer session on {:?}: {}", interface, e
                            );
                            sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    state.lock().await.interfaces.insert(
                        interface,
                        Some(NeighboringRouter {
                            addr,
                            session: Arc::new(session),
                            solicitor: Arc::new(solicitor),
                        }),
                    );
                    info!(log, "neigbor discovery finished on {:?}", interface);
                    return;
                }
                Err(e) => {
                    sleep(Duration::from_millis(100)).await;
                    error!(log, "discovery error on {:?}: {}", interface, e);
                }
            }
        }
    }

    pub async fn advertise(
        &self,
        prefixes: HashSet<Ipv6Prefix>,
    ) -> Result<(), String> {
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
            )
            .await?;
        }

        Ok(())
    }

    pub async fn nexthops(&self, prefix: Ipv6Prefix) -> HashSet<Ipv6Addr> {
        let mut result = HashSet::new();
        let remotes = self.state.lock().await.remote_prefixes.clone();
        debug!(self.log, "[{}] nexthops {:#?}", self.config.name, remotes,);
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
    log: Logger,
) -> Result<Ipv6Addr, String> {
    //
    // Handle solicitation.
    //

    let receiver = rdp::Receiver::new(log.clone(), ifnum as u32)
        .map_err(|e| e.to_string())?;

    loop {
        trace!(log, "waiting for solicitation");
        match receiver.recv().await {
            Ok((src, ICMPv6Packet::RouterSolicitation(_))) => return Ok(src),
            Ok(_) => continue,
            Err(_err) => {
                // log
            }
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
        Ok(Interface {
            ll_addr,
            ifnum: info.index,
        })
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
    pub session: Arc<peer::Session>,
    pub solicitor: Arc<rdp::Solicitor>,
}

#[cfg(test)]
mod tests {

    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;

    use anyhow::Result;
    use slog::debug;
    use slog::info;
    use tokio::time::sleep;
    use util::test::testlab_1x2;
    use util::test::testlab_x2;

    use super::*;

    /// Discover, peer, exchange with two directly connected server routers
    #[tokio::test]
    async fn rs_dpx_x2() -> Result<()> {
        //
        // set up testlab interfaces
        //

        let interfaces = testlab_x2("disc1")?;
        let if1 = format!("{}/v6", interfaces[0].name.clone());
        let if2 = format!("{}/v6", interfaces[1].name.clone());

        //
        // set up routers
        //

        let c1 = Config {
            name: "r1".into(),
            interfaces: vec![if1],
            peer_interval: 100,
            peer_expire: 1000,
            upper_half_only: true,
            ..Default::default()
        };

        let c2 = Config {
            name: "r2".into(),
            interfaces: vec![if2],
            peer_interval: 100,
            peer_expire: 1000,
            upper_half_only: true,
            ..Default::default()
        };

        let log = util::test::logger();
        let mut r1 = Router::new(log.clone(), c1).expect("new router 1");
        let mut r2 = Router::new(log.clone(), c2).expect("new router 2");

        //
        // run the routers
        //

        info!(log, "running routers");
        r1.run().await.expect("run router 1");
        r2.run().await.expect("run router 2");
        info!(log, "routers running");

        //
        // advertise some routes
        //

        let pfx1 =
            Ipv6Prefix::from_str("fd00:1::/64").expect("parse prefix a1");
        let mut a1 = HashSet::new();
        a1.insert(pfx1);
        r1.advertise(a1).await.expect("advertise from r1");

        let pfx2 =
            Ipv6Prefix::from_str("fd00:2::/64").expect("parse prefix a2");
        let mut a2 = HashSet::new();
        a2.insert(pfx2);
        r2.advertise(a2).await.expect("advertise from a2");

        //
        // wait for discovery
        //

        sleep(Duration::from_secs(2)).await;

        //
        // assert expected discovery state
        //

        info!(log, "get n1");
        let n1 = r1.neighbors().await;
        let ifx1: Interface = (&interfaces[0].addr.info).try_into().unwrap();
        let n1 = n1.get(&ifx1).expect("get n1").as_ref().expect("n1 is some");

        info!(log, "get n1");
        let n2s = r2.neighbors().await;
        let ifx2: Interface = (&interfaces[1].addr.info).try_into().unwrap();
        let n2 = n2s
            .get(&ifx2)
            .expect("get n2")
            .as_ref()
            .expect("n2 is some");

        info!(log, "got n1/n2");

        assert_eq!(IpAddr::V6(n1.addr), interfaces[1].addr.info.addr,);

        assert_eq!(IpAddr::V6(n2.addr), interfaces[0].addr.info.addr,);

        //
        // assert expected peer state
        //

        info!(log, "getting peer state");
        let p1 = r1.peer_status().await;
        assert_eq!(p1.len(), 1);
        assert_eq!(p1.get(&ifx1), Some(&Some(peer::Status::Active)));

        let p2 = r2.peer_status().await;
        assert_eq!(p2.len(), 1);
        assert_eq!(p2.get(&ifx2), Some(&Some(peer::Status::Active)));

        //
        // assert expected prefix state
        //

        sleep(Duration::from_secs(2)).await;

        // router1 should have router2's link-local address as a nexthop for
        // fd00:2::/64
        let nexthops = r1.nexthops(pfx2).await;
        debug!(log, "{:?}", nexthops);
        assert!(nexthops.contains(&ifx2.ll_addr));

        // router2 should have router1's link-local address as a nexthop for
        // fd00:1::/64
        let nexthops = r2.nexthops(pfx1).await;
        debug!(log, "{:?}", nexthops);
        assert!(nexthops.contains(&ifx1.ll_addr));

        //
        // drop a peer and test expiration
        //

        // TODO this is fragile, the router interface should not hand back
        // references that can keep threads alive
        info!(log, "dropping r2");
        drop(p2);
        drop(n2);
        drop(r2);
        drop(n2s);
        sleep(Duration::from_secs(3)).await;

        let p1 = r1.peer_status().await;
        assert_eq!(p1.len(), 1);
        assert_eq!(p1.get(&ifx1), Some(&Some(peer::Status::Expired)));

        Ok(())
    }

    /// Discover, peer, exchange with two server routers connected to a single
    /// transit router.
    #[tokio::test]
    async fn rs_dpx_1x2() -> Result<()> {
        //
        // set up testlab interfaces
        //

        let interfaces = testlab_1x2("disc2")?;
        let if0 = format!("{}/v6", interfaces[0].name.clone());
        let if1 = format!("{}/v6", interfaces[1].name.clone());
        let if2 = format!("{}/v6", interfaces[2].name.clone());
        let if3 = format!("{}/v6", interfaces[3].name.clone());

        let ifx1: Interface = (&interfaces[1].addr.info).try_into().unwrap();
        let ifx3: Interface = (&interfaces[3].addr.info).try_into().unwrap();

        //
        // set up routers
        //

        let sc1 = Config {
            name: "r1".into(),
            interfaces: vec![if0],
            peer_interval: 100,
            peer_expire: 1000,
            upper_half_only: true,
            ..Default::default()
        };

        let sc2 = Config {
            name: "r2".into(),
            interfaces: vec![if2],
            peer_interval: 100,
            peer_expire: 1000,
            upper_half_only: true,
            ..Default::default()
        };

        let tc1 = Config {
            name: "t1".into(),
            interfaces: vec![if1, if3],
            peer_interval: 100,
            peer_expire: 1000,
            upper_half_only: true,
            router_kind: RouterKind::Transit,
            ..Default::default()
        };

        let log = util::test::logger();
        let mut s1 = Router::new(log.clone(), sc1).expect("new s-router 1");
        let mut s2 = Router::new(log.clone(), sc2).expect("new s-router 2");
        let mut t1 = Router::new(log.clone(), tc1).expect("new t-router 2");

        //
        // run the routers
        //

        info!(log, "running routers");
        s1.run().await.expect("run server router 1");
        s2.run().await.expect("run server router 2");
        t1.run().await.expect("run transit router 1");
        info!(log, "routers running");

        //
        // advertise some routes
        //

        debug!(log, "advertising!!!");
        let pfx1 =
            Ipv6Prefix::from_str("fd00:1::/64").expect("parse prefix a1");
        let mut a1 = HashSet::new();
        a1.insert(pfx1);
        s1.advertise(a1).await.expect("advertise from r1");

        let pfx2 =
            Ipv6Prefix::from_str("fd00:2::/64").expect("parse prefix a2");
        let mut a2 = HashSet::new();
        a2.insert(pfx2);
        s2.advertise(a2).await.expect("advertise from a2");

        //
        // wait for discovery + peering + exchange
        //

        sleep(Duration::from_secs(5)).await;

        //
        // assert expected prefix state
        //

        // s-router1 should have the transit routers link-local address as a
        // nexthop for fd00:2::/64
        let nexthops = s1.nexthops(pfx2).await;
        debug!(log, "{:?}", nexthops);
        assert!(nexthops.contains(&ifx1.ll_addr));

        // router2 should have the transit routers link-local address as a
        // nexthop for fd00:1::/64
        let nexthops = s2.nexthops(pfx1).await;
        debug!(log, "{:?}", nexthops);
        assert!(nexthops.contains(&ifx3.ll_addr));

        Ok(())
    }
}
