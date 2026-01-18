// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use bgp::{
    connection_tcp::BgpConnectionTcp,
    params::UnnumberedNeighbor,
    router::Router,
    session::{SessionInfo, SessionRunner},
};
use mg_common::lock;
use ndp::{Ipv6NetworkInterface, NdpManager, NewInterfaceNdpManagerError};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use rdb::Db;
use slog::{Logger, error, info, o, warn};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv6Addr, SocketAddrV6},
    sync::{Arc, Mutex, mpsc::channel},
    thread::{sleep, spawn},
    time::Duration,
};

pub const MOD_UNNUMBERED_MANAGER: &str = "unnumbered manager";

pub struct UnnumberedNeighborManager {
    routers: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
    ndp_mgr: Arc<NdpManager>,
    pending_sessions: Mutex<HashMap<NbrKey, NbrInfo>>,
    db: Db,
    log: Logger,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NbrKey {
    pub asn: u32,
    pub interface: Ipv6NetworkInterface,
}

#[derive(Clone)]
pub struct NbrInfo {
    pub nbr: UnnumberedNeighbor,
    pub session: SessionInfo,
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveNeighborError {
    #[error("No such interface")]
    NoSuchInterface,
    #[error("Interface has no IPv6 link local address")]
    NotIpv6Interface,
    #[error("Could not get system interfaces: {0}")]
    System(#[from] network_interface::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum AddNeighborError {
    #[error("resolve neighbor error: {0}")]
    Resolve(#[from] ResolveNeighborError),

    #[error("add interface error: {0}")]
    NdpManager(#[from] NewInterfaceNdpManagerError),
}

impl UnnumberedNeighborManager {
    pub fn new(
        routers: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
        db: Db,
        log: Logger,
    ) -> Arc<Self> {
        let log = log.new(o!(
            "component" => crate::COMPONENT_MGD,
            "unit" => crate::UNIT_DAEMON,
            "module" => MOD_UNNUMBERED_MANAGER,
        ));

        let s = Arc::new(Self {
            routers,
            pending_sessions: Mutex::new(HashMap::default()),
            ndp_mgr: NdpManager::new(log.clone()),
            db,
            log: log.clone(),
        });

        {
            let s = s.clone();
            let log = log.clone();
            // TODO(609) considermanaged threading appraoch
            // https://github.com/oxidecomputer/maghemite/issues/609
            spawn(move || s.run(log));
        }

        s
    }

    pub fn add_neighbor(
        self: &Arc<Self>,
        asn: u32,
        interface: impl AsRef<str>,
        info: SessionInfo,
        nbr: UnnumberedNeighbor,
    ) -> Result<(), AddNeighborError> {
        let ifx = Self::get_interface(interface.as_ref(), &self.log)?;
        self.ndp_mgr
            .add_interface(ifx.clone(), nbr.act_as_a_default_ipv6_router)?;

        lock!(self.pending_sessions).insert(
            NbrKey {
                asn,
                interface: ifx,
            },
            NbrInfo { session: info, nbr },
        );
        Ok(())
    }

    pub fn remove_neighbor(
        self: &Arc<Self>,
        asn: u32,
        interface: impl AsRef<str>,
    ) -> Result<(), ResolveNeighborError> {
        let ifx = Self::get_interface(interface.as_ref(), &self.log)?;
        self.ndp_mgr.remove_interface(ifx.clone());
        self.db.remove_unnumbered_nexthop_for_interface(&ifx);
        lock!(self.pending_sessions).remove(&NbrKey {
            asn,
            interface: ifx,
        });

        Ok(())
    }
    pub fn get_neighbor_addr(
        self: &Arc<Self>,
        interface: impl AsRef<str>,
    ) -> Result<Option<Ipv6Addr>, ResolveNeighborError> {
        let ifx = Self::get_interface(interface.as_ref(), &self.log)?;
        Ok(self.ndp_mgr.get_peer(&ifx))
    }

    pub fn get_neighbor_session(
        self: &Arc<Self>,
        asn: u32,
        interface: impl AsRef<str>,
    ) -> Result<
        Option<Arc<SessionRunner<BgpConnectionTcp>>>,
        ResolveNeighborError,
    > {
        if let Some(addr) = self.get_neighbor_addr(interface)?
            && let Some(rtr) = lock!(self.routers).get(&asn)
            && let Some(session) = rtr.get_session(addr.into())
        {
            return Ok(Some(session));
        };
        Ok(None)
    }

    fn get_interface(
        name: &str,
        log: &Logger,
    ) -> Result<Ipv6NetworkInterface, ResolveNeighborError> {
        let candidates: Vec<_> = NetworkInterface::show()?
            .into_iter()
            .filter(|x| x.name == name)
            .collect();

        if candidates.is_empty() {
            return Err(ResolveNeighborError::NoSuchInterface);
        }

        let mut local: Vec<_> = candidates
            .into_iter()
            .filter_map(|x| x.addr.map(|addr| (addr, x.index)))
            .filter_map(|(addr, idx)| match addr.ip() {
                IpAddr::V6(ip) if ip.is_unicast_link_local() => Some((ip, idx)),
                _ => None,
            })
            .collect();

        let Some((addr, index)) = local.pop() else {
            return Err(ResolveNeighborError::NotIpv6Interface);
        };

        if !local.is_empty() {
            warn!(
                log,
                "more than 1 link local address for interface";
                "using" => addr.to_string(),
                "also found" => local
                    .into_iter()
                    .map(|x| x.0.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }

        Ok(Ipv6NetworkInterface {
            name: name.to_owned(),
            ip: addr,
            index,
        })
    }

    pub fn get_pending(self: &Arc<Self>) -> HashMap<NbrKey, NbrInfo> {
        lock!(self.pending_sessions).clone()
    }

    fn run(self: Arc<Self>, log: Logger) {
        info!(log, "unnumbered manager loop starting");
        const RUN_LOOP_INTERVAL: Duration = Duration::from_secs(1);
        loop {
            // clone the pending list so we don't hold the lock
            //
            // NOTE: sessions must be a named variable, the RHS of this
            // statement cannot go into the for loop directly as that will
            // cause the guard to be held across the for loop creating a
            // deadlock with start_session on pending_sessions. This is known
            // as temporary lifetime extension.
            let sessions = self.get_pending();

            for (key, session) in sessions.into_iter() {
                if let Some(peer_addr) = self.ndp_mgr.get_peer(&key.interface) {
                    self.start_session(
                        key,
                        session.session,
                        session.nbr,
                        peer_addr,
                        &log,
                    );
                }
            }
            sleep(RUN_LOOP_INTERVAL);
        }
    }

    fn start_session(
        self: &Arc<Self>,
        key: NbrKey,
        session: SessionInfo,
        neighbor: UnnumberedNeighbor,
        peer_addr: Ipv6Addr,
        log: &Logger,
    ) {
        let router_guard = lock!(self.routers);
        let Some(router) = router_guard.get(&key.asn) else {
            warn!(
                log,
                "session configured for asn {}, but no router is running",
                key.asn
            );
            return;
        };

        let (event_tx, event_rx) = channel();

        let host = SocketAddrV6::new(peer_addr, 0, 0, key.interface.index);

        if let Err(e) = router.ensure_session(
            neighbor.to_peer_config(host),
            None,
            event_tx.clone(),
            event_rx,
            session,
        ) {
            error!(
                log,
                "error starting unnumbered session";
                "error" => e.to_string(),
                "interface" => &neighbor.interface,
            );
            return;
        }

        drop(router_guard);

        self.db
            .add_unnumbered_nexthop(peer_addr, key.interface.clone());

        // if we are here the session has started, remove it from pending
        lock!(self.pending_sessions).remove(&key);
    }
}
