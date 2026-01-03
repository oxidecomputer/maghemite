// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use bgp::{
    connection_tcp::BgpConnectionTcp,
    params::UnnumberedNeighbor,
    router::Router,
    session::{SessionInfo, SessionRunner},
};
use ndp::{Ipv6NetworkInterface, NdpManager};
use rdb::{BgpNeighborParameters, Db};
use slog::{Logger, error, warn};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv6Addr, SocketAddrV6},
    sync::{Arc, Mutex, mpsc::channel},
    thread::{sleep, spawn},
    time::Duration,
};

pub struct UnnumberedNeighborManager {
    routers: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
    ndp_mgr: Arc<NdpManager>,
    pending_sessions: Mutex<HashMap<NbrKey, NbrInfo>>,
    db: Db,
    log: Logger,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct NbrKey {
    asn: u32,
    interface: Ipv6NetworkInterface,
}

#[derive(Clone)]
struct NbrInfo {
    nbr: UnnumberedNeighbor,
    session: SessionInfo,
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

impl UnnumberedNeighborManager {
    pub fn new(
        routers: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
        db: Db,
        log: Logger,
    ) -> Arc<Self> {
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
    ) -> Result<(), ResolveNeighborError> {
        let ifx = Self::get_interface(interface.as_ref(), &self.log)?;
        self.ndp_mgr.add_interface(ifx.clone());
        self.pending_sessions.lock().unwrap().insert(
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
        self.pending_sessions.lock().unwrap().remove(&NbrKey {
            asn,
            interface: ifx,
        });

        Ok(())
    }

    pub fn get_neighbor_session(
        self: &Arc<Self>,
        asn: u32,
        interface: impl AsRef<str>,
    ) -> Result<
        Option<Arc<SessionRunner<BgpConnectionTcp>>>,
        ResolveNeighborError,
    > {
        let ifx = Self::get_interface(interface.as_ref(), &self.log)?;
        if let Some(addr) = self.ndp_mgr.get_peer(&ifx)
            && let Some(rtr) = self.routers.lock().unwrap().get(&asn)
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
        use network_interface::{NetworkInterface, NetworkInterfaceConfig};

        let candidates: Vec<_> = NetworkInterface::show()?
            .into_iter()
            .filter(|x| x.name == name)
            .collect();

        if candidates.is_empty() {
            return Err(ResolveNeighborError::NoSuchInterface);
        }

        let mut local: Vec<_> = candidates
            .into_iter()
            .flat_map(|x| {
                if let Some(addr) = x.addr {
                    Some((addr, x.index))
                } else {
                    None
                }
            })
            .flat_map(|x| match x.0.ip() {
                IpAddr::V6(ip) => Some((ip, x.1)),
                IpAddr::V4(_) => None,
            })
            .filter(|x| x.0.is_unicast_link_local())
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

    fn run(self: Arc<Self>, log: Logger) {
        const RUN_LOOP_INTERVAL: Duration = Duration::from_secs(1);
        loop {
            // clone the pending list so we don't hold the lock
            for (key, session) in
                self.pending_sessions.lock().unwrap().clone().into_iter()
            {
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
        let router_guard = self.routers.lock().unwrap();
        let Some(router) = router_guard.get(&key.asn) else {
            warn!(
                log,
                "session configured for asn {}, but no router is running",
                key.asn
            );
            return;
        };

        let (event_tx, event_rx) = channel();

        let host = SocketAddrV6::new(
            peer_addr, 0, 0, 179, //TODO hardcoded BGP port
        );

        router
            .ensure_session(
                neighbor.to_peer_config(host),
                None,
                event_tx.clone(),
                event_rx,
                session,
            )
            .unwrap();

        if let Err(e) = self.db.add_bgp_neighbor(rdb::BgpNeighborInfo {
            asn: neighbor.asn,
            name: neighbor.name.clone(),
            group: neighbor.group.clone(),
            host: host.into(),
            parameters: BgpNeighborParameters {
                remote_asn: neighbor.parameters.remote_asn,
                min_ttl: neighbor.parameters.min_ttl,
                hold_time: neighbor.parameters.hold_time,
                idle_hold_time: neighbor.parameters.idle_hold_time,
                delay_open: neighbor.parameters.delay_open,
                connect_retry: neighbor.parameters.connect_retry,
                keepalive: neighbor.parameters.keepalive,
                resolution: neighbor.parameters.resolution,
                passive: neighbor.parameters.passive,
                md5_auth_key: neighbor.parameters.md5_auth_key,
                multi_exit_discriminator: neighbor
                    .parameters
                    .multi_exit_discriminator,
                communities: neighbor.parameters.communities,
                local_pref: neighbor.parameters.local_pref,
                enforce_first_as: neighbor.parameters.enforce_first_as,
                allow_import: neighbor.parameters.allow_import.clone(),
                allow_export: neighbor.parameters.allow_export.clone(),
                vlan_id: neighbor.parameters.vlan_id,
            },
        }) {
            error!(log, "bgp neighbor add failed: {e}");
            return;
        };
        drop(router_guard);

        self.db
            .add_unnumbered_nexthop(peer_addr, key.interface.clone());

        // if we are here the session has started, remove it from pending
        self.pending_sessions.lock().unwrap().remove(&key);
    }
}
