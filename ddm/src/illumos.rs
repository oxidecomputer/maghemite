use std::io::{Result, Error, ErrorKind};
use std::mem::MaybeUninit;
use std::time::Duration;
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::{
    spawn, select,
    time::sleep,
    sync::{
        Mutex,
        mpsc::{Sender, Receiver, channel},
    },
};
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use slog::{Logger, debug, warn, error};
use icmpv6::{
    RDPMessage,
    ICMPv6Packet,
};
use async_trait::async_trait;

use crate::platform;
use crate::port::{Port, PortState};
use crate::protocol::{
    DdmMessage, PeerMessage, 
    RDP_MCAST_ADDR, PEERING_PORT, PREFIX_EXCHANGE_PORT,
};
use crate::router::{Route};

struct PortInfo {
    name: String,
    local: Ipv6Addr,
    peer: Ipv6Addr,
}

pub struct PlatformState {
    portinfo: BTreeMap::<Port, PortInfo>,
}

impl PlatformState {
    pub fn new() -> Self {
        PlatformState{ portinfo: BTreeMap::new() }
    }
}

#[derive(Clone)]
pub struct Platform { 
    pub(crate) log: Logger,
    pub(crate) state: Arc::<Mutex::<PlatformState>>,
}

impl Platform {
    pub fn new(log: Logger) -> Self {
        Platform{
            log,
            state: Arc::new(Mutex::new(PlatformState::new())),
        }
    }
}

impl platform::Capabilities for Platform {
    fn discovery() -> bool {
        true
    }
}

#[async_trait]
impl platform::Ports for Platform {
    async fn ports(&self) -> Result<Vec<Port>> {

        let links = match netadm_sys::get_links() {
            Ok(links) => links,
            Err(e) => return Err(
                Error::new(ErrorKind::Other, format!("get links: {}", e))
            ),
        };

        // try to get v6 link local addresses and add them to the platform state
        // while we are collecting ports
        let addrs = match netadm_sys::get_ipaddrs() {
            Ok(addrs) => addrs,
            Err(e) => return Err(
                Error::new(ErrorKind::Other, format!("get addrs: {}", e))
            ),
        };

        let mut result = Vec::new();
        for l in links {
            let mut p = Port{
                index: l.id as usize,
                state: PortState::Up,
            };
            let addr = match addrs.get(&l.name) {
                Some(addr_infos) => {

                    let mut result = None;
                    for addr_info in addr_infos{
                        if addr_info.ifname == l.name {
                            match addr_info.addr {
                                IpAddr::V6(addr) => {
                                    if !addr.is_unicast_link_local() {
                                        continue;
                                    }
                                    p.index = addr_info.index as usize;
                                    result = Some(addr);
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    match result {
                        Some(addr) => {
                            debug!(
                                self.log,
                                "found link local v6 address, using {} {}",
                                l.name,
                                addr,
                            );
                            addr
                        }
                        None => {
                            warn!(
                                self.log, 
                                "no link local v6 address for {}, skipping",
                                l.name
                            );
                            continue;
                        }
                    }

                }
                None => {
                    warn!(self.log, "no v6 addresses for {}, skipping", l.name);
                    continue;
                }
            };
            {
                let state = self.state.clone();
                let mut s = state.lock().await;
                if !s.portinfo.contains_key(&p) {
                    s.portinfo.insert(p, PortInfo{
                        name: l.name.clone(),
                        local: addr,
                        peer: Ipv6Addr::UNSPECIFIED,
                    });
                }
            }
            result.push(p)
        }

        Ok(result)
    }
}

#[async_trait]
impl platform::Rdp for Platform {

    async fn rdp_channel(&self, p: Port)
    -> Result<(Sender<RDPMessage>, Receiver<RDPMessage>)> {

        // ingress
        let (itx, irx) = channel(0x20);
        // egress
        let (etx, mut erx): 
            (Sender::<RDPMessage>, Receiver::<RDPMessage>) = channel(0x20);

        let socket_rx = Socket::new(
            Domain::IPV6,
            Type::RAW,
            Some(Protocol::ICMPV6),
        )?;
        socket_rx.join_multicast_v6(&RDP_MCAST_ADDR, p.index as u32)?;
        socket_rx.set_nonblocking(true)?;
        socket_rx.set_multicast_loop_v6(false)?;
        let socket_tx = socket_rx.try_clone()?;

        // ingress rx
        let log = self.log.clone();
        let state = self.state.clone();
        spawn(async move { loop {


            let mut _buf = [MaybeUninit::new(0); 1024];

            let (sz, sender) = match socket_rx.recv_from(&mut _buf) {
                Ok(x) => x,
                Err(e) => { 
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                    error!(log, "socket recv: {}", e);
                    continue; 
                },
            };


            let senderv6 = match sender.as_socket_ipv6() {
                Some(v6) => {
                    match state.lock().await.portinfo.get_mut(&p) {
                        Some(pi) => {
                            pi.peer = *v6.ip();
                        }
                        None => error!(log, "bug: no peer info for {:?}", p),
                    }
                    Some(*v6.ip())
                }
                _ => None,
            };

            let msg = match icmpv6::parse_icmpv6(
                unsafe{&MaybeUninit::slice_assume_init_ref(&_buf)[..sz]},
            ) {
                Some(packet) => RDPMessage{
                    from: senderv6,
                    packet,
                },
                None => { continue; },
            };

            match itx.send(msg).await {
                Ok(_) => {},
                Err(e) => {
                    debug!(log, "rdp channel closed, exiting rdp loop: {}", e);
                    break;
                }
            };

        }});

        // egress rx
        let log = self.log.clone();
        spawn(async move { loop {

            match erx.recv().await {
                Some(m) => {
                    let sa = SockAddr::from(
                        SocketAddrV6::new(RDP_MCAST_ADDR, 0, 0, p.index as u32));
                    match m.packet {
                        ICMPv6Packet::RouterSolicitation(rs) => {
                            let wire = rs.wire();
                            match socket_tx.send_to(wire.as_slice(), &sa) {
                                Ok(_) => {},
                                Err(e) => error!(log,
                                    "failed to send router solicitation {}",
                                    e,
                                ),
                            };
                        }
                        ICMPv6Packet::RouterAdvertisement(ra) => {
                            let wire = ra.wire();
                            match socket_tx.send_to(wire.as_slice(), &sa) {
                                Ok(_) => {},
                                Err(e) => error!(log,
                                    "failed to send router advertisement {}",
                                    e,
                                ),
                            };

                        }
                    }
                }
                None => {}
            }


        }});

        Ok((etx, irx))

    }

}

#[async_trait]
impl platform::Ddm for Platform {

    async fn peer_channel(&self, p: Port) 
    -> Result<(Sender<PeerMessage>, Receiver<PeerMessage>)> {

        // get addresses from platform state
        let (local, peer) = match self.state.lock().await.portinfo.get(&p) {
            Some(port_info) => (port_info.local, port_info.peer),
            None => return Err(
                Error::new(ErrorKind::Other, format!("no port info for {:?}", p))
            )
        };

        // ingress channels
        let (_itx, irx) = channel(0x20);
        let itx = Arc::new(Mutex::new(_itx));

        // egress channels
        let (etx, mut erx) = channel(0x20);
        let log = self.log.clone();

        spawn(async move {

            let mut server =
                match crate::peer::peer_handler(local, itx, log.clone()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(log, "failed to crate dropshot peer server: {}", e);
                        return;
                    }
                };

            loop {
                select! {
                    rx_msg = erx.recv() => {
                        let msg = match rx_msg {
                            Some(m) => m,
                            None => {
                                error!(log, "peer egress channel closed");
                                match server.close().await {
                                    Ok(_) => {},
                                    Err(e) => error!(
                                        log, "dropshot peer server close: {}", e),
                                };
                                return;
                            }
                        };

                        let json = match serde_json::to_string(&msg) {
                            Ok(j) => j,
                            Err(e) => {
                                error!(log, "serialize peer message: {}", e);
                                return;
                            }
                        };

                        let uri = format!(
                            "http://[{}%{}]:{}/peer",
                            peer,
                            p.index,
                            PEERING_PORT);

                        let client = hyper::Client::new();
                        let req = match hyper::Request::builder()
                            .method(hyper::Method::POST)
                            .uri(&uri)
                            .body(hyper::Body::from(json)) {

                            Ok(r) => r,
                            Err(e) => {
                                error!(log, "hyper build request: {}", e);
                                return;
                            }

                        };

                        let resp = client.request(req).await;
                        match resp {
                            Ok(_) => {},
                            Err(e) => error!(
                                log, 
                                "hyper send request to {}: {}", 
                                &uri,
                                e,
                            ),
                        };

                    }

                    srv_result = &mut server => {

                        match srv_result {
                            Ok(_) => {},
                            Err(e) => error!(log, 
                                "dropshot server exit: {}", e),
                        };

                    }
                }
            }

        });

        Ok((etx, irx))
    }

    async fn ddm_channel(&self, p: Port) 
    -> Result<(Sender<DdmMessage>, Receiver<DdmMessage>)> {

        // get addresses from platform state
        let (local, peer) = match self.state.lock().await.portinfo.get(&p) {
            Some(port_info) => (port_info.local, port_info.peer),
            None => return Err(
                Error::new(ErrorKind::Other, format!("no port info for {:?}", p))
            )
        };

        // ingress channels
        let (_itx, irx) = channel(0x20);
        let itx = Arc::new(Mutex::new(_itx));

        // egress channels
        let (etx, mut erx) = channel(0x20);
        let log = self.log.clone();

        spawn(async move {

            let mut server =
                match crate::exchange::prefix_handler(local, itx, log.clone()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(log, "failed to crate dropshot prefix server: {}", e);
                        return;
                    }
                };

            loop {
                select! {
                    rx_msg = erx.recv() => {
                        let msg = match rx_msg {
                            Some(m) => m,
                            None => {
                                error!(log, "prefix egress channel closed");
                                match server.close().await {
                                    Ok(_) => {},
                                    Err(e) => error!(
                                        log, "dropshot prefix server close: {}", e),
                                };
                                return;
                            }
                        };

                        let json = match serde_json::to_string(&msg) {
                            Ok(j) => j,
                            Err(e) => {
                                error!(log, "serialize prefix message: {}", e);
                                return;
                            }
                        };

                        let uri= format!(
                            "http://[{}%{}]:{}/prefix",
                            peer,
                            p.index,
                            PREFIX_EXCHANGE_PORT);

                        let client = hyper::Client::new();
                        let req = match hyper::Request::builder()
                            .method(hyper::Method::POST)
                            .uri(&uri)
                            .body(hyper::Body::from(json)) {

                            Ok(r) => r,
                            Err(e) => {
                                error!(log, "hyper build request: {}", e);
                                return;
                            }

                        };

                        let resp = client.request(req).await;
                        match resp {
                            Ok(_) => {},
                            Err(e) => error!(log, "hyper send request: {}", e),
                        };

                    }

                    srv_result = &mut server => {

                        match srv_result {
                            Ok(_) => {},
                            Err(e) => error!(log, 
                                "dropshot server exit: {}", e),
                        };

                    }
                }
            }

        });

        Ok((etx, irx))
    }

}

#[async_trait]
impl platform::Router for Platform {
    async fn get_routes(&self) -> Result<Vec<Route>> {

        let mut result = Vec::new();

        let routes = match netadm_sys::get_routes() {
            Ok(rs) => rs,
            Err(e) => return Err(
                Error::new(ErrorKind::Other, format!("get routes: {}", e))
            ),
        };

        for r in routes {
            result.push(r.into());
        }

        Ok(result)

    }

    async fn set_route(&self, r: Route) -> Result<()> {

        let gw = r.gw;
        match netadm_sys::ensure_route_present(r.into(), gw) {
            Ok(_) => Ok(()),
            Err(e) => return Err(
                Error::new(ErrorKind::Other, format!("set route: {}", e))
            ),
        }

    }

    async fn delete_route(&self, r: Route) -> Result<()> {

        let gw = r.gw;
        match netadm_sys::delete_route(r.into(), gw) {
            Ok(_) => Ok(()),
            Err(e) => return Err(
                Error::new(ErrorKind::Other, format!("set route: {}", e))
            ),
        }
                
    }
}
