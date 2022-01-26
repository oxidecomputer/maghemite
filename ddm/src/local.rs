use std::io::{Result, Error, ErrorKind};
use std::mem::MaybeUninit;
use std::time::Duration;
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
use std::collections::BTreeMap;
use std::sync::Arc;

use slog::{Logger, debug, error, trace};
use tokio::{
    spawn, select,
    time::sleep,
    sync::{
        Mutex,
        mpsc::{Sender, Receiver, channel},
    },
};
use icmpv6::{RDPMessage, ICMPv6Packet};
use async_trait::async_trait;
use netadm_sys::{
    create_simnet_link,
    get_ipaddr_info,
    delete_ipaddr,
    enable_v6_link_local,
    Ipv6Prefix,
    LinkFlags,
};
use socket2::{Socket, Domain, Type, Protocol, SockAddr};

use crate::platform;
use crate::port::{Port, PortState};
use crate::protocol::{
    DdmMessage, PeerMessage, 
    RDP_MCAST_ADDR, PEERING_PORT, PREFIX_EXCHANGE_PORT,
};
use crate::router::Route;

/// This is a local testing platform. 
///
/// A set of link-local addresses on the system's lo0 loopback device in the 
/// following format will be created
///
///     lo0/mgX_N fe80:1de::X:N
///
/// where X is the user provided id of the platform and N is the index of the
/// port the address was created for.
///     
#[derive(Clone)]
pub struct Platform {
    pub id: u16,
    pub(crate) log: Logger,
    pub(crate) state: Arc::<Mutex::<PlatformState>>,
}

pub struct PlatformState {
    ports: BTreeMap::<Port, PortInfo>,
}

#[derive(Clone)]
pub struct PortInfo {
    pub addr: Ipv6Prefix,
    pub name: String,
    pub peer: Ipv6Addr,
}

impl Platform {
    
    pub fn new(log: Logger, id: u16, radix: u16) -> Result<Self> {
        let mut ports = BTreeMap::new();
        for i in 0..radix {
            let (port, info) = Self::create_port(&log, id, i)?;
            ports.insert(port, info);
        }
        let state = Arc::new(Mutex::new(PlatformState{ ports }));
        Ok(Platform{ id, state, log })
    }

    pub fn create_port(log: &Logger, id: u16, i: u16) -> Result<(Port, PortInfo)> {

        let name = format!("mg{}_sim{}", id, i);
        create_simnet_link(&name, LinkFlags::Active).map_err(|e| {
            Error::new(
                ErrorKind::Other, 
                format!("create simnet link {}: {}", i, e.to_string()),
            )
        })?;

        enable_v6_link_local(&name).map_err(|e| {
            Error::new(
                ErrorKind::Other, 
                format!("create port {}: {}", i, e.to_string()),
            )
        })?;


        let objname = format!("{}/v6", name);
        let info = get_ipaddr_info(&objname).map_err(|e| {
            Error::new(
                ErrorKind::Other, 
                format!("get ip info {}: {}", i, e.to_string()),
            )
        })?;
        let addr = match info.addr {
            IpAddr::V6(pfx) => pfx,
            _ => {
                return Err(Error::new(
                        ErrorKind::Other, 
                        format!("expected ipv6 address"),
                ))
            }
        };
        let addr = Ipv6Prefix{
            addr: addr,
            mask: info.mask as u8,
        };

        debug!(log, "created ip {} {:?}", objname, info);

        let port = Port{ index: info.index as usize, state: PortState::Up};
        let info = PortInfo{ addr, name, peer: Ipv6Addr::UNSPECIFIED };
        Ok((port, info))

    }

    pub async fn teardown(&self) -> Result<()> {
        for (p, info) in &self.state.lock().await.ports {
            delete_ipaddr(&info.name)
                .map_err(|e| {
                    Error::new(
                        ErrorKind::Other, 
                        format!("create port {}: {}", p.index, e.to_string()),
                    )
                })?;
        }
        Ok(())
    }

}

impl platform::Capabilities for Platform {
    fn discovery() -> bool { true }
}


#[async_trait]
impl platform::Ports for Platform {

    async fn ports(&self) -> Result<Vec<Port>> {
        Ok(self.state.lock().await.ports.clone().into_keys().collect::<Vec<Port>>())
    }

}

#[async_trait]
impl platform::Rdp for Platform {

    async fn rdp_channel(&self, p: Port)
    -> Result<(Sender<RDPMessage>, Receiver<RDPMessage>)> {

        // ingress
        let (itx, irx):
            (Sender::<RDPMessage>, Receiver::<RDPMessage>) = channel(0x20);

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
                    match state.lock().await.ports.get_mut(&p) {
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
                                Ok(_) => trace!(log, "sent solicit"),
                                Err(e) => error!(log,
                                    "failed to send router solicitation {}",
                                    e,
                                ),
                            };
                        }
                        ICMPv6Packet::RouterAdvertisement(ra) => {
                            let wire = ra.wire();
                            match socket_tx.send_to(wire.as_slice(), &sa) {
                                Ok(_) => trace!(log, "sent advertisement"),
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
        let (local, peer) = match self.state.lock().await.ports.get(&p) {
            Some(port_info) => (port_info.addr.addr, port_info.peer),
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
        let (local, peer) = match self.state.lock().await.ports.get(&p) {
            Some(port_info) => (port_info.addr.addr, port_info.peer),
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
        Ok(Vec::new())
    }

    async fn set_route(&self, _r: Route) -> Result<()> {
        Ok(())
    }

    async fn delete_route(&self, _r: Route) -> Result<()> {
        Ok(())
    }
}
