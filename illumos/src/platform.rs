// Copyright 2021 Oxide Computer Company

use std::sync::Arc;
use std::mem::MaybeUninit;
use slog::{Logger, error, debug};
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
use icmpv6::{RouterSolicitation, RouterAdvertisement, RDPMessage};
use std::time::Duration;
use tokio::{
    spawn, select,
    time::sleep,
    sync::{Mutex, mpsc::{channel, Sender, Receiver}},
};
use rift_protocol::lie::LIEPacket;
use rift::{LINKINFO_PORT, RDP_MADDR};
use platform::{
    IpIfAddr,
    Platform, 
    LinkStatus,
    error::Error,
};

pub(crate) struct Illumos {
    pub(crate) log: Logger,
}

impl Platform for Illumos {

    fn get_links(&self) -> Result<Vec<LinkStatus>, Error> {

        let links = match netadm_sys::get_links() {
            Ok(links) => links,
            Err(e) => return Err(Error::Platform(format!("get links: {}", e))),
        };

        let mut result = Vec::new();
        for l in links {
            result.push(LinkStatus{
                name: l.name,
                state: match l.state {
                    netadm_sys::LinkState::Unknown => platform::LinkState::Unknown,
                    netadm_sys::LinkState::Down => platform::LinkState::Down,
                    netadm_sys::LinkState::Up => platform::LinkState::Up,
                }
            })
        }

        Ok(result)

    }

    fn get_link_status(&self, link_name: impl AsRef<str>) -> Result<LinkStatus, Error> {
        let _link_name = link_name.as_ref().to_string();
        match netadm_sys::linkname_to_id(&_link_name) {
            Err(e) => Err(Error::Platform(format!("linkname to id: {}", e))),
            Ok(id) => {
                match netadm_sys::get_link(id) {
                    Err(e) => Err(Error::Platform(format!("get link info: {}", e))),
                    Ok(info) => Ok(LinkStatus{
                        name: info.name,
                        state: match info.state {
                            netadm_sys::LinkState::Unknown => platform::LinkState::Unknown,
                            netadm_sys::LinkState::Down => platform::LinkState::Down,
                            netadm_sys::LinkState::Up => platform::LinkState::Up,
                        },
                    })
                }
            }
        }
    }

    fn get_interface_v6ll(&self, interface: impl AsRef<str>) -> Result<Option<IpIfAddr>, Error> {

        //TODO provide a function in netadm_sys that gets addrs for a given
        //interface without having to iterate all the interfaces

        let addr_map = match netadm_sys::get_ipaddrs() {
            Ok(addrs) => addrs,
            Err(e) => return Err(Error::Platform(format!("get ip addrs: {}", e))),
        };

        for (ifname, addrs) in addr_map {
            if ifname.as_str() == interface.as_ref() {
                for a in addrs {
                    match a.addr {
                        IpAddr::V4(_) => continue,
                        IpAddr::V6(v6addr) => {
                            if v6addr.is_unicast_link_local() {
                                return Ok(Some(IpIfAddr{
                                    addr: v6addr,
                                    if_index: a.index,
                                }))
                            }
                        }
                    }
                }
            }
        }

        return Ok(None)

    }

    fn advertise_rift_router(&self, interface: Option<IpIfAddr>) -> Result<(), Error> {

        let link_id = match interface.as_ref() {
            None => 0, // any interface
            Some(ipifa) => ipifa.if_index,
        };

        let socket = Socket::new(
            Domain::IPV6, 
            Type::RAW, 
            Some(Protocol::ICMPV6),
         ).map_err(|e| Error::Platform(format!("new socket: {}", e)))?;

        // we don't want to advertise to ourself
        socket
            .set_multicast_loop_v6(false)
            .map_err(|e| 
                Error::Platform(format!("diable multicast loop: {}", e))
            )?;

        let sa = SockAddr::from(SocketAddrV6::new(rift::RDP_MADDR, 0, 0, link_id as u32));

        let ra = RouterAdvertisement::new(
            1,          //hop limit
            false,      // managed address (dhcpv6)
            false,      // other stateful (stateless dhcpv6)
            0,          // not a default router
            3000,        // consider this router reachable for 3000 ms
            0,          // No retrans timer specified
            None,       // no source address,
            Some(9216), // jumbo frames ftw
            None,       // no prefix info
        );
        let wire = ra.wire();

        socket
            .send_to(wire.as_slice(), &sa)
            .map_err(|e| Error::Platform(format!("advertise send: {}", e)))?;

        Ok(())

    }

    fn solicit_rift_routers(&self, interface: Option<IpIfAddr>) -> Result<(), Error> {

        let link_id = match interface.as_ref() {
            None => 0, // any interface
            Some(ipifa) => ipifa.if_index,
        };

        let socket = Socket::new(
            Domain::IPV6, 
            Type::RAW, 
            Some(Protocol::ICMPV6),
         ).map_err(|e| Error::Platform(format!("new socket: {}", e)))?;

        // we don't want to solicit ourself
        socket
            .set_multicast_loop_v6(false)
            .map_err(|e| 
                Error::Platform(format!("diable multicast loop: {}", e))
            )?;

        let sa = SockAddr::from(SocketAddrV6::new(RDP_MADDR, 0, 0, link_id as u32));
        let rs = RouterSolicitation::new(None);
        let wire = rs.wire();

        socket
            .send_to(wire.as_slice(), &sa)
            .map_err(|e| Error::Platform(format!("solicit send: {}", e)))?;

        Ok(())

    }

    fn get_rdp_channel(&self, interface: Option<IpIfAddr>) -> Result<Receiver<RDPMessage>, Error> {

        let link_id = match interface.as_ref() {
            None => 0, // any interface
            Some(ipifa) => ipifa.if_index,
        };

        let socket = Socket::new(
            Domain::IPV6, 
            Type::RAW, 
            Some(Protocol::ICMPV6),
        ).map_err(|e| Error::Platform(format!("new socket: {}", e)))?;

        socket
            .join_multicast_v6(&RDP_MADDR, link_id as u32)
            .map_err(|e| Error::Platform(format!("join multicast: {}", e)))?;

        let (tx, rx): (Sender<RDPMessage>, Receiver<RDPMessage>) = channel(32);

        let log = self.log.clone();
        
        spawn(async move { loop {

            let mut _buf = [MaybeUninit::new(0); 1024];

            match socket.set_nonblocking(true) {
                Ok(_) => {}
                Err(e) => {
                    error!(log, "set nonblocking socket option: {}", e);
                    break;
                }
            };

            let (sz, sender) = match socket.recv_from(&mut _buf) {
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
                Some(v6) => Some(*v6.ip()),
                _ => None,
            };

            let msg = match icmpv6::parse_icmpv6(
                unsafe{&MaybeUninit::slice_assume_init_ref(&_buf)[..sz]},
            ) {
                Some(packet) => RDPMessage{
                    from: senderv6,
                    packet: packet,
                },
                None => { continue; },
            };

            match tx.send(msg).await {
                Ok(_) => {},
                Err(e) => {
                    debug!(log, "rdp channel closed, exiting rdp loop: {}", e);
                    break;
                }
            };


        }});

        Ok(rx)
    }

    fn get_link_channel(&self, local: Ipv6Addr, peer: Ipv6Addr)
    -> Result<(Sender<LIEPacket>, Receiver<LIEPacket>), Error> {

        let (_itx, irx): (Sender<LIEPacket>, Receiver<LIEPacket>) = channel(32);
        let itx = Arc::new(Mutex::new(_itx));

        let elog = self.log.clone();
        let (etx, mut erx): (Sender<LIEPacket>, Receiver<LIEPacket>) = channel(32);

        spawn(async move { 

            let mut server = match crate::link::link_handler(local, itx) {
                Ok(s) => s,
                Err(e) => {
                    error!(elog, "failed to crate dropshot server: {}", e);
                    return;
                }
            };

            loop {

                select! {

                    rx_msg = erx.recv() => {

                        let msg = match rx_msg {
                            Some(m) => m,
                            None => {
                                error!(elog, "linkinfo egress channel closed");
                                match server.close().await {
                                    Ok(_) => {},
                                    Err(e) => error!(elog, "dropshot server close: {}", e),
                                };
                                return;
                            }
                        };

                        let client = reqwest::Client::new();
                        let resp = client
                            .post(format!("http://[{}]:{}/linkinfo", peer, LINKINFO_PORT))
                            .json(&msg)
                            .send()
                            .await;

                        match resp {
                            Ok(_) => {},
                            Err(e) => error!(elog, "failed to send linkinfo: {}", e),
                        };

                    }

                    srv_result = &mut server => {

                        match srv_result {
                            Ok(_) => {},
                            Err(e) => error!(elog, "dropshot server exit: {}", e),
                        };

                    }

                };

            }
        });


        Ok((etx, irx))

    }

}

#[derive(Debug)]
pub struct SysIpv6Addr {
    pub addr: Ipv6Addr,
    pub local_link: String,
}
