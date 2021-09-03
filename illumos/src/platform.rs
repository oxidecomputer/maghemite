// Copyright 2021 Oxide Computer Company

use std::sync::{Arc, Mutex};
use platform::{Platform, error::Error};
use std::mem::MaybeUninit;
use slog::{Logger, debug, error};
use std::{ptr};
use crate::illumos;
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use std::net::{Ipv6Addr, SocketAddrV6};
use icmpv6::{RouterSolicitation, RouterAdvertisement, RDPMessage};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;
use rift_protocol::LinkInfo;
use rift::{LINKINFO_PORT, RDP_MADDR};

pub(crate) struct Illumos {
    pub(crate) log: Logger,
}

impl Platform for Illumos {

    fn advertise_rift_router(&self) -> Result<(), Error> {

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

        let sa = SockAddr::from(SocketAddrV6::new(rift::RDP_MADDR, 0, 0, 0));

        let ra = RouterAdvertisement::new(
            1,          //hop limit
            false,      // managed address (dhcpv6)
            false,      // other stateful (stateless dhcpv6)
            0,          // not a default router
            100,        // consider this router reachable for 100 ms
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

    fn solicit_rift_routers(&self) -> Result<(), Error> {

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

        let sa = SockAddr::from(SocketAddrV6::new(RDP_MADDR, 0, 0, 0));
        let rs = RouterSolicitation::new(None);
        let wire = rs.wire();

        socket
            .send_to(wire.as_slice(), &sa)
            .map_err(|e| Error::Platform(format!("solicit send: {}", e)))?;

        Ok(())

    }

    fn get_rdp_channel(&self) -> Result<Receiver<RDPMessage>, Error> {

        let socket = Socket::new(
            Domain::IPV6, 
            Type::RAW, 
            Some(Protocol::ICMPV6),
        ).map_err(|e| Error::Platform(format!("new socket: {}", e)))?;

        socket
            .join_multicast_v6(&RDP_MADDR, 0)
            .map_err(|e| Error::Platform(format!("join multicast: {}", e)))?;

        let (tx, rx): (Sender<RDPMessage>, Receiver<RDPMessage>) = channel();

        let log = self.log.clone();
        
        thread::spawn(move || loop {

            let mut buf: [u8; 1024] = [0;1024];
            let mut _buf = unsafe{ 
                &mut(*buf.as_mut_ptr().cast::<[MaybeUninit<u8>; 1024]>()) 
            };

            let (sz, sender) = match socket.recv_from(_buf) {
                Ok(x) => x,
                Err(e) => { 
                    error!(log, "socket recv: {}", e);
                    continue; 
                },
            };

            let senderv6 = match sender.as_socket_ipv6() {
                Some(v6) => Some(*v6.ip()),
                _ => None,
            };

            let msg = match icmpv6::parse_icmpv6(&buf[..sz]) {
                Some(packet) => RDPMessage{
                    from: senderv6,
                    packet: packet,
                },
                None => { continue; },
            };

            match tx.send(msg) {
                Ok(_) => {},
                Err(e) => error!(log, "rdp channel send: {}", e),
            };


        });

        Ok(rx)
    }

    fn get_link_channel(&self, peer: Ipv6Addr)
    -> Result<(Sender<LinkInfo>, Receiver<LinkInfo>), Error> {

        //ingress
        let ilog = self.log.clone();
        let (_itx, irx): (Sender<LinkInfo>, Receiver<LinkInfo>) = channel();
        let itx = Arc::new(Mutex::new(_itx));

        tokio::spawn(async move {
            match crate::link::link_handler(peer, itx).await {
                Ok(_) => {},
                Err(e) => error!(ilog, "failed to start link handler: {}", e),
            }
        });

        //egress
        let elog = self.log.clone();
        let (etx, erx): (Sender<LinkInfo>, Receiver<LinkInfo>) = channel();
        tokio::spawn(async move { loop {

            let msg = match erx.recv() {
                Ok(m) => m,
                Err(e) => {
                    error!(elog, "linkinfo egress channel rx: {}", e);
                    continue;
                }
            };

            let client = reqwest::Client::new();
            let resp = client
                .post(format!("http://{}:{}/linkinfo", peer, LINKINFO_PORT))
                .json(&msg)
                .send()
                .await;

            match resp {
                Ok(_) => {},
                Err(e) => error!(elog, "failed to send linkinfo: {}", e),
            }

        }});


        Ok((etx, irx))

    }

}

#[allow(dead_code)]
const LIFC_DEFAULT: u32 = 
    illumos::LIFC_NOXMIT | illumos::LIFC_TEMPORARY |
    illumos::LIFC_ALLZONES | illumos::LIFC_UNDER_IPMP;

impl Illumos {

    #[allow(dead_code)]
    fn ipadm_handle(&self) -> Result<illumos::ipadm_handle_t, Error> {

        let mut handle: illumos::ipadm_handle_t = ptr::null_mut();
        let status = unsafe { illumos::ipadm_open(&mut handle, 0) };
        if status != illumos::ipadm_status_t_IPADM_SUCCESS {
            return Err(Error::Platform(format!("ipadm_open: {}", status)))
        }

        Ok(handle)

    }

    #[allow(dead_code)]
    fn get_ipv6_addrs(&self) -> Result<Vec<SysIpv6Addr>, Error> {
        debug!(self.log, "getting ipv6 addrs");

        // get address info
        let handle = self.ipadm_handle()?;
        let mut addrinfo: *mut illumos::ipadm_addr_info_t = ptr::null_mut();
        let status = unsafe { illumos::ipadm_addr_info(
            handle,
            ptr::null(),
            &mut addrinfo,
            0,
            LIFC_DEFAULT as i64,
        ) };
        if status != illumos::ipadm_status_t_IPADM_SUCCESS {
            return Err(Error::Platform(format!("ipadm_addr_info: {}", status)))
        }

        // populate results from returned addresses
        let mut result: Vec<SysIpv6Addr> = Vec::new();
        let mut addr : *mut illumos::ifaddrs = unsafe { 
            &mut (*addrinfo).ia_ifa 
        };
        loop {
            if addr == ptr::null_mut() { break }

            unsafe {
                // only ipv6
                if (*(*addr).ifa_addr).sa_family == illumos::AF_INET6 as u16 {

                    let sin6 = (*addr).ifa_addr as *mut illumos::sockaddr_in6;

                    // only link local
                    if  (*sin6).sin6_addr._S6_un._S6_u8[0] as u8 == 0xfe &&
                        (*sin6).sin6_addr._S6_un._S6_u8[1] as u8 == 0x80 {

                        // extract address
                        let v6addr = Ipv6Addr::from(
                            (*sin6).sin6_addr._S6_un._S6_u8
                        );

                        // extract name
                        let ifname = std::ffi::CString::from_raw(
                            (*addr).ifa_name
                        );
                        let ifname_s = ifname.into_string()?;

                        debug!(self.log, 
                            "found ipv6-ll interface: {}/{}", 
                            ifname_s.as_str(), 
                            v6addr);

                        result.push(SysIpv6Addr{
                            addr: v6addr,
                            local_link: ifname_s,
                        })

                    }
                }
            }

            addr = unsafe { (*addr).ifa_next };
        }
            
        Ok(result)
    }

}

#[derive(Debug)]
pub struct SysIpv6Addr {
    pub addr: Ipv6Addr,
    pub local_link: String,
}
