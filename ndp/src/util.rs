// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::packet::{Icmp6RouterAdvertisement, Icmp6RouterSolicitation};
use libc::{c_int, socklen_t};
use slog::{Logger, error};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    ffi::c_void,
    net::{Ipv6Addr, SocketAddrV6},
    os::fd::AsRawFd,
    thread::sleep,
    time::{Duration, Instant},
};

pub const ALL_NODES_MCAST: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

pub const ALL_ROUTERS_MCAST: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

const ICMP6_RA_ULP_LEN: u32 = 16;
const ICMP6_RS_ULP_LEN: u32 = 8;

#[derive(Debug, Clone)]
pub struct ReceivedAdvertisement {
    /// When the peer was first discovered
    pub first_seen: Instant,
    /// When the most recent Router Advertisement was received
    pub when: Instant,
    pub adv: Icmp6RouterAdvertisement,
    pub sender: Ipv6Addr,
}

impl ReceivedAdvertisement {
    pub fn expired(&self) -> bool {
        self.when.elapsed() > self.adv.effective_reachable_time()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ListeningSocketError {
    #[error("new socket error: {0}")]
    NewSocketError(std::io::Error),

    #[error("reuse address error: {0}")]
    ReuseAddress(std::io::Error),

    #[error("set multicast interface error: {0}")]
    SetMulticastIf(std::io::Error),

    #[error("set multicast hops v6: {0}")]
    SetMulticastHopsV6(std::io::Error),

    #[error("bind error: {0}")]
    Bind(std::io::Error),

    #[error("set multicast loop error: {0}")]
    SetMulticastLoop(std::io::Error),

    #[error("join all-nodes multicast group error: {0}")]
    JoinAllNodesMulticast(std::io::Error),

    #[error("join all-routers multicast group error: {0}")]
    JoinAllRoutersMulticast(std::io::Error),

    #[error("set read timeout error: {0}")]
    SetReadTimeoutError(std::io::Error),

    #[error("failed to set ipv6 min hop count: {0}")]
    SetIpv6MinHopCount(std::io::Error),
}

pub fn send_ra(
    s: &Socket,
    src: Ipv6Addr,
    dst: Option<Ipv6Addr>,
    ifindex: u32,
    router_lifetime: u16,
    log: &Logger,
) {
    let pkt = Icmp6RouterAdvertisement {
        lifetime: router_lifetime,
        ..Default::default()
    };

    let mut out = match ispf::to_bytes_be(&pkt) {
        Ok(data) => data,
        Err(e) => {
            error!(log, "send_ra: serialize packet: {e}");
            return;
        }
    };
    cksum(src, dst, ICMP6_RA_ULP_LEN, &mut out);

    let dst = SocketAddrV6::new(
        match dst {
            Some(d) => d,
            None => ALL_NODES_MCAST,
        },
        0,
        0,
        ifindex,
    );
    if let Err(e) = s.send_to(&out, &dst.into()) {
        error!(log, "send_ra: send: {e}");
    }
}

pub fn send_rs(
    s: &Socket,
    src: Ipv6Addr,
    dst: Option<Ipv6Addr>,
    ifindex: u32,
    log: &Logger,
) {
    let pkt = Icmp6RouterSolicitation::default();
    let mut out = match ispf::to_bytes_be(&pkt) {
        Ok(data) => data,
        Err(e) => {
            error!(log, "send_rs: serialize packet: {e}");
            return;
        }
    };
    cksum(src, dst, ICMP6_RS_ULP_LEN, &mut out);

    let dst = SocketAddrV6::new(
        match dst {
            Some(d) => d,
            None => ALL_ROUTERS_MCAST,
        },
        0,
        0,
        ifindex,
    );
    if let Err(e) = s.send_to(&out, &dst.into()) {
        error!(log, "send_rs: send: {e}");
    }
}

pub fn cksum(
    src: Ipv6Addr,
    dst: Option<Ipv6Addr>,
    ulp_len: u32,
    data: &mut [u8],
) {
    // IP Protocol number for ICMP6
    const ICMP6_NEXT_HDR: u8 = 58;

    let mut ck = internet_checksum::Checksum::new();
    ck.add_bytes(&src.octets());
    ck.add_bytes(
        &match dst {
            Some(d) => d,
            None => ALL_NODES_MCAST,
        }
        .octets(),
    );
    ck.add_bytes(&ulp_len.to_be_bytes());
    ck.add_bytes(&[0, 0, 0, ICMP6_NEXT_HDR]);
    ck.add_bytes(data);
    let sum = ck.checksum();

    // Checksum is the third octet of the ICMP packet.
    data[2] = sum[0];
    data[3] = sum[1];
}

pub struct DropSleep(pub Duration);

impl Drop for DropSleep {
    fn drop(&mut self) {
        sleep(self.0);
    }
}

/// Create a listening socket for solicitations and advertisements. This
/// socket listens on the unspecified address to pick up both unicast
/// and multicast solicitations and advertisements.
pub fn create_socket(index: u32) -> Result<Socket, ListeningSocketError> {
    use ListeningSocketError as E;
    const READ_TIMEOUT: Duration = Duration::from_secs(1);

    let s = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .map_err(E::NewSocketError)?;

    let sa = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, index).into();

    s.set_reuse_address(true).map_err(E::ReuseAddress)?;

    s.set_multicast_if_v6(index).map_err(E::SetMulticastIf)?;

    s.set_multicast_hops_v6(255)
        .map_err(E::SetMulticastHopsV6)?;

    s.set_multicast_loop_v6(false)
        .map_err(E::SetMulticastLoop)?;

    s.join_multicast_v6(&ALL_NODES_MCAST, index)
        .map_err(E::JoinAllNodesMulticast)?;

    s.join_multicast_v6(&ALL_ROUTERS_MCAST, index)
        .map_err(E::JoinAllRoutersMulticast)?;

    s.bind(&sa).map_err(ListeningSocketError::Bind)?;

    s.set_read_timeout(Some(READ_TIMEOUT))
        .map_err(E::SetReadTimeoutError)?;

    unsafe {
        // from <netinet/in.h>
        const IPV6_MINHOPCOUNT: c_int = 0x2f;
        let min_hops: c_int = 255;
        let rc = libc::setsockopt(
            s.as_raw_fd(),
            libc::IPPROTO_IPV6,
            IPV6_MINHOPCOUNT,
            &min_hops as *const _ as *const c_void,
            std::mem::size_of::<libc::c_int>() as socklen_t,
        );
        if rc < 0 {
            return Err(ListeningSocketError::SetIpv6MinHopCount(
                std::io::Error::last_os_error(),
            ));
        }
    }

    Ok(s)
}
