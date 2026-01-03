// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use slog::{Logger, error};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{Ipv6Addr, SocketAddrV6},
    time::Instant,
};

use crate::packet::Icmp6RouterAdvertisement;

pub const ALL_NODES_MCAST: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

#[derive(Debug, Clone)]
pub struct ReceivedAdvertisement {
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

    #[error("bind error: {0}")]
    Bind(std::io::Error),

    #[error("set multicast loop error: {0}")]
    SetMulticastLoop(std::io::Error),

    #[error("join multicast group error: {0}")]
    JoinAllNodesMulticast(std::io::Error),

    #[error("set read timeout error: {0}")]
    SetReadTimeoutError(std::io::Error),
}

pub fn send_ra(
    src: Ipv6Addr,
    dst: Option<Ipv6Addr>,
    ifindex: u32,
    log: &Logger,
) {
    let s = match Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)) {
        Ok(s) => s,
        Err(e) => {
            error!(log, "send_ra: new socket: {e}");
            return;
        }
    };
    if let Err(e) = s.set_multicast_hops_v6(255) {
        error!(log, "send_ra: set multicast hops: {e}");
        return;
    }

    let sa = SocketAddrV6::new(src, 0, 0, ifindex);
    if let Err(e) = s.bind(&sa.into()) {
        error!(log, "send_ra: bind socket: {e}");
        return;
    }

    let pkt = Icmp6RouterAdvertisement::default();
    let mut out = match ispf::to_bytes_be(&pkt) {
        Ok(data) => data,
        Err(e) => {
            error!(log, "send_ra: serialize packet: {e}");
            return;
        }
    };
    cksum(src, dst, &mut out);

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

pub fn cksum(src: Ipv6Addr, dst: Option<Ipv6Addr>, data: &mut [u8]) {
    const ICMP6_RA_ULP_LEN: u32 = 16;
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
    ck.add_bytes(&ICMP6_RA_ULP_LEN.to_be_bytes());
    ck.add_bytes(&[ICMP6_NEXT_HDR]);
    ck.add_bytes(data);
    let sum = ck.checksum();

    // Checksum is the third octet of the ICMP packet.
    data[2] = sum[0];
    data[3] = sum[1];
}
