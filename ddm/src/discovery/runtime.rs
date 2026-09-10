// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Link-local UDPv6 sockets for ddm router discovery, and the discovery packet
//! codec. illumos-only.
//!
//! This module moves bytes; it makes no decisions. Received packets are decoded
//! into [`Discovery`] values and handed to
//! [`crate::protocol::interface::InterfaceSm`], which decides what to do with
//! them, and sends happen when that core asks for them.

use super::{DiscoveryError, Version};
use crate::protocol::interface::Discovery;
use ddm_api_types::db::RouterKind;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use tokio::net::UdpSocket;

const DDM_MADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xdd);
const DDM_PORT: u16 = 0xddd;
const SOLICIT: u8 = 1;
const ADVERTISE: u8 = 1 << 1;

#[derive(Debug, Serialize, Deserialize)]
struct DiscoveryPacket {
    version: u8,
    flags: u8,
    kind: RouterKind,
    #[serde(with = "ispf::str_lv8")]
    hostname: String,
}

impl DiscoveryPacket {
    fn new_solicitation(hostname: String, kind: RouterKind) -> Self {
        Self {
            version: Version::V2 as u8,
            flags: SOLICIT,
            hostname,
            kind,
        }
    }
    fn new_advertisement(hostname: String, kind: RouterKind) -> Self {
        Self {
            version: Version::V2 as u8,
            flags: ADVERTISE,
            hostname,
            kind,
        }
    }

    /// A packet may set both flags, so this yields one [`Discovery`] per flag
    /// rather than a single value.
    fn decode(self) -> Vec<Discovery> {
        let mut out = Vec::new();
        if (self.flags & SOLICIT) != 0 {
            out.push(Discovery::Solicit);
        }
        if (self.flags & ADVERTISE) != 0 {
            out.push(Discovery::Advertise {
                hostname: self.hostname,
                kind: self.kind,
                version: self.version,
            });
        }
        out
    }
}

/// The pair of sockets discovery runs over on one interface.
///
/// Solicitations go to [`DDM_MADDR`], but advertisements go back to the unicast
/// source address of a solicitation. Binding to a link-scoped multicast address
/// is required for the interface passed as the scope id to be honored, and
/// listening on `::` causes chaos, since every solicitation then shows up on
/// every socket.
pub(crate) struct Sockets {
    pub(crate) mc: UdpSocket,
    pub(crate) uc: UdpSocket,
    hostname: String,
    kind: RouterKind,
    if_index: u32,
}

impl Sockets {
    pub(crate) fn open(
        hostname: String,
        kind: RouterKind,
        addr: Ipv6Addr,
        if_index: u32,
    ) -> Result<Self, DiscoveryError> {
        let mc = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        let uc = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

        let mc_sa: SockAddr =
            SocketAddrV6::new(DDM_MADDR, DDM_PORT, 0, if_index).into();
        mc.set_reuse_address(true)?;
        mc.set_multicast_if_v6(if_index)?;
        mc.bind(&mc_sa)?;
        mc.join_multicast_v6(&DDM_MADDR, if_index)?;
        mc.set_multicast_loop_v6(false)?;

        let uc_sa: SockAddr =
            SocketAddrV6::new(addr, DDM_PORT, 0, if_index).into();
        uc.bind(&uc_sa)?;

        Ok(Self {
            mc: into_tokio(mc)?,
            uc: into_tokio(uc)?,
            hostname,
            kind,
            if_index,
        })
    }

    pub(crate) async fn solicit(&self) -> Result<usize, DiscoveryError> {
        let msg =
            DiscoveryPacket::new_solicitation(self.hostname.clone(), self.kind);
        let data = ispf::to_bytes_be(&msg)?;
        Ok(self.mc.send_to(&data, self.sockaddr(DDM_MADDR)).await?)
    }

    /// Advertise to `dst`, or to the multicast group if there is no particular
    /// solicitor to answer.
    pub(crate) async fn advertise(
        &self,
        dst: Option<Ipv6Addr>,
    ) -> Result<usize, DiscoveryError> {
        let msg = DiscoveryPacket::new_advertisement(
            self.hostname.clone(),
            self.kind,
        );
        let data = ispf::to_bytes_be(&msg)?;
        let addr = dst.unwrap_or(DDM_MADDR);
        Ok(self.uc.send_to(&data, self.sockaddr(addr)).await?)
    }

    fn sockaddr(&self, addr: Ipv6Addr) -> SocketAddr {
        SocketAddrV6::new(addr, DDM_PORT, 0, self.if_index).into()
    }
}

fn into_tokio(s: Socket) -> Result<UdpSocket, DiscoveryError> {
    let s: std::net::UdpSocket = s.into();
    s.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(s)?)
}

/// Wait for one discovery packet.
pub(crate) async fn recv(
    sock: &UdpSocket,
) -> Result<(Ipv6Addr, Vec<Discovery>), DiscoveryError> {
    let mut buf = [0u8; 1024];
    loop {
        let (n, sa) = sock.recv_from(&mut buf).await?;
        let SocketAddr::V6(sa) = sa else {
            // Not reachable on an AF_INET6 socket, but there is nothing
            // sensible to report to the state machine either way.
            continue;
        };
        let msg: DiscoveryPacket = ispf::from_bytes_be(&buf[..n])?;
        return Ok((*sa.ip(), msg.decode()));
    }
}
