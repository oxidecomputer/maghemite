//! This file contains the router discovery protocol (RDP) functionality for
//! DDM. DDM routers emit periodic router solicitations to make other routers
//! aware of their presence, but they do not emit advertisements. A DDM router
//! will respond to an RDP solicitation by attempting to peer with the solicitor
//! using the DDM peering protocol.
//!
//!              *-----*                        *-----*
//!              |  A  |                        |  B  |
//!              *-----*                        *-----*
//!                 |           solicit            |
//!                 |----------------------------->|
//!                 |            peer              |
//!                 |<-----------------------------|
//!                 |                              |
//!                 |    [b peers with a ...]      |
//!                 |                              |
//!
//! DDM peering is directional, so B peering with A is independent of A peering
//! with B.
//!
//! A DDM router will periodically send out solicitations on all interfaces it
//! is configured to use independent of peering status with neighboring routers
//! on those interfaces. This provides a persistent presence detection mechanism
//! for neighbors.
//!
//! Router solicitations are sent on the DDM router discovery link-local
//! multicast address ff02::dd.

use std::io::Result;
use std::mem::MaybeUninit;
use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use std::time::Duration;

use icmpv6::parse_icmpv6;
use icmpv6::ICMPv6Packet;
use icmpv6::RouterSolicitation;
use slog::info;
use slog::trace;
use slog::warn;
use slog::Logger;
use socket2::Domain;
use socket2::Protocol;
use socket2::SockAddr;
use socket2::Socket;
use socket2::Type;
use tokio::io::unix::AsyncFd;
use tokio::spawn;
use tokio::time::sleep;

pub const DDM_RDP_MADDR: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xdd);

pub fn send(msg: ICMPv6Packet, dst: Ipv6Addr, if_index: u32) -> Result<usize> {
    let sa: SockAddr = SocketAddrV6::new(dst, 0, 0, if_index).into();
    let data = msg.wire();

    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_multicast_loop_v6(false)?;

    socket.send_to(data.as_slice(), &sa)
}

pub struct Receiver {
    socket: AsyncFd<Socket>,
    log: Logger,
}

impl Receiver {
    pub fn new(log: Logger, if_index: u32) -> Result<Self> {
        let socket =
            Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        socket.join_multicast_v6(&DDM_RDP_MADDR, if_index)?;
        socket.set_nonblocking(true)?;

        Ok(Receiver {
            log,
            socket: AsyncFd::new(socket)?,
        })
    }

    pub async fn recv(&self) -> Result<(Ipv6Addr, ICMPv6Packet)> {
        loop {
            let mut guard = self.socket.readable().await?;
            let mut buf = [MaybeUninit::new(0); 1024];
            let (size, sender) =
                match guard.try_io(|s| s.get_ref().recv_from(&mut buf)) {
                    Ok(result) => result?,
                    Err(e) => {
                        trace!(self.log, "recv_from error: {:#?}", e);
                        continue;
                    }
                };

            let sender = match sender.as_socket_ipv6() {
                Some(sa) => *sa.ip(),
                // This should never happen as we're listening on an ipv6
                // multicast address, but we need to deal with this situation
                // since the type gymnastics require it.
                None => Ipv6Addr::UNSPECIFIED,
            };

            //TODO trade for `MaybeUninit::slice_assume_init_ref` when it
            //becomes available in stable Rust.
            let ibuf =
                &unsafe { &*(&buf as *const [MaybeUninit<u8>] as *const [u8]) }
                    [..size];

            let msg = match parse_icmpv6(ibuf) {
                Some(packet) => packet,
                None => {
                    trace!(self.log, "parse error");
                    continue;
                }
            };

            return Ok((sender, msg));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use anyhow::Result;
    use tokio::spawn;
    use tokio::sync::mpsc::channel;
    use tokio::time::sleep;
    use util::test::testlab_x2;

    use super::*;
    use icmpv6::ICMPv6Packet;
    use icmpv6::RouterSolicitation;

    #[tokio::test]
    async fn rs_send_recv() -> Result<()> {
        //
        // set up testlab interfaces
        //

        let interfaces = testlab_x2("rdp1")?;
        let tx_ifx = interfaces[0].addr.info.index as u32;
        let rx_ifx = interfaces[1].addr.info.index as u32;

        //
        // set up an rdp listener
        //

        let log = util::test::logger();
        let receiver = Receiver::new(log.clone(), rx_ifx)?;
        let (tx, mut rx) = channel(1);
        spawn(async move {
            let (src, pkt) = receiver.recv().await.unwrap();
            tx.send((src, pkt)).await.unwrap();
        });
        // XXX wait for socket to become ready, need something more
        // deterministic than this.
        sleep(Duration::from_secs(1)).await;

        //
        // send a router advertisement
        //

        println!("sending solicitation");
        let msg =
            ICMPv6Packet::RouterSolicitation(RouterSolicitation::new(None));
        // rdp multicast address for ddm
        let dst = DDM_RDP_MADDR;
        send(msg.clone(), dst, tx_ifx)?;
        println!("sending solicitation sent");

        //
        // wait for the response
        //

        println!("waiting for response");
        let (src, pkt) = rx.recv().await.unwrap();
        assert!(matches!(pkt, ICMPv6Packet::RouterSolicitation(_)));
        assert_eq!(IpAddr::V6(src), interfaces[0].addr.info.addr);

        Ok(())
    }
}

/// A solicitor that solicits in the background and stops soliciting when
/// droppd.
pub struct Solicitor {
    ifnum: i32,
    task: Option<tokio::task::JoinHandle<()>>,
    interval: u64,
    log: Logger,
}

impl Solicitor {
    pub fn new(log: Logger, ifnum: i32, interval: u64) -> Self {
        Solicitor {
            ifnum,
            interval,
            task: None,
            log,
        }
    }

    pub fn start(&mut self) {
        let ifnum = self.ifnum;
        let interval = self.interval;
        let log = self.log.clone();
        self.task = Some(spawn(async move {
            loop {
                trace!(log, "soliciting ddm router");
                match solicit_ddm_router(ifnum).await {
                    Ok(_) => {}
                    Err(e) => {
                        warn!(log, "solicit failed: {}", e);
                    }
                }
                sleep(Duration::from_millis(interval)).await;
            }
        }));
    }
}

impl Drop for Solicitor {
    fn drop(&mut self) {
        info!(self.log, "dropping solicitor on ifnum {}", self.ifnum);
        if let Some(ref t) = self.task {
            t.abort()
        }
    }
}

async fn solicit_ddm_router(ifnum: i32) -> Result<()> {
    let msg = ICMPv6Packet::RouterSolicitation(RouterSolicitation::new(None));
    let dst = DDM_RDP_MADDR;
    send(msg, dst, ifnum as u32)?;
    Ok(())
}
