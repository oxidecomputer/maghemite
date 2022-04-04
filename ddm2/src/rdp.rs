// Router Discovery Protocol

use std::io::Result;
use std::net::{SocketAddrV6, Ipv6Addr};
use std::mem::MaybeUninit;
use slog::{self, trace, Logger};

use icmpv6::{ICMPv6Packet, parse_icmpv6};
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use tokio::io::unix::AsyncFd;

pub const DDM_RDP_MADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0,0,0,0,0,0, 0xdd);

pub fn send(msg: ICMPv6Packet, dst: Ipv6Addr, if_index: u32) -> Result<usize> {

    let sa: SockAddr = SocketAddrV6::new(dst, 0, 0, if_index).into();
    let data = msg.wire();

    let socket = Socket::new(
        Domain::IPV6,
        Type::RAW,
        Some(Protocol::ICMPV6),
    )?;
    socket.set_multicast_loop_v6(false)?;

    socket.send_to(data.as_slice(), &sa)
}

pub struct Receiver {
    socket: AsyncFd<Socket>,
    log: Logger,
}

impl Receiver {

    pub fn new(log: Logger, if_index: u32) -> Result<Self> {
        let socket = Socket::new(
            Domain::IPV6,
            Type::RAW,
            Some(Protocol::ICMPV6),
        )?;
        socket.join_multicast_v6(&DDM_RDP_MADDR, if_index)?;
        socket.set_nonblocking(true)?;

        Ok(Receiver{ log, socket: AsyncFd::new(socket)? })
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

            let msg = match parse_icmpv6(
                unsafe{&MaybeUninit::slice_assume_init_ref(&buf)[..size]},
            ) {
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

    use tokio::{
        spawn,
        time::sleep,
        sync::mpsc::channel,
    };
    use anyhow::Result;
    use util::test::testlab_x2;

    use icmpv6::{ICMPv6Packet, RouterSolicitation};
    use super::*;

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
        let msg = ICMPv6Packet::RouterSolicitation(
            RouterSolicitation::new(None)
        );
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
