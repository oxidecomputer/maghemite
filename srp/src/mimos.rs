use std::io::Result;
use std::sync::Arc;

use tokio::sync::mpsc::{Sender, Receiver, channel};
use tokio::{spawn, select};
use tokio::sync::Mutex;

use crate::platform;
use crate::port::Port;
use crate::flowstat::PortStats;
use crate::rdp::RdpMessage;
use crate::protocol::{SrpMessage, PeerMessage};
use crate::router::Route;

pub struct RdpChannel {
    pub rx: Receiver<RdpMessage>,
    pub tx: Sender<RdpMessage>,
}

pub struct SrpChannel {
    pub rx: Receiver<SrpMessage>,
    pub tx: Sender<SrpMessage>,
}

pub struct PeerChannel {
    pub rx: Receiver<PeerMessage>,
    pub tx: Sender<PeerMessage>,
}

pub struct Neighbor {
    pub rdp_ch: Arc::<Mutex::<RdpChannel>>,
    pub peer_ch: Arc::<Mutex::<PeerChannel>>,
    pub arc_ch: Arc::<Mutex::<SrpChannel>>,
}

pub struct Node {
    neighbors: Vec<Neighbor>,
}

impl Node {
    pub fn new() -> Self {
        Node{
            neighbors: Vec::new(),
        }
    }
}

pub fn connect(a: &mut Node, b: &mut Node) {

    let (rdp_tx_ab, rdp_rx_ab) = channel(0x20);
    let (rdp_tx_ba, rdp_rx_ba) = channel(0x20);

    let (arc_tx_ab, arc_rx_ab) = channel(0x20);
    let (arc_tx_ba, arc_rx_ba) = channel(0x20);

    let (peer_tx_ab, peer_rx_ab) = channel(0x20);
    let (peer_tx_ba, peer_rx_ba) = channel(0x20);

    a.neighbors.push(Neighbor{
        rdp_ch: Arc::new(Mutex::new(RdpChannel{
            rx: rdp_rx_ba,
            tx: rdp_tx_ab,
        })),
        arc_ch: Arc::new(Mutex::new(SrpChannel{
            rx: arc_rx_ba,
            tx: arc_tx_ab,
        })),
        peer_ch: Arc::new(Mutex::new(PeerChannel{
            rx: peer_rx_ba,
            tx: peer_tx_ab,
        }))
    });

    b.neighbors.push(Neighbor{
        rdp_ch: Arc::new(Mutex::new(RdpChannel{
            rx: rdp_rx_ab,
            tx: rdp_tx_ba,
        })),
        arc_ch: Arc::new(Mutex::new(SrpChannel{
            rx: arc_rx_ab,
            tx: arc_tx_ba,
        })),
        peer_ch: Arc::new(Mutex::new(PeerChannel{
            rx: peer_rx_ab,
            tx: peer_tx_ba,
        }))
    });

}

impl platform::Ports for Node {
    fn ports(&self) -> Result<Vec<Port>> {
        let mut result = Vec::new();
        for (index, _) in self.neighbors.iter().enumerate() {
            result.push(Port{index})
        }
        Ok(result)
    }
}

impl platform::FlowStat for Node {
    fn stats(&self, _: Port) -> Result<PortStats> { 
        Ok(PortStats{})
    }
}

impl platform::Rdp for Node {
    fn rdp_channel(&self, p: Port)
    -> Result<(Sender<RdpMessage>, Receiver<RdpMessage>)> {

        let (itx, irx) = channel(0x20);
        let (etx, mut erx) = channel(0x20);

        let rdp = self.neighbors[p.index].rdp_ch.clone();

        spawn(async move{
            //let mut n = nbr.lock().await;
            let mut rdp = rdp.lock().await;
            loop {
                select!(
                    msg = rdp.rx.recv() => {
                        match msg {
                            Some(m) => {
                                match itx.send(m).await {
                                    Ok(()) => {}
                                    Err(e) => {
                                        println!("rdp ingress send: {}", e)
                                    }
                                }
                            }
                            None => {}
                        };
                    }
                    msg = erx.recv() => {
                        match msg {
                            Some(m) => {
                                match rdp.tx.send(m).await {
                                    Ok(()) => {}
                                    Err(e) => {
                                        println!("rdp egress send: {}", e)
                                    }
                                }
                            }
                            None => {}
                        }
                    }
                );
            }
        });

        Ok((etx, irx))
    }
}

impl platform::Srp for Node {

    fn peer_channel(&self, p: Port) 
    -> Result<(Sender<PeerMessage>, Receiver<PeerMessage>)> {
        let (itx, irx) = channel(0x20);
        let (etx, mut erx) = channel(0x20);

        let pc = self.neighbors[p.index].peer_ch.clone();

        spawn(async move{
            loop {
                let mut pc = pc.lock().await;
                select!(
                    msg = pc.rx.recv() => {
                        match msg {
                            Some(m) => {
                                match itx.send(m).await {
                                    Ok(()) => {}
                                    Err(e) => {
                                        println!("peer ingress send: {}", e)
                                    }
                                }
                            }
                            None => {}
                        };
                    }
                    msg = erx.recv() => {
                        match msg {
                            Some(m) => {
                                match pc.tx.send(m).await {
                                    Ok(()) => {}
                                    Err(e) => {
                                        println!("peer egress send: {}", e)
                                    }
                                }
                            }
                            None => {}
                        }
                    }
                );
            }
        });

        Ok((etx, irx))
    }

    fn arc_channel(&self, p: Port) 
    -> Result<(Sender<SrpMessage>, Receiver<SrpMessage>)> {
        let (itx, irx) = channel(0x20);
        let (etx, mut erx) = channel(0x20);

        let arc = self.neighbors[p.index].arc_ch.clone();

        spawn(async move{
            let mut arc = arc.lock().await;
            loop {
                select!(
                    msg = arc.rx.recv() => {
                        match msg {
                            Some(m) => {
                                match itx.send(m).await {
                                    Ok(()) => {}
                                    Err(e) => {
                                        println!("arc ingress send: {}", e)
                                    }
                                }
                            }
                            None => {}
                        };
                    }
                    msg = erx.recv() => {
                        match msg {
                            Some(m) => {
                                match arc.tx.send(m).await {
                                    Ok(()) => {}
                                    Err(e) => {
                                        println!("arc egress send: {}", e)
                                    }
                                }
                            }
                            None => {}
                        }
                    }
                );
            }
        });

        Ok((etx, irx))
    }
}

impl platform::Router for Node {
    fn get_routes(&self) -> Result<Vec<Route>> {
        todo!();
    }

    fn set_route(&self, _r: Route) -> Result<()> {
        todo!();
    }

    fn delete_route(&self, _r: Route) -> Result<()> {
        todo!();
    }
}

#[cfg(test)]
mod test {
    use crate::mimos;
    use crate::port::Port;
    use crate::platform::{Rdp, Srp};
    use crate::rdp::RdpMessage;
    use crate::protocol::{SrpMessage, SrpPrefix};
    use crate::net::Ipv6Prefix;

    use std::str::FromStr;
    use std::collections::HashSet;

    #[tokio::test]
    async fn mimos_2_router_msg() -> anyhow::Result<()> {

        // topology
        let mut a = mimos::Node::new();
        let mut b = mimos::Node::new();
        mimos::connect(&mut a, &mut b);

        // get RDP channel
        let (a_rdp_tx, mut a_rdp_rx) = a.rdp_channel(Port{index: 0}).unwrap();
        let (b_rdp_tx, mut b_rdp_rx) = b.rdp_channel(Port{index: 0}).unwrap();

        // get ARC channel
        let (a_arc_tx, mut a_arc_rx) = a.arc_channel(Port{index: 0}).unwrap();
        let (b_arc_tx, mut b_arc_rx) = b.arc_channel(Port{index: 0}).unwrap();

        // send some RDP messages
        a_rdp_tx.send(RdpMessage{content: "rdp test 1".into()}).await?;
        b_rdp_tx.send(RdpMessage{content: "rdp test 2".into()}).await?;

        // receive RDP messages
        let msg = a_rdp_rx.recv().await;
        assert_eq!(msg, Some(RdpMessage{content: "rdp test 2".into()}));

        let msg = b_rdp_rx.recv().await;
        assert_eq!(msg, Some(RdpMessage{content: "rdp test 1".into()}));

        // send some ARC messages
        let mut prefixes = HashSet::new();
        prefixes.insert(Ipv6Prefix::from_str("fd00::1701/64")?);
        let a_to_b = SrpMessage::Prefix(SrpPrefix{
            origin: "a".to_string(),
            prefixes,
        });
        a_arc_tx.send(a_to_b.clone()).await?;

        let mut prefixes = HashSet::new();
        prefixes.insert(Ipv6Prefix::from_str("fd00::1702/64")?);
        let b_to_a = SrpMessage::Prefix(SrpPrefix{
            origin: "b".to_string(),
            prefixes,
        });
        b_arc_tx.send(b_to_a.clone()).await?;

        // receive ARC messages
        let msg = a_arc_rx.recv().await;
        assert_eq!(msg.unwrap(), b_to_a);

        let msg = b_arc_rx.recv().await;
        assert_eq!(msg.unwrap(), a_to_b);

        Ok(())

    }
}