// Copyright 2021 Oxide Computer Company

use std::sync::Arc;
use tokio::{
    spawn,
    select,
    sync::{Mutex, broadcast, mpsc::{Sender, Receiver}},
};
use rift_protocol::{
    NodeCapabilities,
    Header,
    SystemId,
    LinkId,
    tie::{
        TIEPacket,
        NeighborTIE,
        NodeTIE,
        TIEDirection,
        TIEId,
        TIEElement,
        TIEHeader,
        LinkIdPair,
    },
};
use crate::{
    Platform,
    Peer,
    PeerEvent,
};
use platform::{self, TIEPacketTx, IpIfAddr};
use slog::{
    //info,
    debug,
    error,
    trace,
    warn,
};
use std::collections::{HashSet, HashMap};
use crate::link::LinkSM;
use std::hash::{Hash, Hasher};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

#[derive(Clone, Copy, Serialize, Deserialize, JsonSchema)]
pub struct LSDBEndpoint {
    pub system_id: SystemId,
    pub link_id: LinkId,
}
impl Hash for LSDBEndpoint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.system_id.hash(state);
        self.link_id.hash(state);
    }
}
impl PartialEq for LSDBEndpoint {
    fn eq(&self, other: &Self) -> bool {
        self.system_id == other.system_id && self.link_id == other.link_id
    }
}
impl Eq for LSDBEndpoint {}

#[derive(Clone, Copy, Serialize, Deserialize, JsonSchema)]
pub struct LSDBEntry{
    pub a: LSDBEndpoint,
    pub b: LSDBEndpoint,
}

impl Hash for LSDBEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.a.hash(state);
        self.b.hash(state);
    }
}
impl PartialEq for LSDBEntry {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}
impl Eq for LSDBEntry {}

pub(crate) async fn tie_entry<P: Platform + Send + Sync + 'static>(
    log: slog::Logger,
    platform: Arc::<Mutex::<P>>,
    links: Arc::<Mutex::<HashSet::<LinkSM>>>,
    config: crate::config::Config,
    event_rx: broadcast::Receiver<PeerEvent>,
    lsdb: Arc::<Mutex::<HashSet<LSDBEntry>>>,
) {

    trace!(log, "TIE entry");

    let (tx, rx) = {
        let p = platform.lock().await;
        match p.get_topology_channel() {
            Err(e) => {
                error!(log, "get topology channel: {}", e);
                return;
            }
            Ok(cs) => cs
        }
    };

    tie_loop(
        log.clone(), 
        tx,
        rx,
        links,
        event_rx,
        config,
        lsdb,
    ).await;

}

async fn initial_tie_tx(
    log: &slog::Logger,
    tx: &Sender<TIEPacketTx>,
    links: &Arc::<Mutex::<HashSet::<LinkSM>>>,
    config: &crate::config::Config,
    peer: Peer,
    local_if: IpIfAddr,
) {

    debug!(log, "sending initial TIE tx to {}", match &peer.lie {
        Some(l) => l.name.to_string(),
        None => peer.remote_addr.to_string(),
    });

    let nbrs = build_neighbor_map(&log, &links).await;

    // create a neighbors list to send out in Node TIEs
    let mut nbr_map = HashMap::new();
    for (v6ll, peer) in &nbrs {
        match &peer.lie {
            None => continue,
            Some(l) => {
                nbr_map.insert(
                    l.header.sender,
                    NeighborTIE{
                        level: l.header.level,
                        cost: None, //TODO
                        link_ids: Some([LinkIdPair{
                            local_id: v6ll.if_index as u32,
                            remote_id: match &peer.lie {
                                Some(l) => l.local_id,
                                None => 0,
                            },
                            local_if_index: None, //TODO
                            local_if_name: None, //TODO
                            outer_security_key: None, //TODO
                            bfd_up: None, //TODO
                            address_families: None, //TODO
                        }].iter().cloned().collect()),
                        bandwidth: None, //TODO
                    },
                );
            }
        };
    }

    // Create a Node TIE and send to northbound neighbors.
    let node_tie = NodeTIE{
        level: config.level,
        neighbors: nbr_map,
        capabilities: NodeCapabilities{
            protocol_minor_version: 0,
            flood_reduction: None, //TODO
            hierarchy_indication: None,
        },
        flags: None, //TODO
        pod: None,
        startup_time: None, //TODO
        miscabled_links: None, //TODO
    };

    // Send Node TIE to all northbound neighbors

    match &peer.lie {
        Some(lie) => {
            // only northbound neighbors get link-state info
            if lie.header.level > config.level {
                debug!(log, "sending northbound msg to {}", match &peer.lie {
                    Some(l) => l.name.to_string(),
                    None => peer.remote_addr.to_string(),
                });

                let tx_result = tx.send(TIEPacketTx{
                    packet: TIEPacket{
                        header: Header{
                            sender: config.id,
                            level: config.level,
                            ..Default::default()
                        },
                        tie_header: TIEHeader{
                            id: TIEId{
                                direction: TIEDirection::North,
                                originator: config.id,
                                number: 0, //TODO
                            },
                            seq: 0, //TODO
                            origination_time: None, //TODO
                            origination_lifetime: None, //TODO
                        },
                        element: TIEElement::Node(node_tie.clone())
                    },
                    dest: peer.remote_addr,
                    local_ifx: local_if.if_index,
                }).await;

                match tx_result {
                    Err(e) => error!(log, "send node TIE: {}", e),
                    Ok(_) => trace!(log, "node TIE sent"),
                }
            } else if lie.header.level < config.level {
                //TODO southbound
            }
        },
        None => { }
    }

                

}

async fn build_neighbor_map(
    log: &slog::Logger,
    links: &Arc::<Mutex::<HashSet::<LinkSM>>>,
) -> HashMap<IpIfAddr, Peer> {

    trace!(log, "build neighbor map");

    // build up a remote-addr -> peer-info mapping
    let mut nbrs = HashMap::new();

    let links = links.lock().await;
    for lsm in links.iter() {
        let state = lsm.state.lock().await;
        let peer = match &state.peer {
            None => continue,
            Some(p) => p.clone(),
        };
        let ipif = match &state.v6ll {
            None => continue,
            Some(i) => i.clone(),
        };
        nbrs.insert(ipif, peer); 
    }

    nbrs

}


async fn tie_loop(
    log: slog::Logger,
    tx: Sender<TIEPacketTx>,
    mut rx: Receiver<TIEPacket>,
    links: Arc::<Mutex::<HashSet::<LinkSM>>>,
    mut event_rx: broadcast::Receiver<PeerEvent>,
    config: crate::config::Config,
    lsdb: Arc::<Mutex::<HashSet<LSDBEntry>>>,
) {

    spawn(async move { loop {

        trace!(log, "TIE loop");

        select! {

            tie_msg = rx.recv() => {
                match tie_msg {
                    None => {
                        warn!(log, "TIE rx channel closed");
                        break;
                    },
                    Some(msg) => {
                        debug!(log, "TIE received: {:#?}", msg);
                        handle_tie_rx(&msg, &lsdb, &log).await;
                    }
                }
            }

            event = event_rx.recv() => {
                match event {
                    Err(e) => {
                        error!(log, "peer event rx: {}", e);
                        continue
                    }
                    Ok(e) =>{
                        debug!(log, "tie_loop: peer up, event");
                        match e {
                            PeerEvent::Up((peer, local_if)) => {
                                initial_tie_tx(
                                    &log, 
                                    &tx,
                                    &links,
                                    &config,
                                    peer,
                                    local_if,
                                ).await;
                            }
                            PeerEvent::Down((_peer, _local_if)) => {
                                //TODO
                            }
                        }
                    }
                };
            }

        }



    }});

}

async fn handle_tie_rx(
    pkt: &TIEPacket,
    lsdb: &Arc::<Mutex::<HashSet<LSDBEntry>>>,
    log: &slog::Logger,
) {

    match &pkt.element {
        TIEElement::Node(ref n) => 
            handle_nodetie_rx(&pkt.header, &pkt.tie_header, n, lsdb, log).await,
        TIEElement::Prefixes(_p) => { }
        TIEElement::PositiveDisaggregationPrefixes(_p) => { }
        TIEElement::NegativeDisaggregationPrefixes(_p) => { }
        TIEElement::External(_x) => { }
        TIEElement::PositiveExternalDisaggregationPrefixes(_p) => { }
        TIEElement::KeyValues(_k) => { }
    }

}

async fn handle_nodetie_rx(
    header: &Header,
    _tie_header: &TIEHeader,
    node_tie: &NodeTIE,
    lsdb: &Arc::<Mutex::<HashSet<LSDBEntry>>>,
    log: &slog::Logger,
) {

    debug!(log, "tie: handling node TIE");

    for (nbr_system_id, nbr_tie) in &node_tie.neighbors {
        let link_ids = match &nbr_tie.link_ids {
            None => continue,
            Some(l) => l,
        };
        for link_pair in link_ids {
            let a = LSDBEndpoint{
                system_id: header.sender,
                link_id: link_pair.local_id,
            };
            let b = LSDBEndpoint{
                system_id: *nbr_system_id,
                link_id: link_pair.remote_id,
            };
            lsdb.lock().await.insert(LSDBEntry{a: a, b: b});
        }
    }

}
