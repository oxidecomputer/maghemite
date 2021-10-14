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
    tie::{
        TIEPacket,
        NeighborTIE,
        NodeTIE,
        TIEDirection,
        TIEId,
        TIEElement,
        TIEHeader,
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

pub(crate) async fn tie_entry<P: Platform + Send + Sync + 'static>(
    log: slog::Logger,
    platform: Arc::<Mutex::<P>>,
    links: Arc::<Mutex::<HashSet::<LinkSM>>>,
    config: crate::config::Config,
    event_rx: broadcast::Receiver<PeerEvent>,
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
    );

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
    for (_, peer) in &nbrs {
        match &peer.lie {
            None => continue,
            Some(l) => {
                nbr_map.insert(
                    l.header.sender,
                    NeighborTIE{
                        level: l.header.level,
                        cost: None, //TODO
                        link_ids: None, //TODO
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
                        tie_element: TIEElement::Node(node_tie.clone())
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


fn tie_loop(
    log: slog::Logger,
    tx: Sender<TIEPacketTx>,
    mut rx: Receiver<TIEPacket>,
    links: Arc::<Mutex::<HashSet::<LinkSM>>>,
    mut event_rx: broadcast::Receiver<PeerEvent>,
    config: crate::config::Config,
) {

    spawn(async move { loop {

        // hack, force compiler to move _tx into this context so it does not get
        // dropped
        //let __tx = &_tx;

        trace!(log, "TIE loop");
        //tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        select! {

            tie_msg = rx.recv() => {
                match tie_msg {
                    None => {
                        warn!(log, "TIE rx channel closed");
                        break;
                    },
                    Some(msg) => {
                        debug!(log, "TIE received: {:#?}", msg);
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
