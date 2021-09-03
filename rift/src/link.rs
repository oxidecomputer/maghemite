// Copyright 2021 Oxide Computer Company

use crate::{Rift, Peer};
use std::sync::{Arc, Mutex};
use platform::Platform;
use std::thread;
use slog::{info, error};
use std::sync::mpsc::{Sender, Receiver};
use std::hash::{Hash, Hasher};

pub enum AdjacencyState {
    OneWay,
    TwoWay,
    ThreeWay,
}

pub struct LinkSM {
    state: Arc::<Mutex::<LinkSMState>>,
}

struct LinkSMState {
    current: AdjacencyState,
    peer: Peer,
}

impl<P: Platform + std::marker::Send> Rift<P> {

    pub(crate) fn link_handler(
        &mut self, 
        peer_rx: Receiver<Peer>,
    ) -> Result<(), crate::error::Error> {

        let log = self.log.clone();
        let links = self.links.clone();
        let p = self.platform.clone();

        thread::spawn(move || loop {
            let peer = match peer_rx.recv() {
                Ok(p) => p,
                Err(e) => {
                    error!(log, "peer rx: {}", e);
                    continue;
                }
            };

            info!(log, 
                "starting link state machine for peer {:#?}", 
                peer.remote_addr,
            );

            let mut ls = links.lock().unwrap();
            let pl = p.lock().unwrap();
            let (tx, rx) = match (*pl).get_link_channel(peer.remote_addr) {
                Err(e) => {
                    error!(log, "get link channel for {}: {}", 
                        peer.remote_addr, e);
                    continue;
                },
                Ok(channels) => channels,
            };
            let mut lsm = LinkSM::new(peer);
            lsm.run(tx, rx);
            (*ls).insert(lsm);
        });

        Ok(())

    }

}

// LinkSM implementation ......................................................

impl LinkSM {

    fn new(peer: Peer) -> Self {
        LinkSM{
            state: Arc::new(Mutex::new(LinkSMState{
                current: AdjacencyState::OneWay,
                peer: peer,
            }))
        }
    }

    fn run(
        &mut self,
        tx: Sender<rift_protocol::LinkInfo>,
        rx: Receiver<rift_protocol::LinkInfo>,
    ) {

        //TODO you are here

        thread::spawn(move || loop {

            let _msg = rx.recv();

        });

    }

}

// LinkSM trait implementations ...............................................

impl Hash for LinkSM {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let s = self.state.lock().unwrap();
        (*s).peer.hash(state);
    }
}

impl PartialEq for LinkSM {
    fn eq(&self, other: &Self) -> bool {
        if self == other { return true };

        let s = self.state.lock().unwrap();
        let o = other.state.lock().unwrap();
        (*s).peer == (*o).peer
    }
}
impl Eq for LinkSM {}

