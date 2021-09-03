// Copyright 2021 Oxide Computer Company

use crate::{Rift, Peer};
use platform::Platform;
use std::thread;
use icmpv6::ICMPv6Packet;
use slog::{info, error, debug};
use std::sync::mpsc::Sender;

impl<P: Platform + std::marker::Send> Rift<P> {

    pub(crate) fn rdp_handler(
        &mut self,
        peer_tx: Sender<Peer>,
    ) -> Result<(), crate::error::Error> {

        let p = self.platform.lock().unwrap();

        let peers = self.peers.clone();
        let rdp_rx = (*p).get_rdp_channel()?;
        let log = self.log.clone();

        thread::spawn(move || loop {
            let msg = match rdp_rx.recv() {
                Ok(m) => m,
                Err(e) => {
                    error!(log, "rdp rx: {}", e);
                    continue;
                },
            };

            let from = match msg.from {
                Some(addr) => addr,
                _ => continue,
            };

            match msg.packet {
                ICMPv6Packet::RouterSolicitation(rs) => {
                    info!(log, "got RIFT msg {:#?} from {}", rs, from);
                    //TODO respond to solicitations
                },
                ICMPv6Packet::RouterAdvertisement(ra) => {
                    info!(log, "got RIFT msg {:#?} from {}", ra, from);
                    let mut ps = peers.lock().unwrap();
                    let peer = Peer{
                        remote_addr: from,
                        advertisement: ra,
                    };
                    match (*ps).replace(peer) {
                        None => {},
                        Some(_) => {
                            debug!(log, "peer already known {}", from);
                            continue
                        },
                    };
                    match peer_tx.send(peer) {
                        Ok(_) => {},
                        Err(e) => error!(log, "send peer to handler {}", e),
                    };
                }
            };

        });

        Ok(())

    }

}
