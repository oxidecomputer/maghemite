// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::connection::BgpConnection;
use crate::messages::UpdateMessage;
use crate::session::FsmEvent;
use slog::Logger;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::mpsc::Sender;

pub struct Fanout<Cnx: BgpConnection> {
    /// Indexed neighbor address
    egress: BTreeMap<IpAddr, Egress<Cnx>>,
}

//NOTE necessary as #derive is broken for generic types
impl<Cnx: BgpConnection> Default for Fanout<Cnx> {
    fn default() -> Self {
        Self {
            egress: BTreeMap::new(),
        }
    }
}

pub struct Egress<Cnx: BgpConnection> {
    pub event_tx: Option<Sender<FsmEvent<Cnx>>>,
    pub log: Logger,
}

impl<Cnx: BgpConnection> Fanout<Cnx> {
    pub fn send(&self, origin: IpAddr, update: &UpdateMessage) {
        for (id, e) in &self.egress {
            if *id == origin {
                continue;
            }
            e.send(update);
        }
    }

    pub fn send_all(&self, update: &UpdateMessage) {
        for e in self.egress.values() {
            e.send(update);
        }
    }

    pub fn add_egress(&mut self, peer: IpAddr, egress: Egress<Cnx>) {
        self.egress.insert(peer, egress);
    }

    pub fn remove_egress(&mut self, peer: IpAddr) {
        self.egress.remove(&peer);
    }

    pub fn is_empty(&self) -> bool {
        self.egress.is_empty()
    }
}

impl<Cnx: BgpConnection> Egress<Cnx> {
    fn send(&self, update: &UpdateMessage) {
        if let Some(tx) = self.event_tx.as_ref()
            && let Err(e) = tx.send(FsmEvent::Announce(update.clone())) {
                slog::error!(self.log, "egress fanout failed: {e}");
            }
    }
}
