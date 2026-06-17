// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::AddPeerError;
use crate::AddPeerRequest;
use crate::ListenerShutdownHandle;
use crate::Session;
use crate::dispatcher::Dispatcher;
use crate::single_hop_egress_src_port::SingleHopEgressSrcPort;
use slog::Logger;
use slog::warn;
use std::collections::HashMap;
use std::collections::hash_map;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct Daemon {
    dispatcher: Dispatcher,
    sessions: HashMap<IpAddr, Session>,
    egress_src_port: Arc<SingleHopEgressSrcPort>,
    log: Logger,
}

impl Daemon {
    pub fn new(log: Logger) -> Self {
        Self {
            sessions: HashMap::new(),
            dispatcher: Dispatcher::new(),
            egress_src_port: Arc::new(SingleHopEgressSrcPort::new()),
            log,
        }
    }

    pub fn sessions_iter(&self) -> hash_map::Iter<'_, IpAddr, Session> {
        self.sessions.iter()
    }

    pub fn listen_addr_for_peer(&self, peer: &IpAddr) -> Option<SocketAddr> {
        self.dispatcher.listen_addr_for_peer(peer)
    }

    pub fn add_peer(
        &mut self,
        db: rdb::Db,
        rq: AddPeerRequest,
    ) -> Result<(), AddPeerError> {
        let peer = rq.remote_addr.ip();
        match self.sessions.entry(peer) {
            hash_map::Entry::Occupied(_) => {
                warn!(
                    self.log, "attempt to add peer that already exists";
                    "component" => bfd::COMPONENT_BFD,
                    "module" => bfd::MOD_DAEMON,
                    "unit" => bfd::UNIT_PEER,
                    "peer" => %peer,
                );
                Err(AddPeerError::PeerExists(peer))
            }
            hash_map::Entry::Vacant(entry) => {
                // If `ensure` fails, we can immediately bail out. If it
                // succeeds, we've now modified state inside the dispatcher;
                // it's critical that `Session::new()` is infallible; if that
                // changes in the future, we need to be very careful to ensure
                // that we undo the dispatcher state change if we can't
                // successfully create the associated `Session`.
                let listener_rx =
                    self.dispatcher.ensure(rq.listen_addr, peer, &self.log)?;

                let session = Session::new(
                    db,
                    rq,
                    Arc::clone(&self.egress_src_port),
                    listener_rx,
                    &self.log,
                );

                entry.insert(session);
                Ok(())
            }
        }
    }

    pub fn remove_peer(
        &mut self,
        peer: IpAddr,
    ) -> Option<ListenerShutdownHandle> {
        self.sessions.remove(&peer);
        self.dispatcher.remove(peer)
    }
}
