// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::AddPeerError;
use crate::AddPeerRequest;
use crate::ListenerShutdownHandle;
use crate::Session;
use crate::dispatcher::Dispatcher;
use crate::egress_src_port_iter::EgressSrcPortIter;
use bfd::SessionCounters;
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
    egress_src_port: Arc<EgressSrcPortIter>,
    log: Logger,
}

impl Daemon {
    pub fn new(log: Logger) -> Self {
        Self::with_dispatcher(Dispatcher::new(), log)
    }

    // Non-public method to allow construction with a custom dispatcher.
    //
    // This is used by tests when they want to use a `Dispatcher` with a custom
    // backend (e.g., so we can use nonstandard listening ports in tests).
    pub(crate) fn with_dispatcher(dispatcher: Dispatcher, log: Logger) -> Self {
        Self {
            sessions: HashMap::new(),
            dispatcher,
            egress_src_port: Arc::new(EgressSrcPortIter::new()),
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
                // TODO-correctness Currently clients have no way to update an
                // existing peer: they have to remove it and recreate it. This
                // needs work both here and in omicron to fix.
                // <https://github.com/oxidecomputer/omicron/issues/4921>
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
                let counters = Arc::new(SessionCounters::default());

                // If `ensure` fails, we can immediately bail out. If it
                // succeeds, we've now modified state inside the dispatcher;
                // it's critical that `Session::new()` is infallible; if that
                // changes in the future, we need to be very careful to ensure
                // that we undo the dispatcher state change if we can't
                // successfully create the associated `Session`.
                let listener_rx = self.dispatcher.ensure(
                    rq.listen_addr,
                    peer,
                    Arc::clone(&counters),
                    &self.log,
                )?;

                let session = Session::new(
                    db,
                    rq,
                    counters,
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
