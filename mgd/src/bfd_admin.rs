// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use bfd::Daemon;
use bfd::Session;
use bfd::SessionCounters;
use dropshot::{HttpError, HttpResponseUpdatedNoContent, TypedBody};
use mg_api_types::bfd::BfdPeerConfig;
use mg_api_types::bfd::BfdPeerInfo;
use mg_api_types::bfd::DeleteBfdPeerPathParams;
use mg_common::lock;
use slog::Logger;
use slog_error_chain::InlineErrorChain;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

/// Context for Dropshot requests.
#[derive(Clone)]
pub struct BfdContext {
    /// The underlying deamon being run.
    daemon: Arc<Mutex<Daemon>>,
}

impl BfdContext {
    pub fn new(log: Logger) -> Self {
        Self {
            daemon: Arc::new(Mutex::new(Daemon::new(log.clone()))),
        }
    }

    /// Helper function for constructing a BfdPeerInfo
    fn peer_info(
        peer: &IpAddr,
        session: &Session,
        listener: Option<SocketAddr>,
    ) -> Result<BfdPeerInfo, HttpError> {
        let listen = listener
            .ok_or(HttpError::for_internal_error(format!(
                "no listener for {peer}"
            )))?
            .ip();
        Ok(BfdPeerInfo {
            config: BfdPeerConfig {
                peer: *peer,
                listen,
                required_rx: session.required_rx_micros(),
                detection_threshold: session.detection_threshold(),
                mode: session.mode(),
            },
            state: session.state(),
        })
    }

    /// Get all BFD peers and their associated state.
    /// Peers are identified by IP address.
    pub fn get_peers(&self) -> Result<Vec<BfdPeerInfo>, HttpError> {
        let mut result = Vec::new();
        let daemon = lock!(self.daemon);
        for (addr, session) in daemon.sessions_iter() {
            let info = Self::peer_info(
                addr,
                session,
                daemon.listen_addr_for_peer(addr),
            )?;
            result.push(info);
        }

        Ok(result)
    }

    /// Restore persisted BFD peers to the running daemon.
    ///
    /// This reads the peer configs from the DB itself so callers cannot start
    /// an unpersisted peer through the production API.
    pub fn restore_peers(
        &self,
        db: rdb::Db,
    ) -> Result<(), crate::error::Error> {
        let mut daemon = lock!(self.daemon);
        for config in db.get_bfd_neighbors()? {
            daemon.add_peer(db.clone(), config.into())?;
        }
        Ok(())
    }

    /// Add a new BFD peer to persistent config and the running daemon.
    ///
    /// This first tries to update the persistent DB with the BFD peer config,
    /// starting its runtime only upon success; if the DB update fails, an error
    /// is returned. A rollback of the DB update is attempted if the subsequent
    /// runtime update fails, returning an internal error upon rollback failure.
    pub fn add_new_peer(
        &self,
        db: rdb::Db,
        request: TypedBody<BfdPeerConfig>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let rq = request.into_inner();

        let mut daemon = lock!(self.daemon);

        db.clone()
            .add_bfd_neighbor(rq)
            .map_err(crate::error::Error::Db)?;

        if let Err(e) = daemon.add_peer(db.clone(), rq.into()) {
            db.remove_bfd_neighbor(rq.peer).map_err(|e| {
                HttpError::for_internal_error(
                    InlineErrorChain::new(&e).to_string(),
                )
            })?;
            return Err(crate::error::Error::Bfd(e).into());
        }

        Ok(HttpResponseUpdatedNoContent())
    }

    /// Remove a BFD peer from the persistent DB and the running daemon.
    /// The associated peer session will be stopped immediately.
    pub async fn remove_peer(
        &self,
        db: rdb::Db,
        peer: DeleteBfdPeerPathParams,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let handle = {
            let mut daemon = lock!(self.daemon);
            db.remove_bfd_neighbor(peer.addr).map_err(|e| {
                HttpError::for_internal_error(
                    InlineErrorChain::new(&e).to_string(),
                )
            })?;
            daemon.remove_peer(peer.addr)
        };

        if let Some(handle) = handle {
            // If this was the last peer associated with a given local listening
            // address, wait for the listening socket to be closed (allowing a
            // caller to add a new peer at the same listening address once this
            // returns).
            //
            // We've already unlocked the `bfd.daemon`, so it's possible a
            // _concurrent_ request for the same listen address we're shutting down
            // here could fail, but that's inherently racy: we can only guarantee
            // that a client waiting for this remove to complete is able to add a
            // new peer at the same listening address.
            handle.shutdown().await;
        }

        Ok(HttpResponseUpdatedNoContent {})
    }

    pub fn session_counters(&self) -> Vec<(IpAddr, Arc<SessionCounters>)> {
        lock!(self.daemon)
            .sessions_iter()
            .map(|(ip, session)| (*ip, Arc::clone(session.counters())))
            .collect()
    }
}
