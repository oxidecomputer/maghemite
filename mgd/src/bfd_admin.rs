// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use bfd::Daemon;
use bfd::Session;
use bfd::SessionCounters;
use dropshot::HttpError;
use mg_api_types::bfd::BfdPeerConfig;
use mg_api_types::bfd::BfdPeerInfo;
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

    #[cfg(test)]
    fn new_for_test(log: Logger) -> Self {
        Self {
            daemon: Arc::new(Mutex::new(Daemon::new_for_test(log))),
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
    pub fn restore_db_peers(
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
        rq: BfdPeerConfig,
    ) -> Result<(), HttpError> {
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

        Ok(())
    }

    /// Remove a BFD peer from the persistent DB and the running daemon.
    /// The associated peer session will be stopped immediately.
    pub async fn remove_peer(
        &self,
        db: rdb::Db,
        peer: IpAddr,
    ) -> Result<(), HttpError> {
        let handle = {
            let mut daemon = lock!(self.daemon);
            db.remove_bfd_neighbor(peer).map_err(|e| {
                HttpError::for_internal_error(
                    InlineErrorChain::new(&e).to_string(),
                )
            })?;
            daemon.remove_peer(peer)
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

        Ok(())
    }

    pub fn session_counters(&self) -> Vec<(IpAddr, Arc<SessionCounters>)> {
        lock!(self.daemon)
            .sessions_iter()
            .map(|(ip, session)| (*ip, Arc::clone(session.counters())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::BfdContext;
    use mg_api_types::bfd::{BfdPeerConfig, SessionMode};
    use mg_common::lock;
    use slog::Logger;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU8;
    use tempfile::TempDir;

    fn setup() -> (BfdContext, rdb::Db, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let log = Logger::root(slog::Discard, slog::o!());
        let db = rdb::Db::new(temp_dir.path().to_str().unwrap(), log.clone())
            .unwrap();
        (BfdContext::new_for_test(log), db, temp_dir)
    }

    fn peer_config(host: u8, mode: SessionMode) -> BfdPeerConfig {
        BfdPeerConfig {
            peer: Ipv4Addr::new(127, 0, 1, host).into(),
            listen: Ipv4Addr::LOCALHOST.into(),
            required_rx: 100_000,
            detection_threshold: NonZeroU8::new(3).unwrap(),
            mode,
        }
    }

    fn start_runtime_peer(
        bfd: &BfdContext,
        db: rdb::Db,
        config: BfdPeerConfig,
    ) {
        lock!(bfd.daemon).add_peer(db, config.into()).unwrap();
    }

    fn persisted_and_running_configs(
        bfd: &BfdContext,
        db: &rdb::Db,
    ) -> (Vec<BfdPeerConfig>, Vec<BfdPeerConfig>) {
        let persisted = db.get_bfd_neighbors().unwrap();
        let running = bfd
            .get_peers()
            .unwrap()
            .into_iter()
            .map(|peer| peer.config)
            .collect();
        (persisted, running)
    }

    #[tokio::test]
    async fn add_peer_writes_db() {
        let (bfd, db, _temp_dir) = setup();
        let config = peer_config(1, SessionMode::SingleHop);

        bfd.add_new_peer(db.clone(), config).unwrap();

        assert_eq!(db.get_bfd_neighbors().unwrap(), vec![config]);
        bfd.remove_peer(db, config.peer).await.unwrap();
    }

    #[tokio::test]
    async fn remove_peer_deletes_db_entry() {
        let (bfd, db, _temp_dir) = setup();
        let config = peer_config(2, SessionMode::MultiHop);
        db.add_bfd_neighbor(config).unwrap();
        start_runtime_peer(&bfd, db.clone(), config);

        bfd.remove_peer(db.clone(), config.peer).await.unwrap();

        assert!(db.get_bfd_neighbors().unwrap().is_empty());
    }

    #[tokio::test]
    async fn add_peer_rolls_back_db_on_runtime_error() {
        let (bfd, db, _temp_dir) = setup();
        let config = peer_config(3, SessionMode::SingleHop);
        start_runtime_peer(&bfd, db.clone(), config);

        bfd.add_new_peer(db.clone(), config).unwrap_err();

        assert_eq!(
            persisted_and_running_configs(&bfd, &db),
            (vec![], vec![config]),
        );
        bfd.remove_peer(db, config.peer).await.unwrap();
    }

    #[tokio::test]
    async fn add_peer_skips_runtime_on_db_conflict() {
        let (bfd, db, _temp_dir) = setup();
        let config = peer_config(4, SessionMode::SingleHop);
        db.add_bfd_neighbor(config).unwrap();

        bfd.add_new_peer(db.clone(), config).unwrap_err();

        assert_eq!(
            persisted_and_running_configs(&bfd, &db),
            (vec![config], vec![]),
        );
        bfd.remove_peer(db, config.peer).await.unwrap();
    }

    #[tokio::test]
    async fn restore_peers_leaves_db_unchanged() {
        let (bfd, db, _temp_dir) = setup();
        let config = peer_config(5, SessionMode::SingleHop);
        db.add_bfd_neighbor(config).unwrap();

        bfd.restore_db_peers(db.clone()).unwrap();

        assert_eq!(db.get_bfd_neighbors().unwrap(), vec![config]);
        bfd.remove_peer(db, config.peer).await.unwrap();
    }

    #[tokio::test]
    async fn remove_peer_cleans_up_db_only_peer() {
        let (bfd, db, _temp_dir) = setup();
        let config = peer_config(6, SessionMode::SingleHop);
        db.add_bfd_neighbor(config).unwrap();

        bfd.remove_peer(db.clone(), config.peer).await.unwrap();

        assert_eq!(persisted_and_running_configs(&bfd, &db), (vec![], vec![]));
    }

    #[tokio::test]
    async fn remove_peer_cleans_up_runtime_only_peer() {
        let (bfd, db, _temp_dir) = setup();
        let config = peer_config(7, SessionMode::SingleHop);
        start_runtime_peer(&bfd, db.clone(), config);

        bfd.remove_peer(db.clone(), config.peer).await.unwrap();

        assert_eq!(persisted_and_running_configs(&bfd, &db), (vec![], vec![]));
    }
}
