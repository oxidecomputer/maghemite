// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Persistent storage for the DDM RIB

use crate::rib::{Rib, RibEvent, RibOutput, Route};
use ddm_api_types::db::{RouterKind, TunnelRoute};
use ddm_api_types::net::TunnelOrigin;
use mg_common::lock;
use oxnet::Ipv6Net;
use slog::{Logger, error};
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};

/// The handle used to open a persistent key-value tree for originated
/// prefixes.
const ORIGINATE: &str = "originate";

/// The handle used to open a persistent key-value tree for originated
/// tunnel endpoints.
const TUNNEL_ORIGINATE: &str = "tunnel_originate";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("datastore error {0}")]
    DataStore(#[from] sled::Error),

    #[error("db key error {0}")]
    DbKey(String),

    #[error("db value error {0}")]
    DbValue(String),

    #[error("serialization error {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Sled-backed storage for originated prefixes, plus the in-memory imported
/// route table.
///
/// The route table itself is a pure [`Rib`]; this type only supplies the lock
/// that lets the state machine threads share it. Route decisions belong in
/// [`Rib::apply`], not here.
#[derive(Clone)]
pub struct Db {
    rib: Arc<Mutex<Rib>>,
    persistent_data: sled::Db,
    log: Logger,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Db>()
};

impl Db {
    pub fn new(
        db_path: &str,
        hostname: String,
        kind: RouterKind,
        log: Logger,
    ) -> Result<Self, sled::Error> {
        Ok(Self {
            rib: Arc::new(Mutex::new(Rib::new(hostname, kind))),
            persistent_data: sled::open(db_path)?,
            log,
        })
    }

    /// Apply an event to the route table and return the forwarding-platform
    /// deltas the caller must execute.
    pub fn apply(&self, event: RibEvent) -> RibOutput {
        lock!(self.rib).apply(event)
    }

    pub fn imported(&self) -> HashSet<Route> {
        lock!(self.rib).imported().clone()
    }

    pub fn imported_count(&self) -> usize {
        lock!(self.rib).imported().len()
    }

    pub fn imported_tunnel(&self) -> HashSet<TunnelRoute> {
        lock!(self.rib).imported_tunnel().clone()
    }

    pub fn imported_tunnel_count(&self) -> usize {
        lock!(self.rib).imported_tunnel().len()
    }

    pub fn originate(&self, prefixes: &HashSet<Ipv6Net>) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(ORIGINATE)?;
        for p in prefixes {
            tree.insert(p.db_key(), "")?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn originate_tunnel(
        &self,
        origins: &HashSet<TunnelOrigin>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(TUNNEL_ORIGINATE)?;
        for o in origins {
            let entry = serde_json::to_string(o)?;
            tree.insert(entry.as_str(), "")?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn originated(&self) -> Result<HashSet<Ipv6Net>, Error> {
        let tree = self.persistent_data.open_tree(ORIGINATE)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, _value) = match item {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error ddm originated prefix: {e}"
                        );
                        return None;
                    }
                };
                Some(match Ipv6Net::from_db_key(&key) {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error parsing ddm origin entry value: {e}"
                        );
                        return None;
                    }
                })
            })
            .collect();
        Ok(result)
    }

    pub fn originated_count(&self) -> Result<usize, Error> {
        Ok(self.originated()?.len())
    }

    pub fn originated_tunnel(&self) -> Result<HashSet<TunnelOrigin>, Error> {
        let tree = self.persistent_data.open_tree(TUNNEL_ORIGINATE)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, _value) = match item {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error fetching ddm tunnel origin entry: {e}"
                        );
                        return None;
                    }
                };
                let value = String::from_utf8_lossy(&key);
                let value: TunnelOrigin = match serde_json::from_str(&value) {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error parsing ddm tunnel origin: {e}"
                        );
                        return None;
                    }
                };
                Some(value)
            })
            .collect();
        Ok(result)
    }

    pub fn originated_tunnel_count(&self) -> Result<usize, Error> {
        Ok(self.originated_tunnel()?.len())
    }

    pub fn withdraw(&self, prefixes: &HashSet<Ipv6Net>) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(ORIGINATE)?;
        for p in prefixes {
            tree.remove(p.db_key())?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn withdraw_tunnel(
        &self,
        origins: &HashSet<TunnelOrigin>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(TUNNEL_ORIGINATE)?;
        for o in origins {
            let entry = serde_json::to_string(o)?;
            tree.remove(entry.as_str())?;
        }
        tree.flush()?;
        Ok(())
    }
}

trait DbKey: Sized {
    fn db_key(&self) -> Vec<u8>;
    fn from_db_key(v: &[u8]) -> Result<Self, Error>;
}

impl DbKey for Ipv6Net {
    fn db_key(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = self.addr().octets().into();
        buf.push(self.width());
        buf
    }

    fn from_db_key(v: &[u8]) -> Result<Self, Error> {
        if v.len() < 17 {
            Err(Error::DbKey(format!(
                "buffer too short for prefix 6 key {} < 17",
                v.len()
            )))
        } else {
            Self::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&v[..16]).unwrap()),
                v[16],
            )
            .map_err(|e| Error::DbKey(e.to_string()))
        }
    }
}
