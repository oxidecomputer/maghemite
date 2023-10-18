//! The routing database (rdb).
//!
//! This is the maghmite routing database. The routing database holds both
//! volatile and non-volatile information. Non-volatile information is stored
//! in a sled key-value store that is persisted to disk via flush operations.
//! Volatile information is stored in in-memory data structures such as hash
//! sets.
use crate::error::Error;
use crate::types::*;
use mg_common::{lock, read_lock, write_lock};
use slog::{error, Logger};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};

/// The handle used to open a persistent key-value tree for BGP origin
/// information.
const BGP_ORIGIN: &str = "bgp_origin";

/// The handle used to open a persistent key-value tree for BGP router
/// information.
const BGP_ROUTER: &str = "bgp_router";

/// The handle used to open a persistent key-value tree for BGP neighbor
/// information.
const BGP_NEIGHBOR: &str = "bgp_neighbor";

/// The central routing information base. Both persistent an volatile route
/// information is managed through this structure.
#[derive(Clone)]
pub struct Db {
    /// A sled database handle where persistent routing information is stored.
    persistent: sled::Db,

    /// Routes imported via dynamic routing protocols. These are volatile.
    imported: Arc<Mutex<HashSet<Route4ImportKey>>>,

    /// A generation number for the overall data store.
    generation: Arc<AtomicU64>,

    /// A set of watchers that are notified when changes to the data store occur.
    watchers: Arc<RwLock<Vec<Watcher>>>,

    log: Logger,
}
unsafe impl Sync for Db {}
unsafe impl Send for Db {}

#[derive(Clone)]
struct Watcher {
    tag: String,
    sender: Sender<ChangeSet>,
}

//TODO we need bulk operations with atomic semantics here.
impl Db {
    /// Create a new routing database that stores persistent data at `path`.
    pub fn new(path: &str, log: Logger) -> Result<Self, Error> {
        Ok(Self {
            persistent: sled::open(path)?,
            imported: Arc::new(Mutex::new(HashSet::new())),
            generation: Arc::new(AtomicU64::new(0)),
            watchers: Arc::new(RwLock::new(Vec::new())),
            log,
        })
    }

    /// Register a routing databse watcher.
    pub fn watch(&self, tag: String, sender: Sender<ChangeSet>) {
        write_lock!(self.watchers).push(Watcher { tag, sender });
    }

    fn notify(&self, c: ChangeSet) {
        for Watcher { tag, sender } in read_lock!(self.watchers).iter() {
            if let Err(e) = sender.send(c.clone()) {
                error!(
                    self.log,
                    "failed to send notification to watcher '{tag}': {e}"
                );
            }
        }
    }

    // TODO return previous value if this is an update.
    pub fn add_origin4(&self, r: Route4Key) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN)?;
        tree.insert(r.db_key(), "")?;
        tree.flush()?;
        let g = self.generation.fetch_add(1, Ordering::SeqCst);
        self.notify(ChangeSet::from_origin(OriginChangeSet::added([r]), g + 1));
        Ok(())
    }

    pub fn add_bgp_router(
        &self,
        asn: u32,
        info: BgpRouterInfo,
    ) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ROUTER)?;
        let key = asn.to_string();
        let value = serde_json::to_string(&info)?;
        tree.insert(key.as_str(), value.as_str())?;
        tree.flush()?;
        Ok(())
    }

    pub fn remove_bgp_router(&self, asn: u32) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ROUTER)?;
        let key = asn.to_string();
        tree.remove(key.as_str())?;
        tree.flush()?;
        Ok(())
    }

    pub fn get_bgp_routers(
        &self,
    ) -> Result<HashMap<u32, BgpRouterInfo>, Error> {
        let tree = self.persistent.open_tree(BGP_ROUTER)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, value) = match item {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error fetching bgp router entry: {e}"
                        );
                        return None;
                    }
                };
                let key = match String::from_utf8_lossy(&key).parse() {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error parsing bgp router entry key: {e}"
                        );
                        return None;
                    }
                };
                let value = String::from_utf8_lossy(&value);
                let value: BgpRouterInfo = match serde_json::from_str(&value) {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error parsing bgp router entry value: {e}"
                        );
                        return None;
                    }
                };
                Some((key, value))
            })
            .collect();
        Ok(result)
    }

    pub fn add_bgp_neighbor(&self, nbr: BgpNeighborInfo) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_NEIGHBOR)?;
        let key = nbr.host.ip().to_string();
        let value = serde_json::to_string(&nbr)?;
        tree.insert(key.as_str(), value.as_str())?;
        tree.flush()?;
        Ok(())
    }

    pub fn remove_bgp_neighbor(&self, addr: IpAddr) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_NEIGHBOR)?;
        let key = addr.to_string();
        tree.remove(key)?;
        tree.flush()?;
        Ok(())
    }

    pub fn get_bgp_neighbors(&self) -> Result<Vec<BgpNeighborInfo>, Error> {
        let tree = self.persistent.open_tree(BGP_NEIGHBOR)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (_key, value) = match item {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error fetching bgp neighbor entry: {e}"
                        );
                        return None;
                    }
                };
                let value = String::from_utf8_lossy(&value);
                let value: BgpNeighborInfo = match serde_json::from_str(&value)
                {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error parsing bgp neighbor entry value: {e}"
                        );
                        return None;
                    }
                };
                Some(value)
            })
            .collect();
        Ok(result)
    }

    pub fn remove_origin4(&self, r: Route4Key) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN)?;
        tree.remove(r.db_key())?;
        let g = self.generation.fetch_add(1, Ordering::SeqCst);
        self.notify(ChangeSet::from_origin(
            OriginChangeSet::removed([r]),
            g + 1,
        ));
        Ok(())
    }

    pub fn get_originated4(&self) -> Result<Vec<Route4Key>, Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, _value) = match item {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error fetching bgp origin entry: {e}"
                        );
                        return None;
                    }
                };
                let key = String::from_utf8_lossy(&key);
                Some(match key.parse() {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error parsing bgp origin entry value: {e}"
                        );
                        return None;
                    }
                })
            })
            .collect();
        Ok(result)
    }

    pub fn get_nexthop4(&self, prefix: &Prefix4) -> Vec<Route4ImportKey> {
        lock!(self.imported)
            .iter()
            .filter(|x| prefix == &x.prefix)
            .cloned()
            .collect()
    }

    pub fn get_imported4(&self) -> Vec<Route4ImportKey> {
        lock!(self.imported).clone().into_iter().collect()
    }

    pub fn set_nexthop4(&self, r: Route4ImportKey) {
        let before = self.effective_set_for_prefix4(r.prefix);
        lock!(self.imported).replace(r);
        let after = self.effective_set_for_prefix4(r.prefix);

        if let Some(change_set) = self.import_route_change_set(before, after) {
            self.notify(change_set);
        }
    }

    pub fn remove_nexthop4(&self, r: Route4ImportKey) {
        let before = self.effective_set_for_prefix4(r.prefix);
        lock!(self.imported).remove(&r);
        let after = self.effective_set_for_prefix4(r.prefix);

        if let Some(change_set) = self.import_route_change_set(before, after) {
            self.notify(change_set);
        }
    }

    pub fn remove_peer_nexthop4(&self, id: u32) -> Vec<Route4ImportKey> {
        let mut imported = lock!(self.imported);
        //TODO do in one pass instead of two
        let result = imported.iter().filter(|x| x.id == id).copied().collect();
        imported.retain(|x| x.id != id);
        result
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Given a target prefix, compute the effective route set for that prefix.
    /// This is needed to support graceful shutdown. Routes being shutdown are
    /// always a last resort - so there are three cases.
    ///
    ///   1. Only shutdown routes exist, in which case the effective set is all
    ///      the shutdown routes.
    ///   2. Only active routes (routes not being shut down) exist, in which
    ///      case the effective set is all the active routes.
    ///   3. A mixture of shutdown routes and active routes exist, in which
    ///      case the effective set is only the active routes.
    ///
    fn effective_set_for_prefix4(
        &self,
        prefix: Prefix4,
    ) -> HashSet<Route4ImportKey> {
        let imported = lock!(self.imported);
        let full: HashSet<Route4ImportKey> = imported
            .iter()
            .filter(|x| x.prefix == prefix)
            .copied()
            .collect();

        let shutdown: HashSet<Route4ImportKey> =
            full.iter().filter(|x| x.priority == 0).copied().collect();

        let active: HashSet<Route4ImportKey> =
            full.iter().filter(|x| x.priority > 0).copied().collect();

        match (active.len(), shutdown.len()) {
            (0, _) => shutdown,
            (_, 0) => active,
            _ => active,
        }
    }

    /// Compute a a change set for a before/after set of routes including
    /// bumping the RIB generation number if there are changes.
    fn import_route_change_set(
        &self,
        before: HashSet<Route4ImportKey>,
        after: HashSet<Route4ImportKey>,
    ) -> Option<ChangeSet> {
        let added: HashSet<Route4ImportKey> =
            after.difference(&before).copied().collect();

        let removed: HashSet<Route4ImportKey> =
            before.difference(&after).copied().collect();

        let gen = self.generation.fetch_add(1, Ordering::SeqCst);

        if added.is_empty() && removed.is_empty() {
            return None;
        }

        Some(ChangeSet::from_import(
            ImportChangeSet { added, removed },
            gen,
        ))
    }
}
