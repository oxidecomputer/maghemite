// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The routing database (rdb).
//!
//! This is the maghmite routing database. The routing database holds both
//! volatile and non-volatile information. Non-volatile information is stored
//! in a sled key-value store that is persisted to disk via flush operations.
//! Volatile information is stored in in-memory data structures such as hash
//! sets.
use crate::bestpath::bestpaths;
use crate::error::Error;
use crate::types::*;
use mg_common::{lock, read_lock, write_lock};
use slog::{error, Logger};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
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

/// The handle used to open a persistent key-value tree for settings
/// information.
const SETTINGS: &str = "settings";

/// The handle used to open a persistent key-value tree for static routes.
const STATIC4_ROUTES: &str = "static4_routes";

/// Key used in settings tree for tunnel endpoint setting
const TEP_KEY: &str = "tep";

/// The handle used to open a persistent key-value tree for BFD neighbor
/// information.
const BFD_NEIGHBOR: &str = "bfd_neighbor";

//TODO as parameter
const BESTPATH_FANOUT: usize = 4;

pub type Rib = HashMap<Prefix, HashSet<Path>>;

/// The central routing information base. Both persistent an volatile route
/// information is managed through this structure.
#[derive(Clone)]
pub struct Db {
    /// A sled database handle where persistent routing information is stored.
    persistent: sled::Db,

    /// Routes learned from BGP update messages or administratively added
    /// static routes. These are volatile.
    rib_in: Arc<Mutex<Rib>>,

    /// Routes selected from rib_in according to local policy and added to the
    /// lower half forwarding plane.
    rib_loc: Arc<Mutex<Rib>>,

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
    sender: Sender<PrefixChangeNotification>,
}

//TODO we need bulk operations with atomic semantics here.
impl Db {
    /// Create a new routing database that stores persistent data at `path`.
    pub fn new(path: &str, log: Logger) -> Result<Self, Error> {
        Ok(Self {
            persistent: sled::open(path)?,
            rib_in: Arc::new(Mutex::new(Rib::new())),
            rib_loc: Arc::new(Mutex::new(Rib::new())),
            generation: Arc::new(AtomicU64::new(0)),
            watchers: Arc::new(RwLock::new(Vec::new())),
            log,
        })
    }

    /// Register a routing databse watcher.
    pub fn watch(&self, tag: String, sender: Sender<PrefixChangeNotification>) {
        write_lock!(self.watchers).push(Watcher { tag, sender });
    }

    fn notify(&self, n: PrefixChangeNotification) {
        for Watcher { tag, sender } in read_lock!(self.watchers).iter() {
            if let Err(e) = sender.send(n.clone()) {
                error!(
                    self.log,
                    "failed to send notification to watcher '{tag}': {e}"
                );
            }
        }
    }

    pub fn loc_rib(&self) -> Arc<Mutex<Rib>> {
        self.rib_loc.clone()
    }

    pub fn full_rib(&self) -> Rib {
        lock!(self.rib_in).clone()
    }

    pub fn static_rib(&self) -> Rib {
        let mut rib = lock!(self.rib_in).clone();
        for (_prefix, paths) in rib.iter_mut() {
            paths.retain(|x| x.bgp_id == 0)
        }
        rib
    }

    pub fn bgp_rib(&self) -> Rib {
        let mut rib = lock!(self.rib_in).clone();
        for (_prefix, paths) in rib.iter_mut() {
            paths.retain(|x| x.bgp_id != 0)
        }
        rib
    }

    // TODO return previous value if this is an update.
    pub fn add_origin4(&self, p: Prefix4) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN)?;
        tree.insert(p.db_key(), "")?;
        tree.flush()?;
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

    pub fn add_bfd_neighbor(&self, cfg: BfdPeerConfig) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BFD_NEIGHBOR)?;
        let key = cfg.peer.to_string();
        let value = serde_json::to_string(&cfg)?;
        tree.insert(key.as_str(), value.as_str())?;
        tree.flush()?;
        Ok(())
    }

    pub fn remove_bfd_neighbor(&self, addr: IpAddr) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BFD_NEIGHBOR)?;
        let key = addr.to_string();
        tree.remove(key)?;
        tree.flush()?;
        Ok(())
    }

    pub fn get_bfd_neighbors(&self) -> Result<Vec<BfdPeerConfig>, Error> {
        let tree = self.persistent.open_tree(BFD_NEIGHBOR)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (_key, value) = match item {
                    Ok(item) => item,
                    Err(e) => {
                        error!(self.log, "db: error fetching bfd entry: {e}");
                        return None;
                    }
                };
                let value = String::from_utf8_lossy(&value);
                let value: BfdPeerConfig = match serde_json::from_str(&value) {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error parsing bfd neighbor entry value: {e}"
                        );
                        return None;
                    }
                };
                Some(value)
            })
            .collect();
        Ok(result)
    }

    pub fn remove_origin4(&self, p: Prefix4) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN)?;
        tree.remove(p.db_key())?;
        Ok(())
    }

    pub fn get_originated4(&self) -> Result<Vec<Prefix4>, Error> {
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
                Some(match Prefix4::from_db_key(&key) {
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

    pub fn get_prefix_paths(&self, prefix: &Prefix) -> Vec<Path> {
        let rib = lock!(self.rib_in);
        let paths = rib.get(prefix);
        match paths {
            None => Vec::new(),
            Some(p) => p.iter().cloned().collect(),
        }
    }

    pub fn get_imported(&self) -> Rib {
        lock!(self.rib_in).clone()
    }

    pub fn update_loc_rib(rib_in: &Rib, rib_loc: &mut Rib, prefix: Prefix) {
        let bp = bestpaths(prefix, rib_in, BESTPATH_FANOUT);
        rib_loc.insert(prefix, bp.clone());
    }

    pub fn add_prefix_path(
        &self,
        prefix: Prefix,
        path: Path,
        is_static: bool,
    ) -> Result<(), Error> {
        let mut rib = lock!(self.rib_in);
        match rib.get_mut(&prefix) {
            Some(paths) => {
                paths.insert(path.clone());
            }
            None => {
                rib.insert(prefix, HashSet::from([path.clone()]));
            }
        }
        Self::update_loc_rib(&rib, &mut lock!(self.rib_loc), prefix);

        if is_static {
            let tree = self.persistent.open_tree(STATIC4_ROUTES)?;
            let srk = StaticRouteKey {
                prefix,
                nexthop: path.nexthop,
            };
            let key = serde_json::to_string(&srk)?;
            tree.insert(key.as_str(), "")?;
            tree.flush()?;
        }

        self.notify(prefix.into());
        Ok(())
    }

    pub fn get_static4(&self) -> Result<Vec<StaticRouteKey>, Error> {
        let tree = self.persistent.open_tree(STATIC4_ROUTES)?;
        Ok(tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, _) = match item {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error fetching static route entry: {e}"
                        );
                        return None;
                    }
                };

                let key = String::from_utf8_lossy(&key);
                let rkey: StaticRouteKey = match serde_json::from_str(&key) {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error parsing static router entry: {e}"
                        );
                        return None;
                    }
                };
                Some(rkey)
            })
            .collect())
    }

    pub fn get_static4_count(&self) -> Result<usize, Error> {
        let tree = self.persistent.open_tree(STATIC4_ROUTES)?;
        Ok(tree.len())
    }

    pub fn get_static_nexthop4_count(&self) -> Result<usize, Error> {
        let entries = self.get_static4()?;
        let mut nexthops = HashSet::new();
        for e in entries {
            nexthops.insert(e.nexthop);
        }
        Ok(nexthops.len())
    }

    pub fn disable_nexthop(&self, nexthop: IpAddr) {
        let mut rib = lock!(self.rib_in);
        let mut pcn = PrefixChangeNotification::default();
        for (prefix, paths) in rib.iter_mut() {
            for p in paths.clone().into_iter() {
                if p.nexthop == nexthop && !p.shutdown {
                    let mut replacement = p.clone();
                    replacement.shutdown = true;
                    paths.insert(replacement);
                    pcn.changed.insert(*prefix);
                }
            }
        }

        for prefix in pcn.changed.iter() {
            Self::update_loc_rib(&rib, &mut lock!(self.rib_loc), *prefix);
        }

        self.notify(pcn);
    }

    pub fn enable_nexthop(&self, nexthop: IpAddr) {
        let mut rib = lock!(self.rib_in);
        let mut pcn = PrefixChangeNotification::default();
        for (prefix, paths) in rib.iter_mut() {
            for p in paths.clone().into_iter() {
                if p.nexthop == nexthop && p.shutdown {
                    let mut replacement = p.clone();
                    replacement.shutdown = false;
                    paths.insert(replacement);
                    pcn.changed.insert(*prefix);
                }
            }
        }

        //TODO loc_rib updater as a pcn listener?
        for prefix in pcn.changed.iter() {
            Self::update_loc_rib(&rib, &mut lock!(self.rib_loc), *prefix);
        }
        self.notify(pcn);
    }

    pub fn remove_prefix_path(
        &self,
        prefix: Prefix,
        path: Path,
        is_static: bool, //TODO
    ) -> Result<(), Error> {
        let mut rib = lock!(self.rib_in);
        if let Some(paths) = rib.get_mut(&prefix) {
            paths.retain(|x| x.nexthop != path.nexthop)
        }

        if is_static {
            let tree = self.persistent.open_tree(STATIC4_ROUTES)?;
            let srk = StaticRouteKey {
                prefix,
                nexthop: path.nexthop,
            };
            let key = serde_json::to_string(&srk)?;
            tree.remove(key.as_str())?;
            tree.flush()?;
        }

        Self::update_loc_rib(&rib, &mut lock!(self.rib_loc), prefix);
        self.notify(prefix.into());
        Ok(())
    }

    pub fn remove_peer_prefix(&self, id: u32, prefix: Prefix) {
        let mut rib = lock!(self.rib_in);
        let paths = match rib.get_mut(&prefix) {
            None => return,
            Some(ps) => ps,
        };
        paths.retain(|x| x.bgp_id != id);

        Self::update_loc_rib(&rib, &mut lock!(self.rib_loc), prefix);
        self.notify(prefix.into());
    }

    pub fn remove_peer_prefixes(
        &self,
        id: u32,
    ) -> HashMap<Prefix, HashSet<Path>> {
        let mut rib = lock!(self.rib_in);

        let mut pcn = PrefixChangeNotification::default();
        let mut result = HashMap::new();
        for (prefix, paths) in rib.iter_mut() {
            result.insert(
                *prefix,
                paths.iter().filter(|x| x.bgp_id == id).cloned().collect(),
            );
            paths.retain(|x| x.bgp_id != id);
            pcn.changed.insert(*prefix);
        }

        for prefix in pcn.changed.iter() {
            Self::update_loc_rib(&rib, &mut lock!(self.rib_loc), *prefix);
        }
        self.notify(pcn);
        result
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    pub fn get_tep_addr(&self) -> Result<Option<Ipv6Addr>, Error> {
        let tree = self.persistent.open_tree(SETTINGS)?;
        let result = tree.get(TEP_KEY)?;
        let value = match result {
            Some(value) => value,
            None => return Ok(None),
        };
        let octets: [u8; 16] = (*value).try_into().map_err(|_| {
            Error::DbValue(format!(
                "rdb: tep length error exepcted 16 bytes found {}",
                value.len(),
            ))
        })?;

        Ok(Some(Ipv6Addr::from(octets)))
    }

    pub fn set_tep_addr(&self, addr: Ipv6Addr) -> Result<(), Error> {
        let tree = self.persistent.open_tree(SETTINGS)?;
        let key = addr.octets();
        tree.insert(TEP_KEY, &key)?;
        tree.flush()?;
        Ok(())
    }
}
