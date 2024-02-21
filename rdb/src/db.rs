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
use crate::error::Error;
use crate::{types::*, DEFAULT_ROUTE_PRIORITY};
use mg_common::{lock, read_lock, write_lock};
use slog::{error, info, Logger};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

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

/// Describes a set of routes as either active or inactive.
#[derive(Debug, Clone)]
pub enum EffectiveRouteSet {
    /// The routes in the contained set are active with priority greater than
    /// zero.
    Active(HashSet<Route4ImportKey>),

    /// The routes in the contained set are inactive with a priority equal to
    /// zero.
    Inactive(HashSet<Route4ImportKey>),
}

impl EffectiveRouteSet {
    fn values(&self) -> &HashSet<Route4ImportKey> {
        match self {
            EffectiveRouteSet::Active(s) => s,
            EffectiveRouteSet::Inactive(s) => s,
        }
    }
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
    pub fn add_origin4(&self, p: Prefix4) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN)?;
        tree.insert(p.db_key(), "")?;
        tree.flush()?;
        let g = self.generation.fetch_add(1, Ordering::SeqCst);
        self.notify(ChangeSet::from_origin(OriginChangeSet::added([p]), g + 1));
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
        let g = self.generation.fetch_add(1, Ordering::SeqCst);
        self.notify(ChangeSet::from_origin(
            OriginChangeSet::removed([p]),
            g + 1,
        ));
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

    pub fn set_nexthop4(
        &self,
        r: Route4ImportKey,
        is_static: bool,
    ) -> Result<(), Error> {
        if is_static {
            let tree = self.persistent.open_tree(STATIC4_ROUTES)?;
            let key = serde_json::to_string(&r)?;
            tree.insert(key.as_str(), "")?;
            tree.flush()?;
        }

        let mut imported = lock!(self.imported);
        let before = Self::effective_set_for_prefix4(&imported, r.prefix);
        imported.replace(r);
        let after = Self::effective_set_for_prefix4(&imported, r.prefix);

        if let Some(change_set) = self.import_route_change_set(&before, &after)
        {
            info!(
                self.log,
                "sending notification for change set {:#?}", change_set,
            );
            self.notify(change_set);
        } else {
            info!(
                self.log,
                "no effective change for {:#?} -> {:#?}", before, after
            );
        }

        Ok(())
    }

    pub fn get_static4(&self) -> Result<Vec<Route4ImportKey>, Error> {
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
                let rkey: Route4ImportKey = match serde_json::from_str(&key) {
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

    pub fn disable_nexthop4(&self, addr: Ipv4Addr) {
        let mut imported = lock!(self.imported);
        let changed: Vec<Route4ImportKey> = imported
            .iter()
            .cloned()
            .filter(|x| x.nexthop == addr && x.priority != 0)
            .map(|x| x.with_priority(0))
            .collect();

        for x in changed {
            let before = Self::effective_set_for_prefix4(&imported, x.prefix);
            imported.replace(x);
            let after = Self::effective_set_for_prefix4(&imported, x.prefix);
            if let Some(change_set) =
                self.import_route_change_set(&before, &after)
            {
                self.notify(change_set);
            }
        }
    }

    pub fn enable_nexthop4(&self, addr: Ipv4Addr) {
        let mut imported = lock!(self.imported);
        let changed: Vec<Route4ImportKey> = imported
            .iter()
            .cloned()
            .filter(|x| {
                x.nexthop == addr && x.priority != DEFAULT_ROUTE_PRIORITY
            })
            .map(|x| x.with_priority(DEFAULT_ROUTE_PRIORITY))
            .collect();

        for x in changed {
            let before = Self::effective_set_for_prefix4(&imported, x.prefix);
            imported.replace(x);
            let after = Self::effective_set_for_prefix4(&imported, x.prefix);
            if let Some(change_set) =
                self.import_route_change_set(&before, &after)
            {
                self.notify(change_set);
            }
        }
    }

    pub fn remove_nexthop4(&self, r: Route4ImportKey) {
        let mut imported = lock!(self.imported);
        let before = Self::effective_set_for_prefix4(&imported, r.prefix);
        imported.remove(&r);
        let after = Self::effective_set_for_prefix4(&imported, r.prefix);

        if let Some(change_set) = self.import_route_change_set(&before, &after)
        {
            self.notify(change_set);
        }
    }

    pub fn remove_peer_prefix4(&self, id: u32, prefix: Prefix4) {
        let mut imported = lock!(self.imported);
        imported.retain(|x| !(x.id == id && x.prefix == prefix));
    }

    pub fn remove_peer_prefixes4(&self, id: u32) -> Vec<Route4ImportKey> {
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
        imported: &MutexGuard<HashSet<Route4ImportKey>>,
        prefix: Prefix4,
    ) -> EffectiveRouteSet {
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
            (0, _) => EffectiveRouteSet::Inactive(shutdown),
            (_, 0) => EffectiveRouteSet::Active(active),
            _ => EffectiveRouteSet::Active(active),
        }
    }

    pub fn effective_route_set(&self) -> Vec<Route4ImportKey> {
        let full = lock!(self.imported).clone();
        let mut sets = HashMap::<Prefix4, EffectiveRouteSet>::new();
        for x in full.iter() {
            match sets.get_mut(&x.prefix) {
                Some(set) => {
                    if x.priority > 0 {
                        match set {
                            EffectiveRouteSet::Active(s) => {
                                s.insert(*x);
                            }
                            EffectiveRouteSet::Inactive(_) => {
                                let mut value = HashSet::new();
                                value.insert(*x);
                                sets.insert(
                                    x.prefix,
                                    EffectiveRouteSet::Active(value),
                                );
                            }
                        }
                    } else {
                        match set {
                            EffectiveRouteSet::Active(_) => {
                                //Nothing to do here, the active set takes priority
                            }
                            EffectiveRouteSet::Inactive(s) => {
                                s.insert(*x);
                            }
                        }
                    }
                }
                None => {
                    let mut value = HashSet::new();
                    value.insert(*x);
                    if x.priority > 0 {
                        sets.insert(x.prefix, EffectiveRouteSet::Active(value));
                    } else {
                        sets.insert(
                            x.prefix,
                            EffectiveRouteSet::Inactive(value),
                        );
                    }
                }
            };
        }

        let mut result = Vec::new();
        for xs in sets.values() {
            for x in xs.values() {
                result.push(*x);
            }
        }
        result
    }

    /// Compute a a change set for a before/after set of routes including
    /// bumping the RIB generation number if there are changes.
    fn import_route_change_set(
        &self,
        before: &EffectiveRouteSet,
        after: &EffectiveRouteSet,
    ) -> Option<ChangeSet> {
        let gen = self.generation.fetch_add(1, Ordering::SeqCst);
        match (before, after) {
            (
                EffectiveRouteSet::Active(before),
                EffectiveRouteSet::Active(after),
            ) => {
                let added: HashSet<Route4ImportKey> =
                    after.difference(before).copied().collect();

                let removed: HashSet<Route4ImportKey> =
                    before.difference(after).copied().collect();

                if added.is_empty() && removed.is_empty() {
                    return None;
                }

                Some(ChangeSet::from_import(
                    ImportChangeSet { added, removed },
                    gen,
                ))
            }
            (
                EffectiveRouteSet::Active(before),
                EffectiveRouteSet::Inactive(_after),
            ) => Some(ChangeSet::from_import(
                ImportChangeSet {
                    removed: before.clone(),
                    ..Default::default()
                },
                gen,
            )),
            (
                EffectiveRouteSet::Inactive(_before),
                EffectiveRouteSet::Active(after),
            ) => Some(ChangeSet::from_import(
                ImportChangeSet {
                    added: after.clone(),
                    ..Default::default()
                },
                gen,
            )),

            (
                EffectiveRouteSet::Inactive(_before),
                EffectiveRouteSet::Inactive(_after),
            ) => None,
        }
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
