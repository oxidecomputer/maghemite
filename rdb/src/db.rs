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
use crate::log::rdb_log;
use crate::types::*;
use chrono::Utc;
use mg_common::{lock, read_lock, write_lock};
use sled::Tree;
use slog::{Logger, error};
use std::cmp::Ordering as CmpOrdering;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU8;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{sleep, spawn};

const UNIT_PERSISTENT: &str = "persistent";
const UNIT_RIB: &str = "rib";

/// The handle used to open a persistent key-value tree for BGP IPv4 origin
/// information.
const BGP_ORIGIN4: &str = "bgp_origin";

/// The handle used to open a persistent key-value tree for BGP IPv6 origin
/// information.
const BGP_ORIGIN6: &str = "bgp_origin6";

/// The handle used to open a persistent key-value tree for BGP router
/// information.
const BGP_ROUTER: &str = "bgp_router";

/// The handle used to open a persistent key-value tree for BGP neighbor
/// information.
const BGP_NEIGHBOR: &str = "bgp_neighbor";

/// The handle used to open a persistent key-value tree for BGP neighbor
/// information.
const BGP_UNNUMBERED_NEIGHBOR: &str = "bgp_unnumbered_neighbor";

/// The handle used to open a persistent key-value tree for settings
/// information.
const SETTINGS: &str = "settings";

/// The handle used to open a persistent key-value tree for IPv4 static routes.
const STATIC4_ROUTES: &str = "static4_routes";

/// The handle used to open a persistent key-value tree for IPv6 static routes.
const STATIC6_ROUTES: &str = "static6_routes";

/// Key used in settings tree for tunnel endpoint setting
const TEP_KEY: &str = "tep";

/// The handle used to open a persistent key-value tree for BFD neighbor
/// information.
const BFD_NEIGHBOR: &str = "bfd_neighbor";

/// Key used in settings tree for bestpath fanout setting
const BESTPATH_FANOUT: &str = "bestpath_fanout";

/// Default bestpath fanout value. Maximum number of ECMP paths in RIB.
const DEFAULT_BESTPATH_FANOUT: u8 = 1;

pub type Rib = BTreeMap<Prefix, BTreeSet<Path>>;
pub type Rib4 = BTreeMap<Prefix4, BTreeSet<Path>>;
pub type Rib6 = BTreeMap<Prefix6, BTreeSet<Path>>;

/// The central routing information base. Both persistent an volatile route
/// information is managed through this structure.
#[derive(Clone)]
pub struct Db {
    /// A sled database handle where persistent routing information is stored.
    persistent: sled::Db,

    /// IPv4 Unicast routes learned from BGP update messages or administratively
    /// added static routes. These are volatile.
    rib4_in: Arc<Mutex<Rib4>>,

    /// IPv4 Unicast routes selected from rib_in according to local policy and
    /// added to the lower half forwarding plane.
    rib4_loc: Arc<Mutex<Rib4>>,

    /// IPv6 Unicast routes learned from BGP update messages or administratively
    /// added static routes. These are volatile.
    rib6_in: Arc<Mutex<Rib6>>,

    /// IPv6 Unicast routes selected from rib_in according to local policy and
    /// added to the lower half forwarding plane.
    rib6_loc: Arc<Mutex<Rib6>>,

    /// A generation number for the overall data store.
    generation: Arc<AtomicU64>,

    /// A set of watchers that are notified when changes to the data store occur.
    watchers: Arc<RwLock<Vec<Watcher>>>,

    /// Reaps expired routes from the local RIB.
    reaper: Arc<Reaper>,

    /// Switch slot reported from MGS.
    /// Information is not available until first successful communication with MGS.
    slot: Arc<RwLock<Option<u16>>>,

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
        let rib_loc = Arc::new(Mutex::new(Rib::new()));
        Ok(Self {
            persistent: sled::open(path)?,
            rib4_in: Arc::new(Mutex::new(BTreeMap::new())),
            rib4_loc: Arc::new(Mutex::new(BTreeMap::new())),
            rib6_in: Arc::new(Mutex::new(BTreeMap::new())),
            rib6_loc: Arc::new(Mutex::new(BTreeMap::new())),
            generation: Arc::new(AtomicU64::new(0)),
            watchers: Arc::new(RwLock::new(Vec::new())),
            reaper: Reaper::new(rib_loc),
            slot: Arc::new(RwLock::new(None)),
            log,
        })
    }

    pub fn set_reaper_interval(&self, interval: std::time::Duration) {
        *lock!(self.reaper.interval) = interval;
    }

    pub fn set_reaper_stale_max(&self, stale_max: chrono::Duration) {
        *lock!(self.reaper.stale_max) = stale_max;
    }

    /// Register a routing databse watcher.
    pub fn watch(&self, tag: String, sender: Sender<PrefixChangeNotification>) {
        write_lock!(self.watchers).push(Watcher { tag, sender });
    }

    fn notify(&self, n: PrefixChangeNotification) {
        for Watcher { tag, sender } in read_lock!(self.watchers).iter() {
            if let Err(e) = sender.send(n.clone()) {
                rdb_log!(
                    self,
                    error,
                    "failed to send prefix change notification to watcher {tag}: {e}";
                    "unit" => UNIT_RIB,
                    "message" => "prefix_change_notification",
                    "message_contents" => format!("{n}"),
                    "error" => format!("{e}")
                );
            }
        }
    }

    fn loc_rib4(&self) -> Rib4 {
        lock!(self.rib4_loc).clone()
    }

    fn loc_rib6(&self) -> Rib6 {
        lock!(self.rib6_loc).clone()
    }

    pub fn loc_rib(&self, af: Option<AddressFamily>) -> Rib {
        match af {
            Some(AddressFamily::Ipv4) => self
                .loc_rib4()
                .into_iter()
                .map(|(p4, paths)| (Prefix::from(p4), paths))
                .collect(),

            Some(AddressFamily::Ipv6) => self
                .loc_rib6()
                .into_iter()
                .map(|(p6, paths)| (Prefix::from(p6), paths))
                .collect(),

            None => {
                let mut rib: Rib = self
                    .loc_rib4()
                    .into_iter()
                    .map(|(p4, paths)| (Prefix::from(p4), paths))
                    .collect();
                rib.extend(
                    self.loc_rib6()
                        .into_iter()
                        .map(|(p6, paths)| (Prefix::from(p6), paths)),
                );
                rib
            }
        }
    }

    fn full_rib4(&self) -> Rib4 {
        lock!(self.rib4_in).clone()
    }

    fn full_rib6(&self) -> Rib6 {
        lock!(self.rib6_in).clone()
    }

    pub fn full_rib(&self, af: Option<AddressFamily>) -> Rib {
        match af {
            Some(AddressFamily::Ipv4) => self
                .full_rib4()
                .into_iter()
                .map(|(p4, paths)| (Prefix::from(p4), paths))
                .collect(),
            Some(AddressFamily::Ipv6) => self
                .full_rib6()
                .into_iter()
                .map(|(p6, paths)| (Prefix::from(p6), paths))
                .collect(),
            None => {
                let mut rib: Rib = self
                    .full_rib4()
                    .into_iter()
                    .map(|(p4, paths)| (Prefix::from(p4), paths))
                    .collect();
                rib.extend(
                    self.full_rib6()
                        .into_iter()
                        .map(|(p6, paths)| (Prefix::from(p6), paths)),
                );
                rib
            }
        }
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
    ) -> Result<BTreeMap<u32, BgpRouterInfo>, Error> {
        let tree = self.persistent.open_tree(BGP_ROUTER)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, value) = match item {
                    Ok(item) => item,
                    Err(ref e) => {
                        rdb_log!(self,
                            error,
                            "error fetching bgp router entry {item:?}: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                        return None;
                    }
                };
                let key = match String::from_utf8_lossy(&key).parse() {
                    Ok(item) => item,
                    Err(e) => {
                        rdb_log!(self,
                            error,
                            "error parsing bgp router entry key {key:?}: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                        return None;
                    }
                };
                let value = String::from_utf8_lossy(&value);
                let value: BgpRouterInfo = match serde_json::from_str(&value) {
                    Ok(item) => item,
                    Err(e) => {
                        rdb_log!(self,
                            error,
                            "error parsing bgp router entry value {value:?}: {e}";
                            "unit" => UNIT_PERSISTENT
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

    pub fn add_unnumbered_bgp_neighbor(
        &self,
        nbr: BgpUnnumberedNeighborInfo,
    ) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_UNNUMBERED_NEIGHBOR)?;
        let key = nbr.interface.clone();
        let value = serde_json::to_string(&nbr)?;
        tree.insert(key.as_str(), value.as_str())?;
        tree.flush()?;
        Ok(())
    }

    pub fn remove_unnumbered_bgp_neighbor(
        &self,
        interface: &str,
    ) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_UNNUMBERED_NEIGHBOR)?;
        tree.remove(interface)?;
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
                    Err(ref e) => {
                        rdb_log!(
                            self,
                            error,
                            "error fetching bgp neighbor entry {item:?}: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                        return None;
                    }
                };
                let value = String::from_utf8_lossy(&value);
                let value: BgpNeighborInfo = match serde_json::from_str(&value)
                {
                    Ok(item) => item,
                    Err(ref e) => {
                        rdb_log!(
                            self,
                            error,
                            "error parsing bgp neighbor entry value {value:?}: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                        return None;
                    }
                };
                Some(value)
            })
            .collect();
        Ok(result)
    }

    pub fn get_unnumbered_bgp_neighbors(
        &self,
    ) -> Result<Vec<BgpUnnumberedNeighborInfo>, Error> {
        let tree = self.persistent.open_tree(BGP_UNNUMBERED_NEIGHBOR)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (_key, value) = match item {
                    Ok(item) => item,
                    Err(ref e) => {
                        rdb_log!(
                            self,
                            error,
                            "error fetching unnumbered bgp neighbor entry {item:?}: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                        return None;
                    }
                };
                let value = String::from_utf8_lossy(&value);
                let value: BgpUnnumberedNeighborInfo = match serde_json::from_str(&value)
                {
                    Ok(item) => item,
                    Err(ref e) => {
                        rdb_log!(
                            self,
                            error,
                            "error parsing unnumbered bgp neighbor entry value {value:?}: {e}";
                            "unit" => UNIT_PERSISTENT
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
                    Err(ref e) => {
                        rdb_log!(
                            self,
                            error,
                            "error parsing bfd entry {item:?}: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                        return None;
                    }
                };
                let value = String::from_utf8_lossy(&value);
                let value: BfdPeerConfig = match serde_json::from_str(&value) {
                    Ok(item) => item,
                    Err(ref e) => {
                        rdb_log!(
                            self,
                            error,
                            "error parsing bfd entry value {value:?}: {e}";
                            "unit" => UNIT_PERSISTENT,
                            "error" => format!("{e}")
                        );
                        return None;
                    }
                };
                Some(value)
            })
            .collect();
        Ok(result)
    }

    pub fn create_origin4(&self, ps: &[Prefix4]) -> Result<(), Error> {
        rdb_log!(self, info,
            "create origin4: {ps:?}";
            "unit" => UNIT_PERSISTENT
        );

        let current = self.get_origin4()?;
        if !current.is_empty() {
            return Err(Error::Conflict("origin already exists".to_string()));
        }

        self.set_origin4(ps)
    }

    pub fn set_origin4(&self, ps: &[Prefix4]) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN4)?;
        tree.clear()?;
        for p in ps.iter() {
            tree.insert(p.db_key(), "")?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn clear_origin4(&self) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN4)?;
        tree.clear()?;
        tree.flush()?;
        Ok(())
    }

    pub fn get_origin4(&self) -> Result<Vec<Prefix4>, Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN4)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, _value) = match item {
                    Ok(item) => item,
                    Err(ref e) => {
                        rdb_log!(
                            self,
                            error,
                            "error fetching bgp origin entry {item:?}: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                        return None;
                    }
                };
                Some(match Prefix4::from_db_key(&key) {
                    Ok(item) => item,
                    Err(ref e) => {
                        rdb_log!(
                            self,
                            error,
                            "error parsing bgp origin entry value {key:?}: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                        return None;
                    }
                })
            })
            .collect();
        Ok(result)
    }

    pub fn create_origin6(&self, ps: &[Prefix6]) -> Result<(), Error> {
        let current = self.get_origin6()?;
        if !current.is_empty() {
            return Err(Error::Conflict("origin already exists".to_string()));
        }

        self.set_origin6(ps)
    }

    pub fn set_origin6(&self, ps: &[Prefix6]) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN6)?;
        tree.clear()?;
        for p in ps.iter() {
            tree.insert(p.db_key(), "")?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn clear_origin6(&self) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN6)?;
        tree.clear()?;
        tree.flush()?;
        Ok(())
    }

    pub fn get_origin6(&self) -> Result<Vec<Prefix6>, Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN6)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, _value) = match item {
                    Ok(item) => item,
                    Err(ref e) => {
                        rdb_log!(
                            self,
                            error,
                            "error fetching bgp origin entry {item:?}: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                        return None;
                    }
                };
                Some(match Prefix6::from_db_key(&key) {
                    Ok(item) => item,
                    Err(e) => {
                        rdb_log!(
                            self,
                            error,
                            "error parsing bgp origin entry value {key:?}: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                        return None;
                    }
                })
            })
            .collect();
        Ok(result)
    }

    pub fn get_prefix_paths(&self, prefix: &Prefix) -> Vec<Path> {
        match prefix {
            Prefix::V4(p4) => {
                let rib = lock!(self.rib4_in);
                match rib.get(p4) {
                    None => Vec::new(),
                    Some(p) => p.iter().cloned().collect(),
                }
            }
            Prefix::V6(p6) => {
                let rib = lock!(self.rib6_in);
                match rib.get(p6) {
                    None => Vec::new(),
                    Some(p) => p.iter().cloned().collect(),
                }
            }
        }
    }

    pub fn get_selected_prefix_paths(&self, prefix: &Prefix) -> Vec<Path> {
        match prefix {
            Prefix::V4(p4) => {
                let rib = lock!(self.rib4_loc);
                match rib.get(p4) {
                    None => Vec::new(),
                    Some(p) => p.iter().cloned().collect(),
                }
            }
            Prefix::V6(p6) => {
                let rib = lock!(self.rib6_loc);
                match rib.get(p6) {
                    None => Vec::new(),
                    Some(p) => p.iter().cloned().collect(),
                }
            }
        }
    }

    pub fn update_rib4_loc(
        &self,
        rib_in: &Rib4,
        rib_loc: &mut Rib4,
        prefix: &Prefix4,
    ) {
        let fanout = self.get_bestpath_fanout().unwrap_or_else(|e| {
            rdb_log!(
                self,
                error,
                "failed to get bestpath fanout: {e}";
                "unit" => UNIT_PERSISTENT
            );
            NonZeroU8::new(DEFAULT_BESTPATH_FANOUT).unwrap()
        });

        match rib_in.get(prefix) {
            // rib-in has paths worth evaluating for loc-rib
            Some(paths) => {
                match bestpaths(paths, fanout.get() as usize) {
                    // bestpath found at least 1 path for loc-rib
                    Some(bp) => {
                        rib_loc.insert(*prefix, bp.clone());
                    }
                    // bestpath found no suitable paths
                    None => {
                        rib_loc.remove(prefix);
                    }
                }
            }
            // rib-in has no worthy paths
            None => {
                rib_loc.remove(prefix);
            }
        }
    }

    pub fn update_rib6_loc(
        &self,
        rib_in: &Rib6,
        rib_loc: &mut Rib6,
        prefix: &Prefix6,
    ) {
        let fanout = self.get_bestpath_fanout().unwrap_or_else(|e| {
            rdb_log!(
                self,
                error,
                "failed to get bestpath fanout: {e}";
                "unit" => UNIT_PERSISTENT
            );
            NonZeroU8::new(DEFAULT_BESTPATH_FANOUT).unwrap()
        });

        match rib_in.get(prefix) {
            // rib-in has paths worth evaluating for loc-rib
            Some(paths) => {
                match bestpaths(paths, fanout.get() as usize) {
                    // bestpath found at least 1 path for loc-rib
                    Some(bp) => {
                        rib_loc.insert(*prefix, bp.clone());
                    }
                    // bestpath found no suitable paths
                    None => {
                        rib_loc.remove(prefix);
                    }
                }
            }
            // rib-in has no worthy paths
            None => {
                rib_loc.remove(prefix);
            }
        }
    }

    // generic helper function to kick off a bestpath run for some
    // subset of prefixes in rib_in. the caller chooses which prefixes
    // bestpath is run against via the bestpath_needed closure
    pub fn trigger_bestpath_when<F>(&self, bestpath_needed: F)
    where
        F: Fn(&Prefix, &BTreeSet<Path>) -> bool,
    {
        {
            // only grab the lock once, release it once the loop ends
            let rib4_in = lock!(self.rib4_in);
            let mut rib4_loc = lock!(self.rib4_loc);
            for (prefix, paths) in self.full_rib4().iter() {
                if bestpath_needed(&Prefix::from(*prefix), paths) {
                    self.update_rib4_loc(&rib4_in, &mut rib4_loc, prefix);
                }
            }
        }

        {
            // only grab the lock once, release it once the loop ends
            let rib6_in = lock!(self.rib6_in);
            let mut rib6_loc = lock!(self.rib6_loc);
            for (prefix, paths) in self.full_rib6().iter() {
                if bestpath_needed(&Prefix::from(*prefix), paths) {
                    self.update_rib6_loc(&rib6_in, &mut rib6_loc, prefix);
                }
            }
        }
    }

    fn add_prefix4_path(
        &self,
        p4: &Prefix4,
        path: &Path,
        rib_in: &mut Rib4,
        rib_loc: &mut Rib4,
    ) {
        match rib_in.get_mut(p4) {
            Some(paths) => {
                paths.replace(path.clone());
            }
            None => {
                rib_in.insert(*p4, BTreeSet::from([path.clone()]));
            }
        }
        self.update_rib4_loc(rib_in, rib_loc, p4);
    }

    fn add_prefix6_path(
        &self,
        p6: &Prefix6,
        path: &Path,
        rib_in: &mut Rib6,
        rib_loc: &mut Rib6,
    ) {
        match rib_in.get_mut(p6) {
            Some(paths) => {
                paths.replace(path.clone());
            }
            None => {
                rib_in.insert(*p6, BTreeSet::from([path.clone()]));
            }
        }
        self.update_rib6_loc(rib_in, rib_loc, p6);
    }

    pub fn add_prefix_path(&self, prefix: &Prefix, path: &Path) {
        match prefix {
            Prefix::V4(p4) => {
                let mut rib_in = lock!(self.rib4_in);
                let mut rib_loc = lock!(self.rib4_loc);
                self.add_prefix4_path(p4, path, &mut rib_in, &mut rib_loc);
            }
            Prefix::V6(p6) => {
                let mut rib_in = lock!(self.rib6_in);
                let mut rib_loc = lock!(self.rib6_loc);
                self.add_prefix6_path(p6, path, &mut rib_in, &mut rib_loc);
            }
        };
    }

    fn add_static_routes_to_tree(
        &self,
        tree: Tree,
        routes: &[StaticRouteKey],
        pcn: &mut PrefixChangeNotification,
    ) -> Result<(), Error> {
        let mut route_keys = Vec::new();

        for route in routes {
            let key = serde_json::to_string(&route)?;
            route_keys.push(key);
        }

        tree.transaction(|tx_db| {
            for key in &route_keys {
                tx_db.insert(key.as_str(), "")?;
            }
            Ok(())
        })?;
        tree.flush()?;

        for route in routes {
            self.add_prefix_path(&route.prefix, &Path::from(*route));
            pcn.changed.insert(route.prefix);
        }

        Ok(())
    }

    pub fn add_static_routes(
        &self,
        routes: &[StaticRouteKey],
    ) -> Result<(), Error> {
        let mut pcn = PrefixChangeNotification::default();
        let (routes4, routes6) = routes.iter().cloned().fold(
            (Vec::new(), Vec::new()),
            |(mut v4, mut v6), srk| {
                match srk.prefix {
                    Prefix::V4(_) => v4.push(srk),
                    Prefix::V6(_) => v6.push(srk),
                }
                (v4, v6)
            },
        );

        {
            let tree = self.persistent.open_tree(STATIC4_ROUTES)?;
            self.add_static_routes_to_tree(tree, &routes4, &mut pcn)?;
        }

        {
            let tree = self.persistent.open_tree(STATIC6_ROUTES)?;
            self.add_static_routes_to_tree(tree, &routes6, &mut pcn)?;
        }

        self.notify(pcn);
        Ok(())
    }

    pub fn add_bgp_prefixes(&self, prefixes: &[Prefix], path: Path) {
        let mut pcn = PrefixChangeNotification::default();
        for prefix in prefixes {
            self.add_prefix_path(prefix, &path);
            pcn.changed.insert(*prefix);
        }
        self.notify(pcn);
    }

    fn get_static_from_tree(
        &self,
        tree: Tree,
    ) -> Result<Vec<StaticRouteKey>, Error> {
        Ok(tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, _) = match item {
                    Ok(item) => item,
                    Err(ref e) => {
                        rdb_log!(
                            self,
                            error,
                            "error fetching static route entry {item:?}: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                        return None;
                    }
                };

                let key = String::from_utf8_lossy(&key);
                // XXX: figure out how to handle removal of old static routes
                //      where the host bits aren't zeroed out
                let rkey: StaticRouteKey = match serde_json::from_str(&key) {
                    Ok(item) => item,
                    Err(e) => {
                        rdb_log!(
                            self,
                            error,
                            "error parsing static route entry {key:?}: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                        return None;
                    }
                };
                Some(rkey)
            })
            .collect())
    }

    pub fn get_static(
        &self,
        af: Option<AddressFamily>,
    ) -> Result<Vec<StaticRouteKey>, Error> {
        match af {
            Some(AddressFamily::Ipv4) => {
                let tree = self.persistent.open_tree(STATIC4_ROUTES)?;
                self.get_static_from_tree(tree)
            }
            Some(AddressFamily::Ipv6) => {
                let tree = self.persistent.open_tree(STATIC6_ROUTES)?;
                self.get_static_from_tree(tree)
            }
            None => {
                let tree = self.persistent.open_tree(STATIC4_ROUTES)?;
                let mut routes = self.get_static_from_tree(tree)?;
                let tree = self.persistent.open_tree(STATIC6_ROUTES)?;
                routes.extend(self.get_static_from_tree(tree)?);
                Ok(routes)
            }
        }
    }

    pub fn get_static4_count(&self) -> Result<usize, Error> {
        let tree = self.persistent.open_tree(STATIC4_ROUTES)?;
        Ok(tree.len())
    }

    pub fn get_static_nexthop4_count(&self) -> Result<usize, Error> {
        let entries = self.get_static(Some(AddressFamily::Ipv4))?;
        let mut nexthops = BTreeSet::new();
        for e in entries {
            nexthops.insert(e.nexthop);
        }
        Ok(nexthops.len())
    }

    pub fn get_static6_count(&self) -> Result<usize, Error> {
        let tree = self.persistent.open_tree(STATIC6_ROUTES)?;
        Ok(tree.len())
    }

    pub fn get_static_nexthop6_count(&self) -> Result<usize, Error> {
        let entries = self.get_static(Some(AddressFamily::Ipv6))?;
        let mut nexthops = BTreeSet::new();
        for e in entries {
            nexthops.insert(e.nexthop);
        }
        Ok(nexthops.len())
    }

    pub fn set_nexthop_shutdown(&self, nexthop: IpAddr, shutdown: bool) {
        let mut pcn = PrefixChangeNotification::default();
        let mut pcn6 = PrefixChangeNotification::default();
        {
            let mut rib4_in = lock!(self.rib4_in);
            let mut rib4_loc = lock!(self.rib4_loc);
            for (prefix, paths) in rib4_in.iter_mut() {
                for p in paths.clone().into_iter() {
                    if p.nexthop == nexthop && p.shutdown != shutdown {
                        let mut replacement = p.clone();
                        replacement.shutdown = shutdown;
                        paths.insert(replacement);
                        pcn.changed.insert(Prefix::from(*prefix));
                    }
                }
            }
            for prefix in pcn.changed.iter() {
                if let Prefix::V4(p4) = prefix {
                    self.update_rib4_loc(&rib4_in, &mut rib4_loc, p4);
                }
            }
        }

        {
            let mut rib6_in = lock!(self.rib6_in);
            let mut rib6_loc = lock!(self.rib6_loc);
            for (prefix, paths) in rib6_in.iter_mut() {
                for p in paths.clone().into_iter() {
                    if p.nexthop == nexthop && p.shutdown != shutdown {
                        let mut replacement = p.clone();
                        replacement.shutdown = shutdown;
                        paths.insert(replacement);
                        pcn6.changed.insert(Prefix::from(*prefix));
                    }
                }
            }
            for prefix in pcn6.changed.iter() {
                if let Prefix::V6(p6) = prefix {
                    self.update_rib6_loc(&rib6_in, &mut rib6_loc, p6);
                }
            }
        }

        pcn.changed.extend(pcn6.changed);
        self.notify(pcn);
    }

    fn remove_prefix4_path<F>(
        &self,
        prefix: &Prefix4,
        prefix_cmp: F,
        rib_in: &mut Rib4,
        rib_loc: &mut Rib4,
    ) where
        F: Fn(&Path) -> bool,
    {
        if let Some(paths) = rib_in.get_mut(prefix) {
            paths.retain(|p| !prefix_cmp(p));
            if paths.is_empty() {
                rib_in.remove(prefix);
            }
        }

        self.update_rib4_loc(rib_in, rib_loc, prefix);
    }

    fn remove_prefix6_path<F>(
        &self,
        prefix: &Prefix6,
        prefix_cmp: F,
        rib_in: &mut Rib6,
        rib_loc: &mut Rib6,
    ) where
        F: Fn(&Path) -> bool,
    {
        if let Some(paths) = rib_in.get_mut(prefix) {
            paths.retain(|p| !prefix_cmp(p));
            if paths.is_empty() {
                rib_in.remove(prefix);
            }
        }

        self.update_rib6_loc(rib_in, rib_loc, prefix);
    }

    fn remove_prefix_path<F>(&self, prefix: &Prefix, prefix_cmp: F)
    where
        F: Fn(&Path) -> bool,
    {
        match prefix {
            Prefix::V4(p4) => {
                let mut rib_in = lock!(self.rib4_in);
                let mut rib_loc = lock!(self.rib4_loc);
                self.remove_prefix4_path(
                    p4,
                    prefix_cmp,
                    &mut rib_in,
                    &mut rib_loc,
                );
            }
            Prefix::V6(p6) => {
                let mut rib_in = lock!(self.rib6_in);
                let mut rib_loc = lock!(self.rib6_loc);
                self.remove_prefix6_path(
                    p6,
                    prefix_cmp,
                    &mut rib_in,
                    &mut rib_loc,
                );
            }
        }
    }

    fn remove_path_for_prefixes4<F>(
        &self,
        prefixes: &[Prefix4],
        prefix_cmp: F,
        rib_in: &mut Rib4,
        rib_loc: &mut Rib4,
    ) where
        F: Fn(&Path) -> bool,
    {
        for prefix in prefixes.iter() {
            self.remove_prefix4_path(prefix, &prefix_cmp, rib_in, rib_loc);
        }
    }

    fn remove_path_for_prefixes6<F>(
        &self,
        prefixes: &[Prefix6],
        prefix_cmp: F,
        rib_in: &mut Rib6,
        rib_loc: &mut Rib6,
    ) where
        F: Fn(&Path) -> bool,
    {
        for prefix in prefixes.iter() {
            self.remove_prefix6_path(prefix, &prefix_cmp, rib_in, rib_loc);
        }
    }

    pub fn remove_path_for_prefixes<F>(
        &self,
        prefixes: &[Prefix],
        prefix_cmp: F,
    ) where
        F: Fn(&Path) -> bool,
    {
        // split prefixes into v4 and v6 groups. this allows us to lock the v4
        // and v6 RIBs independently, preventing operations for one protocol
        // from inhibiting the other.
        let (prefixes4, prefixes6) = prefixes.iter().cloned().fold(
            (Vec::new(), Vec::new()),
            |(mut v4, mut v6), prefix| {
                match prefix {
                    Prefix::V4(p4) => v4.push(p4),
                    Prefix::V6(p6) => v6.push(p6),
                }
                (v4, v6)
            },
        );

        {
            let mut rib_in = lock!(self.rib4_in);
            let mut rib_loc = lock!(self.rib4_loc);
            self.remove_path_for_prefixes4(
                &prefixes4,
                &prefix_cmp,
                &mut rib_in,
                &mut rib_loc,
            );
        }

        {
            let mut rib_in = lock!(self.rib6_in);
            let mut rib_loc = lock!(self.rib6_loc);
            self.remove_path_for_prefixes6(
                &prefixes6,
                &prefix_cmp,
                &mut rib_in,
                &mut rib_loc,
            );
        }
    }

    fn remove_static_routes_from_tree(
        &self,
        tree: Tree,
        routes: &[StaticRouteKey],
    ) -> Result<(), Error> {
        let mut pcn = PrefixChangeNotification::default();

        let mut route_keys = Vec::new();
        for route in routes {
            let key = serde_json::to_string(route)?;
            route_keys.push(key);
            pcn.changed.insert(route.prefix);
        }

        tree.transaction(|tx_db| {
            for key in &route_keys {
                tx_db.remove(key.as_str())?;
            }
            Ok(())
        })?;
        tree.flush()?;

        for route in routes {
            self.remove_prefix_path(&route.prefix, |rib_path: &Path| {
                rib_path.cmp(&Path::from(*route)) == CmpOrdering::Equal
            });
        }

        self.notify(pcn);
        Ok(())
    }

    pub fn remove_static_routes(
        &self,
        routes: &[StaticRouteKey],
    ) -> Result<(), Error> {
        let (routes4, routes6) = routes.iter().fold(
            (Vec::new(), Vec::new()),
            |(mut r4, mut r6), srk| {
                match srk.prefix {
                    Prefix::V4(_) => r4.push(*srk),
                    Prefix::V6(_) => r6.push(*srk),
                }
                (r4, r6)
            },
        );

        {
            let tree = self.persistent.open_tree(STATIC4_ROUTES)?;
            self.remove_static_routes_from_tree(tree, &routes4)?;
        }
        {
            let tree = self.persistent.open_tree(STATIC6_ROUTES)?;
            self.remove_static_routes_from_tree(tree, &routes6)?;
        }

        Ok(())
    }

    // for each route in @prefixes, remove all bgp paths learned from @peer
    pub fn remove_bgp_prefixes(&self, prefixes: &[Prefix], peer: &PeerId) {
        let mut pcn = PrefixChangeNotification::default();
        self.remove_path_for_prefixes(
            prefixes,
            |rib_path: &Path| match rib_path.bgp {
                Some(ref bgp) => bgp.peer == *peer,
                None => false,
            },
        );
        pcn.changed.extend(prefixes);
        self.notify(pcn);
    }

    // wrapper for remove_bgp_prefixes to handle the "all routes" corner case.
    // e.g. when peer is deleted or exits Established state
    pub fn remove_bgp_prefixes_from_peer(&self, peer: &PeerId) {
        // TODO(ipv6): call this just for enabled address-families.
        // no need to walk the full rib for an AF that isn't affected
        let peer_routes4: Vec<_> = self
            .full_rib(Some(AddressFamily::Ipv4))
            .keys()
            .copied()
            .collect();
        let peer_routes6: Vec<_> = self
            .full_rib(Some(AddressFamily::Ipv6))
            .keys()
            .copied()
            .collect();
        self.remove_bgp_prefixes(&peer_routes4, peer);
        self.remove_bgp_prefixes(&peer_routes6, peer);
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

    pub fn get_bestpath_fanout(&self) -> Result<NonZeroU8, Error> {
        let tree = self.persistent.open_tree(SETTINGS)?;
        let fan = match tree.get(BESTPATH_FANOUT)? {
            // fanout was not in db
            None => DEFAULT_BESTPATH_FANOUT,
            Some(value) => {
                let value: [u8; 1] = (*value).try_into().map_err(|_| {
                    Error::DbKey("invalid bestpath_fanout value in db".into())
                })?;
                value[0]
            }
        };

        Ok(match NonZeroU8::new(fan) {
            // fanout was in db but was 0 (unexpected)
            None => NonZeroU8::new(DEFAULT_BESTPATH_FANOUT).unwrap(),
            Some(fanout) => fanout,
        })
    }

    pub fn set_bestpath_fanout(&self, fanout: NonZeroU8) -> Result<(), Error> {
        let tree = self.persistent.open_tree(SETTINGS)?;
        tree.insert(BESTPATH_FANOUT, &[fanout.get()])?;
        tree.flush()?;
        self.trigger_bestpath_when(|_pfx, _paths| true);
        Ok(())
    }

    pub fn mark_bgp_peer_stale4(&self, peer: PeerId) {
        let mut rib = lock!(self.rib4_loc);
        rib.iter_mut().for_each(|(_prefix, path)| {
            let targets: Vec<Path> = path
                .iter()
                .filter_map(|p| {
                    if let Some(bgp) = p.bgp.as_ref()
                        && bgp.peer == peer
                    {
                        let mut marked = p.clone();
                        marked.bgp = Some(bgp.as_stale());
                        return Some(marked);
                    }
                    None
                })
                .collect();
            for t in targets.into_iter() {
                path.replace(t);
            }
        });
    }

    pub fn mark_bgp_peer_stale6(&self, peer: PeerId) {
        let mut rib = lock!(self.rib6_loc);
        rib.iter_mut().for_each(|(_prefix, path)| {
            let targets: Vec<Path> = path
                .iter()
                .filter_map(|p| {
                    if let Some(bgp) = p.bgp.as_ref()
                        && bgp.peer == peer
                    {
                        let mut marked = p.clone();
                        marked.bgp = Some(bgp.as_stale());
                        return Some(marked);
                    }
                    None
                })
                .collect();
            for t in targets.into_iter() {
                path.replace(t);
            }
        });
    }

    pub fn slot(&self) -> Option<u16> {
        match self.slot.read() {
            Ok(v) => *v,
            Err(e) => {
                error!(self.log, "unable to read switch slot"; "error" => %e);
                None
            }
        }
    }

    pub fn set_slot(&mut self, slot: Option<u16>) {
        let mut value = self.slot.write().unwrap();
        *value = slot;
    }

    pub fn mark_bgp_peer_stale(&self, peer: PeerId, af: AddressFamily) {
        match af {
            AddressFamily::Ipv4 => self.mark_bgp_peer_stale4(peer.clone()),
            AddressFamily::Ipv6 => self.mark_bgp_peer_stale6(peer),
        }
    }
}

struct Reaper {
    interval: Mutex<std::time::Duration>,
    stale_max: Mutex<chrono::Duration>,
    rib: Arc<Mutex<Rib>>,
}

impl Reaper {
    fn new(rib: Arc<Mutex<Rib>>) -> Arc<Self> {
        let reaper = Arc::new(Self {
            interval: Mutex::new(std::time::Duration::from_millis(100)),
            stale_max: Mutex::new(chrono::Duration::new(1, 0).unwrap()),
            rib,
        });
        reaper.run();
        reaper
    }

    fn run(self: &Arc<Self>) {
        let s = self.clone();
        spawn(move || {
            loop {
                s.reap();
                sleep(*lock!(s.interval));
            }
        });
    }

    fn reap(self: &Arc<Self>) {
        self.rib
            .lock()
            .unwrap()
            .iter_mut()
            .for_each(|(_prefix, paths)| {
                paths.retain(|p| {
                    p.bgp
                        .as_ref()
                        .map(|b| {
                            b.stale
                                .map(|s| {
                                    Utc::now().signed_duration_since(s)
                                        < *lock!(self.stale_max)
                                })
                                .unwrap_or(true)
                        })
                        .unwrap_or(true)
                })
            });
    }
}

#[cfg(test)]
mod test {
    use crate::{
        AddressFamily, DEFAULT_RIB_PRIORITY_STATIC, Path, Prefix, Prefix4,
        Prefix6, StaticRouteKey, db::Db, test::TestDb, types::PrefixDbKey,
        types::test_helpers::path_vecs_equal,
    };
    use mg_common::log::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn get_test_db() -> TestDb {
        let log = init_file_logger("rib.log");
        crate::test::get_test_db("rib_test", log).expect("create db")
    }

    pub fn check_prefix_path(
        db: &Db,
        prefix: &Prefix,
        rib_in_paths: Vec<Path>,
        loc_rib_paths: Vec<Path>,
    ) -> bool {
        let curr_rib_in_paths = db.get_prefix_paths(prefix);
        if !path_vecs_equal(&curr_rib_in_paths, &rib_in_paths) {
            eprintln!("curr_rib_in_paths: {:?}", curr_rib_in_paths);
            eprintln!("rib_in_paths: {:?}", rib_in_paths);
            return false;
        }

        let curr_loc_rib_paths = db.get_selected_prefix_paths(prefix);
        if !path_vecs_equal(&curr_loc_rib_paths, &loc_rib_paths) {
            eprintln!("curr_loc_rib_paths: {:?}", curr_loc_rib_paths);
            eprintln!("loc_rib_paths: {:?}", loc_rib_paths);
            return false;
        }
        true
    }

    #[test]
    fn test_rib() {
        use crate::StaticRouteKey;
        use crate::{
            BgpPathProperties, DEFAULT_RIB_PRIORITY_BGP,
            DEFAULT_RIB_PRIORITY_STATIC, Path, PeerId, Prefix, Prefix4, db::Db,
        };
        // init test vars
        let p0 = Prefix::from("192.168.0.0/24".parse::<Prefix4>().unwrap());
        let p1 = Prefix::from("192.168.1.0/24".parse::<Prefix4>().unwrap());
        let p2 = Prefix::from("192.168.2.0/24".parse::<Prefix4>().unwrap());
        let remote_ip0 = IpAddr::from_str("203.0.113.0").unwrap();
        let remote_ip1 = IpAddr::from_str("203.0.113.1").unwrap();
        let remote_ip2 = IpAddr::from_str("203.0.113.2").unwrap();

        let bgp_path0 = Path {
            nexthop: remote_ip0,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 1111,
                peer: PeerId::Ip(remote_ip0),
                id: 1111,
                med: Some(1111),
                local_pref: Some(1111),
                as_path: vec![1111, 1111, 1111],
                stale: None,
            }),
            vlan_id: None,
        };
        let bgp_path1 = Path {
            nexthop: remote_ip1,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 2222,
                peer: PeerId::Ip(remote_ip1),
                id: 2222,
                med: Some(2222),
                local_pref: Some(2222),
                as_path: vec![2222, 2222, 2222],
                stale: None,
            }),
            vlan_id: None,
        };
        // bgp_path2 has all the same BgpPathProperties as bgp_path1,
        // except it has a different connection and a higher local_pref.
        // This is to simulate multiple connections to the same BGP peer.
        // TODO: set local_pref to Some(2222) to test ECMP when
        // BESTPATH_FANOUT is increased to test ECMP.
        let bgp_path2 = Path {
            nexthop: remote_ip2,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 2222,
                peer: PeerId::Ip(remote_ip2),
                id: 2222,
                med: Some(2222),
                local_pref: Some(4444),
                as_path: vec![2222, 2222, 2222],
                stale: None,
            }),
            vlan_id: None,
        };
        // Static routes for testing replacement semantics:
        // static_key0 and static_key0_updated have the SAME identity (nexthop, vlan_id)
        // but different rib_priority. Adding both should result in replacement.
        let static_key0 = StaticRouteKey {
            prefix: p0,
            nexthop: remote_ip0,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        let static_path0 = Path::from(static_key0);
        let static_key0_updated = StaticRouteKey {
            prefix: p0,
            nexthop: remote_ip0,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC + 10,
        };
        let static_path0_updated = Path::from(static_key0_updated);

        // Static route for testing ECMP:
        // static_key1 has a DIFFERENT identity (different nexthop) than static_key0,
        // so both should coexist in the RIB.
        let static_key1 = StaticRouteKey {
            prefix: p0,
            nexthop: remote_ip1,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        let static_path1 = Path::from(static_key1);

        // setup
        std::fs::create_dir_all("/tmp").expect("create tmp dir");
        let log = init_file_logger("rib.log");
        let db_path = "/tmp/rib.db".to_string();
        let _ = std::fs::remove_dir_all(&db_path);
        let db = Db::new(&db_path, log.clone()).expect("create db");

        // Start test cases

        // start from empty rib
        assert!(db.full_rib(None).is_empty());
        assert!(db.loc_rib(None).is_empty());

        // =====================================================================
        // Test 1: Replacement semantics
        // Adding two static routes with the same identity (nexthop, vlan_id)
        // should result in the second replacing the first.
        // =====================================================================
        db.add_static_routes(&[static_key0])
            .expect("add static_key0");

        // Verify static_path0 is installed
        let rib_in_paths = vec![static_path0.clone()];
        let loc_rib_paths = vec![static_path0.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));

        // Add static_key0_updated (same identity, different rib_priority)
        // This should REPLACE static_path0, not add a second path
        db.add_static_routes(&[static_key0_updated])
            .expect("add static_key0_updated");

        // Verify only static_path0_updated exists (replacement occurred)
        let rib_in_paths = vec![static_path0_updated.clone()];
        let loc_rib_paths = vec![static_path0_updated.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));

        // =====================================================================
        // Test 2: ECMP - multiple static routes with different identities
        // Adding a static route with a different nexthop should coexist.
        // =====================================================================
        db.add_static_routes(&[static_key1])
            .expect("add static_key1");

        // Verify both paths coexist (ECMP)
        // static_path0_updated (nexthop=remote_ip0) and static_path1 (nexthop=remote_ip1)
        let rib_in_paths =
            vec![static_path0_updated.clone(), static_path1.clone()];
        // loc_rib should have static_path0 or static_path1 based on bestpath
        // Both have the same rib_priority (static_path0_updated has +10, static_path1 has base)
        // so static_path1 wins (lower rib_priority is better)
        let loc_rib_paths = vec![static_path1.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));

        // =====================================================================
        // Test 3: Removal by identity
        // Removing static_key0 should only remove static_path0_updated,
        // leaving static_path1 intact (different identity).
        // =====================================================================
        db.remove_static_routes(&[static_key0])
            .expect("remove static_key0");

        // Verify static_path1 still exists
        let rib_in_paths = vec![static_path1.clone()];
        let loc_rib_paths = vec![static_path1.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));

        // install bgp routes
        db.add_bgp_prefixes(&[p0, p1], bgp_path0.clone());
        db.add_bgp_prefixes(&[p1, p2], bgp_path1.clone());
        db.add_bgp_prefixes(&[p1, p2], bgp_path2.clone());

        // expected current state
        // rib_in:
        // - p0 via bgp_path0, static_path1 (ordered by nexthop IP)
        // - p1 via bgp_path{0,1,2}
        // - p2 via bgp_path{1,2}
        // loc_rib:
        // - p0 via static_path1 (win by rib_priority/protocol)
        // - p1 via bgp_path2    (win by local pref)
        // - p2 via bgp_path2    (win by local pref)
        let rib_in_paths = vec![bgp_path0.clone(), static_path1.clone()];
        let loc_rib_paths = vec![static_path1.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));
        let rib_in_paths =
            vec![bgp_path0.clone(), bgp_path1.clone(), bgp_path2.clone()];
        let loc_rib_paths = vec![bgp_path2.clone()];
        assert!(check_prefix_path(&db, &p1, rib_in_paths, loc_rib_paths));
        let rib_in_paths = vec![bgp_path1.clone(), bgp_path2.clone()];
        let loc_rib_paths = vec![bgp_path2.clone()];
        assert!(check_prefix_path(&db, &p2, rib_in_paths, loc_rib_paths));

        // withdrawal of p2 via bgp_path1
        db.remove_bgp_prefixes(&[p2], &bgp_path1.clone().bgp.unwrap().peer);
        // expected current state
        // rib_in:
        // - p0 via bgp_path0, static_path1 (ordered by nexthop IP)
        // - p1 via bgp_path{0,1,2}
        // - p2 via bgp_path2
        // loc_rib:
        // - p0 via static_path1 (win by rib_priority/protocol)
        // - p1 via bgp_path2    (win by local pref)
        // - p2 via bgp_path2    (win by local pref)
        let rib_in_paths = vec![bgp_path0.clone(), static_path1.clone()];
        let loc_rib_paths = vec![static_path1.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));
        let rib_in_paths =
            vec![bgp_path0.clone(), bgp_path1.clone(), bgp_path2.clone()];
        let loc_rib_paths = vec![bgp_path2.clone()];
        assert!(check_prefix_path(&db, &p1, rib_in_paths, loc_rib_paths));
        let rib_in_paths = vec![bgp_path2.clone()];
        let loc_rib_paths = vec![bgp_path2.clone()];
        assert!(check_prefix_path(&db, &p2, rib_in_paths, loc_rib_paths));

        // yank all routes from bgp_path0, simulating peer shutdown
        db.remove_bgp_prefixes_from_peer(&bgp_path0.bgp.unwrap().peer);
        // expected current state
        // rib_in:
        // - p0 via static_path1
        // - p1 via bgp_path{1,2}
        // - p2 via bgp_path2
        // loc_rib:
        // - p0 via static_path1 (only path)
        // - p1 via bgp_path2    (local pref)
        // - p2 via bgp_path2    (only path)
        let rib_in_paths = vec![static_path1.clone()];
        let loc_rib_paths = vec![static_path1.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));
        let rib_in_paths = vec![bgp_path1.clone(), bgp_path2.clone()];
        let loc_rib_paths = vec![bgp_path2.clone()];
        assert!(check_prefix_path(&db, &p1, rib_in_paths, loc_rib_paths));
        let rib_in_paths = vec![bgp_path2.clone()];
        let loc_rib_paths = vec![bgp_path2.clone()];
        assert!(check_prefix_path(&db, &p2, rib_in_paths, loc_rib_paths));

        // yank all routes from bgp_path2, simulating peer shutdown
        // bgp_path2 should be unaffected, despite also having the same RID
        db.remove_bgp_prefixes_from_peer(&bgp_path2.clone().bgp.unwrap().peer);
        // expected current state
        // rib_in:
        // - p0 via static_path1
        // - p1 via bgp_path1
        // loc_rib:
        // - p0 via static_path1  (only path)
        // - p1 via bgp_path1     (only path)
        let rib_in_paths = vec![static_path1.clone()];
        let loc_rib_paths = vec![static_path1.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));
        let rib_in_paths = vec![bgp_path1.clone()];
        let loc_rib_paths = vec![bgp_path1.clone()];
        assert!(check_prefix_path(&db, &p1, rib_in_paths, loc_rib_paths));
        let rib_in_paths = vec![];
        let loc_rib_paths = vec![];
        assert!(check_prefix_path(&db, &p2, rib_in_paths, loc_rib_paths));

        // yank all routes from bgp_path1, simulating peer shutdown
        // p0 should be unaffected, still retaining the static path
        db.remove_bgp_prefixes_from_peer(&bgp_path1.clone().bgp.unwrap().peer);
        // expected current state
        // rib_in:
        // - p0 via static_path1
        // loc_rib:
        // - p0 via static_path1 (only path)
        let rib_in_paths = vec![static_path1.clone()];
        let loc_rib_paths = vec![static_path1.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));
        let rib_in_paths = vec![];
        let loc_rib_paths = vec![];
        assert!(check_prefix_path(&db, &p1, rib_in_paths, loc_rib_paths));
        let rib_in_paths = vec![];
        let loc_rib_paths = vec![];
        assert!(check_prefix_path(&db, &p2, rib_in_paths, loc_rib_paths));

        // removal of final static route (from static_key1) should result
        // in the prefix being completely deleted
        db.remove_static_routes(&[static_key1])
            .expect("remove_static_routes_failed for {static_key1}");
        // expected current state
        // rib_in: (empty)
        // loc_rib: (empty)
        let rib_in_paths = vec![];
        let loc_rib_paths = vec![];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));
        let rib_in_paths = vec![];
        let loc_rib_paths = vec![];
        assert!(check_prefix_path(&db, &p1, rib_in_paths, loc_rib_paths));
        let rib_in_paths = vec![];
        let loc_rib_paths = vec![];
        assert!(check_prefix_path(&db, &p2, rib_in_paths, loc_rib_paths));

        // rib should be empty again
        assert!(db.full_rib(None).is_empty());
        assert!(db.loc_rib(None).is_empty());
    }

    #[test]
    fn test_static_routing_ipv4_basic() {
        let db = get_test_db();
        let nexthop = IpAddr::V4(Ipv4Addr::from_str("10.0.0.1").unwrap());

        // Test adding IPv4 static routes
        let prefix4 =
            Prefix4::new(Ipv4Addr::from_str("192.168.1.0").unwrap(), 24);
        let static_route = StaticRouteKey {
            prefix: Prefix::V4(prefix4),
            nexthop,
            vlan_id: Some(100),
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        // Add the route
        db.add_static_routes(&[static_route]).unwrap();

        // Verify route was added
        let routes = db.get_static(Some(AddressFamily::Ipv4)).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0], static_route);

        // Check that it appears in RIB
        let rib_routes = db.full_rib(Some(AddressFamily::Ipv4));
        assert_eq!(rib_routes.len(), 1);
        assert!(rib_routes.contains_key(&Prefix::V4(prefix4)));

        // Remove the route
        db.remove_static_routes(&[static_route]).unwrap();

        // Verify route was removed
        let routes = db.get_static(Some(AddressFamily::Ipv4)).unwrap();
        assert!(routes.is_empty());

        // Check that RIB is empty
        let rib_routes = db.full_rib(Some(AddressFamily::Ipv4));
        assert!(rib_routes.is_empty());
    }

    #[test]
    fn test_static_routing_ipv6_basic() {
        let db = get_test_db();
        let nexthop = IpAddr::V6(Ipv6Addr::from_str("fe80::1").unwrap());

        // Test adding IPv6 static routes
        let prefix6 =
            Prefix6::new(Ipv6Addr::from_str("2001:db8::").unwrap(), 64);
        let static_route = StaticRouteKey {
            prefix: Prefix::V6(prefix6),
            nexthop,
            vlan_id: Some(200),
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        // Add the route
        db.add_static_routes(&[static_route]).unwrap();

        // Verify route was added
        let routes = db.get_static(Some(AddressFamily::Ipv6)).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0], static_route);

        // Check that it appears in RIB
        let rib_routes = db.full_rib(Some(AddressFamily::Ipv6));
        assert_eq!(rib_routes.len(), 1);
        assert!(rib_routes.contains_key(&Prefix::V6(prefix6)));

        // Remove the route
        db.remove_static_routes(&[static_route]).unwrap();

        // Verify route was removed
        let routes = db.get_static(Some(AddressFamily::Ipv6)).unwrap();
        assert!(routes.is_empty());

        // Check that RIB is empty
        let rib_routes = db.full_rib(Some(AddressFamily::Ipv6));
        assert!(rib_routes.is_empty());
    }

    #[test]
    fn test_static_routing_ipv6_vlan_id_handling() {
        let db = get_test_db();
        let prefix6 =
            Prefix6::new(Ipv6Addr::from_str("2001:db8:1::").unwrap(), 48);

        // Test route without VLAN ID
        let route_no_vlan = StaticRouteKey {
            prefix: Prefix::V6(prefix6),
            nexthop: IpAddr::V6(Ipv6Addr::from_str("fe80::1").unwrap()),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        // Test route with VLAN ID
        let route_with_vlan = StaticRouteKey {
            prefix: Prefix::V6(prefix6),
            nexthop: IpAddr::V6(Ipv6Addr::from_str("fe80::2").unwrap()),
            vlan_id: Some(4094), // Maximum VLAN ID
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        // Add both routes
        db.add_static_routes(&[route_no_vlan, route_with_vlan])
            .unwrap();

        // Verify both routes were added correctly
        let routes = db.get_static(Some(AddressFamily::Ipv6)).unwrap();
        assert_eq!(routes.len(), 2);

        let no_vlan_route =
            routes.iter().find(|r| r.vlan_id.is_none()).unwrap();
        assert_eq!(no_vlan_route.vlan_id, None);

        let vlan_route = routes.iter().find(|r| r.vlan_id.is_some()).unwrap();
        assert_eq!(vlan_route.vlan_id, Some(4094));

        // Clean up
        db.remove_static_routes(&[route_no_vlan, route_with_vlan])
            .unwrap();
    }

    #[test]
    fn test_static_routing_mixed_address_families() {
        let db = get_test_db();

        // Create IPv4 and IPv6 routes
        let prefix4 = Prefix4::new(Ipv4Addr::from_str("10.0.0.0").unwrap(), 8);
        let prefix6 = Prefix6::new(Ipv6Addr::from_str("fd00::").unwrap(), 8);

        let route4 = StaticRouteKey {
            prefix: Prefix::V4(prefix4),
            nexthop: IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        let route6 = StaticRouteKey {
            prefix: Prefix::V6(prefix6),
            nexthop: IpAddr::V6(Ipv6Addr::from_str("fe80::1").unwrap()),
            vlan_id: Some(300),
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        // Add both routes
        db.add_static_routes(&[route4, route6]).unwrap();

        // Test IPv4-only retrieval
        let ipv4_routes = db.get_static(Some(AddressFamily::Ipv4)).unwrap();
        assert_eq!(ipv4_routes.len(), 1);
        assert_eq!(ipv4_routes[0], route4);

        // Test IPv6-only retrieval
        let ipv6_routes = db.get_static(Some(AddressFamily::Ipv6)).unwrap();
        assert_eq!(ipv6_routes.len(), 1);
        assert_eq!(ipv6_routes[0], route6);

        // Test all address families retrieval
        let all_routes = db.get_static(None).unwrap();
        assert_eq!(all_routes.len(), 2);
        assert!(all_routes.contains(&route4));
        assert!(all_routes.contains(&route6));

        // Test counts
        assert_eq!(db.get_static4_count().unwrap(), 1);
        assert_eq!(db.get_static6_count().unwrap(), 1);

        // Remove routes and verify cleanup
        db.remove_static_routes(&[route4, route6]).unwrap();
        assert_eq!(db.get_static4_count().unwrap(), 0);
        assert_eq!(db.get_static6_count().unwrap(), 0);
    }

    #[test]
    fn test_static_routing_multiple_routes_same_prefix() {
        let db = get_test_db();
        let prefix4 =
            Prefix4::new(Ipv4Addr::from_str("172.16.0.0").unwrap(), 16);

        // Create multiple routes to the same prefix with different next-hops and priorities
        let route1 = StaticRouteKey {
            prefix: Prefix::V4(prefix4),
            nexthop: IpAddr::V4(Ipv4Addr::from_str("10.0.0.1").unwrap()),
            vlan_id: None,
            rib_priority: 100,
        };

        let route2 = StaticRouteKey {
            prefix: Prefix::V4(prefix4),
            nexthop: IpAddr::V4(Ipv4Addr::from_str("10.0.0.2").unwrap()),
            vlan_id: Some(100),
            rib_priority: 200,
        };

        // Add both routes
        db.add_static_routes(&[route1, route2]).unwrap();

        // Verify both routes were added
        let routes = db.get_static(Some(AddressFamily::Ipv4)).unwrap();
        assert_eq!(routes.len(), 2);
        assert!(routes.contains(&route1));
        assert!(routes.contains(&route2));

        // Remove one route, other should remain
        db.remove_static_routes(&[route1]).unwrap();
        let routes = db.get_static(Some(AddressFamily::Ipv4)).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0], route2);

        // Remove final route
        db.remove_static_routes(&[route2]).unwrap();
        let routes = db.get_static(Some(AddressFamily::Ipv4)).unwrap();
        assert!(routes.is_empty());
    }

    #[test]
    fn test_static_routing_vlan_id_handling() {
        let db = get_test_db();
        let prefix4 =
            Prefix4::new(Ipv4Addr::from_str("203.0.113.0").unwrap(), 24);

        // Test route without VLAN ID
        let route_no_vlan = StaticRouteKey {
            prefix: Prefix::V4(prefix4),
            nexthop: IpAddr::V4(Ipv4Addr::from_str("198.51.100.1").unwrap()),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        // Test route with VLAN ID
        let route_with_vlan = StaticRouteKey {
            prefix: Prefix::V4(prefix4),
            nexthop: IpAddr::V4(Ipv4Addr::from_str("198.51.100.2").unwrap()),
            vlan_id: Some(4094), // Maximum VLAN ID
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        // Add both routes
        db.add_static_routes(&[route_no_vlan, route_with_vlan])
            .unwrap();

        // Verify both routes were added correctly
        let routes = db.get_static(Some(AddressFamily::Ipv4)).unwrap();
        assert_eq!(routes.len(), 2);

        let no_vlan_route =
            routes.iter().find(|r| r.vlan_id.is_none()).unwrap();
        assert_eq!(no_vlan_route.vlan_id, None);

        let vlan_route = routes.iter().find(|r| r.vlan_id.is_some()).unwrap();
        assert_eq!(vlan_route.vlan_id, Some(4094));

        // Clean up
        db.remove_static_routes(&[route_no_vlan, route_with_vlan])
            .unwrap();
    }

    #[test]
    fn test_prefix_host_bit_normalization() {
        let db = get_test_db();

        // Test that Prefix4::new() properly zeros host bits
        let prefix4_with_host_bits =
            Prefix4::new(Ipv4Addr::from_str("192.168.1.5").unwrap(), 24);
        assert_eq!(
            prefix4_with_host_bits.value,
            Ipv4Addr::from_str("192.168.1.0").unwrap()
        );
        assert_eq!(prefix4_with_host_bits.length, 24);

        // Test that Prefix6::new() properly zeros host bits
        let prefix6_with_host_bits =
            Prefix6::new(Ipv6Addr::from_str("2001:db8::1234").unwrap(), 64);
        assert_eq!(
            prefix6_with_host_bits.value,
            Ipv6Addr::from_str("2001:db8::").unwrap()
        );
        assert_eq!(prefix6_with_host_bits.length, 64);

        // Test with static route to ensure normalization works through the full stack
        let route = StaticRouteKey {
            prefix: Prefix::V4(prefix4_with_host_bits),
            nexthop: IpAddr::V4(Ipv4Addr::from_str("10.0.0.1").unwrap()),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        db.add_static_routes(&[route]).unwrap();
        let routes = db.get_static(Some(AddressFamily::Ipv4)).unwrap();
        assert_eq!(routes.len(), 1);

        // Verify the stored route has normalized prefix
        if let Prefix::V4(stored_prefix) = routes[0].prefix {
            assert_eq!(
                stored_prefix.value,
                Ipv4Addr::from_str("192.168.1.0").unwrap()
            );
        } else {
            panic!("Expected IPv4 prefix");
        }

        db.remove_static_routes(&[route]).unwrap();
    }

    #[test]
    fn test_ipv4_origin_crud() {
        let db = get_test_db();

        // Test creating IPv4 origins
        let prefixes = vec![
            Prefix4::new(Ipv4Addr::new(192, 168, 1, 0), 24),
            Prefix4::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        ];

        // Create origin4 - should succeed
        db.create_origin4(&prefixes).expect("create origin4");

        // Get origin4 - should return created prefixes
        let retrieved = db.get_origin4().expect("get origin4");
        assert_eq!(retrieved.len(), 2);
        assert!(retrieved.contains(&prefixes[0]));
        assert!(retrieved.contains(&prefixes[1]));

        // Try to create again - should fail with conflict
        assert!(db.create_origin4(&prefixes).is_err());

        // Update origin4 with different prefixes
        let new_prefixes = vec![Prefix4::new(Ipv4Addr::new(172, 16, 0, 0), 12)];
        db.set_origin4(&new_prefixes).expect("set origin4");

        let updated = db.get_origin4().expect("get updated origin4");
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0], new_prefixes[0]);

        // Clear origin4
        db.clear_origin4().expect("clear origin4");
        let empty = db.get_origin4().expect("get empty origin4");
        assert!(empty.is_empty());

        // Create again after clear - should succeed
        db.create_origin4(&prefixes).expect("create after clear");
        let final_result = db.get_origin4().expect("get final origin4");
        assert_eq!(final_result.len(), 2);
    }

    #[test]
    fn test_ipv6_origin_crud() {
        let db = get_test_db();

        // Test creating IPv6 origins
        let prefixes = vec![
            Prefix6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
            Prefix6::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 8),
        ];

        // Create origin6 - should succeed
        db.create_origin6(&prefixes).expect("create origin6");

        // Get origin6 - should return created prefixes
        let retrieved = db.get_origin6().expect("get origin6");
        assert_eq!(retrieved.len(), 2);
        assert!(retrieved.contains(&prefixes[0]));
        assert!(retrieved.contains(&prefixes[1]));

        // Try to create again - should fail with conflict
        assert!(db.create_origin6(&prefixes).is_err());

        // Update origin6 with different prefixes
        let new_prefixes = vec![Prefix6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
            48,
        )];
        db.set_origin6(&new_prefixes).expect("set origin6");

        let updated = db.get_origin6().expect("get updated origin6");
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0], new_prefixes[0]);

        // Clear origin6
        db.clear_origin6().expect("clear origin6");
        let empty = db.get_origin6().expect("get empty origin6");
        assert!(empty.is_empty());

        // Create again after clear - should succeed
        db.create_origin6(&prefixes).expect("create after clear");
        let final_result = db.get_origin6().expect("get final origin6");
        assert_eq!(final_result.len(), 2);
    }

    #[test]
    fn test_prefix4_db_key_serialization() {
        let prefix = Prefix4::new(Ipv4Addr::new(192, 168, 100, 0), 24);
        let key = prefix.db_key();

        // IPv4 address should be 4 bytes + 1 byte for length
        assert_eq!(key.len(), 5);
        assert_eq!(key[4], 24); // length byte

        // Test round-trip serialization
        let recovered =
            Prefix4::from_db_key(&key).expect("recover from db key");
        assert_eq!(recovered, prefix);
    }

    #[test]
    fn test_prefix6_db_key_serialization() {
        let prefix = Prefix6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0xdead, 0xbeef, 0, 0, 0, 0),
            64,
        );
        let key = prefix.db_key();

        // IPv6 address should be 16 bytes + 1 byte for length
        assert_eq!(key.len(), 17);
        assert_eq!(key[16], 64); // length byte

        // Test round-trip serialization
        let recovered =
            Prefix6::from_db_key(&key).expect("recover from db key");
        assert_eq!(recovered, prefix);
    }

    #[test]
    fn test_prefix4_from_str() {
        let prefix_str = "192.168.1.0/24";
        let prefix: Prefix4 = prefix_str.parse().expect("parse IPv4 prefix");
        assert_eq!(prefix.value, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix.length, 24);

        // Test invalid format
        assert!("invalid".parse::<Prefix4>().is_err());
        assert!("192.168.1".parse::<Prefix4>().is_err());
        assert!("192.168.1.0/abc".parse::<Prefix4>().is_err());
    }

    #[test]
    fn test_prefix6_from_str() {
        let prefix_str = "2001:db8::/32";
        let prefix: Prefix6 = prefix_str.parse().expect("parse IPv6 prefix");
        assert_eq!(
            prefix.value,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(prefix.length, 32);

        // Test invalid format
        assert!("invalid".parse::<Prefix6>().is_err());
        assert!("2001:db8:".parse::<Prefix6>().is_err());
        assert!("2001:db8::/abc".parse::<Prefix6>().is_err());
    }
}
