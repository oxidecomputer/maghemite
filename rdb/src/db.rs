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
use chrono::Utc;
use mg_common::{lock, read_lock, write_lock};
use slog::{error, Logger};
use std::cmp::Ordering as CmpOrdering;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU8;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{sleep, spawn};

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

/// Key used in settings tree for bestpath fanout setting
const BESTPATH_FANOUT: &str = "bestpath_fanout";

/// Default bestpath fanout value. Maximum number of ECMP paths in RIB.
const DEFAULT_BESTPATH_FANOUT: u8 = 1;

pub type Rib = BTreeMap<Prefix, BTreeSet<Path>>;

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

    /// Reaps expired routes from the local RIB
    reaper: Arc<Reaper>,

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
            rib_in: Arc::new(Mutex::new(Rib::new())),
            rib_loc: rib_loc.clone(),
            generation: Arc::new(AtomicU64::new(0)),
            watchers: Arc::new(RwLock::new(Vec::new())),
            reaper: Reaper::new(rib_loc),
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
                error!(
                    self.log,
                    "failed to send notification to watcher '{tag}': {e}"
                );
            }
        }
    }

    pub fn loc_rib(&self) -> Rib {
        lock!(self.rib_loc).clone()
    }

    pub fn full_rib(&self) -> Rib {
        lock!(self.rib_in).clone()
    }

    pub fn static_rib(&self) -> Rib {
        let mut rib = lock!(self.rib_in).clone();
        for (_prefix, paths) in rib.iter_mut() {
            paths.retain(|x| x.bgp.is_none())
        }
        rib
    }

    pub fn bgp_rib(&self) -> Rib {
        let mut rib = lock!(self.rib_in).clone();
        for (_prefix, paths) in rib.iter_mut() {
            paths.retain(|x| x.bgp.is_some())
        }
        rib
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

    pub fn create_origin4(&self, ps: &[Prefix4]) -> Result<(), Error> {
        let current = self.get_origin4()?;
        if !current.is_empty() {
            return Err(Error::Conflict("origin already exists".to_string()));
        }

        self.set_origin4(ps)
    }

    pub fn set_origin4(&self, ps: &[Prefix4]) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN)?;
        tree.clear()?;
        for p in ps.iter() {
            tree.insert(p.db_key(), "")?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn clear_origin4(&self) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_ORIGIN)?;
        tree.clear()?;
        tree.flush()?;
        Ok(())
    }

    pub fn get_origin4(&self) -> Result<Vec<Prefix4>, Error> {
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

    pub fn get_selected_prefix_paths(&self, prefix: &Prefix) -> Vec<Path> {
        let rib = lock!(self.rib_loc);
        let paths = rib.get(prefix);
        match paths {
            None => Vec::new(),
            Some(p) => p.iter().cloned().collect(),
        }
    }

    pub fn update_loc_rib(
        &self,
        rib_in: &Rib,
        rib_loc: &mut Rib,
        prefix: Prefix,
    ) {
        let fanout = self.get_bestpath_fanout().unwrap_or_else(|e| {
            error!(self.log, "failed to get bestpath fanout: {e}");
            NonZeroU8::new(DEFAULT_BESTPATH_FANOUT).unwrap()
        });
        let bp = bestpaths(prefix, rib_in, fanout.get() as usize);
        match bp {
            Some(bp) => {
                rib_loc.insert(prefix, bp.clone());
            }
            None => {
                rib_loc.remove(&prefix);
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
        for (prefix, paths) in self.full_rib().iter() {
            if bestpath_needed(prefix, paths) {
                self.update_loc_rib(
                    &lock!(self.rib_in),
                    &mut lock!(self.rib_loc),
                    *prefix,
                );
            }
        }
    }

    pub fn add_prefix_path(&self, prefix: Prefix, path: &Path) {
        let mut rib = lock!(self.rib_in);
        match rib.get_mut(&prefix) {
            Some(paths) => {
                paths.replace(path.clone());
            }
            None => {
                rib.insert(prefix, BTreeSet::from([path.clone()]));
            }
        }
        self.update_loc_rib(&rib, &mut lock!(self.rib_loc), prefix);
    }

    pub fn add_static_routes(
        &self,
        routes: &Vec<StaticRouteKey>,
    ) -> Result<(), Error> {
        let tree = self.persistent.open_tree(STATIC4_ROUTES)?;

        let mut route_keys = Vec::new();
        for route in routes {
            let key = serde_json::to_string(route)?;
            route_keys.push(key);
        }

        tree.transaction(|tx_db| {
            for key in &route_keys {
                tx_db.insert(key.as_str(), "")?;
            }
            Ok(())
        })?;
        tree.flush()?;

        let mut pcn = PrefixChangeNotification::default();
        for route in routes {
            self.add_prefix_path(route.prefix, &Path::from(*route));
            pcn.changed.insert(route.prefix);
        }

        self.notify(pcn);
        Ok(())
    }

    pub fn add_bgp_prefixes(&self, prefixes: Vec<Prefix>, path: Path) {
        let mut pcn = PrefixChangeNotification::default();
        for prefix in prefixes {
            self.add_prefix_path(prefix, &path);
            pcn.changed.insert(prefix);
        }
        self.notify(pcn);
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
        let mut nexthops = BTreeSet::new();
        for e in entries {
            nexthops.insert(e.nexthop);
        }
        Ok(nexthops.len())
    }

    pub fn set_nexthop_shutdown(&self, nexthop: IpAddr, shutdown: bool) {
        let mut rib = lock!(self.rib_in);
        let mut pcn = PrefixChangeNotification::default();
        for (prefix, paths) in rib.iter_mut() {
            for p in paths.clone().into_iter() {
                if p.nexthop == nexthop && p.shutdown != shutdown {
                    let mut replacement = p.clone();
                    replacement.shutdown = shutdown;
                    paths.insert(replacement);
                    pcn.changed.insert(*prefix);
                }
            }
        }

        for prefix in pcn.changed.iter() {
            self.update_loc_rib(&rib, &mut lock!(self.rib_loc), *prefix);
        }
        self.notify(pcn);
    }

    pub fn remove_prefix_path<F>(&self, prefix: Prefix, prefix_cmp: F)
    where
        F: Fn(&Path) -> bool,
    {
        let mut rib = lock!(self.rib_in);
        if let Some(paths) = rib.get_mut(&prefix) {
            paths.retain(|p| !prefix_cmp(p));
            if paths.is_empty() {
                rib.remove(&prefix);
            }
        }

        self.update_loc_rib(&rib, &mut lock!(self.rib_loc), prefix);
    }

    pub fn remove_static_routes(
        &self,
        routes: &Vec<StaticRouteKey>,
    ) -> Result<(), Error> {
        let tree = self.persistent.open_tree(STATIC4_ROUTES)?;

        let mut route_keys = Vec::new();
        for route in routes {
            let key = serde_json::to_string(route)?;
            route_keys.push(key);
        }

        tree.transaction(|tx_db| {
            for key in &route_keys {
                tx_db.remove(key.as_str())?;
            }
            Ok(())
        })?;
        tree.flush()?;

        let mut pcn = PrefixChangeNotification::default();
        for route in routes {
            self.remove_prefix_path(route.prefix, |rib_path: &Path| {
                rib_path.cmp(&Path::from(*route)) == CmpOrdering::Equal
            });
            pcn.changed.insert(route.prefix);
        }

        self.notify(pcn);
        Ok(())
    }

    pub fn remove_bgp_prefixes(&self, prefixes: Vec<Prefix>, peer: &IpAddr) {
        let mut pcn = PrefixChangeNotification::default();
        for prefix in prefixes {
            self.remove_prefix_path(prefix, |rib_path: &Path| {
                match rib_path.bgp {
                    Some(ref bgp) => bgp.peer == *peer,
                    None => false,
                }
            });
            pcn.changed.insert(prefix);
        }
        self.notify(pcn);
    }

    // helper function to remove all routes learned from a given peer
    // e.g. when peer is deleted or exits Established state
    pub fn remove_bgp_peer_prefixes(&self, peer: &IpAddr) {
        self.remove_bgp_prefixes(
            self.full_rib().keys().copied().collect(),
            peer,
        );
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

    pub fn mark_bgp_peer_stale(&self, peer: IpAddr) {
        let mut rib = lock!(self.rib_loc);
        rib.iter_mut().for_each(|(_prefix, path)| {
            let targets: Vec<Path> = path
                .iter()
                .filter_map(|p| {
                    if let Some(bgp) = p.bgp.as_ref() {
                        if bgp.peer == peer {
                            let mut marked = p.clone();
                            marked.bgp = Some(bgp.as_stale());
                            return Some(marked);
                        }
                    }
                    None
                })
                .collect();
            for t in targets.into_iter() {
                path.replace(t);
            }
        });
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
        spawn(move || loop {
            s.reap();
            sleep(*lock!(s.interval));
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
    use crate::{db::Db, Path, Prefix};
    use mg_common::log::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    pub fn check_prefix_path(
        db: &Db,
        prefix: &Prefix,
        rib_in_paths: Vec<Path>,
        loc_rib_paths: Vec<Path>,
    ) -> bool {
        let curr_rib_in_paths = db.get_prefix_paths(prefix);
        if curr_rib_in_paths != rib_in_paths {
            eprintln!("curr_rib_in_paths: {:?}", curr_rib_in_paths);
            eprintln!("rib_in_paths: {:?}", rib_in_paths);
            return false;
        }

        let curr_loc_rib_paths = db.get_selected_prefix_paths(prefix);
        if curr_loc_rib_paths != loc_rib_paths {
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
            db::Db, BgpPathProperties, Path, Prefix, Prefix4,
            DEFAULT_RIB_PRIORITY_BGP, DEFAULT_RIB_PRIORITY_STATIC,
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
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 1111,
                peer: remote_ip0,
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
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 2222,
                peer: remote_ip1,
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
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 2222,
                peer: remote_ip2,
                id: 2222,
                med: Some(2222),
                local_pref: Some(4444),
                as_path: vec![2222, 2222, 2222],
                stale: None,
            }),
            vlan_id: None,
        };
        let static_key0 = StaticRouteKey {
            prefix: p0,
            nexthop: remote_ip0,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        let static_path0 = Path::from(static_key0);
        let static_key1 = StaticRouteKey {
            prefix: p0,
            nexthop: remote_ip0,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC + 10,
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
        assert!(db.full_rib().is_empty());
        assert!(db.loc_rib().is_empty());

        // both paths have the same next-hop, but not all fields
        // from StaticRouteKey match (rib_priority is different).
        db.add_static_routes(&vec![static_key0, static_key1])
            .expect(
                "add_static_routes failed for {static_key0} and {static_key1}",
            );

        // expected current state
        // rib_in:
        // - p0 via static_path0, static_path1
        // loc_rib:
        // - p0 via static_path0  (win by rib_priority)
        let rib_in_paths = vec![static_path0.clone(), static_path1.clone()];
        let loc_rib_paths = vec![static_path0.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));

        // rib_priority differs, so removal of static_key0
        // should not affect path from static_key1
        db.remove_static_routes(&vec![static_key0])
            .expect("remove_static_routes_failed for {static_key0}");
        let rib_in_paths = vec![static_path1.clone()];
        let loc_rib_paths = vec![static_path1.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));

        // install bgp routes
        db.add_bgp_prefixes(vec![p0, p1], bgp_path0.clone());
        db.add_bgp_prefixes(vec![p1, p2], bgp_path1.clone());
        db.add_bgp_prefixes(vec![p1, p2], bgp_path2.clone());

        // expected current state
        // rib_in:
        // - p0 via static_path1, bgp_path0
        // - p1 via bgp_path{0,1,2}
        // - p2 via bgp_path{1,2}
        // loc_rib:
        // - p0 via static_path1 (win by rib_priority/protocol)
        // - p1 via bgp_path2    (win by local pref)
        // - p2 via bgp_path2    (win by local pref)
        let rib_in_paths = vec![static_path1.clone(), bgp_path0.clone()];
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
        db.remove_bgp_prefixes(vec![p2], &bgp_path1.clone().bgp.unwrap().peer);
        // expected current state
        // rib_in:
        // - p0 via static_path1, bgp_path0
        // - p1 via bgp_path{0,1,2}
        // - p2 via bgp_path2
        // loc_rib:
        // - p0 via static_path1 (win by rib_priority/protocol)
        // - p1 via bgp_path2    (win by local pref)
        // - p2 via bgp_path2    (win by local pref)
        let rib_in_paths = vec![static_path1.clone(), bgp_path0.clone()];
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
        db.remove_bgp_peer_prefixes(&bgp_path0.bgp.unwrap().peer);
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
        db.remove_bgp_peer_prefixes(&bgp_path2.clone().bgp.unwrap().peer);
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
        db.remove_bgp_peer_prefixes(&bgp_path1.clone().bgp.unwrap().peer);
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
        db.remove_static_routes(&vec![static_key1])
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
        assert!(db.full_rib().is_empty());
        assert!(db.loc_rib().is_empty());
    }
}
