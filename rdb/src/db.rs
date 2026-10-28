// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The routing database (rdb).
//!
//! This is the maghemite routing database. The routing database holds both
//! volatile and non-volatile information. Non-volatile information is stored
//! in a sled key-value store that is persisted to disk via flush operations.
//! Volatile information is stored in in-memory data structures such as hash
//! sets.
use crate::bestpath::bestpaths;
use crate::error::Error;
use crate::log::rdb_log;
use crate::mrib::store::StaticMcastStore;
use crate::mrib::{Mrib, MribTable};
use crate::types::*;
use chrono::Utc;
use mg_api_types::bfd::BfdPeerConfig;
use mg_api_types::bgp::peer::PeerId;
use mg_api_types::rdb::neighbor::{BgpNeighborInfo, BgpUnnumberedNeighborInfo};
use mg_api_types::rdb::path::Path;
use mg_api_types::rdb::rib::AddressFamily;
use mg_api_types::rdb::router::BgpRouterInfo;
use mg_common::{lock, read_lock, write_lock};
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
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

/// Log unit for persistence operations.
pub(crate) const UNIT_PERSISTENT: &str = "persistent";
const UNIT_RIB: &str = "rib";

/// Maximum number of `(S,G)` keys processed while a loc-rib lock is held.
const MRIB_SOURCE_CHUNK: usize = 64;

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

use crate::rib::{Rib, Rib4, Rib6};

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

    /// Multicast routing information base (MRIB).
    mrib: Mrib,

    /// Persistent store of static multicast routes.
    ///
    /// The guard is held from the read of a previously persisted entry,
    /// through the sled write and flush, to the in-memory MRIB update. A
    /// sled transaction cannot include the in-memory `mrib_in`. Static add,
    /// remove, load, and list all take this guard.
    ///
    /// See the lock order in the [`crate::mrib`] module docs.
    static_mcast_store: Arc<Mutex<StaticMcastStore>>,

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

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Db>()
};

/// Width in bytes of the ASN prefix prepended to keys in router-scoped trees
/// (neighbors, originated prefixes). Scoping every per-router key by ASN keeps
/// state belonging to distinct routers from colliding in the shared sled trees
/// and lets a router's state be enumerated/dropped with a single prefix scan.
const ASN_KEY_LEN: usize = 4;

/// Prepend `asn` to `key`, producing the on-disk key for a router-scoped entry.
fn asn_scoped_key(asn: u32, key: &[u8]) -> Vec<u8> {
    let mut buf = asn.to_be_bytes().to_vec();
    buf.extend_from_slice(key);
    buf
}

/// Strip the ASN prefix from a router-scoped key, yielding the inner key bytes.
fn strip_asn(key: &[u8]) -> &[u8] {
    &key[ASN_KEY_LEN..]
}

/// Remove every entry in `tree` scoped to `asn`.
fn remove_asn_scoped(tree: &sled::Tree, asn: u32) -> Result<(), Error> {
    for item in tree.scan_prefix(asn.to_be_bytes()) {
        let (key, _) = item?;
        tree.remove(key)?;
    }
    Ok(())
}

#[derive(Clone)]
struct Watcher {
    tag: String,
    sender: Sender<PrefixChangeNotification>,
}

//TODO we need bulk operations with atomic semantics here.
impl Db {
    /// Create a new routing database that stores persistent data at `path`.
    ///
    /// Persisted static multicast routes are restored before returning.
    /// `(*,G)` routes are selected immediately. `(S,G)` routes are selected
    /// once a unicast route makes their source reachable.
    ///
    /// Invalid persisted multicast entries are logged and skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if the persistent database cannot be opened or read.
    pub fn new(path: &str, log: Logger) -> Result<Self, Error> {
        let rib_loc = Arc::new(Mutex::new(Rib::new()));
        let persistent = sled::open(path)?;
        let static_mcast_store =
            StaticMcastStore::open(&persistent, log.clone())?;

        let db = Self {
            persistent,
            rib4_in: Arc::new(Mutex::new(BTreeMap::new())),
            rib4_loc: Arc::new(Mutex::new(BTreeMap::new())),
            rib6_in: Arc::new(Mutex::new(BTreeMap::new())),
            rib6_loc: Arc::new(Mutex::new(BTreeMap::new())),
            mrib: Mrib::new(log.clone()),
            static_mcast_store: Arc::new(Mutex::new(static_mcast_store)),
            generation: Arc::new(AtomicU64::new(0)),
            watchers: Arc::new(RwLock::new(Vec::new())),
            reaper: Reaper::new(rib_loc),
            slot: Arc::new(RwLock::new(None)),
            log,
        };

        db.load_static_mcast_routes()?;
        Ok(db)
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

        // Deliver unicast notifications before MRIB work to avoid delaying
        // unicast consumers.
        //
        // MRIB selection may still be pending when they wake. Multicast
        // consumers should watch MRIB notifications rather than infer MRIB
        // state from unicast notifications.
        self.revalidate_mrib(Some(&n.changed));
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
                .map(|(p4, paths)| (IpNet::from(p4), paths))
                .collect(),

            Some(AddressFamily::Ipv6) => self
                .loc_rib6()
                .into_iter()
                .map(|(p6, paths)| (IpNet::from(p6), paths))
                .collect(),

            None => {
                let mut rib: Rib = self
                    .loc_rib4()
                    .into_iter()
                    .map(|(p4, paths)| (IpNet::from(p4), paths))
                    .collect();
                rib.extend(
                    self.loc_rib6()
                        .into_iter()
                        .map(|(p6, paths)| (IpNet::from(p6), paths)),
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
                .map(|(p4, paths)| (IpNet::from(p4), paths))
                .collect(),
            Some(AddressFamily::Ipv6) => self
                .full_rib6()
                .into_iter()
                .map(|(p6, paths)| (IpNet::from(p6), paths))
                .collect(),
            None => {
                let mut rib: Rib = self
                    .full_rib4()
                    .into_iter()
                    .map(|(p4, paths)| (IpNet::from(p4), paths))
                    .collect();
                rib.extend(
                    self.full_rib6()
                        .into_iter()
                        .map(|(p6, paths)| (IpNet::from(p6), paths)),
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
        let key = asn_scoped_key(nbr.asn, nbr.host.ip().to_string().as_bytes());
        let value = serde_json::to_string(&nbr)?;
        tree.insert(key, value.as_str())?;
        tree.flush()?;
        Ok(())
    }

    pub fn add_unnumbered_bgp_neighbor(
        &self,
        nbr: BgpUnnumberedNeighborInfo,
    ) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_UNNUMBERED_NEIGHBOR)?;
        let key = asn_scoped_key(nbr.asn, nbr.interface.as_bytes());
        let value = serde_json::to_string(&nbr)?;
        tree.insert(key, value.as_str())?;
        tree.flush()?;
        Ok(())
    }

    pub fn remove_unnumbered_bgp_neighbor(
        &self,
        asn: Asn,
        interface: &str,
    ) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_UNNUMBERED_NEIGHBOR)?;
        tree.remove(asn_scoped_key(asn.as_u32(), interface.as_bytes()))?;
        tree.flush()?;
        Ok(())
    }

    pub fn remove_bgp_neighbor(
        &self,
        asn: Asn,
        addr: IpAddr,
    ) -> Result<(), Error> {
        let tree = self.persistent.open_tree(BGP_NEIGHBOR)?;
        tree.remove(asn_scoped_key(asn.as_u32(), addr.to_string().as_bytes()))?;
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

    pub fn create_origin4(
        &self,
        asn: Asn,
        ps: &[Ipv4Net],
    ) -> Result<(), Error> {
        rdb_log!(self, info,
            "create origin4 (asn {asn}): {ps:?}";
            "unit" => UNIT_PERSISTENT
        );

        let current = self.get_origin4(asn)?;
        if !current.is_empty() {
            return Err(Error::Conflict("origin already exists".to_string()));
        }

        self.set_origin4(asn, ps)
    }

    pub fn set_origin4(&self, asn: Asn, ps: &[Ipv4Net]) -> Result<(), Error> {
        let asn = asn.as_u32();
        let tree = self.persistent.open_tree(BGP_ORIGIN4)?;
        remove_asn_scoped(&tree, asn)?;
        for p in ps.iter() {
            tree.insert(asn_scoped_key(asn, &p.db_key()), "")?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn clear_origin4(&self, asn: Asn) -> Result<(), Error> {
        let asn = asn.as_u32();
        let tree = self.persistent.open_tree(BGP_ORIGIN4)?;
        remove_asn_scoped(&tree, asn)?;
        tree.flush()?;
        Ok(())
    }

    pub fn get_origin4(&self, asn: Asn) -> Result<Vec<Ipv4Net>, Error> {
        let asn = asn.as_u32();
        let tree = self.persistent.open_tree(BGP_ORIGIN4)?;
        let result = tree
            .scan_prefix(asn.to_be_bytes())
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
                Some(match Ipv4Net::from_db_key(strip_asn(&key)) {
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

    pub fn create_origin6(
        &self,
        asn: Asn,
        ps: &[Ipv6Net],
    ) -> Result<(), Error> {
        let current = self.get_origin6(asn)?;
        if !current.is_empty() {
            return Err(Error::Conflict("origin already exists".to_string()));
        }

        self.set_origin6(asn, ps)
    }

    pub fn set_origin6(&self, asn: Asn, ps: &[Ipv6Net]) -> Result<(), Error> {
        let asn = asn.as_u32();
        let tree = self.persistent.open_tree(BGP_ORIGIN6)?;
        remove_asn_scoped(&tree, asn)?;
        for p in ps.iter() {
            tree.insert(asn_scoped_key(asn, &p.db_key()), "")?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn clear_origin6(&self, asn: Asn) -> Result<(), Error> {
        let asn = asn.as_u32();
        let tree = self.persistent.open_tree(BGP_ORIGIN6)?;
        remove_asn_scoped(&tree, asn)?;
        tree.flush()?;
        Ok(())
    }

    pub fn get_origin6(&self, asn: Asn) -> Result<Vec<Ipv6Net>, Error> {
        let asn = asn.as_u32();
        let tree = self.persistent.open_tree(BGP_ORIGIN6)?;
        let result = tree
            .scan_prefix(asn.to_be_bytes())
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
                Some(match Ipv6Net::from_db_key(strip_asn(&key)) {
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

    pub fn get_prefix_paths(&self, prefix: &IpNet) -> Vec<Path> {
        match prefix {
            IpNet::V4(p4) => {
                let rib = lock!(self.rib4_in);
                match rib.get(p4) {
                    None => Vec::new(),
                    Some(p) => p.iter().cloned().collect(),
                }
            }
            IpNet::V6(p6) => {
                let rib = lock!(self.rib6_in);
                match rib.get(p6) {
                    None => Vec::new(),
                    Some(p) => p.iter().cloned().collect(),
                }
            }
        }
    }

    pub fn get_selected_prefix_paths(&self, prefix: &IpNet) -> Vec<Path> {
        match prefix {
            IpNet::V4(p4) => {
                let rib = lock!(self.rib4_loc);
                match rib.get(p4) {
                    None => Vec::new(),
                    Some(p) => p.iter().cloned().collect(),
                }
            }
            IpNet::V6(p6) => {
                let rib = lock!(self.rib6_loc);
                match rib.get(p6) {
                    None => Vec::new(),
                    Some(p) => p.iter().cloned().collect(),
                }
            }
        }
    }

    fn update_rib4_loc(
        &self,
        rib_in: &Rib4,
        rib_loc: &mut Rib4,
        prefix: &Ipv4Net,
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
                match bestpaths(paths, fanout.get().into()) {
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

    fn update_rib6_loc(
        &self,
        rib_in: &Rib6,
        rib_loc: &mut Rib6,
        prefix: &Ipv6Net,
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
                match bestpaths(paths, fanout.get().into()) {
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
        F: Fn(&IpNet, &BTreeSet<Path>) -> bool,
    {
        // Fetch fanout once before the loops to avoid repeated sled access
        let fanout = self.get_bestpath_fanout().unwrap_or_else(|e| {
            rdb_log!(
                self,
                error,
                "failed to get bestpath fanout: {e}";
                "unit" => UNIT_RIB
            );
            NonZeroU8::new(DEFAULT_BESTPATH_FANOUT).unwrap()
        });

        {
            // only grab the lock once, release it once the loop ends
            let rib4_in = lock!(self.rib4_in);
            let mut rib4_loc = lock!(self.rib4_loc);
            for (prefix, paths) in rib4_in.iter() {
                if bestpath_needed(&IpNet::from(*prefix), paths) {
                    Self::update_rib_loc(
                        prefix,
                        paths,
                        &mut rib4_loc,
                        fanout.get().into(),
                    );
                }
            }
        }

        {
            // only grab the lock once, release it once the loop ends
            let rib6_in = lock!(self.rib6_in);
            let mut rib6_loc = lock!(self.rib6_loc);
            for (prefix, paths) in rib6_in.iter() {
                if bestpath_needed(&IpNet::from(*prefix), paths) {
                    Self::update_rib_loc(
                        prefix,
                        paths,
                        &mut rib6_loc,
                        fanout.get().into(),
                    );
                }
            }
        }

        self.revalidate_mrib(None);
    }

    fn update_rib_loc<P: Ord + Copy>(
        prefix: &P,
        paths: &BTreeSet<Path>,
        rib_loc: &mut BTreeMap<P, BTreeSet<Path>>,
        fanout: usize,
    ) {
        match bestpaths(paths, fanout) {
            Some(bp) => {
                rib_loc.insert(*prefix, bp);
            }
            None => {
                rib_loc.remove(prefix);
            }
        }
    }

    /// Whether the first of `candidates` present in `rib` has at least one
    /// active path.
    ///
    /// `candidates` runs from the longest prefix width to the shortest, and
    /// the first hit is the longest-prefix match. For a W-bit address, there
    /// are at most W + 1 exact-key lookups. With N loc-rib entries and p
    /// paths on the longest match, the cost is O(W log N + p).
    ///
    /// This relies on loc-rib keys having their host bits unset.
    // TODO: Enforce canonical loc-rib keys in rdb by normalizing or
    // rejecting host bits in `add_static_routes`, `remove_static_routes`,
    // and `add_bgp_prefixes`. Preserve removal of legacy persisted keys
    // with the host bits set.
    fn longest_match_is_active<P: Ord>(
        rib: &BTreeMap<P, BTreeSet<Path>>,
        mut candidates: impl Iterator<Item = P>,
    ) -> bool {
        candidates
            .find_map(|prefix| rib.get(&prefix))
            .is_some_and(|paths| paths.iter().any(|p| !p.shutdown))
    }

    fn add_prefix4_path(
        &self,
        p4: &Ipv4Net,
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
        p6: &Ipv6Net,
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

    fn add_prefix_path(&self, prefix: &IpNet, path: &Path) {
        match prefix {
            IpNet::V4(p4) => {
                let mut rib_in = lock!(self.rib4_in);
                let mut rib_loc = lock!(self.rib4_loc);
                self.add_prefix4_path(p4, path, &mut rib_in, &mut rib_loc);
            }
            IpNet::V6(p6) => {
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
                    IpNet::V4(_) => v4.push(srk),
                    IpNet::V6(_) => v6.push(srk),
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

    pub fn add_bgp_prefixes(&self, prefixes: &[IpNet], path: Path) {
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
        // Fetch fanout once before modifying paths
        let fanout = self.get_bestpath_fanout().unwrap_or_else(|e| {
            rdb_log!(
                self,
                error,
                "failed to get bestpath fanout: {e}";
                "unit" => UNIT_RIB
            );
            NonZeroU8::new(DEFAULT_BESTPATH_FANOUT).unwrap()
        });

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
                        paths.replace(replacement);
                        pcn.changed.insert(IpNet::from(*prefix));
                    }
                }
            }
            for prefix in pcn.changed.iter() {
                if let IpNet::V4(p4) = prefix
                    && let Some(paths) = rib4_in.get(p4)
                {
                    Self::update_rib_loc(
                        p4,
                        paths,
                        &mut rib4_loc,
                        fanout.get().into(),
                    );
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
                        paths.replace(replacement);
                        pcn6.changed.insert(IpNet::from(*prefix));
                    }
                }
            }
            for prefix in pcn6.changed.iter() {
                if let IpNet::V6(p6) = prefix
                    && let Some(paths) = rib6_in.get(p6)
                {
                    Self::update_rib_loc(
                        p6,
                        paths,
                        &mut rib6_loc,
                        fanout.get().into(),
                    );
                }
            }
        }

        pcn.changed.extend(pcn6.changed);
        self.notify(pcn);
    }

    fn remove_prefix4_path<F>(
        &self,
        prefix: &Ipv4Net,
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
        prefix: &Ipv6Net,
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

    fn remove_prefix_path<F>(&self, prefix: &IpNet, prefix_cmp: F)
    where
        F: Fn(&Path) -> bool,
    {
        match prefix {
            IpNet::V4(p4) => {
                let mut rib_in = lock!(self.rib4_in);
                let mut rib_loc = lock!(self.rib4_loc);
                self.remove_prefix4_path(
                    p4,
                    prefix_cmp,
                    &mut rib_in,
                    &mut rib_loc,
                );
            }
            IpNet::V6(p6) => {
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
        prefixes: &[Ipv4Net],
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
        prefixes: &[Ipv6Net],
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

    fn remove_path_for_prefixes<F>(&self, prefixes: &[IpNet], prefix_cmp: F)
    where
        F: Fn(&Path) -> bool,
    {
        // split prefixes into v4 and v6 groups. this allows us to lock the v4
        // and v6 RIBs independently, preventing operations for one protocol
        // from inhibiting the other.
        let (prefixes4, prefixes6) = prefixes.iter().cloned().fold(
            (Vec::new(), Vec::new()),
            |(mut v4, mut v6), prefix| {
                match prefix {
                    IpNet::V4(p4) => v4.push(p4),
                    IpNet::V6(p6) => v6.push(p6),
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
                    IpNet::V4(_) => r4.push(*srk),
                    IpNet::V6(_) => r6.push(*srk),
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
    pub fn remove_bgp_prefixes(&self, prefixes: &[IpNet], peer: &PeerId) {
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

    /// Select or withdraw the `(S,G)` routes in `keys` by the reachability of
    /// their shared `source` in the unicast loc-rib.
    ///
    /// Reachability is governed by the longest-prefix match over the IP
    /// family's loc-rib, with a default route accepted as the last possible
    /// match.
    ///
    /// The longest-prefix match must carry at least one path that is not
    /// marked for shutdown. If it carries just shutdown paths, the source is
    /// unreachable, even when a shorter covering prefix, e.g., the default
    /// route, has active paths.
    ///
    /// Keys are processed in chunks of [`MRIB_SOURCE_CHUNK`]. Each chunk is
    /// checked and applied while the IP family's loc-rib lock is held.
    /// Updates to the same key follow the order of their reachability checks.
    /// Reachability is rechecked on each chunk, as the loc-rib may change
    /// between chunks.
    ///
    /// NOTE: Selection of a source is not atomic. Between chunks, readers of
    /// `mrib_loc` can see some of the source's keys updated and others still
    /// pending. The caller notifies after processing all chunks. A watcher
    /// handling an earlier notification can still observe a partial update.
    ///
    /// Returns the keys whose `mrib_loc` entry was modified.
    fn select_by_source(
        &self,
        source: IpAddr,
        keys: &[MulticastRouteKey],
    ) -> BTreeSet<MulticastRouteKey> {
        let mut changed = BTreeSet::new();
        for chunk in keys.chunks(MRIB_SOURCE_CHUNK) {
            let selected = match source {
                IpAddr::V4(addr) => {
                    let rib = lock!(self.rib4_loc);
                    let host = Ipv4Net::host_net(addr);
                    let reachable = Self::longest_match_is_active(
                        &rib,
                        (0..=host.width())
                            .rev()
                            .filter_map(|width| host.resize(width, 0).ok()),
                    );
                    self.mrib.set_source_reachable(chunk, reachable)
                }
                IpAddr::V6(addr) => {
                    let rib = lock!(self.rib6_loc);
                    let host = Ipv6Net::host_net(addr);
                    let reachable = Self::longest_match_is_active(
                        &rib,
                        (0..=host.width())
                            .rev()
                            .filter_map(|width| host.resize(width, 0).ok()),
                    );
                    self.mrib.set_source_reachable(chunk, reachable)
                }
            };
            changed.extend(selected);
        }
        changed
    }

    fn notify_mrib(&self, changed: BTreeSet<MulticastRouteKey>) {
        if !changed.is_empty() {
            self.mrib.notify(MribChangeNotification { changed });
        }
    }

    /// Re-run `(S,G)` selection via [`Self::select_by_source`] after the
    /// unicast loc-rib changes.
    ///
    /// Callers must not hold `rib4_loc` or `rib6_loc` because reachability
    /// checks acquire them per chunk.
    ///
    /// With `Some(changed)`, only sources covered by changed prefixes of the
    /// same IP family are revisited. Changes outside those ranges cannot alter
    /// a source's longest-prefix match. An empty set does no work.
    ///
    /// Affected routes are discovered via a range query over the MRIB's source
    /// index. Routes sharing a source use one reachability check per chunk of
    /// [`MRIB_SOURCE_CHUNK`] keys.
    ///
    /// A `changed` value of `None` revisits every `(S,G)` route after a
    /// bestpath rerun.
    fn revalidate_mrib(&self, changed: Option<&BTreeSet<IpNet>>) {
        if changed.is_some_and(BTreeSet::is_empty) {
            return;
        }

        let mut updated = BTreeSet::new();
        for (source, keys) in self.mrib.source_specific_keys(changed) {
            updated.extend(self.select_by_source(source, &keys));
        }

        self.notify_mrib(updated);
    }

    /// Restore persisted static multicast routes during construction.
    fn load_static_mcast_routes(&self) -> Result<(), Error> {
        let store = lock!(self.static_mcast_store);
        let changed = self.apply_static_mcast_routes(store.list()?);
        self.notify_mrib(changed);
        Ok(())
    }

    /// Add `routes` to `mrib_in` and run selection.
    ///
    /// A `(*,G)` route is always selected. `(S,G)` routes are grouped by source
    /// for [`Self::select_by_source`].
    ///
    /// Returns the keys whose `mrib_in` or `mrib_loc` entry was modified.
    fn apply_static_mcast_routes(
        &self,
        routes: impl IntoIterator<Item = MulticastRoute>,
    ) -> BTreeSet<MulticastRouteKey> {
        let mut changed = BTreeSet::new();
        let mut by_source: BTreeMap<IpAddr, Vec<MulticastRouteKey>> =
            BTreeMap::new();
        for route in routes {
            // TODO: Handle dynamically learned origins (IGMP, MLD) when they
            // are added to `MulticastSourceProtocol`.
            let MulticastSourceProtocol::Static = route.source;
            let key = route.key;
            if self.mrib.add_route(route) {
                changed.insert(key);
            }
            match key.source() {
                None => {
                    if self.mrib.select_any_source(&key) {
                        changed.insert(key);
                    }
                }
                Some(source) => by_source.entry(source).or_default().push(key),
            }
        }
        for (source, keys) in by_source {
            changed.extend(self.select_by_source(source, &keys));
        }
        changed
    }

    /// Persist static multicast routes and apply them to the MRIB.
    ///
    /// Routes with the same key replace the previous configuration. An
    /// unchanged route preserves both timestamps. Selection is rerun against
    /// the current unicast loc-rib.
    ///
    /// # Errors
    ///
    /// Returns an error if route serialization, storage, or flushing fails.
    pub fn add_static_mcast_routes(
        &self,
        routes: &[MulticastRoute],
    ) -> Result<(), Error> {
        let store = lock!(self.static_mcast_store);

        // Flush before updating the MRIB, as consumers may act on
        // notifications immediately.
        let normalized = store.upsert(routes)?;

        let changed = self.apply_static_mcast_routes(normalized);
        self.notify_mrib(changed);
        Ok(())
    }

    /// Remove static multicast routes from persistence and the MRIB.
    ///
    /// Routes are removed from persistence and from both `mrib_in` and
    /// `mrib_loc`.
    ///
    /// # Errors
    ///
    /// Returns an error if key serialization, storage, or flushing fails.
    pub fn remove_static_mcast_routes(
        &self,
        keys: &[MulticastRouteKey],
    ) -> Result<(), Error> {
        let store = lock!(self.static_mcast_store);
        store.remove(keys)?;
        self.notify_mrib(self.mrib.remove_routes(keys));

        Ok(())
    }

    /// Get all static multicast routes from persistence.
    ///
    /// Invalid entries are logged and skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if the persistent tree cannot be read.
    pub fn get_static_mcast_routes(
        &self,
    ) -> Result<Vec<MulticastRoute>, Error> {
        lock!(self.static_mcast_store).list()
    }

    /// Get a multicast route from `mrib_in`.
    pub fn get_mcast_route(
        &self,
        key: &MulticastRouteKey,
    ) -> Option<MulticastRoute> {
        self.mrib.get_route(key)
    }

    /// Get the MRIB input table, optionally filtered by address family.
    ///
    /// `None` includes both address families.
    pub fn full_mrib(&self, af: Option<AddressFamily>) -> MribTable {
        self.mrib.full_mrib(af)
    }

    /// Get the selected MRIB table, optionally filtered by address family.
    ///
    /// `None` includes both address families.
    pub fn loc_mrib(&self, af: Option<AddressFamily>) -> MribTable {
        self.mrib.loc_mrib(af)
    }

    /// Get a specific multicast route from `mrib_loc` (selected routes).
    pub fn get_selected_mcast_route(
        &self,
        key: &MulticastRouteKey,
    ) -> Option<MulticastRoute> {
        self.mrib.get_selected_route(key)
    }

    /// Register a watcher for MRIB changes.
    pub fn watch_mrib(
        &self,
        tag: String,
        sender: Sender<MribChangeNotification>,
    ) {
        self.mrib.watch(tag, sender);
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
        StaticRouteKey,
        db::{Db, MRIB_SOURCE_CHUNK},
        test::{TestDb, underlay_group, vni},
        types::{
            Asn, MulticastAddr, MulticastAddrV4, MulticastAddrV6,
            MulticastRoute, MulticastRouteKey, MulticastSourceProtocol,
            PrefixDbKey, UnderlayMulticastIpv6, UnicastAddrV4, UnicastAddrV6,
            test_helpers::path_vecs_equal,
        },
    };
    use client_common::eprintln_nopipe;
    use mg_api_types::rdb::DEFAULT_RIB_PRIORITY_STATIC;
    use mg_api_types::rdb::path::Path;
    use mg_api_types::rdb::rib::AddressFamily;
    use mg_common::lock;
    use mg_common::log::*;
    use oxnet::{IpNet, Ipv4Net, Ipv6Net};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::mpsc;

    fn get_test_db() -> TestDb {
        let log = init_file_logger("rib.log");
        crate::test::get_test_db("rib_test", log).expect("create db")
    }

    pub fn check_prefix_path(
        db: &Db,
        prefix: &IpNet,
        rib_in_paths: Vec<Path>,
        loc_rib_paths: Vec<Path>,
    ) -> bool {
        let curr_rib_in_paths = db.get_prefix_paths(prefix);
        if !path_vecs_equal(&curr_rib_in_paths, &rib_in_paths) {
            eprintln_nopipe!("curr_rib_in_paths: {:?}", curr_rib_in_paths);
            eprintln_nopipe!("rib_in_paths: {:?}", rib_in_paths);
            return false;
        }

        let curr_loc_rib_paths = db.get_selected_prefix_paths(prefix);
        if !path_vecs_equal(&curr_loc_rib_paths, &loc_rib_paths) {
            eprintln_nopipe!("curr_loc_rib_paths: {:?}", curr_loc_rib_paths);
            eprintln_nopipe!("loc_rib_paths: {:?}", loc_rib_paths);
            return false;
        }
        true
    }

    #[test]
    fn test_rib() {
        use crate::StaticRouteKey;
        use crate::db::Db;
        use mg_api_types::bgp::peer::PeerId;
        use mg_api_types::rdb::path::{BgpPathProperties, Path};
        use mg_api_types::rdb::{
            DEFAULT_RIB_PRIORITY_BGP, DEFAULT_RIB_PRIORITY_STATIC,
        };
        use oxnet::{IpNet, Ipv4Net};
        // init test vars
        let p0 = IpNet::from("192.168.0.0/24".parse::<Ipv4Net>().unwrap());
        let p1 = IpNet::from("192.168.1.0/24".parse::<Ipv4Net>().unwrap());
        let p2 = IpNet::from("192.168.2.0/24".parse::<Ipv4Net>().unwrap());
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
        // - p0 via static_path1, bgp_path0 (static before BGP)
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
        db.remove_bgp_prefixes(&[p2], &bgp_path1.clone().bgp.unwrap().peer);
        // expected current state
        // rib_in:
        // - p0 via static_path1, bgp_path0 (static before BGP)
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
    fn test_mrib_revalidation_on_rib_change() {
        // Exercise selection and withdrawal for both address families.
        fn test_address_family<P: Into<IpNet> + Copy>(
            db: &Db,
            source: IpAddr,
            prefix: P,
            nexthop: IpAddr,
            group: MulticastAddr,
        ) {
            let static_route = StaticRouteKey {
                prefix: prefix.into(),
                nexthop,
                vlan_id: None,
                rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
            };
            db.add_static_routes(&[static_route]).unwrap();

            let key = MulticastRouteKey::new(Some(source), group, vni())
                .expect("valid unicast source in the group's address family");
            let route = MulticastRoute::new(
                key,
                underlay_group(),
                MulticastSourceProtocol::Static,
            );
            db.add_static_mcast_routes(&[route]).unwrap();

            assert!(
                db.get_selected_mcast_route(&key).is_some(),
                "(S,G) was not selected initially"
            );

            db.remove_static_routes(&[static_route]).unwrap();

            assert!(
                db.get_selected_mcast_route(&key).is_none(),
                "(S,G) remained selected after unicast route removed"
            );

            db.add_static_routes(&[static_route]).unwrap();

            assert!(
                db.get_selected_mcast_route(&key).is_some(),
                "(S,G) not re-selected after unicast route restored"
            );

            db.remove_static_routes(&[static_route]).unwrap();
            db.remove_static_mcast_routes(&[key]).unwrap();
        }

        let log = init_file_logger("mrib_reval.log");
        let db =
            crate::test::get_test_db("mrib_reval", log).expect("create db");

        // IPv4
        test_address_family(
            &db,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            "192.0.2.0/24".parse::<Ipv4Net>().unwrap(),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            MulticastAddr::new_v4(225, 1, 1, 1).expect("valid mcast"),
        );

        // IPv6
        test_address_family(
            &db,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10)),
            "2001:db8::/32".parse::<Ipv6Net>().unwrap(),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            MulticastAddr::new_v6([0xff0e, 0, 0, 0, 0, 0, 0, 1])
                .expect("valid mcast"),
        );
    }

    #[test]
    fn test_mrib_default_route_and_shutdown_path() {
        let log = init_file_logger("mrib_default.log");
        let db =
            crate::test::get_test_db("mrib_default", log).expect("create db");

        let source = UnicastAddrV4::new(Ipv4Addr::new(203, 0, 113, 9))
            .expect("valid unicast");
        let group = MulticastAddrV4::new(Ipv4Addr::new(232, 9, 9, 9))
            .expect("valid mcast");
        let key = MulticastRouteKey::source_specific_v4(source, group, vni());
        let route = MulticastRoute::new(
            key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );
        db.add_static_mcast_routes(&[route]).unwrap();
        assert!(db.get_selected_mcast_route(&key).is_none());

        let nexthop = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let default = StaticRouteKey {
            prefix: "0.0.0.0/0".parse::<Ipv4Net>().unwrap().into(),
            nexthop,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        db.add_static_routes(&[default]).unwrap();
        assert!(
            db.get_selected_mcast_route(&key).is_some(),
            "default route should resolve the source"
        );

        db.set_nexthop_shutdown(nexthop, true);
        assert!(
            db.get_selected_mcast_route(&key).is_none(),
            "shutdown path should not resolve the source"
        );

        db.set_nexthop_shutdown(nexthop, false);
        assert!(db.get_selected_mcast_route(&key).is_some());

        let specific_nexthop = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let specific = StaticRouteKey {
            prefix: "203.0.113.0/24".parse::<Ipv4Net>().unwrap().into(),
            nexthop: specific_nexthop,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        db.add_static_routes(&[specific]).unwrap();
        assert!(db.get_selected_mcast_route(&key).is_some());

        db.set_nexthop_shutdown(specific_nexthop, true);
        assert!(
            db.get_selected_mcast_route(&key).is_none(),
            "shut-down longest match wins over a live default route"
        );

        let host: Ipv4Net = "203.0.113.9/32".parse().unwrap();
        let host_path = Path::from(StaticRouteKey {
            prefix: host.into(),
            nexthop,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        });
        db.add_prefix_path(&host.into(), &host_path);

        let unrelated = StaticRouteKey {
            prefix: "192.0.2.0/24".parse::<Ipv4Net>().unwrap().into(),
            nexthop,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        db.add_static_routes(&[unrelated]).unwrap();
        assert!(
            db.get_selected_mcast_route(&key).is_none(),
            "change to a prefix not covering the source leaves selection alone"
        );

        let covering = StaticRouteKey {
            prefix: "203.0.113.0/26".parse::<Ipv4Net>().unwrap().into(),
            nexthop,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        db.add_static_routes(&[covering]).unwrap();
        assert!(
            db.get_selected_mcast_route(&key).is_some(),
            "change to a prefix covering the source revalidates it"
        );

        db.remove_path_for_prefixes(&[host.into()], |path| *path == host_path);
        db.remove_static_routes(&[unrelated, covering]).unwrap();
        assert!(db.get_selected_mcast_route(&key).is_none());

        db.set_nexthop_shutdown(specific_nexthop, false);
        assert!(db.get_selected_mcast_route(&key).is_some());

        let (tx, rx) = mpsc::channel();
        db.watch_mrib("test".to_string(), tx);
        db.remove_static_mcast_routes(&[key]).unwrap();
        let n = rx.try_recv().expect("removing a selected route notifies");
        assert!(n.changed.contains(&key));
        assert!(db.get_mcast_route(&key).is_none());
        assert!(db.get_selected_mcast_route(&key).is_none());
        assert!(db.full_mrib(None).is_empty());
        assert!(db.loc_mrib(None).is_empty());

        db.remove_static_routes(&[default, specific]).unwrap();
    }

    /// An idempotent static replay preserves timestamps without notifying
    /// watchers.
    #[test]
    fn test_mrib_static_replay_keeps_timestamps() {
        let log = init_file_logger("mrib_replay_timestamps.log");
        let db = crate::test::get_test_db("mrib_replay_timestamps", log)
            .expect("create db");

        let nexthop = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let static_route = StaticRouteKey {
            prefix: "192.0.2.0/24".parse::<Ipv4Net>().unwrap().into(),
            nexthop,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        db.add_static_routes(&[static_route]).unwrap();

        let key = MulticastRouteKey::new(
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            MulticastAddr::new_v4(225, 1, 1, 2).expect("valid mcast"),
            vni(),
        )
        .expect("valid unicast source in the group's address family");

        let route = MulticastRoute::new(
            key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );
        db.add_static_mcast_routes(&[route]).unwrap();

        assert!(
            db.get_selected_mcast_route(&key).is_some(),
            "(S,G) was not selected"
        );

        let before = db.get_mcast_route(&key).expect("route in mrib_in");

        let persisted_before = db
            .get_static_mcast_routes()
            .unwrap()
            .into_iter()
            .find(|r| r.key == key)
            .expect("route persisted");

        let (tx, rx) = mpsc::channel();
        db.watch_mrib("test".to_string(), tx);

        let mut replay = MulticastRoute::new(
            key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );
        let past = chrono::DateTime::UNIX_EPOCH;
        replay.created = past;
        replay.updated = past;
        db.add_static_mcast_routes(&[replay]).unwrap();
        assert!(
            rx.try_recv().is_err(),
            "idempotent upsert notified a watcher"
        );

        let after = db.get_mcast_route(&key).expect("route in mrib_in");
        assert_eq!(
            after.created, before.created,
            "idempotent upsert changed mrib_in.created"
        );
        assert_eq!(
            after.updated, before.updated,
            "idempotent upsert changed mrib_in.updated"
        );

        let persisted = db
            .get_static_mcast_routes()
            .unwrap()
            .into_iter()
            .find(|r| r.key == key)
            .expect("route persisted");

        assert_eq!(
            persisted.created, persisted_before.created,
            "idempotent upsert changed persisted created timestamp"
        );
        assert_eq!(
            persisted.updated, persisted_before.updated,
            "idempotent upsert changed persisted updated timestamp"
        );

        db.remove_static_routes(&[static_route]).unwrap();
        db.remove_static_mcast_routes(&[key]).unwrap();
    }

    #[test]
    fn test_mrib_static_update_refreshes_route() {
        let log = init_file_logger("mrib_update.log");
        let db =
            crate::test::get_test_db("mrib_update", log).expect("create db");

        let static_route = StaticRouteKey {
            prefix: "192.0.2.0/24".parse::<Ipv4Net>().unwrap().into(),
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        db.add_static_routes(&[static_route]).unwrap();

        let key = MulticastRouteKey::new(
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            MulticastAddr::new_v4(225, 1, 1, 2).expect("valid mcast"),
            vni(),
        )
        .expect("valid unicast source in the group address family");
        let route = MulticastRoute {
            created: chrono::DateTime::UNIX_EPOCH,
            updated: chrono::DateTime::UNIX_EPOCH,
            ..MulticastRoute::new(
                key,
                underlay_group(),
                MulticastSourceProtocol::Static,
            )
        };
        db.add_static_mcast_routes(std::slice::from_ref(&route))
            .unwrap();
        assert_eq!(db.get_selected_mcast_route(&key), Some(route.clone()));

        let (tx, rx) = mpsc::channel();
        db.watch_mrib("test".to_string(), tx);

        let timestamp =
            chrono::DateTime::UNIX_EPOCH + chrono::Duration::seconds(1);
        let replacement = MulticastRoute {
            underlay_group: UnderlayMulticastIpv6::new(Ipv6Addr::new(
                0xff04, 0, 0, 0, 0, 0, 0, 2,
            ))
            .expect("valid underlay group"),
            created: timestamp,
            updated: timestamp,
            ..route.clone()
        };
        db.add_static_mcast_routes(std::slice::from_ref(&replacement))
            .unwrap();

        let after = db.get_mcast_route(&key).expect("route in mrib_in");
        assert_eq!(after.underlay_group, replacement.underlay_group);
        assert_eq!(after.created, route.created);
        assert!(after.updated > replacement.updated);
        assert_eq!(db.get_selected_mcast_route(&key), Some(after.clone()));
        assert_eq!(db.get_static_mcast_routes().unwrap(), vec![after]);

        let n = rx.try_recv().expect("update notifies");
        assert_eq!(n.changed, [key].into_iter().collect());
        assert!(rx.try_recv().is_err(), "one notification per update");

        db.remove_static_mcast_routes(&[key]).unwrap();
        db.remove_static_routes(&[static_route]).unwrap();
    }

    /// Test `(*,G)` vs `(S,G)` selection behavior.
    ///
    /// - `(*,G)` routes are always selected
    /// - `(S,G)` routes require a unicast route to the source
    #[test]
    fn test_mrib_any_source_vs_source_specific() {
        let log = init_file_logger("mrib_asm_ssm.log");
        let db =
            crate::test::get_test_db("mrib_asm_ssm", log).expect("create db");

        let asm_group =
            MulticastAddr::new_v4(225, 5, 5, 5).expect("valid mcast");
        let star_g_key =
            MulticastRouteKey::any_source(asm_group, vni()).expect("ASM group");
        let star_g_route = MulticastRoute::new(
            star_g_key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );

        db.add_static_mcast_routes(&[star_g_route]).unwrap();

        assert!(
            db.get_selected_mcast_route(&star_g_key).is_some(),
            "(*,G) should be in mrib_loc immediately"
        );
        assert!(
            db.get_mcast_route(&star_g_key).is_some(),
            "(*,G) should also be in mrib_in"
        );

        let ssm_group = MulticastAddrV4::new(Ipv4Addr::new(232, 1, 1, 1))
            .expect("valid mcast");
        let source = UnicastAddrV4::new(Ipv4Addr::new(10, 0, 0, 100))
            .expect("valid unicast");
        let sg_key =
            MulticastRouteKey::source_specific_v4(source, ssm_group, vni());
        let sg_route = MulticastRoute::new(
            sg_key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );

        db.add_static_mcast_routes(&[sg_route]).unwrap();

        assert!(
            db.get_mcast_route(&sg_key).is_some(),
            "(S,G) should be in mrib_in"
        );
        assert!(
            db.get_selected_mcast_route(&sg_key).is_none(),
            "(S,G) should NOT be in mrib_loc without unicast route"
        );

        let v6_group =
            MulticastAddr::new_v6([0xff0e, 0, 0, 0, 0, 0, 0, 0x5555])
                .expect("valid mcast");
        let v6_star_g_key =
            MulticastRouteKey::any_source(v6_group, vni()).expect("ASM group");
        let v6_star_g_route = MulticastRoute::new(
            v6_star_g_key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );

        db.add_static_mcast_routes(&[v6_star_g_route]).unwrap();

        assert!(
            db.get_selected_mcast_route(&v6_star_g_key).is_some(),
            "IPv6 (*,G) should be selected immediately"
        );

        let v6_ssm_group = MulticastAddrV6::new(Ipv6Addr::new(
            0xff3e, 0, 0, 0, 0, 0, 0x8000, 0x1234,
        ))
        .expect("valid mcast");
        let v6_source = UnicastAddrV6::new(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100,
        ))
        .expect("valid unicast");
        let v6_sg_key = MulticastRouteKey::source_specific_v6(
            v6_source,
            v6_ssm_group,
            vni(),
        );
        let v6_sg_route = MulticastRoute::new(
            v6_sg_key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );

        db.add_static_mcast_routes(&[v6_sg_route]).unwrap();

        assert!(
            db.get_mcast_route(&v6_sg_key).is_some(),
            "IPv6 (S,G) should be in mrib_in"
        );
        assert!(
            db.get_selected_mcast_route(&v6_sg_key).is_none(),
            "IPv6 (S,G) should NOT be in mrib_loc without unicast route"
        );

        db.remove_static_mcast_routes(&[
            star_g_key,
            sg_key,
            v6_star_g_key,
            v6_sg_key,
        ])
        .unwrap();
    }

    #[test]
    fn test_mrib_static_persistence() {
        let db_path =
            format!("/tmp/mrib_persist_test_{}.db", std::process::id());
        let _ = std::fs::remove_dir_all(&db_path);

        let group = MulticastAddr::new_v4(225, 2, 2, 2).expect("valid mcast");
        let key =
            MulticastRouteKey::any_source(group, vni()).expect("ASM group");
        let route = MulticastRoute::new(
            key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );

        let source = UnicastAddrV4::new(Ipv4Addr::new(10, 2, 2, 2))
            .expect("valid unicast");
        let sg_group = MulticastAddrV4::new(Ipv4Addr::new(232, 2, 2, 2))
            .expect("valid mcast");
        let sg_key =
            MulticastRouteKey::source_specific_v4(source, sg_group, vni());
        let sg_route = MulticastRoute::new(
            sg_key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );
        let static_route = StaticRouteKey {
            prefix: "10.2.2.0/24".parse::<Ipv4Net>().unwrap().into(),
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        // Persist both wildcard and source-specific routes.
        {
            let log = init_file_logger("mrib_persist1.log");
            let db = Db::new(&db_path, log).expect("create db");
            db.add_static_mcast_routes(&[route, sg_route])
                .expect("add static mcast routes");
            assert_eq!(db.get_static_mcast_routes().unwrap().len(), 2);
            assert!(db.get_mcast_route(&key).is_some());
            assert!(db.get_mcast_route(&sg_key).is_some());
        }

        // Reload with no unicast route for the source.
        {
            let log = init_file_logger("mrib_persist2.log");
            let db = Db::new(&db_path, log).expect("reopen db");
            assert_eq!(db.full_mrib(None).len(), 2);
            assert!(db.get_selected_mcast_route(&key).is_some());
            assert!(db.get_mcast_route(&sg_key).is_some());
            assert!(db.get_selected_mcast_route(&sg_key).is_none());
            assert_eq!(db.get_static_mcast_routes().unwrap().len(), 2);
            db.add_static_routes(&[static_route]).unwrap();
            assert!(db.get_selected_mcast_route(&key).is_some());
            assert!(db.get_selected_mcast_route(&sg_key).is_some());
        }

        let _ = std::fs::remove_dir_all(&db_path);
    }

    #[test]
    fn test_mrib_static_load_skips_undecodable() {
        let db_path =
            format!("/tmp/mrib_load_skip_test_{}.db", std::process::id());
        let _ = std::fs::remove_dir_all(&db_path);

        let group = MulticastAddr::new_v4(225, 3, 3, 3).expect("valid mcast");
        let key =
            MulticastRouteKey::any_source(group, vni()).expect("ASM group");
        let route = MulticastRoute::new(
            key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );

        let other_group =
            MulticastAddr::new_v4(225, 4, 4, 4).expect("valid mcast");
        let other_key = MulticastRouteKey::any_source(other_group, vni())
            .expect("ASM group");

        let bad_json_group =
            MulticastAddr::new_v4(225, 5, 5, 5).expect("valid mcast");
        let bad_json_key = MulticastRouteKey::any_source(bad_json_group, vni())
            .expect("ASM group");

        // Write a valid entry and three corrupt ones.
        {
            let log = init_file_logger("mrib_load_skip1.log");
            let db = Db::new(&db_path, log).expect("create db");
            db.add_static_mcast_routes(std::slice::from_ref(&route))
                .unwrap();

            let store = lock!(db.static_mcast_store);
            let tree = store.tree();
            tree.insert(b"garbage-key", b"garbage-value").unwrap();
            let corrupt_route = MulticastRoute {
                created: chrono::DateTime::UNIX_EPOCH,
                updated: chrono::DateTime::UNIX_EPOCH,
                ..route
            };
            tree.insert(
                serde_json::to_vec(&other_key).unwrap(),
                serde_json::to_vec(&corrupt_route).unwrap(),
            )
            .unwrap();
            tree.insert(serde_json::to_vec(&bad_json_key).unwrap(), b"{")
                .unwrap();
            tree.flush().unwrap();
        }

        // Reopen, and replace the corrupt entries.
        {
            let log = init_file_logger("mrib_load_skip2.log");
            let db = Db::new(&db_path, log).expect("reopen db");

            let loaded = db.get_static_mcast_routes().unwrap();
            assert_eq!(loaded.len(), 1);
            assert_eq!(loaded[0].key, key);

            assert_eq!(db.full_mrib(None).len(), 1);
            assert!(db.get_mcast_route(&key).is_some());
            assert!(db.get_mcast_route(&other_key).is_none());
            assert!(db.get_mcast_route(&bad_json_key).is_none());

            for replaced in [other_key, bad_json_key] {
                let mut replacement = MulticastRoute::new(
                    replaced,
                    underlay_group(),
                    MulticastSourceProtocol::Static,
                );
                let timestamp =
                    chrono::DateTime::UNIX_EPOCH + chrono::Duration::seconds(1);
                replacement.created = timestamp;
                replacement.updated = timestamp;
                db.add_static_mcast_routes(std::slice::from_ref(&replacement))
                    .unwrap();

                let persisted = db
                    .get_static_mcast_routes()
                    .unwrap()
                    .into_iter()
                    .find(|route| route.key == replaced)
                    .expect("replacement persisted");
                assert_eq!(persisted, replacement);
                assert_eq!(
                    db.get_mcast_route(&replaced),
                    Some(replacement.clone())
                );
                assert_eq!(
                    db.get_selected_mcast_route(&replaced),
                    Some(replacement)
                );
            }
        }

        let _ = std::fs::remove_dir_all(&db_path);
    }

    #[test]
    fn test_mrib_revalidation_batches_notification() {
        let log = init_file_logger("mrib_reval_batch.log");
        let db = crate::test::get_test_db("mrib_reval_batch", log)
            .expect("create db");

        let group = MulticastAddrV4::new(Ipv4Addr::new(232, 8, 8, 8))
            .expect("valid mcast");
        let keys: Vec<MulticastRouteKey> = [1u8, 2]
            .into_iter()
            .map(|host| {
                let source = UnicastAddrV4::new(Ipv4Addr::new(10, 8, 8, host))
                    .expect("valid unicast");
                MulticastRouteKey::source_specific_v4(source, group, vni())
            })
            .collect();
        let routes: Vec<MulticastRoute> = keys
            .iter()
            .map(|key| {
                MulticastRoute::new(
                    *key,
                    underlay_group(),
                    MulticastSourceProtocol::Static,
                )
            })
            .collect();
        db.add_static_mcast_routes(&routes).unwrap();
        assert!(
            keys.iter()
                .all(|key| db.get_selected_mcast_route(key).is_none())
        );

        let (tx, rx) = mpsc::channel();
        db.watch_mrib("test".to_string(), tx);

        let static_route = StaticRouteKey {
            prefix: "10.8.8.0/24".parse::<Ipv4Net>().unwrap().into(),
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        db.add_static_routes(&[static_route]).unwrap();

        let n = rx.try_recv().expect("revalidation notifies");
        assert_eq!(n.changed, keys.iter().copied().collect());
        assert!(rx.try_recv().is_err(), "one notification per revalidation");
        assert!(
            keys.iter()
                .all(|key| db.get_selected_mcast_route(key).is_some())
        );

        db.remove_static_routes(&[static_route]).unwrap();
        let n = rx.try_recv().expect("deselection notifies");
        assert_eq!(n.changed, keys.iter().copied().collect());
        assert!(rx.try_recv().is_err(), "one notification per revalidation");
        assert!(
            keys.iter()
                .all(|key| db.get_selected_mcast_route(key).is_none())
        );

        db.remove_static_mcast_routes(&keys).unwrap();
    }

    #[test]
    fn test_mrib_revalidation_spans_source_chunks() {
        let log = init_file_logger("mrib_reval_chunks.log");
        let db = crate::test::get_test_db("mrib_reval_chunks", log)
            .expect("create db");

        let source = UnicastAddrV4::new(Ipv4Addr::new(10, 9, 9, 9))
            .expect("valid unicast");
        let count = u8::try_from(MRIB_SOURCE_CHUNK * 2 + 1).unwrap();
        let keys: Vec<MulticastRouteKey> = (1..=count)
            .map(|octet| {
                let group =
                    MulticastAddrV4::new(Ipv4Addr::new(232, 9, 0, octet))
                        .expect("valid mcast");
                MulticastRouteKey::source_specific_v4(source, group, vni())
            })
            .collect();
        let routes: Vec<MulticastRoute> = keys
            .iter()
            .map(|key| {
                MulticastRoute::new(
                    *key,
                    underlay_group(),
                    MulticastSourceProtocol::Static,
                )
            })
            .collect();
        db.add_static_mcast_routes(&routes).unwrap();

        let (tx, rx) = mpsc::channel();
        db.watch_mrib("test".to_string(), tx);

        let static_route = StaticRouteKey {
            prefix: "10.9.9.0/24".parse::<Ipv4Net>().unwrap().into(),
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        db.add_static_routes(&[static_route]).unwrap();

        let n = rx.try_recv().expect("revalidation notifies");
        assert_eq!(n.changed, keys.iter().copied().collect());
        assert!(rx.try_recv().is_err(), "one notification across chunks");
        assert_eq!(db.loc_mrib(None).len(), keys.len());

        db.remove_static_routes(&[static_route]).unwrap();
        let n = rx.try_recv().expect("deselection notifies");
        assert_eq!(n.changed, keys.iter().copied().collect());
        assert!(rx.try_recv().is_err(), "one notification across chunks");
        assert!(db.loc_mrib(None).is_empty());

        db.remove_static_mcast_routes(&keys).unwrap();
    }

    #[test]
    fn test_mrib_static_batch_notifies_once() {
        let log = init_file_logger("mrib_batch_notify.log");
        let db = crate::test::get_test_db("mrib_batch_notify", log)
            .expect("create db");

        db.add_static_routes(&[StaticRouteKey {
            prefix: "10.9.0.0/16".parse::<Ipv4Net>().unwrap().into(),
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        }])
        .unwrap();

        let (tx, rx) = mpsc::channel();
        db.watch_mrib("test".to_string(), tx);

        let any_source = MulticastRouteKey::any_source(
            MulticastAddr::new_v4(225, 9, 9, 9).expect("valid mcast"),
            vni(),
        )
        .expect("ASM group");
        let source_specific = [(1u8, 1u8), (1, 2), (2, 3)].map(|(host, g)| {
            let source = UnicastAddrV4::new(Ipv4Addr::new(10, 9, 0, host))
                .expect("valid unicast");
            let group = MulticastAddrV4::new(Ipv4Addr::new(232, 9, 9, g))
                .expect("valid mcast");
            MulticastRouteKey::source_specific_v4(source, group, vni())
        });
        let keys: Vec<MulticastRouteKey> =
            std::iter::once(any_source).chain(source_specific).collect();

        let routes: Vec<MulticastRoute> = keys
            .iter()
            .map(|key| {
                MulticastRoute::new(
                    *key,
                    underlay_group(),
                    MulticastSourceProtocol::Static,
                )
            })
            .collect();

        db.add_static_mcast_routes(&routes).unwrap();
        let n = rx.try_recv().expect("add notifies");
        assert_eq!(n.changed, keys.iter().copied().collect());
        assert!(rx.try_recv().is_err(), "one notification per add");
        assert_eq!(db.loc_mrib(None).len(), keys.len());

        db.remove_static_mcast_routes(&keys).unwrap();
        let n = rx.try_recv().expect("remove notifies");
        assert_eq!(n.changed, keys.iter().copied().collect());
        assert!(rx.try_recv().is_err(), "one notification per remove");
    }

    #[test]
    fn test_static_routing_ipv4_basic() {
        let db = get_test_db();
        let nexthop = IpAddr::V4(Ipv4Addr::from_str("10.0.0.1").unwrap());

        // Test adding IPv4 static routes
        let prefix4 = Ipv4Net::new_unchecked(
            Ipv4Addr::from_str("192.168.1.0").unwrap(),
            24,
        );
        let static_route = StaticRouteKey {
            prefix: IpNet::V4(prefix4),
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
        assert!(rib_routes.contains_key(&IpNet::V4(prefix4)));

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
        let prefix6 = Ipv6Net::new_unchecked(
            Ipv6Addr::from_str("2001:db8::").unwrap(),
            64,
        );
        let static_route = StaticRouteKey {
            prefix: IpNet::V6(prefix6),
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
        assert!(rib_routes.contains_key(&IpNet::V6(prefix6)));

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
        let prefix6 = Ipv6Net::new_unchecked(
            Ipv6Addr::from_str("2001:db8:1::").unwrap(),
            48,
        );

        // Test route without VLAN ID
        let route_no_vlan = StaticRouteKey {
            prefix: IpNet::V6(prefix6),
            nexthop: IpAddr::V6(Ipv6Addr::from_str("fe80::1").unwrap()),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        // Test route with VLAN ID
        let route_with_vlan = StaticRouteKey {
            prefix: IpNet::V6(prefix6),
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
        let prefix4 =
            Ipv4Net::new_unchecked(Ipv4Addr::from_str("10.0.0.0").unwrap(), 8);
        let prefix6 =
            Ipv6Net::new_unchecked(Ipv6Addr::from_str("fd00::").unwrap(), 8);

        let route4 = StaticRouteKey {
            prefix: IpNet::V4(prefix4),
            nexthop: IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        let route6 = StaticRouteKey {
            prefix: IpNet::V6(prefix6),
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
        let prefix4 = Ipv4Net::new_unchecked(
            Ipv4Addr::from_str("172.16.0.0").unwrap(),
            16,
        );

        // Create multiple routes to the same prefix with different next-hops and priorities
        let route1 = StaticRouteKey {
            prefix: IpNet::V4(prefix4),
            nexthop: IpAddr::V4(Ipv4Addr::from_str("10.0.0.1").unwrap()),
            vlan_id: None,
            rib_priority: 100,
        };

        let route2 = StaticRouteKey {
            prefix: IpNet::V4(prefix4),
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
        let prefix4 = Ipv4Net::new_unchecked(
            Ipv4Addr::from_str("203.0.113.0").unwrap(),
            24,
        );

        // Test route without VLAN ID
        let route_no_vlan = StaticRouteKey {
            prefix: IpNet::V4(prefix4),
            nexthop: IpAddr::V4(Ipv4Addr::from_str("198.51.100.1").unwrap()),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        // Test route with VLAN ID
        let route_with_vlan = StaticRouteKey {
            prefix: IpNet::V4(prefix4),
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

        // Ipv4Net::new_unchecked does NOT zero host bits, so use a proper network address.
        let prefix4 = Ipv4Net::new_unchecked(
            Ipv4Addr::from_str("192.168.1.0").unwrap(),
            24,
        );
        assert_eq!(prefix4.addr(), Ipv4Addr::from_str("192.168.1.0").unwrap());
        assert_eq!(prefix4.width(), 24);

        // Ipv6Net::new_unchecked does NOT zero host bits, so use a proper network address.
        let prefix6 = Ipv6Net::new_unchecked(
            Ipv6Addr::from_str("2001:db8::").unwrap(),
            64,
        );
        assert_eq!(prefix6.addr(), Ipv6Addr::from_str("2001:db8::").unwrap());
        assert_eq!(prefix6.width(), 64);

        // Test with static route to ensure the prefix works through the full stack
        let route = StaticRouteKey {
            prefix: IpNet::V4(prefix4),
            nexthop: IpAddr::V4(Ipv4Addr::from_str("10.0.0.1").unwrap()),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };

        db.add_static_routes(&[route]).unwrap();
        let routes = db.get_static(Some(AddressFamily::Ipv4)).unwrap();
        assert_eq!(routes.len(), 1);

        // Verify the stored route has the correct prefix
        if let IpNet::V4(stored_prefix) = routes[0].prefix {
            assert_eq!(
                stored_prefix.addr(),
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
            Ipv4Net::new_unchecked(Ipv4Addr::new(192, 168, 1, 0), 24),
            Ipv4Net::new_unchecked(Ipv4Addr::new(10, 0, 0, 0), 8),
        ];

        const ASN: Asn = Asn::FourOctet(65001);

        // Create origin4 - should succeed
        db.create_origin4(ASN, &prefixes).expect("create origin4");

        // Get origin4 - should return created prefixes
        let retrieved = db.get_origin4(ASN).expect("get origin4");
        assert_eq!(retrieved.len(), 2);
        assert!(retrieved.contains(&prefixes[0]));
        assert!(retrieved.contains(&prefixes[1]));

        // Try to create again - should fail with conflict
        assert!(db.create_origin4(ASN, &prefixes).is_err());

        // A different ASN must not see the first ASN's origins, and may
        // create its own without conflicting.
        const OTHER_ASN: Asn = Asn::FourOctet(65002);
        assert!(
            db.get_origin4(OTHER_ASN)
                .expect("get other origin4")
                .is_empty()
        );
        let other_prefixes =
            vec![Ipv4Net::new_unchecked(Ipv4Addr::new(203, 0, 113, 0), 24)];
        db.create_origin4(OTHER_ASN, &other_prefixes)
            .expect("create other origin4");
        assert_eq!(db.get_origin4(ASN).expect("get origin4").len(), 2);

        // Update origin4 with different prefixes
        let new_prefixes =
            vec![Ipv4Net::new_unchecked(Ipv4Addr::new(172, 16, 0, 0), 12)];
        db.set_origin4(ASN, &new_prefixes).expect("set origin4");

        let updated = db.get_origin4(ASN).expect("get updated origin4");
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0], new_prefixes[0]);

        // Clear origin4 - must only clear this ASN's entries
        db.clear_origin4(ASN).expect("clear origin4");
        let empty = db.get_origin4(ASN).expect("get empty origin4");
        assert!(empty.is_empty());
        assert_eq!(
            db.get_origin4(OTHER_ASN).expect("get other origin4").len(),
            1
        );

        // Create again after clear - should succeed
        db.create_origin4(ASN, &prefixes)
            .expect("create after clear");
        let final_result = db.get_origin4(ASN).expect("get final origin4");
        assert_eq!(final_result.len(), 2);
    }

    #[test]
    fn test_ipv6_origin_crud() {
        let db = get_test_db();

        // Test creating IPv6 origins
        let prefixes = vec![
            Ipv6Net::new_unchecked(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                32,
            ),
            Ipv6Net::new_unchecked(
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
                8,
            ),
        ];

        const ASN: Asn = Asn::FourOctet(65001);

        // Create origin6 - should succeed
        db.create_origin6(ASN, &prefixes).expect("create origin6");

        // Get origin6 - should return created prefixes
        let retrieved = db.get_origin6(ASN).expect("get origin6");
        assert_eq!(retrieved.len(), 2);
        assert!(retrieved.contains(&prefixes[0]));
        assert!(retrieved.contains(&prefixes[1]));

        // Try to create again - should fail with conflict
        assert!(db.create_origin6(ASN, &prefixes).is_err());

        // A different ASN must not see the first ASN's origins.
        const OTHER_ASN: Asn = Asn::FourOctet(65002);
        assert!(
            db.get_origin6(OTHER_ASN)
                .expect("get other origin6")
                .is_empty()
        );

        // Update origin6 with different prefixes
        let new_prefixes = vec![Ipv6Net::new_unchecked(
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
            48,
        )];
        db.set_origin6(ASN, &new_prefixes).expect("set origin6");

        let updated = db.get_origin6(ASN).expect("get updated origin6");
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0], new_prefixes[0]);

        // Clear origin6
        db.clear_origin6(ASN).expect("clear origin6");
        let empty = db.get_origin6(ASN).expect("get empty origin6");
        assert!(empty.is_empty());

        // Create again after clear - should succeed
        db.create_origin6(ASN, &prefixes)
            .expect("create after clear");
        let final_result = db.get_origin6(ASN).expect("get final origin6");
        assert_eq!(final_result.len(), 2);
    }

    #[test]
    fn test_prefix4_db_key_serialization() {
        let prefix =
            Ipv4Net::new_unchecked(Ipv4Addr::new(192, 168, 100, 0), 24);
        let key = prefix.db_key();

        // IPv4 address should be 4 bytes + 1 byte for length
        assert_eq!(key.len(), 5);
        assert_eq!(key[4], 24); // length byte

        // Test round-trip serialization
        let recovered =
            Ipv4Net::from_db_key(&key).expect("recover from db key");
        assert_eq!(recovered, prefix);
    }

    #[test]
    fn test_prefix6_db_key_serialization() {
        let prefix = Ipv6Net::new_unchecked(
            Ipv6Addr::new(0x2001, 0xdb8, 0xdead, 0xbeef, 0, 0, 0, 0),
            64,
        );
        let key = prefix.db_key();

        // IPv6 address should be 16 bytes + 1 byte for length
        assert_eq!(key.len(), 17);
        assert_eq!(key[16], 64); // length byte

        // Test round-trip serialization
        let recovered =
            Ipv6Net::from_db_key(&key).expect("recover from db key");
        assert_eq!(recovered, prefix);
    }

    #[test]
    fn test_prefix4_from_str() {
        let prefix_str = "192.168.1.0/24";
        let prefix: Ipv4Net = prefix_str.parse().expect("parse IPv4 prefix");
        assert_eq!(prefix.addr(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix.width(), 24);

        // Test invalid format
        assert!("invalid".parse::<Ipv4Net>().is_err());
        assert!("192.168.1".parse::<Ipv4Net>().is_err());
        assert!("192.168.1.0/abc".parse::<Ipv4Net>().is_err());
    }

    /// Regression test for oxidecomputer/maghemite#651.
    ///
    /// `set_nexthop_shutdown` must actually update the `shutdown` field on
    /// existing paths. Before the fix, `BTreeSet::insert` was used instead
    /// of `BTreeSet::replace`, which silently dropped the update because
    /// `shutdown` is not part of `Path::Ord` identity.
    #[test]
    fn test_set_nexthop_shutdown_replaces_path() {
        use crate::StaticRouteKey;
        use mg_api_types::bgp::peer::PeerId;
        use mg_api_types::rdb::path::{BgpPathProperties, Path};
        use mg_api_types::rdb::{
            DEFAULT_RIB_PRIORITY_BGP, DEFAULT_RIB_PRIORITY_STATIC,
        };
        use oxnet::{IpNet, Ipv4Net, Ipv6Net};

        let db = get_test_db();

        // --- IPv4 static path ---
        let nexthop4 = IpAddr::V4(Ipv4Addr::from_str("198.51.100.1").unwrap());
        let prefix4 =
            Ipv4Net::new_unchecked(Ipv4Addr::from_str("10.0.0.0").unwrap(), 24);
        let static_key4 = StaticRouteKey {
            prefix: IpNet::V4(prefix4),
            nexthop: nexthop4,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        db.add_static_routes(&[static_key4]).unwrap();

        // Verify path starts not-shutdown.
        let paths = db.get_prefix_paths(&IpNet::V4(prefix4));
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].shutdown, "static v4 path should start active");

        // Shut it down.
        db.set_nexthop_shutdown(nexthop4, true);
        let paths = db.get_prefix_paths(&IpNet::V4(prefix4));
        assert_eq!(paths.len(), 1);
        assert!(paths[0].shutdown, "static v4 path should be shutdown");

        // Bring it back up.
        db.set_nexthop_shutdown(nexthop4, false);
        let paths = db.get_prefix_paths(&IpNet::V4(prefix4));
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].shutdown, "static v4 path should be active again");

        // --- IPv6 static path ---
        let nexthop6 = IpAddr::V6(Ipv6Addr::from_str("fe80::1").unwrap());
        let prefix6 = Ipv6Net::new_unchecked(
            Ipv6Addr::from_str("2001:db8::").unwrap(),
            48,
        );
        let static_key6 = StaticRouteKey {
            prefix: IpNet::V6(prefix6),
            nexthop: nexthop6,
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        };
        db.add_static_routes(&[static_key6]).unwrap();

        db.set_nexthop_shutdown(nexthop6, true);
        let paths = db.get_prefix_paths(&IpNet::V6(prefix6));
        assert_eq!(paths.len(), 1);
        assert!(paths[0].shutdown, "static v6 path should be shutdown");

        db.set_nexthop_shutdown(nexthop6, false);
        let paths = db.get_prefix_paths(&IpNet::V6(prefix6));
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].shutdown, "static v6 path should be active again");

        // --- IPv4 BGP path ---
        let bgp_nexthop =
            IpAddr::V4(Ipv4Addr::from_str("203.0.113.1").unwrap());
        let bgp_prefix = IpNet::V4(Ipv4Net::new_unchecked(
            Ipv4Addr::from_str("172.16.0.0").unwrap(),
            16,
        ));
        let bgp_path = Path {
            nexthop: bgp_nexthop,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 65001,
                peer: PeerId::Ip(bgp_nexthop),
                id: 1,
                med: None,
                local_pref: Some(100),
                as_path: vec![65001],
                stale: None,
            }),
            vlan_id: None,
        };
        db.add_bgp_prefixes(&[bgp_prefix], bgp_path.clone());

        // Verify path starts not-shutdown.
        let paths = db.get_prefix_paths(&bgp_prefix);
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].shutdown, "bgp path should start active");

        // Shut it down.
        db.set_nexthop_shutdown(bgp_nexthop, true);
        let paths = db.get_prefix_paths(&bgp_prefix);
        assert_eq!(paths.len(), 1);
        assert!(paths[0].shutdown, "bgp path should be shutdown");

        // Bring it back up.
        db.set_nexthop_shutdown(bgp_nexthop, false);
        let paths = db.get_prefix_paths(&bgp_prefix);
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].shutdown, "bgp path should be active again");
    }

    #[test]
    fn test_prefix6_from_str() {
        let prefix_str = "2001:db8::/32";
        let prefix: Ipv6Net = prefix_str.parse().expect("parse IPv6 prefix");
        assert_eq!(
            prefix.addr(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(prefix.width(), 32);

        // Test invalid format
        assert!("invalid".parse::<Ipv6Net>().is_err());
        assert!("2001:db8:".parse::<Ipv6Net>().is_err());
        assert!("2001:db8::/abc".parse::<Ipv6Net>().is_err());
    }
}
