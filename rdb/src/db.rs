//! The routing database (rdb).
//!
//! ## Structure
//!
//! The rdb is a key-value store for routing information. There are a
//! pre-defined set of keys for routing elements such as routes and and
//! nexthops. Each key may exist in multiple key spaces. For example in one
//! keyspace a route key may map to a nexthop, and in another the route key may
//! map to a set of BGP attributes.
//!
//! ### Key Spaces
//!
//! - nexthop:       /:nexthop/:prefix          -> ()
//! - bgp:           /:nexthop/:prefix          -> BgpAttributes
//! - metrics:       /:nexthop:prefix:/:metricy -> u64
//! - bfd:           /:nexthop                  -> Status
//! - import-policy: /:peer/:prefix/:tag        -> Policy
//! - export-policy: /:peer/:prefix/:tag        -> Policy
//!

// TODO: break out key spaces into
// - inbound RIB
// - local RIB
// - outbound RIB

const BGP_ORIGIN: &str = "bgp_origin";
const BGP_ROUTER: &str = "bgp_router";
const BGP_NEIGHBOR: &str = "bgp_neighbor";

use crate::types::*;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Clone)]
pub struct Db {
    persistent: sled::Db,
    imported: Arc<Mutex<HashSet<Route4ImportKey>>>,
    generation: Arc<AtomicU64>,
    watchers: Arc<RwLock<Vec<Sender<ChangeSet>>>>,
}
unsafe impl Sync for Db {}
unsafe impl Send for Db {}

//TODO we need bulk operations with atomic semantics here.
impl Db {
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self {
            persistent: sled::open(path)?,
            imported: Arc::new(Mutex::new(HashSet::new())),
            generation: Arc::new(AtomicU64::new(0)),
            watchers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub fn watch(&self, s: Sender<ChangeSet>) {
        self.watchers.write().unwrap().push(s);
    }

    fn notify(&self, c: ChangeSet) {
        for w in self.watchers.read().unwrap().iter() {
            if let Err(_e) = w.send(c.clone()) {
                //TODO log
            }
        }
    }

    // TODO return previous value if this is an update.
    pub fn add_origin4(&self, r: Route4Key) -> Result<()> {
        let tree = self.persistent.open_tree(BGP_ORIGIN)?;
        tree.insert(r.db_key(), "")?;
        tree.flush()?;
        let g = self.generation.fetch_add(1, Ordering::SeqCst);
        self.notify(ChangeSet::from_origin(OriginChangeSet::added([r]), g + 1));
        Ok(())
    }

    pub fn add_bgp_router(&self, asn: u32, info: BgpRouterInfo) -> Result<()> {
        let tree = self.persistent.open_tree(BGP_ROUTER)?;
        let key = asn.to_string();
        let value = serde_json::to_string(&info)?;
        tree.insert(key.as_str(), value.as_str())?;
        tree.flush()?;
        Ok(())
    }

    pub fn get_bgp_routers(&self) -> Result<HashMap<u32, BgpRouterInfo>> {
        let tree = self.persistent.open_tree(BGP_ROUTER)?;
        let result = tree
            .scan_prefix(vec![])
            .map(|item| {
                // TODO don't unwrap
                let (key, value) = item.unwrap();
                let key = String::from_utf8_lossy(&key).parse().unwrap();
                let value = String::from_utf8_lossy(&value);
                let value: BgpRouterInfo =
                    serde_json::from_str(&value).unwrap();
                (key, value)
            })
            .collect();
        Ok(result)
    }

    pub fn add_bgp_neighbor(&self, nbr: BgpNeighborInfo) -> Result<()> {
        let tree = self.persistent.open_tree(BGP_NEIGHBOR)?;
        let key = nbr.host.ip().to_string();
        let value = serde_json::to_string(&nbr)?;
        tree.insert(key.as_str(), value.as_str())?;
        tree.flush()?;
        Ok(())
    }

    pub fn get_bgp_neighbors(&self) -> Result<Vec<BgpNeighborInfo>> {
        let tree = self.persistent.open_tree(BGP_NEIGHBOR)?;
        let result = tree
            .scan_prefix(vec![])
            .map(|item| {
                // TODO don't unwrap
                let (_key, value) = item.unwrap();
                let value = String::from_utf8_lossy(&value);
                let value: BgpNeighborInfo =
                    serde_json::from_str(&value).unwrap();
                value
            })
            .collect();
        Ok(result)
    }

    pub fn remove_origin4(&self, r: Route4Key) -> Result<()> {
        let tree = self.persistent.open_tree(BGP_ORIGIN)?;
        tree.remove(r.db_key())?;
        let g = self.generation.fetch_add(1, Ordering::SeqCst);
        self.notify(ChangeSet::from_origin(
            OriginChangeSet::removed([r]),
            g + 1,
        ));
        Ok(())
    }

    pub fn get_originated4(&self) -> Result<Vec<Route4Key>> {
        let tree = self.persistent.open_tree(BGP_ORIGIN)?;
        let result = tree
            .scan_prefix(vec![])
            .map(|item| {
                let (key, _) = item.unwrap();
                let key = String::from_utf8_lossy(&key);
                key.parse().unwrap()
            })
            .collect();
        Ok(result)
    }

    pub fn get_nexthop4(&self, prefix: &Prefix4) -> Vec<Route4ImportKey> {
        self.imported
            .lock()
            .unwrap()
            .iter()
            .filter(|x| prefix == &x.prefix)
            .cloned()
            .collect()
    }

    pub fn get_imported4(&self) -> Vec<Route4ImportKey> {
        self.imported.lock().unwrap().clone().into_iter().collect()
    }

    pub fn set_nexthop4(&self, r: Route4ImportKey) {
        self.imported.lock().unwrap().insert(r);
        let g = self.generation.fetch_add(1, Ordering::SeqCst);
        self.notify(ChangeSet::from_import(ImportChangeSet::added([r]), g + 1));
    }

    pub fn remove_nexthop4(&self, r: Route4ImportKey) {
        self.imported.lock().unwrap().remove(&r);
        let g = self.generation.fetch_add(1, Ordering::SeqCst);
        self.notify(ChangeSet::from_import(
            ImportChangeSet::removed([r]),
            g + 1,
        ));
    }

    pub fn remove_peer_nexthop4(&self, id: u32) -> Vec<Route4ImportKey> {
        let mut imported = self.imported.lock().unwrap();
        //TODO do in one pass instead of two
        let result = imported.iter().filter(|x| x.id == id).copied().collect();
        imported.retain(|x| x.id != id);
        result
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
}
