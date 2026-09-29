// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The routing database (rdb).
//!
//! This is the maghemite routing database. It holds routing configuration
//! (BGP routers, neighbors, originated prefixes, static routes and settings)
//! and the routes learned or selected from that configuration. Everything is
//! held in memory; nothing is written to disk, so all of it is lost when the
//! process exits.
use crate::bestpath::bestpaths;
use crate::error::Error;
use crate::log::rdb_log;
use crate::types::*;
use chrono::Utc;
use mg_api_types::bgp::peer::PeerId;
use mg_api_types::rdb::neighbor::{BgpNeighborInfo, BgpUnnumberedNeighborInfo};
use mg_api_types::rdb::path::Path;
use mg_api_types::rdb::rib::AddressFamily;
use mg_api_types::rdb::router::BgpRouterInfo;
use mg_common::{lock, read_lock, write_lock};
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
use slog::{Logger, error};
use std::cmp::Ordering as CmpOrdering;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::num::NonZeroU8;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{sleep, spawn};

const UNIT_RIB: &str = "rib";

/// Default bestpath fanout value. Maximum number of ECMP paths in RIB.
const DEFAULT_BESTPATH_FANOUT: u8 = 1;

use crate::rib::{Rib, Rib4, Rib6};

/// The central routing information base. Both routing configuration and route
/// information is managed through this structure.
#[derive(Clone)]
pub struct Db {
    /// BGP routers, keyed by ASN.
    bgp_routers: Arc<Mutex<BTreeMap<u32, BgpRouterInfo>>>,

    /// BGP neighbors, keyed by the ASN of the router they belong to and the
    /// neighbor's address.
    bgp_neighbors: Arc<Mutex<BTreeMap<(u32, IpAddr), BgpNeighborInfo>>>,

    /// BGP unnumbered neighbors, keyed by the ASN of the router they belong
    /// to and the neighbor's interface name.
    bgp_unnumbered_neighbors:
        Arc<Mutex<BTreeMap<(u32, String), BgpUnnumberedNeighborInfo>>>,

    /// IPv4 prefixes originated by BGP, keyed by the ASN of the router
    /// originating them.
    origin4: Arc<Mutex<BTreeMap<u32, BTreeSet<Ipv4Net>>>>,

    /// IPv6 prefixes originated by BGP, keyed by the ASN of the router
    /// originating them.
    origin6: Arc<Mutex<BTreeMap<u32, BTreeSet<Ipv6Net>>>>,

    /// Administratively added static routes (both address families).
    static_routes: Arc<Mutex<BTreeSet<StaticRouteKey>>>,

    /// Maximum number of paths bestpath selects per prefix.
    bestpath_fanout: Arc<RwLock<NonZeroU8>>,

    /// IPv4 Unicast routes learned from BGP update messages or administratively
    /// added static routes.
    rib4_in: Arc<Mutex<Rib4>>,

    /// IPv4 Unicast routes selected from rib_in according to local policy and
    /// added to the lower half forwarding plane.
    rib4_loc: Arc<Mutex<Rib4>>,

    /// IPv6 Unicast routes learned from BGP update messages or administratively
    /// added static routes.
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

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Db>()
};

#[derive(Clone)]
struct Watcher {
    tag: String,
    sender: Sender<PrefixChangeNotification>,
}

//TODO we need bulk operations with atomic semantics here.
impl Db {
    /// Create a new, empty routing database.
    pub fn new(log: Logger) -> Self {
        let rib_loc = Arc::new(Mutex::new(Rib::new()));
        Self {
            bgp_routers: Arc::new(Mutex::new(BTreeMap::new())),
            bgp_neighbors: Arc::new(Mutex::new(BTreeMap::new())),
            bgp_unnumbered_neighbors: Arc::new(Mutex::new(BTreeMap::new())),
            origin4: Arc::new(Mutex::new(BTreeMap::new())),
            origin6: Arc::new(Mutex::new(BTreeMap::new())),
            static_routes: Arc::new(Mutex::new(BTreeSet::new())),
            bestpath_fanout: Arc::new(RwLock::new(
                NonZeroU8::new(DEFAULT_BESTPATH_FANOUT).unwrap(),
            )),
            rib4_in: Arc::new(Mutex::new(BTreeMap::new())),
            rib4_loc: Arc::new(Mutex::new(BTreeMap::new())),
            rib6_in: Arc::new(Mutex::new(BTreeMap::new())),
            rib6_loc: Arc::new(Mutex::new(BTreeMap::new())),
            generation: Arc::new(AtomicU64::new(0)),
            watchers: Arc::new(RwLock::new(Vec::new())),
            reaper: Reaper::new(rib_loc),
            slot: Arc::new(RwLock::new(None)),
            log,
        }
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

    pub fn add_bgp_router(&self, asn: u32, info: BgpRouterInfo) {
        lock!(self.bgp_routers).insert(asn, info);
    }

    pub fn remove_bgp_router(&self, asn: u32) {
        lock!(self.bgp_routers).remove(&asn);
    }

    pub fn get_bgp_routers(&self) -> BTreeMap<u32, BgpRouterInfo> {
        lock!(self.bgp_routers).clone()
    }

    pub fn add_bgp_neighbor(&self, nbr: BgpNeighborInfo) {
        lock!(self.bgp_neighbors).insert((nbr.asn, nbr.host.ip()), nbr);
    }

    pub fn add_unnumbered_bgp_neighbor(&self, nbr: BgpUnnumberedNeighborInfo) {
        lock!(self.bgp_unnumbered_neighbors)
            .insert((nbr.asn, nbr.interface.clone()), nbr);
    }

    pub fn remove_unnumbered_bgp_neighbor(&self, asn: Asn, interface: &str) {
        lock!(self.bgp_unnumbered_neighbors)
            .remove(&(asn.as_u32(), interface.to_string()));
    }

    pub fn remove_bgp_neighbor(&self, asn: Asn, addr: IpAddr) {
        lock!(self.bgp_neighbors).remove(&(asn.as_u32(), addr));
    }

    pub fn get_bgp_neighbors(&self) -> Vec<BgpNeighborInfo> {
        lock!(self.bgp_neighbors).values().cloned().collect()
    }

    pub fn get_unnumbered_bgp_neighbors(
        &self,
    ) -> Vec<BgpUnnumberedNeighborInfo> {
        lock!(self.bgp_unnumbered_neighbors)
            .values()
            .cloned()
            .collect()
    }

    pub fn create_origin4(
        &self,
        asn: Asn,
        ps: &[Ipv4Net],
    ) -> Result<(), Error> {
        rdb_log!(self, info,
            "create origin4 (asn {asn}): {ps:?}";
            "unit" => UNIT_RIB
        );

        if !self.get_origin4(asn).is_empty() {
            return Err(Error::Conflict("origin already exists".to_string()));
        }

        self.set_origin4(asn, ps);
        Ok(())
    }

    pub fn set_origin4(&self, asn: Asn, ps: &[Ipv4Net]) {
        let mut origin = lock!(self.origin4);
        if ps.is_empty() {
            origin.remove(&asn.as_u32());
        } else {
            origin.insert(asn.as_u32(), ps.iter().copied().collect());
        }
    }

    pub fn clear_origin4(&self, asn: Asn) {
        lock!(self.origin4).remove(&asn.as_u32());
    }

    pub fn get_origin4(&self, asn: Asn) -> Vec<Ipv4Net> {
        lock!(self.origin4)
            .get(&asn.as_u32())
            .map(|ps| ps.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn create_origin6(
        &self,
        asn: Asn,
        ps: &[Ipv6Net],
    ) -> Result<(), Error> {
        if !self.get_origin6(asn).is_empty() {
            return Err(Error::Conflict("origin already exists".to_string()));
        }

        self.set_origin6(asn, ps);
        Ok(())
    }

    pub fn set_origin6(&self, asn: Asn, ps: &[Ipv6Net]) {
        let mut origin = lock!(self.origin6);
        if ps.is_empty() {
            origin.remove(&asn.as_u32());
        } else {
            origin.insert(asn.as_u32(), ps.iter().copied().collect());
        }
    }

    pub fn clear_origin6(&self, asn: Asn) {
        lock!(self.origin6).remove(&asn.as_u32());
    }

    pub fn get_origin6(&self, asn: Asn) -> Vec<Ipv6Net> {
        lock!(self.origin6)
            .get(&asn.as_u32())
            .map(|ps| ps.iter().copied().collect())
            .unwrap_or_default()
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

    pub fn update_rib4_loc(
        &self,
        rib_in: &Rib4,
        rib_loc: &mut Rib4,
        prefix: &Ipv4Net,
    ) {
        let fanout = self.get_bestpath_fanout();

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

    pub fn update_rib6_loc(
        &self,
        rib_in: &Rib6,
        rib_loc: &mut Rib6,
        prefix: &Ipv6Net,
    ) {
        let fanout = self.get_bestpath_fanout();

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
        // Fetch fanout once before the loops to avoid repeated lock acquisition
        let fanout = self.get_bestpath_fanout();

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

    pub fn add_prefix_path(&self, prefix: &IpNet, path: &Path) {
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

    pub fn add_static_routes(&self, routes: &[StaticRouteKey]) {
        lock!(self.static_routes).extend(routes.iter().copied());

        let mut pcn = PrefixChangeNotification::default();
        for route in routes {
            self.add_prefix_path(&route.prefix, &Path::from(*route));
            pcn.changed.insert(route.prefix);
        }

        self.notify(pcn);
    }

    pub fn add_bgp_prefixes(&self, prefixes: &[IpNet], path: Path) {
        let mut pcn = PrefixChangeNotification::default();
        for prefix in prefixes {
            self.add_prefix_path(prefix, &path);
            pcn.changed.insert(*prefix);
        }
        self.notify(pcn);
    }

    pub fn get_static(&self, af: Option<AddressFamily>) -> Vec<StaticRouteKey> {
        lock!(self.static_routes)
            .iter()
            .filter(|r| match af {
                Some(AddressFamily::Ipv4) => r.prefix.is_ipv4(),
                Some(AddressFamily::Ipv6) => r.prefix.is_ipv6(),
                None => true,
            })
            .copied()
            .collect()
    }

    pub fn get_static4_count(&self) -> usize {
        self.get_static(Some(AddressFamily::Ipv4)).len()
    }

    pub fn get_static_nexthop4_count(&self) -> usize {
        let entries = self.get_static(Some(AddressFamily::Ipv4));
        let mut nexthops = BTreeSet::new();
        for e in entries {
            nexthops.insert(e.nexthop);
        }
        nexthops.len()
    }

    pub fn get_static6_count(&self) -> usize {
        self.get_static(Some(AddressFamily::Ipv6)).len()
    }

    pub fn get_static_nexthop6_count(&self) -> usize {
        let entries = self.get_static(Some(AddressFamily::Ipv6));
        let mut nexthops = BTreeSet::new();
        for e in entries {
            nexthops.insert(e.nexthop);
        }
        nexthops.len()
    }

    pub fn set_nexthop_shutdown(&self, nexthop: IpAddr, shutdown: bool) {
        // Fetch fanout once before modifying paths
        let fanout = self.get_bestpath_fanout();

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

    pub fn remove_path_for_prefixes<F>(&self, prefixes: &[IpNet], prefix_cmp: F)
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

    pub fn remove_static_routes(&self, routes: &[StaticRouteKey]) {
        {
            let mut static_routes = lock!(self.static_routes);
            for route in routes {
                static_routes.remove(route);
            }
        }

        let mut pcn = PrefixChangeNotification::default();
        for route in routes {
            self.remove_prefix_path(&route.prefix, |rib_path: &Path| {
                rib_path.cmp(&Path::from(*route)) == CmpOrdering::Equal
            });
            pcn.changed.insert(route.prefix);
        }

        self.notify(pcn);
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

    pub fn get_bestpath_fanout(&self) -> NonZeroU8 {
        *read_lock!(self.bestpath_fanout)
    }

    pub fn set_bestpath_fanout(&self, fanout: NonZeroU8) {
        *write_lock!(self.bestpath_fanout) = fanout;
        self.trigger_bestpath_when(|_pfx, _paths| true);
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
        StaticRouteKey, db::Db, types::Asn,
        types::test_helpers::path_vecs_equal,
    };
    use client_common::eprintln_nopipe;
    use mg_api_types::rdb::DEFAULT_RIB_PRIORITY_STATIC;
    use mg_api_types::rdb::path::Path;
    use mg_api_types::rdb::rib::AddressFamily;
    use mg_common::log::*;
    use oxnet::{IpNet, Ipv4Net, Ipv6Net};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn get_test_db() -> Db {
        Db::new(init_file_logger("rib.log"))
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
        let db = Db::new(init_file_logger("rib.log"));

        // Start test cases

        // start from empty rib
        assert!(db.full_rib(None).is_empty());
        assert!(db.loc_rib(None).is_empty());

        // =====================================================================
        // Test 1: Replacement semantics
        // Adding two static routes with the same identity (nexthop, vlan_id)
        // should result in the second replacing the first.
        // =====================================================================
        db.add_static_routes(&[static_key0]);

        // Verify static_path0 is installed
        let rib_in_paths = vec![static_path0.clone()];
        let loc_rib_paths = vec![static_path0.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));

        // Add static_key0_updated (same identity, different rib_priority)
        // This should REPLACE static_path0, not add a second path
        db.add_static_routes(&[static_key0_updated]);

        // Verify only static_path0_updated exists (replacement occurred)
        let rib_in_paths = vec![static_path0_updated.clone()];
        let loc_rib_paths = vec![static_path0_updated.clone()];
        assert!(check_prefix_path(&db, &p0, rib_in_paths, loc_rib_paths));

        // =====================================================================
        // Test 2: ECMP - multiple static routes with different identities
        // Adding a static route with a different nexthop should coexist.
        // =====================================================================
        db.add_static_routes(&[static_key1]);

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
        db.remove_static_routes(&[static_key0]);

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
        db.remove_static_routes(&[static_key1]);
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
        db.add_static_routes(&[static_route]);

        // Verify route was added
        let routes = db.get_static(Some(AddressFamily::Ipv4));
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0], static_route);

        // Check that it appears in RIB
        let rib_routes = db.full_rib(Some(AddressFamily::Ipv4));
        assert_eq!(rib_routes.len(), 1);
        assert!(rib_routes.contains_key(&IpNet::V4(prefix4)));

        // Remove the route
        db.remove_static_routes(&[static_route]);

        // Verify route was removed
        let routes = db.get_static(Some(AddressFamily::Ipv4));
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
        db.add_static_routes(&[static_route]);

        // Verify route was added
        let routes = db.get_static(Some(AddressFamily::Ipv6));
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0], static_route);

        // Check that it appears in RIB
        let rib_routes = db.full_rib(Some(AddressFamily::Ipv6));
        assert_eq!(rib_routes.len(), 1);
        assert!(rib_routes.contains_key(&IpNet::V6(prefix6)));

        // Remove the route
        db.remove_static_routes(&[static_route]);

        // Verify route was removed
        let routes = db.get_static(Some(AddressFamily::Ipv6));
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
        db.add_static_routes(&[route_no_vlan, route_with_vlan]);

        // Verify both routes were added correctly
        let routes = db.get_static(Some(AddressFamily::Ipv6));
        assert_eq!(routes.len(), 2);

        let no_vlan_route =
            routes.iter().find(|r| r.vlan_id.is_none()).unwrap();
        assert_eq!(no_vlan_route.vlan_id, None);

        let vlan_route = routes.iter().find(|r| r.vlan_id.is_some()).unwrap();
        assert_eq!(vlan_route.vlan_id, Some(4094));

        // Clean up
        db.remove_static_routes(&[route_no_vlan, route_with_vlan]);
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
        db.add_static_routes(&[route4, route6]);

        // Test IPv4-only retrieval
        let ipv4_routes = db.get_static(Some(AddressFamily::Ipv4));
        assert_eq!(ipv4_routes.len(), 1);
        assert_eq!(ipv4_routes[0], route4);

        // Test IPv6-only retrieval
        let ipv6_routes = db.get_static(Some(AddressFamily::Ipv6));
        assert_eq!(ipv6_routes.len(), 1);
        assert_eq!(ipv6_routes[0], route6);

        // Test all address families retrieval
        let all_routes = db.get_static(None);
        assert_eq!(all_routes.len(), 2);
        assert!(all_routes.contains(&route4));
        assert!(all_routes.contains(&route6));

        // Test counts
        assert_eq!(db.get_static4_count(), 1);
        assert_eq!(db.get_static6_count(), 1);

        // Remove routes and verify cleanup
        db.remove_static_routes(&[route4, route6]);
        assert_eq!(db.get_static4_count(), 0);
        assert_eq!(db.get_static6_count(), 0);
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
        db.add_static_routes(&[route1, route2]);

        // Verify both routes were added
        let routes = db.get_static(Some(AddressFamily::Ipv4));
        assert_eq!(routes.len(), 2);
        assert!(routes.contains(&route1));
        assert!(routes.contains(&route2));

        // Remove one route, other should remain
        db.remove_static_routes(&[route1]);
        let routes = db.get_static(Some(AddressFamily::Ipv4));
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0], route2);

        // Remove final route
        db.remove_static_routes(&[route2]);
        let routes = db.get_static(Some(AddressFamily::Ipv4));
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
        db.add_static_routes(&[route_no_vlan, route_with_vlan]);

        // Verify both routes were added correctly
        let routes = db.get_static(Some(AddressFamily::Ipv4));
        assert_eq!(routes.len(), 2);

        let no_vlan_route =
            routes.iter().find(|r| r.vlan_id.is_none()).unwrap();
        assert_eq!(no_vlan_route.vlan_id, None);

        let vlan_route = routes.iter().find(|r| r.vlan_id.is_some()).unwrap();
        assert_eq!(vlan_route.vlan_id, Some(4094));

        // Clean up
        db.remove_static_routes(&[route_no_vlan, route_with_vlan]);
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

        db.add_static_routes(&[route]);
        let routes = db.get_static(Some(AddressFamily::Ipv4));
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

        db.remove_static_routes(&[route]);
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
        let retrieved = db.get_origin4(ASN);
        assert_eq!(retrieved.len(), 2);
        assert!(retrieved.contains(&prefixes[0]));
        assert!(retrieved.contains(&prefixes[1]));

        // Try to create again - should fail with conflict
        assert!(db.create_origin4(ASN, &prefixes).is_err());

        // A different ASN must not see the first ASN's origins, and may
        // create its own without conflicting.
        const OTHER_ASN: Asn = Asn::FourOctet(65002);
        assert!(db.get_origin4(OTHER_ASN).is_empty());
        let other_prefixes =
            vec![Ipv4Net::new_unchecked(Ipv4Addr::new(203, 0, 113, 0), 24)];
        db.create_origin4(OTHER_ASN, &other_prefixes)
            .expect("create other origin4");
        assert_eq!(db.get_origin4(ASN).len(), 2);

        // Update origin4 with different prefixes
        let new_prefixes =
            vec![Ipv4Net::new_unchecked(Ipv4Addr::new(172, 16, 0, 0), 12)];
        db.set_origin4(ASN, &new_prefixes);

        let updated = db.get_origin4(ASN);
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0], new_prefixes[0]);

        // Clear origin4 - must only clear this ASN's entries
        db.clear_origin4(ASN);
        let empty = db.get_origin4(ASN);
        assert!(empty.is_empty());
        assert_eq!(db.get_origin4(OTHER_ASN).len(), 1);

        // Create again after clear - should succeed
        db.create_origin4(ASN, &prefixes)
            .expect("create after clear");
        let final_result = db.get_origin4(ASN);
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
        let retrieved = db.get_origin6(ASN);
        assert_eq!(retrieved.len(), 2);
        assert!(retrieved.contains(&prefixes[0]));
        assert!(retrieved.contains(&prefixes[1]));

        // Try to create again - should fail with conflict
        assert!(db.create_origin6(ASN, &prefixes).is_err());

        // A different ASN must not see the first ASN's origins.
        const OTHER_ASN: Asn = Asn::FourOctet(65002);
        assert!(db.get_origin6(OTHER_ASN).is_empty());

        // Update origin6 with different prefixes
        let new_prefixes = vec![Ipv6Net::new_unchecked(
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
            48,
        )];
        db.set_origin6(ASN, &new_prefixes);

        let updated = db.get_origin6(ASN);
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0], new_prefixes[0]);

        // Clear origin6
        db.clear_origin6(ASN);
        let empty = db.get_origin6(ASN);
        assert!(empty.is_empty());

        // Create again after clear - should succeed
        db.create_origin6(ASN, &prefixes)
            .expect("create after clear");
        let final_result = db.get_origin6(ASN);
        assert_eq!(final_result.len(), 2);
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
        db.add_static_routes(&[static_key4]);

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
        db.add_static_routes(&[static_key6]);

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
