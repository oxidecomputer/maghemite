// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multicast Routing Information Base (MRIB).
//!
//! The MRIB manages in-memory multicast routing state, including:
//! - (*,G) entries (any-source multicast)
//! - (S,G) entries (source-specific multicast)
//! - Replication targets (local interfaces and remote nexthops)
//! - TODO: IGMP/MLD-learned routes (dynamic)
//!
//! ## Lock Ordering
//!
//! When acquiring multiple locks, we acquire them in this ordering:
//! 1. `mrib_in`
//! 2. `mrib_loc`
//! 3. `watchers`

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use slog::{Logger, error, info};

use mg_common::{lock, read_lock, write_lock};

use crate::error::Error;
use crate::types::{
    AddressFamily, MribChangeNotification, MulticastAddr, MulticastRoute,
    MulticastRouteKey, MulticastRouteSource,
};

pub mod rpf;

// Re-export from rpf module
pub use rpf::DEFAULT_REVALIDATION_INTERVAL;

/// The MRIB table type: maps multicast route keys to route entries.
/// Each entry maps a [MulticastRouteKey] to a [MulticastRoute].
pub type MribTable = BTreeMap<MulticastRouteKey, MulticastRoute>;

/// The Multicast Routing Information Base.
///
/// Pure in-memory multicast routing tables, matching the unicast RIB pattern.
/// Persistence is handled by [`crate::Db`].
///
/// The MRIB maintains two tables:
/// - `mrib_in`: All multicast routes from all sources (static, IGMP)
/// - `mrib_loc`: Selected routes that pass Reverse Path Forwarding (RPF)
///   checks and are installed in the data plane.
///
///   Note: `(*,G)` routes have no source address, so they always pass
///   to `mrib_loc` immediately (RPF only applies to `(S,G)` routes).
#[derive(Clone)]
pub struct Mrib {
    /// All multicast routes from all sources (static, IGMP).
    mrib_in: Arc<Mutex<MribTable>>,

    /// Selected multicast routes that have passed RPF verification.
    mrib_loc: Arc<Mutex<MribTable>>,

    /// Watchers notified of MRIB changes.
    watchers: Arc<RwLock<Vec<MribWatcher>>>,

    log: Logger,
}

#[derive(Clone)]
struct MribWatcher {
    tag: String,
    sender: Sender<MribChangeNotification>,
}

impl Mrib {
    pub fn new(log: Logger) -> Self {
        Self {
            mrib_in: Arc::new(Mutex::new(MribTable::new())),
            mrib_loc: Arc::new(Mutex::new(MribTable::new())),
            watchers: Arc::new(RwLock::new(Vec::new())),
            log,
        }
    }

    /// Register a watcher for MRIB changes.
    pub fn watch(&self, tag: String, sender: Sender<MribChangeNotification>) {
        write_lock!(self.watchers).push(MribWatcher { tag, sender });
    }

    /// Remove a watcher by tag.
    pub fn unwatch(&self, tag: &str) {
        write_lock!(self.watchers).retain(|w| w.tag != tag);
    }

    /// Notify all watchers of MRIB changes.
    ///
    /// Automatically removes watchers whose channels have been closed.
    ///
    /// This function releases the lock before sending to avoid potential
    /// deadlocks if a watcher's receiver calls back into the MRIB.
    fn notify(&self, n: MribChangeNotification) {
        // Snapshot watchers under lock, then release before sending
        let snapshot: Vec<_> =
            read_lock!(self.watchers).iter().cloned().collect();

        // Send to all watchers (lock released, no deadlock risk)
        let mut dead_tags = Vec::new();
        for MribWatcher { tag, sender } in &snapshot {
            if let Err(e) = sender.send(n.clone()) {
                error!(self.log, "watcher '{tag}' disconnected, removing: {e}");
                dead_tags.push(tag.clone());
            }
        }

        // Remove dead watchers
        if !dead_tags.is_empty() {
            write_lock!(self.watchers).retain(|w| !dead_tags.contains(&w.tag));
        }
    }

    /// Get a copy of the full MRIB input table (all routes from all sources).
    pub fn full_mrib(&self) -> MribTable {
        lock!(self.mrib_in).clone()
    }

    /// Get a copy of the local MRIB table (selected/installed routes).
    pub fn loc_mrib(&self) -> MribTable {
        lock!(self.mrib_loc).clone()
    }

    /// List routes with filtering, cloning only matching entries.
    ///
    /// Arguments:
    /// - `af`: Filter by address family (`None = all`)
    /// - `static_only`: Filter by origin (`None = all`, `Some(true) = static`,
    ///   Some(false) = dynamic)
    /// - `installed`: If true, query `mrib_loc`; otherwise `mrib_in`
    pub fn list_routes(
        &self,
        af: Option<AddressFamily>,
        static_only: Option<bool>,
        installed: bool,
    ) -> Vec<MulticastRoute> {
        let filter = |route: &&MulticastRoute| -> bool {
            // Address family filter
            let af_match = match af {
                None => true,
                Some(AddressFamily::Ipv4) => {
                    matches!(route.key.group, MulticastAddr::V4(_))
                }
                Some(AddressFamily::Ipv6) => {
                    matches!(route.key.group, MulticastAddr::V6(_))
                }
            };
            // Origin filter
            let origin_match = match static_only {
                None => true,
                Some(true) => {
                    matches!(route.source, MulticastRouteSource::Static)
                }
                Some(false) => {
                    !matches!(route.source, MulticastRouteSource::Static)
                }
            };
            af_match && origin_match
        };

        if installed {
            lock!(self.mrib_loc)
                .values()
                .filter(filter)
                .cloned()
                .collect()
        } else {
            lock!(self.mrib_in)
                .values()
                .filter(filter)
                .cloned()
                .collect()
        }
    }

    /// Get a specific multicast route from `mrib_in`.
    ///
    /// Returns a cloned [MulticastRoute], if present.
    pub fn get_route(&self, key: &MulticastRouteKey) -> Option<MulticastRoute> {
        lock!(self.mrib_in).get(key).cloned()
    }

    /// Get a specific multicast route from `mrib_loc` (selected/installed).
    ///
    /// Returns a cloned [MulticastRoute], if present.
    pub fn get_selected_route(
        &self,
        key: &MulticastRouteKey,
    ) -> Option<MulticastRoute> {
        lock!(self.mrib_loc).get(key).cloned()
    }

    /// Atomically promote a (*,G) route from `mrib_in` to `mrib_loc`.
    ///
    /// (*,G) routes have no source address, so they always pass RPF checks.
    /// This method atomically copies the fresh route data to `mrib_loc`,
    /// avoiding races with concurrent route updates.
    ///
    /// Returns `true` if the route was found and promoted.
    pub(crate) fn promote_any_source(&self, key: &MulticastRouteKey) -> bool {
        let changed = {
            let mrib_in = lock!(self.mrib_in);
            let mut mrib_loc = lock!(self.mrib_loc);

            let Some(route) = mrib_in.get(key) else {
                return false;
            };

            match mrib_loc.entry(*key) {
                Entry::Occupied(mut e) => {
                    let unchanged = e.get().rpf_neighbor == route.rpf_neighbor
                        && e.get().underlay_group == route.underlay_group
                        && e.get().underlay_nexthops == route.underlay_nexthops
                        && e.get().source == route.source;
                    if !unchanged {
                        e.insert(route.clone());
                    }
                    !unchanged
                }
                Entry::Vacant(e) => {
                    e.insert(route.clone());
                    true
                }
            }
        };

        if changed {
            self.notify(MribChangeNotification::from(*key));
        }
        true
    }

    /// Apply an RPF verification result atomically for (S,G) routes.
    ///
    /// Updates `rpf_neighbor` in `mrib_in` (so API queries show the derived
    /// neighbor) and then promotes/removes the fresh route to/from `mrib_loc`.
    ///
    /// By holding both locks and re-fetching from `mrib_in`, we avoid a race
    /// where concurrent route updates (e.g., adding underlay nexthops) could
    /// be lost if we used a stale snapshot.
    ///
    /// Only notifies watchers if `mrib_loc` actually changed.
    pub(crate) fn apply_rpf_result(
        &self,
        key: &MulticastRouteKey,
        neighbor: Option<IpAddr>,
    ) {
        let changed = {
            let mut mrib_in = lock!(self.mrib_in);
            let mut mrib_loc = lock!(self.mrib_loc);

            match mrib_in.get_mut(key) {
                None => {
                    // Route removed from mrib_in, ensure gone from mrib_loc
                    mrib_loc.remove(key).is_some()
                }
                Some(route) => {
                    // Update rpf_neighbor in mrib_in
                    route.rpf_neighbor = neighbor;

                    // Promote or remove from mrib_loc based on RPF result
                    if neighbor.is_some() {
                        match mrib_loc.entry(*key) {
                            Entry::Occupied(mut e) => {
                                let unchanged = e.get().rpf_neighbor
                                    == route.rpf_neighbor
                                    && e.get().underlay_group
                                        == route.underlay_group
                                    && e.get().underlay_nexthops
                                        == route.underlay_nexthops
                                    && e.get().source == route.source;
                                if !unchanged {
                                    e.insert(route.clone());
                                }
                                !unchanged
                            }
                            Entry::Vacant(e) => {
                                e.insert(route.clone());
                                true
                            }
                        }
                    } else {
                        // No unicast route to source -> remove from mrib_loc
                        mrib_loc.remove(key).is_some()
                    }
                }
            }
        };

        if changed {
            self.notify(MribChangeNotification::from(*key));
        }
    }

    /// Add or update a multicast route in `mrib_in`.
    ///
    /// The route is added to `mrib_in` only. The caller (`Db`) is responsible
    /// for calling [`crate::Db::update_mrib_loc()`] to perform RPF verification
    /// and potentially promote the route to `mrib_loc`.
    ///
    /// Accepts a full [MulticastRoute].
    pub fn add_route(&self, route: MulticastRoute) -> Result<(), Error> {
        let key = route.key;
        let changed = {
            let mut mrib_in = lock!(self.mrib_in);
            let changed = match mrib_in.get(&key) {
                Some(existing) => {
                    // Check if route actually changed
                    existing.underlay_nexthops != route.underlay_nexthops
                        || existing.rpf_neighbor != route.rpf_neighbor
                        || existing.source != route.source
                        || existing.underlay_group != route.underlay_group
                }
                None => true, // New route
            };
            mrib_in.insert(key, route);
            changed
        };

        if changed {
            self.notify(MribChangeNotification::from(key));
        }
        Ok(())
    }

    /// Remove a multicast route from both `mrib_in` and `mrib_loc`.
    pub fn remove_route(&self, key: &MulticastRouteKey) -> Result<bool, Error> {
        // Acquire both locks following documented order to ensure atomicity
        let removed = {
            let mut mrib_in = lock!(self.mrib_in);
            let mut mrib_loc = lock!(self.mrib_loc);
            let removed_in = mrib_in.remove(key).is_some();
            let removed_loc = mrib_loc.remove(key).is_some();
            removed_in || removed_loc
        };

        if removed {
            self.notify(MribChangeNotification::from(*key));
        }
        Ok(removed)
    }

    /// Add a replication target to an existing route in both `mrib_in` and
    /// `mrib_loc`.
    pub fn add_target(
        &self,
        key: &MulticastRouteKey,
        target: Ipv6Addr,
    ) -> Result<(), Error> {
        // Acquire both locks following documented order to ensure atomicity
        {
            let mut mrib_in = lock!(self.mrib_in);
            let mut mrib_loc = lock!(self.mrib_loc);

            if let Some(route) = mrib_in.get_mut(key) {
                route.add_target(target);
            } else {
                return Err(Error::NotFound(format!(
                    "multicast route {key} not found",
                )));
            }

            if let Some(route) = mrib_loc.get_mut(key) {
                route.add_target(target);
            }
        }

        self.notify(MribChangeNotification::from(*key));
        Ok(())
    }

    /// Remove a replication target from an existing route in both `mrib_in` and
    /// `mrib_loc`.
    pub fn remove_target(
        &self,
        key: &MulticastRouteKey,
        target: &Ipv6Addr,
    ) -> Result<bool, Error> {
        // Acquire both locks following documented order to ensure atomicity
        let removed = {
            let mut mrib_in = lock!(self.mrib_in);
            let mut mrib_loc = lock!(self.mrib_loc);

            let removed_in = if let Some(route) = mrib_in.get_mut(key) {
                route.remove_target(target)
            } else {
                return Err(Error::NotFound(format!(
                    "multicast route {key} not found",
                )));
            };

            let removed_loc = if let Some(route) = mrib_loc.get_mut(key) {
                route.remove_target(target)
            } else {
                false
            };

            removed_in || removed_loc
        };

        if removed {
            self.notify(MribChangeNotification::from(*key));
        }
        Ok(removed)
    }

    /// Get all routes for a specific multicast group from `mrib_in`.
    pub fn get_routes_for_group(
        &self,
        group: &MulticastAddr,
    ) -> Vec<MulticastRoute> {
        lock!(self.mrib_in)
            .values()
            .filter(|route| &route.key.group == group)
            .cloned()
            .collect()
    }

    /// Get all routes with a specific source from `mrib_in`.
    pub fn get_routes_for_source(
        &self,
        source: &IpAddr,
    ) -> Vec<MulticastRoute> {
        lock!(self.mrib_in)
            .values()
            .filter(|route| route.key.source.as_ref() == Some(source))
            .cloned()
            .collect()
    }

    /// Get all any-source (*,G) routes from `mrib_in`.
    pub fn get_any_source_routes(&self) -> Vec<MulticastRoute> {
        lock!(self.mrib_in)
            .values()
            .filter(|route| route.key.source.is_none())
            .cloned()
            .collect()
    }

    /// Get keys for all source-specific (S,G) routes.
    pub fn get_source_specific_keys(&self) -> Vec<MulticastRouteKey> {
        lock!(self.mrib_in)
            .keys()
            .filter(|key| key.source.is_some())
            .copied()
            .collect()
    }
}

/// Spawn the RPF revalidator background thread.
///
/// Listens for RPF cache rebuild events and re-checks RPF validity for all
/// source-specific (S,G) multicast routes. Routes that pass RPF validation
/// are installed in `mrib_loc`, while routes that fail are removed.
///
/// Returns the sender for rebuild events if spawn succeeded, `None` if failed.
/// The caller should only install the notifier in `RpfTable` if this returns
/// `Some`, ensuring the channel receiver is actually running.
pub(crate) fn spawn_rpf_revalidator(
    db: crate::Db,
) -> Option<mpsc::Sender<rpf::RebuildEvent>> {
    let err_log = db.log().clone();
    let sweep_interval_ms = db.get_mrib_rpf_revalidation_interval_ms();
    let (tx, rx) = mpsc::channel::<rpf::RebuildEvent>();

    match thread::Builder::new()
        .name("rpf-revalidator".to_string())
        .spawn(move || {
            loop {
                let ms = sweep_interval_ms.load(Ordering::Relaxed);
                let timeout = if ms == 0 {
                    DEFAULT_REVALIDATION_INTERVAL
                } else {
                    Duration::from_millis(ms)
                };

                // Wait for an event or timeout
                let first_event = match rx.recv_timeout(timeout) {
                    Ok(evt) => Some(evt),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => break,
                };

                // Drain any queued events to avoid redundant full MRIB scans
                // when many events arrive in quick succession.
                let mut extra_events = 0usize;
                while rx.try_recv().is_ok() {
                    extra_events += 1;
                }

                // If we coalesced multiple events, do a full sweep.
                // Otherwise use the specific event for targeted revalidation.
                let event = if extra_events > 0 { None } else { first_event };
                db.revalidate_mrib(event);
            }
            info!(db.log(), "rpf revalidator shutting down");
        }) {
        Ok(_) => Some(tx),
        Err(e) => {
            error!(err_log, "failed to spawn rpf-revalidator: {e}");
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::net::Ipv4Addr;

    use mg_common::log::*;

    use crate::test::{mcast_v4, mcast_v6};

    // Valid admin-scoped underlay address for tests
    const TEST_UNDERLAY: Ipv6Addr = Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1);

    #[test]
    fn test_mrib_basic() {
        let log = init_file_logger("mrib_test.log");
        let mrib = Mrib::new(log);

        // Test ASM route (*,G)
        let group = mcast_v4(225, 1, 1, 1);
        let key = MulticastRouteKey::any_source(group);
        let route = MulticastRoute::new(
            key,
            TEST_UNDERLAY,
            MulticastRouteSource::Static,
        );

        mrib.add_route(route.clone()).expect("add route");
        assert!(mrib.get_route(&key).is_some());

        // Test source-specific multicast route (S,G)
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let key_sg = MulticastRouteKey::source_specific(source, group);
        let mut route_sg = MulticastRoute::new(
            key_sg,
            TEST_UNDERLAY,
            MulticastRouteSource::Static,
        );

        // Add replication targets
        let target1 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let target2 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

        route_sg.add_target(target1);
        route_sg.add_target(target2);

        mrib.add_route(route_sg.clone()).expect("add S,G route");
        assert_eq!(mrib.full_mrib().len(), 2);

        // Test queries
        let group_routes = mrib.get_routes_for_group(&group);
        assert_eq!(group_routes.len(), 2);

        let any_source = mrib.get_any_source_routes();
        assert_eq!(any_source.len(), 1);

        let source_specific = mrib.get_source_specific_keys();
        assert_eq!(source_specific.len(), 1);

        // Test removal
        mrib.remove_route(&key).expect("remove *,G route");
        assert_eq!(mrib.full_mrib().len(), 1);
        assert!(mrib.get_route(&key).is_none());
    }

    #[test]
    fn test_mrib_watchers() {
        use std::sync::mpsc::channel;

        let log = init_file_logger("mrib_watcher_test.log");
        let mrib = Mrib::new(log);

        // Register watcher
        let (tx, rx) = channel();
        mrib.watch("test-watcher".to_string(), tx);

        // Add a route and verify notification
        let group = mcast_v4(225, 3, 3, 3);
        let key = MulticastRouteKey::any_source(group);
        let route = MulticastRoute::new(
            key,
            TEST_UNDERLAY,
            MulticastRouteSource::Static,
        );

        mrib.add_route(route.clone()).expect("add route");

        // Should receive notification
        let notification = rx.recv().expect("receive notification");
        assert_eq!(notification.changed.len(), 1);
        assert!(notification.changed.contains(&key));

        // Remove route and verify notification
        mrib.remove_route(&key).expect("remove route");

        let notification = rx.recv().expect("receive notification");
        assert_eq!(notification.changed.len(), 1);
        assert!(notification.changed.contains(&key));
    }

    #[test]
    fn test_mrib_in_vs_loc() {
        let log = init_file_logger("mrib_in_loc_test.log");
        let mrib = Mrib::new(log);

        // Add a (*,G) route to mrib_in only
        let group = mcast_v4(225, 4, 4, 4);
        let key = MulticastRouteKey::any_source(group);
        let route = MulticastRoute::new(
            key,
            TEST_UNDERLAY,
            MulticastRouteSource::Static,
        );

        mrib.add_route(route.clone()).expect("add route");

        // Verify route exists in `mrib_in` but not in `mrib_loc`
        assert_eq!(mrib.full_mrib().len(), 1);
        assert_eq!(mrib.loc_mrib().len(), 0);
        assert!(mrib.get_route(&key).is_some());
        assert!(mrib.get_selected_route(&key).is_none());

        // Promote (*,G) route to `mrib_loc`
        assert!(mrib.promote_any_source(&key));

        // Now verify route exists in both tables
        assert_eq!(mrib.full_mrib().len(), 1);
        assert_eq!(mrib.loc_mrib().len(), 1);
        assert!(mrib.get_route(&key).is_some());
        assert!(mrib.get_selected_route(&key).is_some());

        // Remove route completely (from both tables)
        mrib.remove_route(&key).expect("remove route");
        assert_eq!(mrib.full_mrib().len(), 0);
        assert_eq!(mrib.loc_mrib().len(), 0);
        assert!(mrib.get_route(&key).is_none());
        assert!(mrib.get_selected_route(&key).is_none());
    }

    #[test]
    fn test_mrib_ipv6_groups() {
        let log = init_file_logger("mrib_v6_test.log");
        let mrib = Mrib::new(log);

        // IPv6 ASM route (*,G)
        let group = mcast_v6([0xff0e, 0, 0, 0, 0, 0, 0, 1]);
        let key = MulticastRouteKey::any_source(group);
        let route = MulticastRoute::new(
            key,
            TEST_UNDERLAY,
            MulticastRouteSource::Static,
        );

        mrib.add_route(route.clone()).expect("add v6 route");
        assert!(mrib.get_route(&key).is_some());

        // IPv6 source-specific multicast route (S,G)
        let source = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let key_sg = MulticastRouteKey::source_specific(source, group);
        let route_sg = MulticastRoute::new(
            key_sg,
            TEST_UNDERLAY,
            MulticastRouteSource::Static,
        );

        mrib.add_route(route_sg).expect("add v6 S,G route");
        assert_eq!(mrib.full_mrib().len(), 2);

        // Verify address family filtering
        let v6_routes: Vec<_> =
            mrib.get_routes_for_group(&group).into_iter().collect();
        assert_eq!(v6_routes.len(), 2);

        // Cleanup
        mrib.remove_route(&key).expect("remove *,G");
        mrib.remove_route(&key_sg).expect("remove S,G");
        assert_eq!(mrib.full_mrib().len(), 0);
    }
}
