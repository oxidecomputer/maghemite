// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multicast Routing Information Base (MRIB).
//!
//! The MRIB manages in-memory multicast routing state, including:
//!
//! - `(*,G)` entries (any-source multicast)
//! - `(S,G)` entries (source-specific multicast)
//!
//! ## Selection
//!
//! `(*,G)` routes don't need to check sources and are always selected.
//! Source-specific `(S,G)` routes are selected by source reachability:
//!
//! ```text
//! mrib_in: configured (G,VNI) and (S,G,VNI) routes
//!   |
//!   +-- (*,G) --> mrib_in -> mrib_loc
//!   |
//!   +-- (S,G) --> group keys by source S
//!   |               for each chunk of up to 64 keys:
//!   |                 hold the IP family's loc-rib lock
//!   |                 longest match for S has an active path?
//!   |                   yes: mrib_in -> mrib_loc
//!   |                   no:  mrib_loc -= keys
//!   |
//!   +-- then: notify modified keys as one batch, if any
//! ```
//!
//! Unicast supplies source reachability. G and VNI identify the multicast
//! entries that receive that selection decision. No RPF neighbor or incoming
//! interface is derived.
//!
//! ## Lock Ordering
//!
//! Acquire multiple locks in this order:
//!
//! 1. `Db::static_mcast_store` (static add, remove, load, and list)
//! 2. `Db::rib4_in` or `Db::rib6_in`, when a unicast path also modifies the
//!    loc-rib
//! 3. `Db::rib4_loc` or `Db::rib6_loc`, held across an `(S,G)` source check
//!    and its `mrib_loc` update
//! 4. `Mrib::state` (`mrib_in`, `mrib_loc`, and the source index)
//! 5. `Mrib::watchers`, taken after `Mrib::state` is released
//!
//! Unicast paths release every RIB lock before notifying `Db::watchers` or
//! revalidating the MRIB.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};

use mg_api_types::rdb::rib::AddressFamily;
use mg_common::{lock, read_lock, write_lock};
use oxnet::IpNet;
use slog::Logger;

use crate::log::rdb_log;
use crate::types::{MribChangeNotification, MulticastRoute, MulticastRouteKey};

pub(crate) mod store;

/// Log unit for MRIB operations.
const UNIT_MRIB: &str = "mrib";

/// MRIB table mapping multicast route keys to routes.
pub type MribTable = BTreeMap<MulticastRouteKey, MulticastRoute>;

/// The Multicast Routing Information Base.
///
/// In-memory multicast routing tables and the watchers notified of their
/// changes. This follows the unicast RIB pattern.
///
/// Persistence is handled by [`crate::Db`].
///
/// The MRIB maintains two tables:
///
/// - `mrib_in`: All configured multicast routes (currently static only).
/// - `mrib_loc`: Routes that passed selection.
///   - A `(*,G)` wildcard route is always selected.
///   - An `(S,G)` route is selected when the longest unicast match for
///     source S has at least one path not marked for shutdown. A default
///     route is accepted.
///
///     This is a next-hop reachability rule in the vein of
///     [RFC 4271 §9.1.2.1][RFC 4271], and not an RPF check. We do not currently
///     track which neighbor or interface resolved source S.
///
/// Today, both tables hold one route per [`MulticastRouteKey`].
///
/// NOTE: Dynamically learned routes may later share a key with a static one.
/// In that case, `mrib_in` will need to track each origin's contribution and
/// keep the rest when an origin is withdrawn. `mrib_loc` will still hold at
/// most one selected route per key. Origin tracking does not change the route
/// key or the persisted static key encoding.
///
/// [RFC 4271]: https://www.rfc-editor.org/rfc/rfc4271.html#section-9.1.2.1
#[derive(Clone)]
pub(crate) struct Mrib {
    /// One lock covers both tables and the source index, so selection and
    /// removal actions do not need to order multiple locks.
    state: Arc<Mutex<MribState>>,

    /// Watchers notified of MRIB changes.
    ///
    /// Each registration has its own inner `Arc`. Cleanup in
    /// [`Self::notify`] uses that identity to keep a newer registration
    /// under the same tag.
    watchers: Arc<RwLock<Vec<Arc<MribWatcher>>>>,

    log: Logger,
}

#[derive(Default)]
struct MribState {
    /// All configured multicast routes (currently static only).
    mrib_in: MribTable,

    /// Selected multicast routes. See the [`Mrib`] docs for the selection
    /// rules.
    mrib_loc: MribTable,

    /// Keys of the `(S,G)` routes in `mrib_in`, indexed by source address.
    ///
    /// A unicast prefix mutation finds the routes it affects via a range
    /// query over the prefix's addresses, instead of scanning every route.
    sources: BTreeMap<IpAddr, BTreeSet<MulticastRouteKey>>,
}

struct MribWatcher {
    /// Name that a watcher registers under.
    ///
    /// A later registration with the same tag replaces this one.
    tag: String,
    /// Channel that receives MRIB change notifications.
    sender: Sender<MribChangeNotification>,
}

/// Remove `key` from the source index.
///
/// A source with no remaining keys associated with it is dropped.
fn unindex(
    sources: &mut BTreeMap<IpAddr, BTreeSet<MulticastRouteKey>>,
    key: &MulticastRouteKey,
) {
    let Some(source) = key.source() else {
        return;
    };
    if let Entry::Occupied(mut e) = sources.entry(source) {
        e.get_mut().remove(key);
        if e.get().is_empty() {
            e.remove();
        }
    }
}

/// Insert or refresh `route` in `mrib_loc`.
///
/// An existing entry is replaced only if it differs from `route` in a field
/// other than its timestamps.
///
/// Returns `true` if `mrib_loc` was modified.
fn install(mrib_loc: &mut MribTable, route: &MulticastRoute) -> bool {
    match mrib_loc.entry(route.key) {
        Entry::Occupied(mut e) => {
            let changed = !e.get().eq_ignore_timestamps(route);
            if changed {
                e.insert(route.clone());
            }
            changed
        }
        Entry::Vacant(e) => {
            e.insert(route.clone());
            true
        }
    }
}

impl Mrib {
    /// Create an empty MRIB with an empty set of registered watchers.
    pub(crate) fn new(log: Logger) -> Self {
        Self {
            state: Arc::new(Mutex::new(MribState::default())),
            watchers: Arc::new(RwLock::new(Vec::new())),
            log,
        }
    }

    /// Register a watcher for MRIB changes.
    ///
    /// A registration under an existing tag replaces the previous watcher.
    ///
    /// NOTE: Each consumer must use its own, unique tag.
    pub(crate) fn watch(
        &self,
        tag: String,
        sender: Sender<MribChangeNotification>,
    ) {
        let mut watchers = write_lock!(self.watchers);
        watchers.retain(|w| w.tag != tag);
        watchers.push(Arc::new(MribWatcher { tag, sender }));
    }

    /// Notify all watchers of MRIB changes.
    ///
    /// [`Self::add_route`], [`Self::remove_routes`],
    /// [`Self::select_any_source`], and [`Self::set_source_reachable`] do not
    /// trigger notifications.
    ///
    /// [`crate::Db`] collects the keys a logical operation modifies
    /// and calls this once with the entire set.
    ///
    /// Sends happen under the read lock. A watcher whose channel has closed
    /// is logged and then removed under the write lock, matched by its `Arc`
    /// and not its tag. A consumer that re-registers under the same tag
    /// between the send and the removal holds a new `Arc` and is kept.
    pub(crate) fn notify(&self, n: MribChangeNotification) {
        let mut closed = Vec::new();
        for watcher in read_lock!(self.watchers).iter() {
            if let Err(e) = watcher.sender.send(n.clone()) {
                rdb_log!(
                    self,
                    error,
                    "failed to send MRIB change notification to watcher \
                     {}: {e}",
                    watcher.tag;
                    "unit" => UNIT_MRIB,
                    "message" => "mrib_change_notification",
                    "message_contents" => format!("{n}"),
                    "error" => format!("{e}")
                );
                closed.push(Arc::clone(watcher));
            }
        }
        if !closed.is_empty() {
            write_lock!(self.watchers)
                .retain(|w| !closed.iter().any(|c| Arc::ptr_eq(c, w)));
        }
    }

    /// Get the MRIB input table, optionally filtered by address family.
    pub(crate) fn full_mrib(&self, af: Option<AddressFamily>) -> MribTable {
        let state = lock!(self.state);
        Self::filter_routes(&state.mrib_in, af)
    }

    /// Get the selected MRIB table, optionally filtered by address family.
    pub(crate) fn loc_mrib(&self, af: Option<AddressFamily>) -> MribTable {
        let state = lock!(self.state);
        Self::filter_routes(&state.mrib_loc, af)
    }

    fn filter_routes(
        table: &MribTable,
        af: Option<AddressFamily>,
    ) -> MribTable {
        let filter = |route: &&MulticastRoute| -> bool {
            matches!(
                (af, &route.key),
                (None, _)
                    | (Some(AddressFamily::Ipv4), MulticastRouteKey::V4(_))
                    | (Some(AddressFamily::Ipv6), MulticastRouteKey::V6(_))
            )
        };

        table
            .values()
            .filter(filter)
            .map(|route| (route.key, route.clone()))
            .collect()
    }

    /// Get a specific multicast route from `mrib_in`.
    ///
    /// Returns a cloned [`MulticastRoute`] if present.
    pub(crate) fn get_route(
        &self,
        key: &MulticastRouteKey,
    ) -> Option<MulticastRoute> {
        lock!(self.state).mrib_in.get(key).cloned()
    }

    /// Get a specific multicast route from `mrib_loc` (selected routes).
    ///
    /// Returns a cloned [`MulticastRoute`], if present.
    pub(crate) fn get_selected_route(
        &self,
        key: &MulticastRouteKey,
    ) -> Option<MulticastRoute> {
        lock!(self.state).mrib_loc.get(key).cloned()
    }

    /// Select a `(*,G)` route from `mrib_in` into `mrib_loc`.
    ///
    /// The route is read from `mrib_in` and installed under one table lock.
    ///
    /// Returns `true` if `mrib_loc` was modified.
    pub(crate) fn select_any_source(&self, key: &MulticastRouteKey) -> bool {
        let mut state = lock!(self.state);
        let MribState {
            mrib_in, mrib_loc, ..
        } = &mut *state;
        mrib_in
            .get(key)
            .is_some_and(|route| install(mrib_loc, route))
    }

    /// Select or withdraw `(S,G)` routes according to their shared source's
    /// reachability.
    ///
    /// If the source is reachable, each route in `keys` is installed or
    /// refreshed in `mrib_loc` from its current `mrib_in` entry. Otherwise, or
    /// if a key is no longer in `mrib_in`, the key is removed from `mrib_loc`.
    ///
    /// All reads and updates in the batch share one table lock.
    ///
    /// Returns the keys whose `mrib_loc` entry was modified.
    pub(crate) fn set_source_reachable(
        &self,
        keys: &[MulticastRouteKey],
        reachable: bool,
    ) -> BTreeSet<MulticastRouteKey> {
        let mut state = lock!(self.state);
        let MribState {
            mrib_in, mrib_loc, ..
        } = &mut *state;
        let mut changed = BTreeSet::new();
        for key in keys {
            let modified = match mrib_in.get(key) {
                Some(route) if reachable => install(mrib_loc, route),
                _ => mrib_loc.remove(key).is_some(),
            };
            if modified {
                changed.insert(*key);
            }
        }
        changed
    }

    /// Add or update a multicast route in `mrib_in`.
    ///
    /// Upserts compare every field except timestamps.
    ///
    /// An idempotent upsert leaves the entry untouched. A non-idempotent
    /// upsert keeps the existing [`MulticastRoute::created`] and takes
    /// [`MulticastRoute::updated`] from `route`. By this point, the caller
    /// has already merged both timestamps against the persisted entry.
    ///
    /// The route is added to `mrib_in` only. The caller (`Db`) is responsible
    /// for selecting the route into `mrib_loc`.
    ///
    /// Returns `true` if `mrib_in` was modified.
    pub(crate) fn add_route(&self, mut route: MulticastRoute) -> bool {
        let mut state = lock!(self.state);
        let MribState {
            mrib_in, sources, ..
        } = &mut *state;
        match mrib_in.entry(route.key) {
            Entry::Occupied(mut e) => {
                let existing = e.get();
                let changed = !existing.eq_ignore_timestamps(&route);
                if changed {
                    route.created = existing.created;
                    e.insert(route);
                }
                changed
            }
            Entry::Vacant(e) => {
                if let Some(source) = route.key.source() {
                    sources.entry(source).or_default().insert(route.key);
                }
                e.insert(route);
                true
            }
        }
    }

    /// Remove multicast routes from both `mrib_in` and `mrib_loc`.
    ///
    /// Returns the keys removed from either table.
    pub(crate) fn remove_routes(
        &self,
        keys: &[MulticastRouteKey],
    ) -> BTreeSet<MulticastRouteKey> {
        let mut state = lock!(self.state);
        let MribState {
            mrib_in,
            mrib_loc,
            sources,
        } = &mut *state;
        let mut removed = BTreeSet::new();
        for key in keys {
            let removed_in = mrib_in.remove(key).is_some();
            let removed_loc = mrib_loc.remove(key).is_some();
            if removed_in {
                unindex(sources, key);
            }
            if removed_in || removed_loc {
                removed.insert(*key);
            }
        }
        removed
    }

    /// Group the `(S,G)` keys in `mrib_in` by source.
    ///
    /// `prefixes` selects which sources are returned:
    ///
    /// - `None`: every source
    /// - `Some(prefixes)`: sources covered by any prefix in the set
    /// - `Some` with an empty set: no sources
    ///
    /// Sources are found with one range query per prefix over the source
    /// index. A prefix already covered by an earlier one in the set is
    /// skipped.
    pub(crate) fn source_specific_keys(
        &self,
        prefixes: Option<&BTreeSet<IpNet>>,
    ) -> BTreeMap<IpAddr, Vec<MulticastRouteKey>> {
        let state = lock!(self.state);
        let collect = |keys: &BTreeSet<MulticastRouteKey>| {
            keys.iter().copied().collect::<Vec<_>>()
        };
        let Some(prefixes) = prefixes else {
            return state
                .sources
                .iter()
                .map(|(source, keys)| (*source, collect(keys)))
                .collect();
        };

        let mut grouped = BTreeMap::new();
        let mut cover: Option<&IpNet> = None;
        for prefix in prefixes {
            if cover.is_some_and(|c| prefix.is_subnet_of(c)) {
                continue;
            }
            cover = Some(prefix);
            let range: RangeInclusive<IpAddr> = match prefix {
                IpNet::V4(p) => p.first_addr().into()..=p.last_addr().into(),
                IpNet::V6(p) => p.first_addr().into()..=p.last_addr().into(),
            };
            for (source, keys) in state.sources.range(range) {
                grouped.entry(*source).or_insert_with(|| collect(keys));
            }
        }
        grouped
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::mpsc::channel;

    use mg_common::log::*;

    use super::*;
    use crate::test::underlay_group;
    use crate::types::{
        MulticastAddr, MulticastAddrV4, MulticastAddrV6,
        MulticastSourceProtocol, UnicastAddrV4, UnicastAddrV6,
    };

    #[test]
    fn test_mrib_watchers() {
        let log = init_file_logger("mrib_watcher_test.log");
        let mrib = Mrib::new(log);

        let (tx, rx) = channel();
        mrib.watch("test-watcher".to_string(), tx);

        let group = MulticastAddr::new_v4(225, 3, 3, 3).expect("valid mcast");
        let key = MulticastRouteKey::any_source(group).expect("ASM group");
        let route = MulticastRoute::new(
            key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );

        // The caller batches notifications after updating the tables.
        assert!(mrib.add_route(route));
        assert!(mrib.remove_routes(&[key]).contains(&key));
        assert!(rx.try_recv().is_err());

        mrib.notify(MribChangeNotification::from(key));
        let notification = rx.try_recv().expect("receive notification");
        assert_eq!(notification.changed.len(), 1);
        assert!(notification.changed.contains(&key));
    }

    #[test]
    fn test_mrib_watch_replaces_same_tag() {
        let log = init_file_logger("mrib_watcher_replace_test.log");
        let mrib = Mrib::new(log);

        let (dead_tx, dead_rx) = channel();
        mrib.watch("same-tag".to_string(), dead_tx);
        drop(dead_rx);

        let (live_tx, live_rx) = channel();
        mrib.watch("same-tag".to_string(), live_tx);
        assert_eq!(read_lock!(mrib.watchers).len(), 1);

        let group = MulticastAddr::new_v4(225, 6, 6, 6).expect("valid mcast");
        let key = MulticastRouteKey::any_source(group).expect("ASM group");

        mrib.notify(MribChangeNotification::from(key));
        assert_eq!(read_lock!(mrib.watchers).len(), 1);
        assert!(live_rx.try_recv().unwrap().changed.contains(&key));

        mrib.notify(MribChangeNotification::from(key));
        assert!(live_rx.try_recv().unwrap().changed.contains(&key));
    }

    #[test]
    fn test_mrib_notify_reaps_on_closed_watcher() {
        let log = init_file_logger("mrib_watcher_reap_test.log");
        let mrib = Mrib::new(log);

        let (dead_tx, dead_rx) = channel();
        mrib.watch("dead".to_string(), dead_tx);
        drop(dead_rx);

        let (live_tx, live_rx) = channel();
        mrib.watch("live".to_string(), live_tx);
        assert_eq!(read_lock!(mrib.watchers).len(), 2);

        let group = MulticastAddr::new_v4(225, 7, 7, 7).expect("valid mcast");
        let key = MulticastRouteKey::any_source(group).expect("ASM group");

        mrib.notify(MribChangeNotification::from(key));
        assert!(live_rx.try_recv().unwrap().changed.contains(&key));

        let watchers = read_lock!(mrib.watchers);
        assert_eq!(watchers.len(), 1);
        assert_eq!(watchers[0].tag, "live");
    }

    #[test]
    fn test_mrib_in_vs_loc() {
        let log = init_file_logger("mrib_in_loc_test.log");
        let mrib = Mrib::new(log);

        let group = MulticastAddr::new_v4(225, 4, 4, 4).expect("valid mcast");
        let key = MulticastRouteKey::any_source(group).expect("ASM group");
        let route = MulticastRoute::new(
            key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );

        mrib.add_route(route);

        let source = UnicastAddrV4::new(Ipv4Addr::new(10, 0, 0, 1))
            .expect("valid unicast");
        let group_v4 = MulticastAddrV4::new(Ipv4Addr::new(225, 4, 4, 4))
            .expect("valid mcast");
        let key_sg = MulticastRouteKey::source_specific_v4(source, group_v4);
        mrib.add_route(MulticastRoute::new(
            key_sg,
            underlay_group(),
            MulticastSourceProtocol::Static,
        ));

        assert_eq!(mrib.full_mrib(None).len(), 2);
        assert_eq!(mrib.loc_mrib(None).len(), 0);
        assert!(mrib.get_route(&key).is_some());
        assert!(mrib.get_selected_route(&key).is_none());

        assert!(mrib.select_any_source(&key));

        assert_eq!(mrib.full_mrib(None).len(), 2);
        assert_eq!(mrib.loc_mrib(None).len(), 1);
        assert!(mrib.get_route(&key).is_some());
        assert!(mrib.get_selected_route(&key).is_some());

        assert!(mrib.remove_routes(&[key]).contains(&key));
        assert_eq!(mrib.full_mrib(None).len(), 1);
        assert_eq!(mrib.loc_mrib(None).len(), 0);
        assert!(mrib.get_route(&key).is_none());
        assert!(mrib.get_selected_route(&key).is_none());
        assert!(mrib.get_route(&key_sg).is_some());
    }

    #[test]
    fn test_mrib_source_idx() {
        let log = init_file_logger("mrib_source_idx_test.log");
        let mrib = Mrib::new(log);

        let shared = UnicastAddrV4::new(Ipv4Addr::new(10, 1, 1, 1))
            .expect("valid unicast");
        let other = UnicastAddrV4::new(Ipv4Addr::new(10, 2, 2, 2))
            .expect("valid unicast");
        let keys: Vec<MulticastRouteKey> =
            [(shared, 1u8), (shared, 2), (other, 3)]
                .into_iter()
                .map(|(source, octet)| {
                    let group =
                        MulticastAddrV4::new(Ipv4Addr::new(232, 1, 1, octet))
                            .expect("valid mcast");
                    MulticastRouteKey::source_specific_v4(source, group)
                })
                .collect();
        for key in &keys {
            mrib.add_route(MulticastRoute::new(
                *key,
                underlay_group(),
                MulticastSourceProtocol::Static,
            ));
        }
        let any_source = MulticastRouteKey::any_source(
            MulticastAddr::new_v4(225, 1, 1, 1).expect("valid mcast"),
        )
        .expect("ASM group");
        mrib.add_route(MulticastRoute::new(
            any_source,
            underlay_group(),
            MulticastSourceProtocol::Static,
        ));

        assert_eq!(mrib.source_specific_keys(None).len(), 2);

        let covering: BTreeSet<IpNet> =
            BTreeSet::from(["10.1.0.0/16".parse().unwrap()]);
        let grouped = mrib.source_specific_keys(Some(&covering));
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[&IpAddr::from(shared)], keys[..2]);

        let nested: BTreeSet<IpNet> = BTreeSet::from([
            "10.0.0.0/8".parse().unwrap(),
            "10.1.0.0/16".parse().unwrap(),
            "10.2.2.0/24".parse().unwrap(),
        ]);
        let grouped = mrib.source_specific_keys(Some(&nested));
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[&IpAddr::from(shared)], keys[..2]);
        assert_eq!(grouped[&IpAddr::from(other)], keys[2..]);

        let unrelated: BTreeSet<IpNet> =
            BTreeSet::from(["192.0.2.0/24".parse().unwrap()]);
        assert!(mrib.source_specific_keys(Some(&unrelated)).is_empty());

        let v6_default: BTreeSet<IpNet> =
            BTreeSet::from(["::/0".parse().unwrap()]);
        assert!(mrib.source_specific_keys(Some(&v6_default)).is_empty());

        let v6_source =
            UnicastAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
                .expect("valid unicast");
        let v6_group = MulticastAddrV6::new(Ipv6Addr::new(
            0xff3e, 0, 0, 0, 0, 0, 0x8000, 1,
        ))
        .expect("valid mcast");
        let v6_key = MulticastRouteKey::source_specific_v6(v6_source, v6_group);
        mrib.add_route(MulticastRoute::new(
            v6_key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        ));

        let mixed: BTreeSet<IpNet> = BTreeSet::from([
            "10.1.0.0/16".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ]);
        let grouped = mrib.source_specific_keys(Some(&mixed));
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[&IpAddr::from(shared)], keys[..2]);
        assert_eq!(grouped[&IpAddr::from(v6_source)], [v6_key]);

        mrib.remove_routes(&keys[..1]);
        let grouped = mrib.source_specific_keys(None);
        assert_eq!(grouped[&IpAddr::from(shared)], keys[1..2]);

        mrib.remove_routes(&keys);
        mrib.remove_routes(&[v6_key]);
        assert!(mrib.source_specific_keys(None).is_empty());
    }

    #[test]
    fn test_mrib_set_source_reachable() {
        let log = init_file_logger("mrib_reachable_test.log");
        let mrib = Mrib::new(log);

        let source = UnicastAddrV4::new(Ipv4Addr::new(10, 0, 0, 7))
            .expect("valid unicast");
        let group = MulticastAddrV4::new(Ipv4Addr::new(232, 7, 7, 7))
            .expect("valid mcast");
        let key = MulticastRouteKey::source_specific_v4(source, group);
        let route = MulticastRoute::new(
            key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );

        mrib.add_route(route);
        assert!(mrib.get_selected_route(&key).is_none());

        mrib.set_source_reachable(&[key], true);
        assert!(mrib.get_selected_route(&key).is_some());

        mrib.set_source_reachable(&[key], false);
        assert!(mrib.get_selected_route(&key).is_none());

        mrib.set_source_reachable(&[key], true);
        assert!(mrib.get_selected_route(&key).is_some());

        mrib.remove_routes(&[key]);
        assert!(mrib.source_specific_keys(None).is_empty());
        mrib.set_source_reachable(&[key], true);
        assert!(mrib.get_selected_route(&key).is_none());
        assert_eq!(mrib.loc_mrib(None).len(), 0);
    }

    #[test]
    fn test_mrib_ipv6_groups() {
        let log = init_file_logger("mrib_v6_test.log");
        let mrib = Mrib::new(log);

        // IPv6 any-source multicast route (*,G)
        let group = MulticastAddr::new_v6([0xff0e, 0, 0, 0, 0, 0, 0, 1])
            .expect("valid mcast");
        let key = MulticastRouteKey::any_source(group).expect("ASM group");
        let route = MulticastRoute::new(
            key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );

        mrib.add_route(route);
        assert!(mrib.get_route(&key).is_some());

        // IPv6 source-specific multicast route (S,G)
        let source =
            UnicastAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
                .expect("valid unicast");
        let group_v6 =
            MulticastAddrV6::new(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 1))
                .expect("valid mcast");
        let key_sg = MulticastRouteKey::source_specific_v6(source, group_v6);
        let route_sg = MulticastRoute::new(
            key_sg,
            underlay_group(),
            MulticastSourceProtocol::Static,
        );

        mrib.add_route(route_sg);
        assert_eq!(mrib.full_mrib(None).len(), 2);

        let v6_routes = mrib.full_mrib(Some(AddressFamily::Ipv6));
        assert_eq!(v6_routes.len(), 2);
        let v4_routes = mrib.full_mrib(Some(AddressFamily::Ipv4));
        assert!(v4_routes.is_empty());
        assert!(mrib.loc_mrib(None).is_empty());

        let v4_key = MulticastRouteKey::any_source(
            MulticastAddr::new_v4(225, 1, 1, 1).expect("valid mcast"),
        )
        .expect("ASM group");
        mrib.add_route(MulticastRoute::new(
            v4_key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        ));
        assert_eq!(mrib.full_mrib(None).len(), 3);
        assert_eq!(mrib.full_mrib(Some(AddressFamily::Ipv6)).len(), 2);
        let v4_routes = mrib.full_mrib(Some(AddressFamily::Ipv4));
        assert_eq!(v4_routes.len(), 1);
        assert!(v4_routes.contains_key(&v4_key));

        assert!(mrib.select_any_source(&key));
        assert!(mrib.select_any_source(&v4_key));
        assert_eq!(mrib.loc_mrib(None).len(), 2);
        let v6_selected = mrib.loc_mrib(Some(AddressFamily::Ipv6));
        assert_eq!(v6_selected.len(), 1);
        assert!(v6_selected.contains_key(&key));
        let v4_selected = mrib.loc_mrib(Some(AddressFamily::Ipv4));
        assert_eq!(v4_selected.len(), 1);
        assert!(v4_selected.contains_key(&v4_key));

        assert_eq!(
            mrib.remove_routes(&[key, key_sg, v4_key]),
            BTreeSet::from([key, key_sg, v4_key])
        );
        assert_eq!(mrib.full_mrib(None).len(), 0);
    }
}
