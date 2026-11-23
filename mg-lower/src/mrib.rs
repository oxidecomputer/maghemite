// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! MRIB (Multicast Routing Information Base) lower-half synchronization.
//!
//! Advertises locally originated MRIB multicast groups to the DDM admin API,
//! which distributes them across the underlay to other sleds and racks. This is
//! the multicast analog of the unicast lower-half's tunnel-endpoint
//! origination.
//!
//! Origination reads from the local MRIB (`loc_mrib`) by way of its watcher. On
//! each change notification, or once `MRIB_PERIODIC_SYNC_INTERVAL` elapses
//! without a notification, the loop reconciles `loc_mrib` against the groups
//! originated from DDM. This works similarly to the unicast lower-half's loop
//! (see [`crate::spawn`]).
//!
//! After an `mgd` restart, the in-memory MRIB starts with the empty set and
//! `ddmd` can still include old(er) origins. If Nexus replays a selected route
//! with the same key and underlay address, `mg-lower` disregards re-advertising
//! it. A tombstone can trigger withdrawal for a route missing from the
//! MRIB.
//!
//! An origin without a matching MRIB key or tombstone (e.g., from `ddmadm`)
//! remains in DDM until explicitly withdrawn or until `ddmd` restarts.
//!
//! The inbound membership half (resolving DDM-imported routes into switch
//! replication members in DPD) lives in ddmd (`ddm::mcast`), where its input,
//! the imported set with each route's interface, is owned in-process.
//!
//! ## Data Flow
//!
//! ```text
//!   Origination (MRIB -> DDM -> underlay)
//!     MRIB (loc_mrib changes)
//!         | [MribChangeNotification]
//!         v [MulticastOrigin] (diff vs DDM originated)
//!     DDM admin API --[DDM exchange]--> other sleds/racks
//! ```
//!
//! See RFD 488 for the multicast architecture.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread::{Builder, JoinHandle, sleep};
use std::time::Duration;

use ddm_api_types_versions::latest::net::{
    MulticastOrigin, OverlayMulticast, OverlayMulticastError, Vni,
};
use rdb::types::{MribChangeNotification, MulticastRoute, MulticastRouteKey};
use rdb::{Db, MribTombstones};
use slog::{Logger, error, info, warn};

use crate::ddm::{add_multicast_routes, remove_multicast_routes};
use crate::platform::Ddm;

pub(crate) const MG_LOWER_MRIB_TAG: &str = "mg-lower-mrib";

/// Interval between periodic MRIB full syncs.
///
/// This interval covers the case where an MRIB change notification is missed,
/// following from the unicast lower-half's 1s resync cadence (see
/// [`crate::spawn`]).
const MRIB_PERIODIC_SYNC_INTERVAL: Duration = Duration::from_secs(1);

/// The delay before retrying a failed MRIB sync.
///
/// This is independent of [`MRIB_PERIODIC_SYNC_INTERVAL`], separating
/// resync configuration from changing the retry rate.
const MRIB_SYNC_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Convert an MRIB `MulticastRoute` to a DDM `MulticastOrigin`.
///
/// # Errors
///
/// Returns an error if the route's group or source fails DDM origin
/// validation.
fn ddm_origin(route: &MulticastRoute) -> Result<MulticastOrigin, String> {
    let overlay_group = OverlayMulticast::new(route.key.group().ip())
        .map_err(|e| format!("invalid overlay group: {e}"))?;

    MulticastOrigin::new(
        overlay_group,
        route.underlay_group,
        route.key.vni(),
        route.key.source(),
    )
    .map_err(|e| format!("invalid multicast origin: {e}"))
}

/// The identity of a DDM multicast origin without its underlay group.
///
/// [`sync`] compares full origins with matching keys to detect underlay
/// group changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OriginKey {
    group: OverlayMulticast,
    vni: Vni,
    source: Option<IpAddr>,
}

impl From<&MulticastOrigin> for OriginKey {
    fn from(origin: &MulticastOrigin) -> Self {
        Self {
            group: origin.overlay_group(),
            vni: origin.vni(),
            source: origin.source(),
        }
    }
}

impl TryFrom<&MulticastRouteKey> for OriginKey {
    type Error = OverlayMulticastError;

    fn try_from(key: &MulticastRouteKey) -> Result<Self, Self::Error> {
        Ok(Self {
            group: OverlayMulticast::new(key.group().ip())?,
            vni: key.vni(),
            source: key.source(),
        })
    }
}

/// DDM origin keys and `(group, VNI)` pairs from MRIB tombstones.
struct RemovedOrigins {
    keys: HashSet<OriginKey>,
    groups: HashSet<(OverlayMulticast, Vni)>,
}

impl From<&MribTombstones> for RemovedOrigins {
    fn from(tombstones: &MribTombstones) -> Self {
        Self {
            keys: tombstones
                .keys
                .iter()
                .filter_map(|key| OriginKey::try_from(key).ok())
                .collect(),
            groups: tombstones
                .groups
                .iter()
                .filter_map(|g| {
                    OverlayMulticast::new(g.group.ip()).ok().map(|o| (o, g.vni))
                })
                .collect(),
        }
    }
}

impl RemovedOrigins {
    fn covers(&self, key: &OriginKey) -> bool {
        self.keys.contains(key) || self.groups.contains(&(key.group, key.vni))
    }
}

/// Run the MRIB origination loop on a dedicated `mg-lower-mrib` thread.
///
/// # Errors
///
/// Returns an error if the thread cannot be spawned.
pub fn spawn(
    db: Db,
    log: Logger,
    rt: Arc<tokio::runtime::Handle>,
    ddm: impl Ddm + Send + 'static,
) -> std::io::Result<JoinHandle<()>> {
    db.track_mcast_tombstones();
    Builder::new()
        .name(MG_LOWER_MRIB_TAG.to_string())
        .spawn(move || run(db, log, rt, &ddm))
}

/// Run the MRIB origination loop.
///
/// This function loops ad infinitum, watching for MRIB changes and advertising
/// locally originated multicast groups to DDM.
fn run(db: Db, log: Logger, rt: Arc<tokio::runtime::Handle>, ddm: &impl Ddm) {
    let mut rx = watch(&db);
    let mut untracked_origins = HashSet::new();
    loop {
        if let Err(e) =
            sync_pending(&db, ddm, &mut untracked_origins, &log, &rt, &rx)
        {
            error!(log, "MRIB sync failed: {e}");
            sleep(MRIB_SYNC_RETRY_DELAY);
            continue;
        }

        match rx.recv_timeout(MRIB_PERIODIC_SYNC_INTERVAL) {
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                error!(log, "MRIB watcher disconnected");
                rx = watch(&db);
            }
        }
    }
}

fn watch(db: &Db) -> Receiver<MribChangeNotification> {
    let (tx, rx) = channel();
    // Registering under the same tag replaces any watcher left over from a
    // previous registration.
    db.watch_mrib(MG_LOWER_MRIB_TAG.into(), tx);
    rx
}

/// Drain all pending notifications and reconcile the current MRIB with DDM.
///
/// `sync` reads the selected MRIB, the `mrib_in` keys and any pending
/// tombstones. Individual notifications are discarded.
///
/// # Errors
///
/// Propagates errors from `sync`.
fn sync_pending(
    db: &Db,
    ddm: &impl Ddm,
    untracked_origins: &mut HashSet<MulticastOrigin>,
    log: &Logger,
    rt: &Arc<tokio::runtime::Handle>,
    rx: &Receiver<MribChangeNotification>,
) -> Result<(), String> {
    rx.try_iter().for_each(std::mem::drop);
    sync(db, ddm, untracked_origins, log, rt)
}

/// Synchronize MRIB origination to DDM.
///
/// This compares the current MRIB (`loc_mrib`) with what DDM has originated.
/// Selected routes missing from DDM are directly advertised. An origin is
/// withdrawn when its key is selected with a different underlay group, when its
/// key is in `mrib_in` but not selected, or when a tombstone covers it. A
/// selected key with the same underlay group is retained, even when a tombstone
/// covers it, because this means the route was added back after its initial
/// removal.
///
/// Each pass takes the pending tombstones and requeues them if the pass fails.
/// The untracked set, used only for logging, is replaced after a successful
/// pass.
///
/// # Errors
///
/// Returns an error if DDM's originated groups cannot be read, or if
/// advertising or withdrawing an origin fails.
pub(crate) fn sync<D: Ddm>(
    db: &Db,
    ddm: &D,
    untracked_origins: &mut HashSet<MulticastOrigin>,
    log: &Logger,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<(), String> {
    let tombstones = db.take_mcast_tombstones();
    sync_with_tombstones(db, ddm, untracked_origins, log, rt, &tombstones)
        .inspect_err(|_| db.requeue_mcast_tombstones(tombstones))
}

fn sync_with_tombstones<D: Ddm>(
    db: &Db,
    ddm: &D,
    untracked_origins: &mut HashSet<MulticastOrigin>,
    log: &Logger,
    rt: &Arc<tokio::runtime::Handle>,
    tombstones: &MribTombstones,
) -> Result<(), String> {
    let wanted: HashMap<OriginKey, MulticastOrigin> = db
        .loc_mrib(None)
        .values()
        .filter_map(|route| match ddm_origin(route) {
            Ok(origin) => Some((OriginKey::from(&origin), origin)),
            Err(e) => {
                warn!(log, "skipping MRIB route {}: {e}", route.key);
                None
            }
        })
        .collect();

    // A replayed `(S,G)` route can still have an origin in DDM before
    // mgd has a unicast path to the source.
    let configured: HashSet<OriginKey> = db
        .mrib_in_keys()
        .iter()
        .filter_map(|key| OriginKey::try_from(key).ok())
        .collect();

    let removed = RemovedOrigins::from(tombstones);

    let current: HashSet<MulticastOrigin> = rt
        .block_on(ddm.get_originated_multicast_groups())
        .map_err(|e| format!("failed to get DDM multicast groups: {e}"))?
        .into_inner()
        .into_iter()
        .collect();

    add_multicast_routes(
        ddm,
        wanted.values().filter(|origin| !current.contains(*origin)),
        rt,
        log,
    )
    .map_err(|e| format!("failed to advertise multicast groups: {e}"))?;

    let claimed =
        |key: &OriginKey| configured.contains(key) || removed.covers(key);

    let to_withdraw = current.iter().filter(|origin| {
        let key = OriginKey::from(*origin);
        match wanted.get(&key) {
            Some(want) => want != *origin,
            None => claimed(&key),
        }
    });
    remove_multicast_routes(ddm, to_withdraw, rt, log)
        .map_err(|e| format!("failed to withdraw multicast groups: {e}"))?;

    let still_untracked: HashSet<MulticastOrigin> = current
        .into_iter()
        .filter(|origin| {
            let key = OriginKey::from(origin);
            !wanted.contains_key(&key) && !claimed(&key)
        })
        .collect();
    match still_untracked.len() {
        _ if still_untracked == *untracked_origins => (),
        0 => info!(log, "no untracked DDM multicast origins remain"),
        count => info!(
            log,
            "leaving untracked DDM multicast origins in place";
            "count" => count
        ),
    }

    *untracked_origins = still_untracked;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::Ordering;

    use mg_api_types::rdb::DEFAULT_RIB_PRIORITY_STATIC;
    use rdb::test::{TestDb, get_test_db};
    use rdb::types::{
        MulticastAddr, MulticastRouteKey, MulticastSourceProtocol,
        StaticMulticastGroupKey, StaticRouteKey, UnderlayMulticastIpv6, Vni,
    };

    use super::*;
    use crate::platform::test::{MulticastCall, TestDdm};

    struct SyncFixture {
        _rt: tokio::runtime::Runtime,
        handle: Arc<tokio::runtime::Handle>,
        log: Logger,
        db: TestDb,
        ddm: TestDdm,
        untracked_origins: HashSet<MulticastOrigin>,
    }

    impl SyncFixture {
        fn new(name: &str) -> Self {
            let rt = tokio::runtime::Runtime::new().expect("build runtime");
            let handle = Arc::new(rt.handle().clone());
            let log = Logger::root(slog::Discard, slog::o!());
            let db = get_test_db(name, log.clone()).unwrap();
            db.track_mcast_tombstones();
            Self {
                _rt: rt,
                handle,
                log,
                db,
                ddm: TestDdm::default(),
                untracked_origins: HashSet::new(),
            }
        }

        fn sync(&mut self) -> Result<(), String> {
            sync(
                &self.db,
                &self.ddm,
                &mut self.untracked_origins,
                &self.log,
                &self.handle,
            )
        }

        fn seed_ddm(&self, route: &MulticastRoute) {
            self.ddm
                .multicast_originated
                .lock()
                .unwrap()
                .push(origin(route));
        }

        fn originated(&self) -> Vec<MulticastOrigin> {
            self.ddm.multicast_originated.lock().unwrap().clone()
        }

        fn take_calls(&self) -> Vec<MulticastCall> {
            std::mem::take(&mut *self.ddm.multicast_calls.lock().unwrap())
        }
    }

    fn vni() -> Vni {
        Vni::new(77).expect("valid VNI")
    }

    fn test_underlay() -> UnderlayMulticastIpv6 {
        UnderlayMulticastIpv6::new(Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1))
            .expect("valid underlay address")
    }

    fn origin(route: &MulticastRoute) -> MulticastOrigin {
        ddm_origin(route).expect("valid origin")
    }

    /// Build an any-source (*,G) static route for the given IPv4 group.
    fn asm_route(a: u8, b: u8, c: u8, d: u8) -> MulticastRoute {
        let group = MulticastAddr::new(Ipv4Addr::new(a, b, c, d).into())
            .expect("valid group");
        let key = MulticastRouteKey::any_source(group, vni()).unwrap();
        MulticastRoute::new(
            key,
            test_underlay(),
            MulticastSourceProtocol::Static,
        )
    }

    /// Build an any-source (*,G) static route for an IPv6 group in
    /// `ff0e::/16`, with a distinct underlay (1:1 overlay-to-underlay
    /// mapping).
    fn asm_route_v6(last: u16) -> MulticastRoute {
        let group = MulticastAddr::new(
            Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, last).into(),
        )
        .expect("valid group");
        let underlay = UnderlayMulticastIpv6::new(Ipv6Addr::new(
            0xff04, 0, 0, 0, 0, 0, 0x1, last,
        ))
        .expect("valid underlay address");
        let key = MulticastRouteKey::any_source(group, vni()).unwrap();
        MulticastRoute::new(key, underlay, MulticastSourceProtocol::Static)
    }

    fn with_underlay(route: &MulticastRoute, last: u16) -> MulticastRoute {
        let underlay = UnderlayMulticastIpv6::new(Ipv6Addr::new(
            0xff04, 0, 0, 0, 0, 0, 0x2, last,
        ))
        .expect("valid underlay address");
        MulticastRoute::new(
            route.key,
            underlay,
            MulticastSourceProtocol::Static,
        )
    }

    fn ssm_route() -> MulticastRoute {
        let group = MulticastAddr::new(Ipv4Addr::new(232, 1, 1, 1).into())
            .expect("valid group");
        let key = MulticastRouteKey::new(
            Some(Ipv4Addr::new(10, 0, 0, 1).into()),
            group,
            vni(),
        )
        .unwrap();
        MulticastRoute::new(
            key,
            test_underlay(),
            MulticastSourceProtocol::Static,
        )
    }

    #[test]
    fn sync_advertises_groups_missing_from_ddm() {
        let mut f = SyncFixture::new("mrib_sync_add");
        let route = asm_route(225, 1, 1, 1);
        f.db.add_static_mcast_routes(std::slice::from_ref(&route));

        f.sync().unwrap();

        assert_eq!(f.originated(), vec![origin(&route)]);
    }

    #[test]
    fn sync_advertises_v4_and_v6_overlay_groups() {
        let mut f = SyncFixture::new("mrib_sync_v6");
        let v4 = asm_route(225, 1, 1, 1);
        let v6 = asm_route_v6(1);
        f.db.add_static_mcast_routes(&[v4.clone(), v6.clone()]);

        f.sync().unwrap();

        assert_eq!(
            f.originated().into_iter().collect::<HashSet<_>>(),
            HashSet::from([origin(&v4), origin(&v6)])
        );
    }

    #[test]
    fn sync_preserves_untracked_origins() {
        let mut f = SyncFixture::new("mrib_sync_untracked");
        let untracked = asm_route(225, 9, 9, 9);
        f.seed_ddm(&untracked);

        f.sync().unwrap();

        assert_eq!(f.originated(), vec![origin(&untracked)]);
        assert_eq!(f.untracked_origins, HashSet::from([origin(&untracked)]));
    }

    #[test]
    fn sync_in_sync_makes_no_changes() {
        let mut f = SyncFixture::new("mrib_sync_noop");
        let route = asm_route(225, 5, 5, 5);
        f.db.add_static_mcast_routes(std::slice::from_ref(&route));
        f.seed_ddm(&route);

        f.sync().unwrap();

        assert_eq!(f.originated(), vec![origin(&route)]);
        assert!(f.take_calls().is_empty());
        assert!(f.untracked_origins.is_empty());
    }

    #[test]
    fn sync_adds_and_withdraws_together() {
        let mut f = SyncFixture::new("mrib_sync_mixed");
        let removed = asm_route(225, 1, 1, 1);
        let untracked = asm_route(225, 3, 3, 3);
        f.db.add_static_mcast_routes(std::slice::from_ref(&removed));
        f.seed_ddm(&untracked);
        f.sync().unwrap();

        let added = asm_route(225, 2, 2, 2);
        f.db.remove_static_mcast_routes(&[removed.key]);
        f.db.add_static_mcast_routes(std::slice::from_ref(&added));
        f.sync().unwrap();

        assert_eq!(
            f.originated().into_iter().collect::<HashSet<_>>(),
            HashSet::from([origin(&added), origin(&untracked)])
        );
    }

    #[test]
    fn sync_withdraws_removed_route() {
        let mut f = SyncFixture::new("mrib_sync_withdraw");
        let removed = asm_route(225, 1, 1, 1);
        let other = asm_route(225, 2, 2, 2);
        f.db.add_static_mcast_routes(&[removed.clone(), other.clone()]);
        f.sync().unwrap();

        f.db.remove_static_mcast_routes(&[removed.key]);
        f.sync().unwrap();

        assert_eq!(
            f.originated(),
            vec![origin(&other)],
            "unrelated group must remain advertised"
        );
    }

    #[test]
    fn sync_adopts_untracked_origin() {
        let mut f = SyncFixture::new("mrib_sync_adopt_untracked");
        let route = asm_route(225, 1, 1, 1);
        f.seed_ddm(&route);

        f.sync().expect("sync empty MRIB");
        assert_eq!(f.originated(), vec![origin(&route)]);

        f.db.add_static_mcast_routes(std::slice::from_ref(&route));
        f.sync().expect("sync replay");
        assert_eq!(f.originated(), vec![origin(&route)]);
        assert!(f.untracked_origins.is_empty());

        f.db.remove_static_mcast_routes(&[route.key]);
        f.sync().expect("sync removal");
        assert!(f.originated().is_empty());
    }

    #[test]
    fn sync_readvertises_missing_origins() {
        let mut f = SyncFixture::new("mrib_sync_readvertise");
        let route = asm_route(225, 1, 1, 1);
        f.db.add_static_mcast_routes(std::slice::from_ref(&route));
        f.sync().unwrap();

        f.ddm.multicast_originated.lock().unwrap().clear();
        f.sync().expect("sync after ddmd restart");

        assert_eq!(f.originated(), vec![origin(&route)]);
    }

    #[test]
    fn sync_replaces_stale_underlay() {
        let mut f = SyncFixture::new("mrib_sync_underlay");
        let before = asm_route(225, 1, 1, 1);
        let after = with_underlay(&before, 1);
        f.db.add_static_mcast_routes(std::slice::from_ref(&before));
        f.sync().unwrap();

        f.db.add_static_mcast_routes(std::slice::from_ref(&after));
        f.take_calls();
        f.sync().unwrap();

        assert_eq!(f.originated(), vec![origin(&after)]);
        assert_eq!(
            f.take_calls(),
            vec![
                MulticastCall::Advertise(vec![origin(&after)]),
                MulticastCall::Withdraw(vec![origin(&before)]),
            ]
        );
    }

    #[test]
    fn sync_replaces_untracked_stale_underlay() {
        let mut f = SyncFixture::new("mrib_sync_untracked_underlay");
        let previous = asm_route(225, 1, 1, 1);
        let current = with_underlay(&previous, 1);
        f.seed_ddm(&previous);
        f.db.add_static_mcast_routes(std::slice::from_ref(&current));

        f.sync().unwrap();

        assert_eq!(f.originated(), vec![origin(&current)]);
        assert_eq!(
            f.take_calls(),
            vec![
                MulticastCall::Advertise(vec![origin(&current)]),
                MulticastCall::Withdraw(vec![origin(&previous)]),
            ]
        );
    }

    #[test]
    fn sync_retries_failed_withdrawal() {
        let mut f = SyncFixture::new("mrib_sync_retry");
        let route = asm_route(225, 1, 1, 1);
        f.db.add_static_mcast_routes(std::slice::from_ref(&route));
        f.sync().unwrap();

        f.db.remove_static_mcast_routes(&[route.key]);
        f.ddm.fail_multicast_withdraw.store(true, Ordering::SeqCst);
        f.sync().expect_err("withdraw fails");
        assert_eq!(f.originated(), vec![origin(&route)]);
        f.ddm.fail_multicast_withdraw.store(false, Ordering::SeqCst);

        f.db.add_static_mcast_routes(std::slice::from_ref(&route));
        f.take_calls();
        f.sync().expect("sync reselect");
        assert_eq!(f.originated(), vec![origin(&route)]);
        assert!(f.take_calls().is_empty());

        f.db.remove_static_mcast_routes(&[route.key]);
        f.sync().expect("sync retry");
        assert!(f.originated().is_empty());
    }

    #[test]
    fn sync_adopts_lost_advertisement() {
        let mut f = SyncFixture::new("mrib_sync_failed_add");
        let route = asm_route(225, 1, 1, 1);
        f.db.add_static_mcast_routes(std::slice::from_ref(&route));

        f.ddm.fail_multicast_advertise.store(true, Ordering::SeqCst);
        f.sync().expect_err("advertise fails");
        assert_eq!(f.originated(), vec![origin(&route)]);
        f.ddm
            .fail_multicast_advertise
            .store(false, Ordering::SeqCst);

        f.take_calls();
        f.sync().expect("sync after lost reply");
        assert_eq!(f.originated(), vec![origin(&route)]);
        assert!(f.take_calls().is_empty());

        f.db.remove_static_mcast_routes(&[route.key]);
        f.sync().expect("sync removal");

        assert!(f.originated().is_empty());
        assert!(f.untracked_origins.is_empty());
    }

    fn source_route() -> StaticRouteKey {
        StaticRouteKey {
            prefix: "10.0.0.0/24".parse::<oxnet::IpNet>().unwrap(),
            nexthop: Ipv4Addr::new(198, 51, 100, 1).into(),
            vlan_id: None,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
        }
    }

    #[test]
    fn sync_follows_source_specific_selection() {
        let mut f = SyncFixture::new("mrib_sync_ssm_adopt");
        let route = ssm_route();
        f.seed_ddm(&route);
        f.db.add_static_routes(&[source_route()])
            .expect("unicast add");
        f.db.add_static_mcast_routes(std::slice::from_ref(&route));
        assert!(f.db.loc_mrib(None).contains_key(&route.key));

        f.sync().expect("sync selected");
        assert_eq!(f.originated(), vec![origin(&route)]);
        assert!(f.take_calls().is_empty());
        assert!(f.untracked_origins.is_empty());

        f.db.remove_static_routes(&[source_route()])
            .expect("unicast remove");
        assert!(f.db.loc_mrib(None).is_empty());
        f.sync().expect("sync deselected");
        assert!(f.originated().is_empty());
    }

    #[test]
    fn sync_withdraws_unselected_source_specific_origin() {
        let mut f = SyncFixture::new("mrib_sync_ssm_unselected");
        let route = ssm_route();
        f.seed_ddm(&route);
        f.db.add_static_mcast_routes(std::slice::from_ref(&route));
        assert!(f.db.loc_mrib(None).is_empty());

        f.sync().expect("sync unselected");
        assert!(f.originated().is_empty());
        assert!(f.untracked_origins.is_empty());

        f.db.add_static_routes(&[source_route()])
            .expect("unicast add");
        f.sync().expect("sync selected");
        assert_eq!(f.originated(), vec![origin(&route)]);
    }

    fn group_remove(route: &MulticastRoute) -> StaticMulticastGroupKey {
        StaticMulticastGroupKey {
            key: route.key.group_key(),
            group_id: uuid::Uuid::new_v4(),
        }
    }

    #[test]
    fn removed_origins_cover_keys_and_groups() {
        let asm = asm_route(225, 1, 1, 1);
        let ssm = ssm_route();
        let other = asm_route(225, 2, 2, 2);
        let removed = RemovedOrigins::from(&MribTombstones {
            keys: HashSet::from([asm.key]),
            groups: HashSet::from([ssm.key.group_key()]),
        });

        assert!(removed.covers(&OriginKey::from(&origin(&asm))));
        let mvd = with_underlay(&asm, 1);
        assert!(removed.covers(&OriginKey::from(&origin(&mvd))));
        assert!(removed.covers(&OriginKey::from(&origin(&ssm))));
        assert!(!removed.covers(&OriginKey::from(&origin(&other))));
    }

    #[test]
    fn sync_withdraws_removed_untracked_origin() {
        let mut f = SyncFixture::new("mrib_sync_removed_key");
        let removed = asm_route(225, 1, 1, 1);
        let untracked = asm_route(225, 2, 2, 2);
        f.seed_ddm(&removed);
        f.seed_ddm(&untracked);

        f.db.remove_static_mcast_routes(&[removed.key]);
        f.sync().unwrap();

        assert_eq!(f.originated(), vec![origin(&untracked)]);
        assert!(f.db.take_mcast_tombstones().is_empty());
    }

    #[test]
    fn sync_withdraws_group_scoped_removed_origin() {
        let mut f = SyncFixture::new("mrib_sync_scoped_key");
        let removed = asm_route(225, 1, 1, 1);
        f.seed_ddm(&removed);

        f.db.remove_group_static_mcast_routes(
            uuid::Uuid::new_v4(),
            &[removed.key],
        );
        f.sync().unwrap();

        assert!(f.originated().is_empty());
        assert!(f.db.take_mcast_tombstones().is_empty());
    }

    #[test]
    fn sync_withdraws_removed_group() {
        let mut f = SyncFixture::new("mrib_sync_removed_group");
        let route = ssm_route();
        let other_source = MulticastRoute::new(
            MulticastRouteKey::new(
                Some(Ipv4Addr::new(10, 0, 0, 2).into()),
                route.key.group(),
                vni(),
            )
            .unwrap(),
            test_underlay(),
            MulticastSourceProtocol::Static,
        );
        let untracked = asm_route(225, 2, 2, 2);
        for r in [&route, &other_source, &untracked] {
            f.seed_ddm(r);
        }

        f.db.remove_static_mcast_groups(&[group_remove(&route)]);
        f.sync().unwrap();

        assert_eq!(f.originated(), vec![origin(&untracked)]);
        assert!(f.db.take_mcast_tombstones().is_empty());
    }

    #[test]
    fn sync_keeps_readded_route() {
        let mut f = SyncFixture::new("mrib_sync_readded");
        let route = asm_route(225, 1, 1, 1);
        f.seed_ddm(&route);

        f.db.remove_static_mcast_groups(&[group_remove(&route)]);
        f.db.add_static_mcast_routes(std::slice::from_ref(&route));
        f.sync().unwrap();

        assert_eq!(f.originated(), vec![origin(&route)]);
        assert!(f.take_calls().is_empty());
        assert!(f.db.take_mcast_tombstones().is_empty());
    }

    #[test]
    fn sync_keeps_concurrent_delete_queued() {
        let mut f = SyncFixture::new("mrib_sync_repeat_delete");
        let route = asm_route(225, 1, 1, 1);
        f.seed_ddm(&route);
        let groups = [group_remove(&route)];

        f.db.remove_static_mcast_groups(&groups);
        let tombstones = f.db.take_mcast_tombstones();
        assert!(!tombstones.is_empty());
        assert!(f.db.take_mcast_tombstones().is_empty());

        f.db.remove_static_mcast_groups(&groups);
        sync_with_tombstones(
            &f.db,
            &f.ddm,
            &mut f.untracked_origins,
            &f.log,
            &f.handle,
            &tombstones,
        )
        .unwrap();
        assert!(f.originated().is_empty());
        assert_eq!(f.db.take_mcast_tombstones(), tombstones);
    }

    #[test]
    fn sync_keeps_replacement_group_after_stale_delete() {
        let mut f = SyncFixture::new("mrib_sync_replacement_group");
        let route = MulticastRoute {
            group_id: Some(uuid::Uuid::new_v4()),
            ..asm_route(225, 1, 1, 1)
        };
        f.db.add_static_mcast_routes(std::slice::from_ref(&route));
        f.seed_ddm(&route);

        f.db.remove_static_mcast_groups(&[group_remove(&route)]);
        f.sync().unwrap();

        assert_eq!(f.originated(), vec![origin(&route)]);
        assert!(f.take_calls().is_empty());
        assert!(f.db.get_mcast_route(&route.key).is_some());
    }

    #[test]
    fn sync_requeues_tombstones_when_ddm_read_fails() {
        let mut f = SyncFixture::new("mrib_sync_read_failure");
        let route = asm_route(225, 1, 1, 1);
        f.seed_ddm(&route);
        f.db.remove_static_mcast_routes(&[route.key]);

        f.ddm.fail_multicast_get.store(true, Ordering::SeqCst);
        f.sync().expect_err("DDM read fails");
        assert_eq!(f.originated(), vec![origin(&route)]);
        f.ddm.fail_multicast_get.store(false, Ordering::SeqCst);

        f.sync().unwrap();
        assert!(f.originated().is_empty());
        assert!(f.db.take_mcast_tombstones().is_empty());
    }
}
