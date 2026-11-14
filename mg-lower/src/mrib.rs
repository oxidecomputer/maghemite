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
//! without a notification, the loop runs the same full reconciliation
//! of `loc_mrib` against the groups originated from DDM. This works similarly
//! to the unicast lower-half's loop (see [`crate::spawn`]).
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

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread::{Builder, JoinHandle, sleep};
use std::time::Duration;

use ddm_api_types_versions::latest::net::{MulticastOrigin, OverlayMulticast};
use rdb::Db;
use rdb::types::{MribChangeNotification, MulticastRoute};
use slog::{Logger, error, warn};

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
    loop {
        if let Err(e) = sync_pending(&db, ddm, &log, &rt, &rx) {
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
/// `sync` reads the fully selected MRIB, discarding individual notifications.
///
/// # Errors
///
/// Propagates errors from `sync`.
fn sync_pending(
    db: &Db,
    ddm: &impl Ddm,
    log: &Logger,
    rt: &Arc<tokio::runtime::Handle>,
    rx: &Receiver<MribChangeNotification>,
) -> Result<(), String> {
    rx.try_iter().for_each(std::mem::drop);
    sync(db, ddm, log, rt)
}

/// Synchronize MRIB origination to DDM.
///
/// This compares the current MRIB (`loc_mrib`) with what DDM has advertised,
/// reconciling any differences.
///
/// # Errors
///
/// Returns an error if DDM's originated groups cannot be read.
pub(crate) fn sync<D: Ddm>(
    db: &Db,
    ddm: &D,
    log: &Logger,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<(), String> {
    let wanted: HashSet<MulticastOrigin> = db
        .loc_mrib(None)
        .values()
        .filter_map(|route| match ddm_origin(route) {
            Ok(origin) => Some(origin),
            Err(e) => {
                warn!(log, "skipping MRIB route {}: {e}", route.key);
                None
            }
        })
        .collect();

    let current: HashSet<MulticastOrigin> = rt
        .block_on(ddm.get_originated_multicast_groups())
        .map_err(|e| format!("failed to get DDM multicast groups: {e}"))?
        .into_inner()
        .into_iter()
        .collect();

    add_multicast_routes(ddm, wanted.difference(&current), rt, log)
        .map_err(|e| format!("failed to advertise multicast groups: {e}"))?;
    remove_multicast_routes(ddm, current.difference(&wanted), rt, log)
        .map_err(|e| format!("failed to withdraw multicast groups: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::mpsc::TryRecvError;

    use rdb::test::get_test_db;
    use rdb::types::{
        MulticastAddr, MulticastRouteKey, MulticastSourceProtocol,
        UnderlayMulticastIpv6, Vni,
    };

    use super::*;
    use crate::platform::test::TestDdm;

    fn discard_logger() -> Logger {
        Logger::root(slog::Discard, slog::o!())
    }

    /// Runtime handle for `sync`'s internal `block_on`. Tests run on a std
    /// thread (not a tokio worker).
    fn runtime() -> (tokio::runtime::Runtime, Arc<tokio::runtime::Handle>) {
        let rt = tokio::runtime::Runtime::new().expect("build runtime");
        let handle = Arc::new(rt.handle().clone());
        (rt, handle)
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
        let key = MulticastRouteKey::any_source(group, vni()).expect("key");
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
        let key = MulticastRouteKey::any_source(group, vni()).expect("key");
        MulticastRoute::new(key, underlay, MulticastSourceProtocol::Static)
    }

    #[test]
    fn sync_pending_reconciles_after_dropping_notifications() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_sync_pending", log.clone()).expect("db");
        let rx = watch(&db);
        let removed = asm_route(225, 1, 1, 1);
        let added = asm_route_v6(1);
        let ddm = TestDdm::default();
        ddm.multicast_originated
            .lock()
            .unwrap()
            .push(origin(&removed));

        db.add_static_mcast_routes(std::slice::from_ref(&removed))
            .expect("add initial route");
        db.add_static_mcast_routes(std::slice::from_ref(&added))
            .expect("add replacement route");
        db.remove_static_mcast_routes(&[removed.key])
            .expect("remove initial route");
        rx.try_recv().expect("queued change notification");

        sync_pending(&db, &ddm, &log, &handle, &rx).expect("sync burst");

        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(
            *ddm.multicast_originated.lock().unwrap(),
            vec![origin(&added)]
        );

        db.remove_static_mcast_routes(&[added.key])
            .expect("remove remaining route");
        rx.try_recv().expect("subsequent change notification");

        sync_pending(&db, &ddm, &log, &handle, &rx)
            .expect("sync subsequent change");

        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(ddm.multicast_originated.lock().unwrap().is_empty());
    }

    #[test]
    fn sync_advertises_groups_missing_from_ddm() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_sync_add", log.clone()).expect("db");
        let route = asm_route(225, 1, 1, 1);
        db.add_static_mcast_routes(std::slice::from_ref(&route))
            .expect("add route");

        let ddm = TestDdm::default();
        sync(&db, &ddm, &log, &handle).expect("sync");

        let originated = ddm.multicast_originated.lock().unwrap();
        assert_eq!(*originated, vec![origin(&route)]);
    }

    #[test]
    fn sync_advertises_v4_and_v6_overlay_groups() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_sync_v6", log.clone()).expect("db");
        let v4 = asm_route(225, 1, 1, 1);
        let v6 = asm_route_v6(1);
        db.add_static_mcast_routes(&[v4.clone(), v6.clone()])
            .expect("add routes");

        let ddm = TestDdm::default();
        sync(&db, &ddm, &log, &handle).expect("sync");

        let originated = ddm.multicast_originated.lock().unwrap();
        assert_eq!(originated.len(), 2);
        assert!(originated.contains(&origin(&v4)));
        assert!(originated.contains(&origin(&v6)));
    }

    #[test]
    fn sync_withdraws_groups_absent_from_mrib() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_sync_remove", log.clone()).expect("db");

        let stale = asm_route(225, 9, 9, 9);
        let ddm = TestDdm::default();
        ddm.multicast_originated
            .lock()
            .unwrap()
            .push(origin(&stale));

        sync(&db, &ddm, &log, &handle).expect("sync");

        assert!(ddm.multicast_originated.lock().unwrap().is_empty());
    }

    #[test]
    fn sync_in_sync_makes_no_changes() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_sync_noop", log.clone()).expect("db");
        let route = asm_route(225, 5, 5, 5);
        db.add_static_mcast_routes(std::slice::from_ref(&route))
            .expect("add route");

        let ddm = TestDdm::default();
        ddm.multicast_originated
            .lock()
            .unwrap()
            .push(origin(&route));

        sync(&db, &ddm, &log, &handle).expect("sync");

        let originated = ddm.multicast_originated.lock().unwrap();
        assert_eq!(
            *originated,
            vec![origin(&route)],
            "in-sync group must not be re-added"
        );
    }

    #[test]
    fn sync_adds_and_withdraws_together() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_sync_mixed", log.clone()).expect("db");
        let keep = asm_route(225, 1, 1, 1);
        db.add_static_mcast_routes(std::slice::from_ref(&keep))
            .expect("add route");

        let ddm = TestDdm::default();
        let stale = asm_route(225, 2, 2, 2);
        ddm.multicast_originated
            .lock()
            .unwrap()
            .push(origin(&stale));

        sync(&db, &ddm, &log, &handle).expect("sync");

        let originated = ddm.multicast_originated.lock().unwrap();
        assert_eq!(*originated, vec![origin(&keep)]);
    }

    #[test]
    fn sync_withdraws_removed_route() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_sync_withdraw", log.clone()).expect("db");
        let removed = asm_route(225, 1, 1, 1);
        let other = asm_route(225, 2, 2, 2);
        db.add_static_mcast_routes(&[removed.clone(), other.clone()])
            .expect("add routes");

        let ddm = TestDdm::default();
        sync(&db, &ddm, &log, &handle).expect("sync");

        db.remove_static_mcast_routes(&[removed.key])
            .expect("remove route");
        sync(&db, &ddm, &log, &handle).expect("sync");

        let originated = ddm.multicast_originated.lock().unwrap();
        assert_eq!(
            *originated,
            vec![origin(&other)],
            "unrelated group must remain advertised"
        );
    }
}
