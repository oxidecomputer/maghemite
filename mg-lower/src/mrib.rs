// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! MRIB (Multicast Routing Information Base) lower-half synchronization.
//!
//! Advertises locally originated MRIB multicast groups to the DDM admin API,
//! which distributes them across the underlay to other sleds and racks. This is
//! the multicast analog of the unicast lower-half's tunnel-endpoint origination.
//!
//! Origination reads the local MRIB (`loc_mrib`) and is watch-driven, with the
//! periodic resync only as a backstop, the same shape as the unicast
//! lower-half's crate-level loop [`crate::run`].
//!
//! The inbound membership half (resolving DDM-imported routes to switch
//! replication members in DPD) lives in ddmd (`ddm::mcast`), where both inputs,
//! the imported set and the peer table, are owned in-process.
//!
//! ## Data Flow
//!
//! ```text
//!   Origination (MRIB -> DDM -> underlay)
//!     MRIB (loc_mrib changes)
//!         | [MribChangeNotification]
//!         v [MulticastOrigin]
//!     DDM admin API --[DDM exchange]--> other sleds/racks
//! ```
//!
//! See RFD 488 for the multicast architecture.

use crate::ddm::{add_multicast_routes, remove_multicast_routes};
use crate::platform::Ddm;
use ddm_api_types_versions::latest::net::{MulticastOrigin, OverlayMulticast};
use rdb::Mrib;
use rdb::types::{MribChangeNotification, MulticastAddr, MulticastRoute};
use slog::{Logger, debug, error, info};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread::sleep;
use std::time::Duration;

pub(crate) const MG_LOWER_MRIB_TAG: &str = "mg-lower-mrib";

/// Interval between periodic MRIB full syncs.
///
/// Acts as a backstop in case an MRIB change notification is missed. Mirrors the
/// unicast lower-half's 1s resync cadence in `crate::run`.
const MRIB_PERIODIC_SYNC_INTERVAL: Duration = Duration::from_secs(1);

/// Convert an MRIB `MulticastRoute` to a DDM `MulticastOrigin`.
fn ddm_origin(route: &MulticastRoute) -> MulticastOrigin {
    MulticastOrigin {
        // The MRIB key's group is a `MulticastAddr`, multicast by construction,
        // so promotion to the validated overlay type cannot fail here.
        overlay_group: OverlayMulticast::new(route.key.group().ip())
            .expect("MRIB group is multicast by construction"),
        underlay_group: route.underlay_group,
        vni: route.key.vni(),
        metric: 0,
        source: route.key.source(),
    }
}

/// Run the MRIB origination loop.
///
/// This function loops forever, watching for MRIB changes and advertising
/// locally originated multicast groups to DDM.
///
/// It runs on the calling thread, so callers are responsible for running it in
/// a separate thread if asynchronous execution is required.
pub fn run(
    mrib: Mrib,
    log: Logger,
    rt: Arc<tokio::runtime::Handle>,
    ddm: &impl Ddm,
) {
    loop {
        let (tx, rx) = channel();

        // Register as MRIB watcher
        mrib.watch(MG_LOWER_MRIB_TAG.into(), tx);

        // Initial full sync
        if let Err(e) = full_sync(&mrib, ddm, &log, &rt) {
            error!(log, "MRIB full sync failed: {e}");
            info!(log, "restarting MRIB sync loop in one second");
            // Drop this iteration's watcher before retrying. The continue
            // re-registers a fresh watcher, so without this the failed
            // registration would accumulate in the MRIB watcher list on every
            // retry.
            mrib.unwatch(MG_LOWER_MRIB_TAG);
            // Pause before retrying to keep a persistent failure from spinning.
            // This is a backoff floor, kept independent of the resync cadence so
            // tuning one does not silently change the other.
            //
            // Note: the unicast lower-half pauses in the same way
            // (see `crate::run`).
            sleep(Duration::from_secs(1));
            continue;
        }

        // Handle incremental changes
        loop {
            match rx.recv_timeout(MRIB_PERIODIC_SYNC_INTERVAL) {
                Ok(notification) => {
                    if let Err(e) =
                        handle_change(&mrib, notification, ddm, &log, &rt)
                    {
                        error!(log, "MRIB change handling failed: {e}");
                    }
                }
                // if we've not received updates in the timeout interval, do a
                // full sync in case something has changed out from under us.
                Err(RecvTimeoutError::Timeout) => {
                    if let Err(e) = full_sync(&mrib, ddm, &log, &rt) {
                        error!(log, "MRIB periodic sync failed: {e}");
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    error!(log, "MRIB watcher disconnected");
                    break;
                }
            }
        }
    }
}

/// Perform a full synchronization of MRIB origination to DDM.
///
/// Compares the current MRIB `loc_mrib` with what DDM has advertised and
/// reconciles any differences.
pub(crate) fn full_sync<D: Ddm>(
    mrib: &Mrib,
    ddm: &D,
    log: &Logger,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<(), String> {
    // Get current MRIB state (installed/selected routes)
    let mrib_routes = mrib.loc_mrib();

    // Convert to DDM MulticastOrigin set
    let mrib_origins: HashSet<MulticastOrigin> =
        mrib_routes.values().map(ddm_origin).collect();

    // Get current DDM advertised state
    let ddm_current: HashSet<MulticastOrigin> = rt
        .block_on(async { ddm.get_originated_multicast_groups().await })
        .map_err(|e| format!("failed to get DDM multicast groups: {e}"))?
        .into_inner()
        .into_iter()
        .collect();

    // Compute diff
    let to_add: Vec<_> = mrib_origins.difference(&ddm_current).collect();
    let to_remove: Vec<_> = ddm_current.difference(&mrib_origins).collect();

    if !to_add.is_empty() {
        info!(
            log,
            "MRIB sync: adding {} multicast groups to DDM",
            to_add.len()
        );
        add_multicast_routes(ddm, to_add.into_iter(), rt, log);
    }

    if !to_remove.is_empty() {
        info!(
            log,
            "MRIB sync: removing {} multicast groups from DDM",
            to_remove.len()
        );
        remove_multicast_routes(ddm, to_remove.into_iter(), rt, log);
    }

    Ok(())
}

/// Handle an incremental MRIB change notification.
fn handle_change<D: Ddm>(
    mrib: &Mrib,
    notification: MribChangeNotification,
    ddm: &D,
    log: &Logger,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<(), String> {
    // Get current DDM state for comparison
    let ddm_current: HashSet<MulticastOrigin> = rt
        .block_on(async { ddm.get_originated_multicast_groups().await })
        .map_err(|e| format!("failed to get DDM multicast groups: {e}"))?
        .into_inner()
        .into_iter()
        .collect();

    let mut to_add = Vec::new();
    let mut to_remove = Vec::new();

    for key in notification.changed {
        // Check if route exists in `loc_mrib` (installed)
        if let Some(route) = mrib.get_selected_route(&key) {
            let origin = ddm_origin(&route);
            if !ddm_current.contains(&origin) {
                to_add.push(origin);
            }
        } else {
            // Route is not in `loc_mrib`, so we need to find matching DDM
            // origin. We check all DDM origins to find any that match this key
            for ddm_origin in &ddm_current {
                // Reconstruct the key from the DDM origin to compare
                if let Ok(overlay_group) =
                    MulticastAddr::try_from(ddm_origin.overlay_group.ip())
                    && let Ok(ddm_key) = rdb::types::MulticastRouteKey::new(
                        ddm_origin.source,
                        overlay_group,
                        ddm_origin.vni,
                    )
                    && ddm_key == key
                {
                    to_remove.push(ddm_origin.clone());
                }
            }
        }
    }

    if !to_add.is_empty() {
        debug!(log, "MRIB change: adding {} multicast groups", to_add.len());
        add_multicast_routes(ddm, to_add.iter(), rt, log);
    }

    if !to_remove.is_empty() {
        debug!(
            log,
            "MRIB change: removing {} multicast groups",
            to_remove.len()
        );
        remove_multicast_routes(ddm, to_remove.iter(), rt, log);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::test::TestDdm;
    use rdb::test::get_test_db;
    use rdb::types::{
        MulticastRouteKey, MulticastSourceProtocol, UnderlayMulticastIpv6,
    };
    use std::net::Ipv6Addr;

    fn discard_logger() -> Logger {
        Logger::root(slog::Discard, slog::o!())
    }

    /// Runtime handle for `full_sync`'s internal `block_on`. Tests run on a
    /// plain thread (not a tokio worker), so blocking on this handle is safe.
    fn runtime() -> (tokio::runtime::Runtime, Arc<tokio::runtime::Handle>) {
        let rt = tokio::runtime::Runtime::new().expect("build runtime");
        let handle = Arc::new(rt.handle().clone());
        (rt, handle)
    }

    fn test_underlay() -> UnderlayMulticastIpv6 {
        UnderlayMulticastIpv6::new(Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1))
            .expect("valid underlay address")
    }

    /// Build an any-source (*,G) static route for the given IPv4 group.
    fn asm_route(a: u8, b: u8, c: u8, d: u8) -> MulticastRoute {
        let group = MulticastAddr::new_v4(a, b, c, d).expect("valid group");
        let key = MulticastRouteKey::any_source(group);
        MulticastRoute::new(
            key,
            test_underlay(),
            MulticastSourceProtocol::Static,
        )
    }

    #[test]
    fn full_sync_advertises_groups_missing_from_ddm() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_full_sync_add", log.clone()).expect("db");
        let route = asm_route(225, 1, 1, 1);
        db.add_static_mcast_routes(std::slice::from_ref(&route))
            .expect("add route");

        let ddm = TestDdm::default();
        full_sync(db.mrib(), &ddm, &log, &handle).expect("full sync");

        let originated = ddm.multicast_originated.lock().unwrap();
        assert_eq!(originated.len(), 1);
        assert_eq!(originated[0], ddm_origin(&route));
    }

    #[test]
    fn full_sync_withdraws_groups_absent_from_mrib() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_full_sync_remove", log.clone()).expect("db");

        let stale = asm_route(225, 9, 9, 9);
        let ddm = TestDdm::default();
        ddm.multicast_originated
            .lock()
            .unwrap()
            .push(ddm_origin(&stale));

        full_sync(db.mrib(), &ddm, &log, &handle).expect("full sync");

        assert!(ddm.multicast_originated.lock().unwrap().is_empty());
    }

    #[test]
    fn full_sync_in_sync_makes_no_changes() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_full_sync_noop", log.clone()).expect("db");
        let route = asm_route(225, 5, 5, 5);
        db.add_static_mcast_routes(std::slice::from_ref(&route))
            .expect("add route");

        let ddm = TestDdm::default();
        ddm.multicast_originated
            .lock()
            .unwrap()
            .push(ddm_origin(&route));

        full_sync(db.mrib(), &ddm, &log, &handle).expect("full sync");

        let originated = ddm.multicast_originated.lock().unwrap();
        assert_eq!(originated.len(), 1, "in-sync group must not be re-added");
        assert_eq!(originated[0], ddm_origin(&route));
    }

    #[test]
    fn full_sync_adds_and_withdraws_together() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_full_sync_mixed", log.clone()).expect("db");
        let keep = asm_route(225, 1, 1, 1);
        db.add_static_mcast_routes(std::slice::from_ref(&keep))
            .expect("add route");

        let ddm = TestDdm::default();
        let stale = asm_route(225, 2, 2, 2);
        ddm.multicast_originated
            .lock()
            .unwrap()
            .push(ddm_origin(&stale));

        full_sync(db.mrib(), &ddm, &log, &handle).expect("full sync");

        let originated = ddm.multicast_originated.lock().unwrap();
        assert_eq!(originated.len(), 1);
        assert_eq!(originated[0], ddm_origin(&keep));
    }

    #[test]
    fn handle_change_advertises_newly_installed_group() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_change_add", log.clone()).expect("db");
        let route = asm_route(225, 1, 1, 1);
        db.add_static_mcast_routes(std::slice::from_ref(&route))
            .expect("add route");

        let ddm = TestDdm::default();
        let notification = MribChangeNotification::from(route.key);
        handle_change(db.mrib(), notification, &ddm, &log, &handle)
            .expect("handle change");

        let originated = ddm.multicast_originated.lock().unwrap();
        assert_eq!(originated.len(), 1);
        assert_eq!(originated[0], ddm_origin(&route));
    }

    #[test]
    fn handle_change_withdraws_removed_group() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_change_remove", log.clone()).expect("db");

        // The group is advertised by DDM but never installed in the MRIB,
        // modeling a route that was removed from `loc_mrib`.
        let removed = asm_route(225, 9, 9, 9);
        let ddm = TestDdm::default();
        ddm.multicast_originated
            .lock()
            .unwrap()
            .push(ddm_origin(&removed));

        let notification = MribChangeNotification::from(removed.key);
        handle_change(db.mrib(), notification, &ddm, &log, &handle)
            .expect("handle change");

        assert!(ddm.multicast_originated.lock().unwrap().is_empty());
    }

    #[test]
    fn handle_change_is_noop_when_already_advertised() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_change_noop", log.clone()).expect("db");
        let route = asm_route(225, 5, 5, 5);
        db.add_static_mcast_routes(std::slice::from_ref(&route))
            .expect("add route");

        let ddm = TestDdm::default();
        ddm.multicast_originated
            .lock()
            .unwrap()
            .push(ddm_origin(&route));

        let notification = MribChangeNotification::from(route.key);
        handle_change(db.mrib(), notification, &ddm, &log, &handle)
            .expect("handle change");

        let originated = ddm.multicast_originated.lock().unwrap();
        assert_eq!(
            originated.len(),
            1,
            "already-advertised group must not be re-added"
        );
        assert_eq!(originated[0], ddm_origin(&route));
    }

    #[test]
    fn handle_change_withdraws_only_the_matching_group() {
        let (_rt, handle) = runtime();
        let log = discard_logger();
        let db = get_test_db("mrib_change_selective", log.clone()).expect("db");

        // DDM advertises two groups; only one is named in the change set and is
        // absent from the MRIB, so only that one must be withdrawn. Exercises
        // the key-reconstruction match in the removal path.
        let removed = asm_route(225, 1, 1, 1);
        let other = asm_route(225, 2, 2, 2);
        let ddm = TestDdm::default();
        {
            let mut originated = ddm.multicast_originated.lock().unwrap();
            originated.push(ddm_origin(&removed));
            originated.push(ddm_origin(&other));
        }

        let notification = MribChangeNotification::from(removed.key);
        handle_change(db.mrib(), notification, &ddm, &log, &handle)
            .expect("handle change");

        let originated = ddm.multicast_originated.lock().unwrap();
        assert_eq!(
            originated.len(),
            1,
            "unrelated group must remain advertised"
        );
        assert_eq!(originated[0], ddm_origin(&other));
    }
}
