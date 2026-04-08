// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! MRIB (Multicast Routing Information Base) synchronization to DDM.
//!
//! This module watches for MRIB changes and propagates multicast group
//! subscriptions to DDM for distribution across the underlay network.
//!
//! ## Data Flow
//!
//! ```text
//!    MRIB (loc_mrib changes)
//!        |
//!        v [MribChangeNotification]
//!    mg-lower/mrib.rs
//!        |
//!        v [MulticastOrigin]
//!    DDM admin API
//!        |
//!        v [DDM exchange protocol]
//!    Other sleds/racks
//! ```

use crate::ddm::{
    add_multicast_routes, new_ddm_client, remove_multicast_routes,
};
use crate::platform::{Ddm, ProductionDdm};
use ddm_admin_client::types::MulticastOrigin;
use mg_common::net::Vni;
use rdb::Mrib;
use rdb::types::{MribChangeNotification, MulticastAddr, MulticastRoute};
use slog::{Logger, debug, error, info};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread::sleep;
use std::time::Duration;

const MG_LOWER_MRIB_TAG: &str = "mg-lower-mrib";

/// Convert an MRIB [`MulticastRoute`] to a DDM [`MulticastOrigin`].
///
/// [`MulticastOrigin`]: ddm_admin_client::types::MulticastOrigin
fn ddm_origin(route: &MulticastRoute) -> MulticastOrigin {
    mg_common::net::MulticastOrigin::from(route).into()
}

/// Run the MRIB synchronization loop.
///
/// This function loops forever, watching for MRIB changes and synchronizing
/// them to DDM. It runs on the calling thread.
pub fn run(mrib: Mrib, log: Logger, rt: Arc<tokio::runtime::Handle>) {
    loop {
        let (tx, rx) = channel();

        // Register as MRIB watcher
        mrib.watch(MG_LOWER_MRIB_TAG.into(), tx);

        let ddm = ProductionDdm {
            client: new_ddm_client(&log),
        };

        // Initial full sync
        if let Err(e) = full_sync(&mrib, &ddm, &log, &rt) {
            error!(log, "MRIB full sync failed: {e}");
            info!(log, "restarting MRIB sync loop in one second");
            sleep(Duration::from_secs(1));
            continue;
        }

        // Handle incremental changes
        loop {
            match rx.recv_timeout(Duration::from_secs(10)) {
                Ok(notification) => {
                    if let Err(e) =
                        handle_change(&mrib, notification, &ddm, &log, &rt)
                    {
                        error!(log, "MRIB change handling failed: {e}");
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Periodic full sync to catch any missed changes
                    if let Err(e) = full_sync(&mrib, &ddm, &log, &rt) {
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

/// Perform a full synchronization of MRIB to DDM.
///
/// This compares the current MRIB loc_mrib with what DDM has advertised
/// and reconciles any differences.
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
        // Check if route exists in loc_mrib (installed)
        if let Some(route) = mrib.get_selected_route(&key) {
            let origin = ddm_origin(&route);
            if !ddm_current.contains(&origin) {
                to_add.push(origin);
            }
        } else {
            // Route was removed from loc_mrib, so we need to find matching DDM
            // origin. We check all DDM origins to find any that match this key
            for ddm_origin in &ddm_current {
                // Reconstruct the key from the DDM origin to compare
                if let Ok(overlay_group) =
                    MulticastAddr::try_from(ddm_origin.overlay_group)
                    && let Ok(ddm_key) = rdb::types::MulticastRouteKey::new(
                        ddm_origin.source,
                        overlay_group,
                        Vni::DEFAULT_MULTICAST_VNI,
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
