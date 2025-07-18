// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This is the Maghemite external networking lower half. Its responsible for
//! synchronizing information in a routing information base onto an underlying
//! routing platform. The only platform currently supported is Dendrite.

use crate::dendrite::{
    get_routes_for_prefix, new_dpd_client, update_dendrite, RouteHash,
};
use crate::error::Error;
use ddm::{
    add_tunnel_routes, new_ddm_client, remove_tunnel_routes,
    BOUNDARY_SERVICES_VNI,
};
use ddm_admin_client::types::TunnelOrigin;
use ddm_admin_client::Client as DdmClient;
use dendrite::{ensure_tep_addr, link_is_up};
use dpd_client::Client as DpdClient;
use mg_common::stats::MgLowerStats as Stats;
use rdb::db::Rib;
use rdb::{Db, Prefix, PrefixChangeNotification, DEFAULT_ROUTE_PRIORITY};
use slog::{error, info, warn, Logger};
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

mod ddm;
mod dendrite;
mod error;

/// Tag used for managing both dpd and rdb elements.
const MG_LOWER_TAG: &str = "mg-lower";

/// This is the primary entry point for the lower half. It loops forever,
/// observing changes in the routing databse and synchronizing them to the
/// underlying forwarding platform. The loop sets up a watcher to start
/// receiving events, does an initial synchronization, then responds to changes
/// moving foward. The loop runs on the calling thread, so callers are
/// responsible for running this function in a separate thread if asynchronous
/// execution is required.
pub fn run(
    tep: Ipv6Addr, //tunnel endpoint address
    db: Db,
    log: Logger,
    stats: Arc<Stats>,
    rt: Arc<tokio::runtime::Handle>,
) {
    loop {
        let (tx, rx) = channel();

        // start the db watcher first so we catch any changes that may occur while
        // we're initializing
        db.watch(MG_LOWER_TAG.into(), tx);

        // initialize the underlying router with the current state
        let dpd = new_dpd_client(&log);
        let ddm = new_ddm_client(&log);
        if let Err(e) =
            full_sync(tep, &db, &log, &dpd, &ddm, &stats, rt.clone())
        {
            error!(log, "initializing failed: {e}");
            info!(log, "restarting sync loop in one second");
            sleep(Duration::from_secs(1));
            continue;
        };

        // handle any changes that occur
        loop {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(change) => {
                    if let Err(e) = handle_change(
                        tep,
                        &db,
                        change,
                        &log,
                        &dpd,
                        &ddm,
                        rt.clone(),
                    ) {
                        error!(log, "handling change failed: {e}");
                        info!(log, "restarting sync loop");
                        continue;
                    }
                }
                // if we've not received updates in the timeout interval, do a
                // full sync in case something has changed out from under us.
                Err(RecvTimeoutError::Timeout) => {
                    if let Err(e) = full_sync(
                        tep,
                        &db,
                        &log,
                        &dpd,
                        &ddm,
                        &stats,
                        rt.clone(),
                    ) {
                        error!(log, "initializing failed: {e}");
                        info!(log, "restarting sync loop in one second");
                        sleep(Duration::from_secs(1));
                        continue;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    error!(log, "mg-lower rdb watcher disconnected");
                    break;
                }
            }
        }
    }
}

/// Synchronize the underlying platforms with a complete set of routes from the
/// RIB.
fn full_sync(
    tep: Ipv6Addr, // tunnel endpoint address
    db: &Db,
    log: &Logger,
    dpd: &DpdClient,
    ddm: &DdmClient,
    _stats: &Arc<Stats>, //TODO(ry)
    rt: Arc<tokio::runtime::Handle>,
) -> Result<(), Error> {
    let rib = db.full_rib();

    // Make sure our tunnel endpoint address is on the switch ASIC
    ensure_tep_addr(tep, dpd, rt.clone(), log);

    // Compute the bestpath for each prefix and synchronize the ASIC routing
    // tables with the chosen paths.
    for (prefix, _paths) in rib.iter() {
        sync_prefix(tep, &db.loc_rib(), prefix, dpd, ddm, log, &rt)?;
    }

    Ok(())
}

/// Synchronize a change set from the RIB to the underlying platform.
fn handle_change(
    tep: Ipv6Addr, // tunnel endpoint address
    db: &Db,
    notification: PrefixChangeNotification,
    log: &Logger,
    dpd: &DpdClient,
    ddm: &DdmClient,
    rt: Arc<tokio::runtime::Handle>,
) -> Result<(), Error> {
    for prefix in notification.changed.iter() {
        sync_prefix(tep, &db.loc_rib(), prefix, dpd, ddm, log, &rt)?;
    }

    Ok(())
}

fn sync_prefix(
    tep: Ipv6Addr,
    rib_loc: &Rib,
    prefix: &Prefix,
    dpd: &DpdClient,
    ddm: &DdmClient,
    log: &Logger,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<(), Error> {
    // The current routes that are on the ASIC.
    let dpd_current =
        get_routes_for_prefix(dpd, prefix, rt.clone(), log.clone())?;

    // The current tunnel routes in ddm
    let ddm_current = rt
        .block_on(async { ddm.get_originated_tunnel_endpoints().await })?
        .into_inner()
        .into_iter()
        .collect::<HashSet<_>>();

    // The best routes in the RIB
    let mut best: HashSet<RouteHash> = HashSet::new();
    if let Some(paths) = rib_loc.get(prefix) {
        for path in paths {
            best.insert(RouteHash::for_prefix_path(*prefix, path.clone())?);
        }
    }

    // Remove paths for which the link is down.
    best.retain(|x| match link_is_up(dpd, &x.port_id, &x.link_id, rt) {
        Err(e) => {
            error!(
                log,
                "sync_prefix: failed to get link state for {:?}/{:?} \
                    not installing route {:?} -> {:?}: {e}",
                x.port_id,
                x.link_id,
                x.cidr,
                x.nexthop,
            );
            false
        }
        Ok(false) => {
            warn!(
                log,
                "sync_prefix: link {:?}/{:?} is not up, \
                    not installing route {:?} -> {:?}",
                x.port_id,
                x.link_id,
                x.cidr,
                x.nexthop,
            );
            false
        }
        Ok(true) => true,
    });

    //
    // Update the ASIC routing tables
    //

    // Routes that are in the best set but not on the asic should be added.
    let add: HashSet<RouteHash> =
        best.difference(&dpd_current).cloned().collect();

    // Routes that are on the asic but not in the best set should be removed.
    let del: HashSet<RouteHash> =
        dpd_current.difference(&best).cloned().collect();

    update_dendrite(add.iter(), del.iter(), dpd, rt.clone(), log)?;

    //
    // Update the ddm tunnel advertisements
    //

    let best_tunnel = best
        .clone()
        .into_iter()
        .map(|x| TunnelOrigin {
            boundary_addr: tep,
            overlay_prefix: x.cidr,
            metric: DEFAULT_ROUTE_PRIORITY,
            vni: BOUNDARY_SERVICES_VNI,
        })
        .collect::<HashSet<_>>();

    // Routes that are in the best set but not in ddm should be added.
    let add: HashSet<TunnelOrigin> =
        best_tunnel.difference(&ddm_current).cloned().collect();

    // Routes that are in ddm but not in the best set should be removed.
    let del: HashSet<TunnelOrigin> =
        ddm_current.difference(&best_tunnel).cloned().collect();

    add_tunnel_routes(tep, ddm, add.iter(), rt, log);
    remove_tunnel_routes(ddm, del.iter(), rt, log);

    Ok(())
}
