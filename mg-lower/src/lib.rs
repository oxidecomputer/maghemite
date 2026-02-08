// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This is the Maghemite external networking lower half. Its responsible for
//! synchronizing information in a routing information base onto an underlying
//! routing platform. The only platform currently supported is Dendrite.

#![allow(clippy::result_large_err)]
use crate::dendrite::{
    RouteHash, ensure_tep_addr, get_routes_for_prefix, update_dendrite,
};
use crate::error::Error;
use ddm::{BOUNDARY_SERVICES_VNI, add_tunnel_routes, remove_tunnel_routes};
use ddm_admin_client::types::TunnelOrigin;
use dendrite::link_is_up;
use log::mgl_log;
use mg_common::stats::MgLowerStats as Stats;
use platform::{Ddm, Dpd, SwitchZone};
use rdb::db::Rib;
use rdb::{DEFAULT_ROUTE_PRIORITY, Db, Prefix, PrefixChangeNotification};
use slog::Logger;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread::sleep;
use std::time::Duration;

// Re-export production backends so callers (e.g. mgd) can construct them.
#[cfg(target_os = "illumos")]
pub use {
    crate::dendrite::new_dpd_client,
    ddm::new_ddm_client,
    platform::{ProductionDdm, ProductionDpd, ProductionSwitchZone},
};

mod ddm;
mod dendrite;
mod error;
mod log;
mod platform;

#[cfg(test)]
mod test;

/// Tag used for managing both dpd and rdb elements.
const MG_LOWER_TAG: &str = "mg-lower";
const COMPONENT_MG_LOWER: &str = MG_LOWER_TAG;
const MOD_SYNC: &str = "sync";
const UNIT_EVENT_LOOP: &str = "event_loop";

/// This is the primary entry point for the lower half. It loops forever,
/// observing changes in the routing databse and synchronizing them to the
/// underlying forwarding platform. The loop sets up a watcher to start
/// receiving events, does an initial synchronization, then responds to changes
/// moving foward. The loop runs on the calling thread, so callers are
/// responsible for running this function in a separate thread if asynchronous
/// execution is required.
#[allow(clippy::too_many_arguments)]
pub fn run(
    tep: Ipv6Addr, //tunnel endpoint address
    db: Db,
    log: Logger,
    stats: Arc<Stats>,
    rt: Arc<tokio::runtime::Handle>,
    dpd: &impl Dpd,
    ddm: &impl Ddm,
    sw: &impl SwitchZone,
) {
    loop {
        let (tx, rx) = channel();

        // start the db watcher first so we catch any changes that may occur while
        // we're initializing
        db.watch(MG_LOWER_TAG.into(), tx);

        if let Err(e) =
            full_sync(tep, &db, &log, dpd, ddm, sw, &stats, rt.clone())
        {
            mgl_log!(log,
                error,
                "initialization failed: {e}";
                "error" => format!("{e}")
            );
            mgl_log!(log, info, "restarting sync loop in one second";);
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
                        dpd,
                        ddm,
                        sw,
                        rt.clone(),
                    ) {
                        mgl_log!(log,
                            error,
                            "handling change failed: {e}";
                            "error" => format!("{e}")
                        );
                        mgl_log!(log, info, "restarting sync loop";);
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
                        dpd,
                        ddm,
                        sw,
                        &stats,
                        rt.clone(),
                    ) {
                        mgl_log!(log,
                            error,
                            "initialization failed: {e}";
                            "error" => format!("{e}")
                        );
                        mgl_log!(log, info, "restarting sync loop in one second";);
                        sleep(Duration::from_secs(1));
                        continue;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    mgl_log!(log,
                        error,
                        "mg-lower rdb watcher disconnected";
                        "error" => format!("{}", RecvTimeoutError::Disconnected)
                    );
                    break;
                }
            }
        }
    }
}

/// Synchronize the underlying platforms with a complete set of routes from the
/// RIB.
#[allow(clippy::too_many_arguments)]
fn full_sync(
    tep: Ipv6Addr, // tunnel endpoint address
    db: &Db,
    log: &Logger,
    dpd: &impl Dpd,
    ddm: &impl Ddm,
    sw: &impl SwitchZone,
    _stats: &Arc<Stats>, //TODO(ry)
    rt: Arc<tokio::runtime::Handle>,
) -> Result<(), Error> {
    let rib_in = db.full_rib(None);
    let rib_loc = db.loc_rib(None);

    // Make sure our tunnel endpoint address is on the switch ASIC
    ensure_tep_addr(tep, dpd, rt.clone(), log);

    // Compute the bestpath for each prefix and synchronize the ASIC routing
    // tables with the chosen paths.
    for (prefix, _paths) in rib_in.iter() {
        sync_prefix(tep, &rib_loc, prefix, dpd, ddm, sw, log, &rt)?;
    }

    Ok(())
}

/// Synchronize a change set from the RIB to the underlying platform.
#[allow(clippy::too_many_arguments)]
fn handle_change(
    tep: Ipv6Addr, // tunnel endpoint address
    db: &Db,
    notification: PrefixChangeNotification,
    log: &Logger,
    dpd: &impl Dpd,
    ddm: &impl Ddm,
    sw: &impl SwitchZone,
    rt: Arc<tokio::runtime::Handle>,
) -> Result<(), Error> {
    let rib_loc = db.loc_rib(None);

    for prefix in notification.changed.iter() {
        sync_prefix(tep, &rib_loc, prefix, dpd, ddm, sw, log, &rt)?
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sync_prefix(
    tep: Ipv6Addr,
    rib_loc: &Rib,
    prefix: &Prefix,
    dpd: &impl Dpd,
    ddm: &impl Ddm,
    sw: &impl SwitchZone,
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
        .filter(|x| x.overlay_prefix == prefix)
        .collect::<HashSet<_>>();

    // The best routes in the RIB
    let mut best: HashSet<RouteHash> = HashSet::new();
    if let Some(paths) = rib_loc.get(prefix) {
        for path in paths {
            best.insert(RouteHash::for_prefix_path(sw, *prefix, path.clone())?);
        }
    }

    // Remove paths for which the link is down.
    best.retain(|x| match link_is_up(dpd, &x.port_id, &x.link_id, rt) {
        Err(e) => {
            mgl_log!(log,
                error,
                "skipping install of route {} via {} ({}/{}), \
                error getting link state: {e}",
                x.cidr, x.nexthop, x.port_id, x.link_id;
                "prefix" => format!("{}", x.cidr),
                "nexthop" => format!("{}", x.nexthop),
                "port" => format!("{}", x.port_id),
                "link" => format!("{}", x.link_id),
                "error" => format!("{e}")
            );
            false
        }
        Ok(false) => {
            mgl_log!(log,
                warn,
                "skipping install of route {} via {} ({}/{}), \
                link is not up",
                x.cidr, x.nexthop, x.port_id, x.link_id;
                "prefix" => format!("{}", x.cidr),
                "nexthop" => format!("{}", x.nexthop),
                "port" => format!("{}", x.port_id),
                "link" => format!("{}", x.link_id)
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
