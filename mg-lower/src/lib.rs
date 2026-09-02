// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This is the Maghemite external networking lower half. Its responsible for
//! synchronizing information in a routing information base onto an underlying
//! routing platform. The only platform currently supported is Dendrite.

#![allow(clippy::result_large_err)]
use crate::dendrite::{
    RouteHash, ensure_tep_addr, get_routes_for_prefix, update_dendrite,
    withdraw_tep_addr,
};
use crate::error::Error;
use ddm::{BOUNDARY_SERVICES_VNI, add_tunnel_routes, remove_tunnel_routes};
use ddm_api_types_versions::latest::net::TunnelOrigin;
use dendrite::link_is_up;
use log::mgl_log;
use mg_common::stats::MgLowerStats as Stats;
use oxnet::IpNet;
use platform::{Ddm, Dpd, SwitchZone};
use rdb::Rib;
use rdb::types::RouterId;
use rdb::{DEFAULT_ROUTE_PRIORITY, PrefixChangeNotification, RouterDb};
use slog::Logger;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// The id stamped on this router's ddm tunnel origins. The default router
/// advertises unscoped origins (`None`): they serialize byte-identically to
/// the legacy pre-multi-router shape and are the only origins ddm forwards
/// to pre-v4 peers. Non-default routers' origins carry the router's uuid and
/// are invisible to old peers.
fn tunnel_origin_id(db: &RouterDb) -> Option<uuid::Uuid> {
    (db.name() != rdb::DEFAULT_ROUTER).then(|| db.id().0)
}
const COMPONENT_MG_LOWER: &str = MG_LOWER_TAG;
const MOD_SYNC: &str = "sync";
const UNIT_EVENT_LOOP: &str = "event_loop";

/// This is the primary entry point for the lower half. It loops until
/// `shutdown` is set, observing changes in the routing databse and
/// synchronizing them to the underlying forwarding platform. The loop sets up
/// a watcher to start receiving events, does an initial synchronization, then
/// responds to changes moving foward. When `shutdown` is set, all of this
/// router's platform state (ASIC routes, ddm tunnel advertisements) is
/// withdrawn before returning; the return value reports whether dpd
/// confirmed the router's switch table is clean (see [`withdraw_all`]). The
/// loop runs on the calling thread, so callers are responsible for running
/// this function in a separate thread if asynchronous execution is required.
#[allow(clippy::too_many_arguments)]
pub fn run(
    tep: Ipv6Addr, //tunnel endpoint address
    db: RouterDb,
    log: Logger,
    stats: Arc<Stats>,
    rt: Arc<tokio::runtime::Handle>,
    shutdown: Arc<AtomicBool>,
    dpd: &impl Dpd,
    ddm: &impl Ddm,
    sw: &impl SwitchZone,
) -> bool {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return withdraw_all(tep, &db, &log, dpd, ddm, &rt);
        }

        let (tx, rx) = channel();

        // start the db watcher first so we catch any changes that may occur while
        // we're initializing
        db.watch(format!("{MG_LOWER_TAG}/{}", db.name()), tx);

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
            if shutdown.load(Ordering::Relaxed) {
                return withdraw_all(tep, &db, &log, dpd, ddm, &rt);
            }
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
    db: &RouterDb,
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
    ensure_tep_addr(db.id(), tep, dpd, rt.clone(), log);

    // Compute the bestpath for each prefix and synchronize the ASIC routing
    // tables with the chosen paths.
    for prefix in rib_in.keys() {
        sync_prefix(
            db.id(),
            tunnel_origin_id(db),
            tep,
            &rib_loc,
            prefix,
            dpd,
            ddm,
            sw,
            log,
            &rt,
        )?;
    }

    Ok(())
}

/// Withdraw all of this router's state from the underlying platforms: its
/// routes from the ASIC, its tunnel advertisements from ddm, and its TEP
/// address claim. Called when the router is being torn down. Failures are
/// logged and skipped — teardown should always run to completion.
///
/// Returns true only when dpd confirmed the router's switch table is clean
/// (no routes, TEP withdrawn). ddm failures are excluded: tunnel origins are
/// scoped to the router's never-reused id/TEP, so stale ones cannot be
/// inherited by a later router the way a dirty switch table can. Callers use
/// the result to decide whether the router's switch table index may be
/// reused.
fn withdraw_all(
    tep: Ipv6Addr,
    db: &RouterDb,
    log: &Logger,
    dpd: &impl Dpd,
    ddm: &impl Ddm,
    rt: &Arc<tokio::runtime::Handle>,
) -> bool {
    mgl_log!(log, info, "shutting down: withdrawing all platform state";);

    let mut clean = true;
    let nothing = HashSet::new();
    for prefix in db.full_rib(None).keys() {
        let current = match get_routes_for_prefix(
            db.id(),
            dpd,
            prefix,
            rt.clone(),
            log.clone(),
        ) {
            Ok(current) => current,
            Err(e) => {
                mgl_log!(log,
                    error,
                    "withdraw: failed to get ASIC routes for {prefix}: {e}";
                    "error" => format!("{e}"),
                    "prefix" => format!("{prefix}")
                );
                clean = false;
                continue;
            }
        };
        if let Err(e) = update_dendrite(
            db.id(),
            nothing.iter(),
            current.iter(),
            dpd,
            rt.clone(),
            log,
        ) {
            mgl_log!(log,
                error,
                "withdraw: failed to remove ASIC routes for {prefix}: {e}";
                "error" => format!("{e}"),
                "prefix" => format!("{prefix}")
            );
            clean = false;
        }
    }

    // Tunnel origins are scoped to this router by its origin id. For the
    // default router (None) this also adopts unscoped origins left behind by
    // pre-multi-router daemons.
    match rt.block_on(async { ddm.get_originated_tunnel_endpoints().await }) {
        Ok(origins) => {
            let ours: Vec<TunnelOrigin> = origins
                .into_inner()
                .into_iter()
                .filter(|x| x.router_id == tunnel_origin_id(db))
                .collect();
            remove_tunnel_routes(ddm, ours.iter(), rt, log);
        }
        Err(e) => {
            mgl_log!(log,
                error,
                "withdraw: failed to get ddm tunnel endpoints: {e}";
                "error" => format!("{e}")
            );
        }
    }

    // The RIB-driven withdraw above misses anything the volatile RIB no
    // longer knows about (e.g. routes programmed before an mgd restart), so
    // for non-default routers scrub the whole dedicated switch table. The
    // default router's table (index 0) is dendrite's shared implicit table
    // and must never be scrubbed wholesale.
    if db.switch_index() != 0 {
        clean = scrub_switch_table(db.id(), dpd, rt, log) && clean;
    }

    clean = withdraw_tep_addr(db.id(), tep, dpd, rt.clone(), log) && clean;

    clean
}

/// Remove every route from a non-default router's dedicated switch table and
/// verify with dpd that the table ends up empty. Returns true only on
/// dpd-confirmed success. Must never be called for the default router: its
/// table index 0 is dendrite's shared implicit table.
pub fn scrub_switch_table(
    router: RouterId,
    dpd: &impl Dpd,
    rt: &Arc<tokio::runtime::Handle>,
    log: &Logger,
) -> bool {
    let mut clean = true;

    match rt.block_on(async { dpd.route_ipv4_list_full(router).await }) {
        Ok(routes) => {
            for r in routes {
                if let Err(e) = rt.block_on(async {
                    dpd.route_ipv4_delete_prefix(router, &r.cidr).await
                }) {
                    mgl_log!(log,
                        error,
                        "scrub: failed to remove {} from switch table: {e}",
                        r.cidr;
                        "error" => format!("{e}"),
                        "prefix" => format!("{}", r.cidr)
                    );
                    clean = false;
                }
            }
        }
        Err(e) => {
            mgl_log!(log,
                error,
                "scrub: failed to list IPv4 switch table routes: {e}";
                "error" => format!("{e}")
            );
            clean = false;
        }
    }

    match rt.block_on(async { dpd.route_ipv6_list_full(router).await }) {
        Ok(routes) => {
            for r in routes {
                if let Err(e) = rt.block_on(async {
                    dpd.route_ipv6_delete_prefix(router, &r.cidr).await
                }) {
                    mgl_log!(log,
                        error,
                        "scrub: failed to remove {} from switch table: {e}",
                        r.cidr;
                        "error" => format!("{e}"),
                        "prefix" => format!("{}", r.cidr)
                    );
                    clean = false;
                }
            }
        }
        Err(e) => {
            mgl_log!(log,
                error,
                "scrub: failed to list IPv6 switch table routes: {e}";
                "error" => format!("{e}")
            );
            clean = false;
        }
    }

    // Only dpd's word that the table is empty counts as clean.
    if clean {
        clean = match rt.block_on(async {
            Ok::<_, crate::error::Error>((
                dpd.route_ipv4_list_full(router).await?,
                dpd.route_ipv6_list_full(router).await?,
            ))
        }) {
            Ok((v4, v6)) => v4.is_empty() && v6.is_empty(),
            Err(e) => {
                mgl_log!(log,
                    error,
                    "scrub: failed to verify switch table is empty: {e}";
                    "error" => format!("{e}")
                );
                false
            }
        };
    }

    clean
}

/// Synchronize a change set from the RIB to the underlying platform.
#[allow(clippy::too_many_arguments)]
fn handle_change(
    tep: Ipv6Addr, // tunnel endpoint address
    db: &RouterDb,
    notification: PrefixChangeNotification,
    log: &Logger,
    dpd: &impl Dpd,
    ddm: &impl Ddm,
    sw: &impl SwitchZone,
    rt: Arc<tokio::runtime::Handle>,
) -> Result<(), Error> {
    let rib_loc = db.loc_rib(None);

    for prefix in notification.changed.iter() {
        sync_prefix(
            db.id(),
            tunnel_origin_id(db),
            tep,
            &rib_loc,
            prefix,
            dpd,
            ddm,
            sw,
            log,
            &rt,
        )?
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sync_prefix(
    router: RouterId,
    origin_id: Option<uuid::Uuid>,
    tep: Ipv6Addr,
    rib_loc: &Rib,
    prefix: &IpNet,
    dpd: &impl Dpd,
    ddm: &impl Ddm,
    sw: &impl SwitchZone,
    log: &Logger,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<(), Error> {
    // The current routes that are on the ASIC.
    let dpd_current =
        get_routes_for_prefix(router, dpd, prefix, rt.clone(), log.clone())?;

    // The current tunnel routes in ddm, scoped to this router's origin id so
    // that one router's sync never withdraws another router's origins for
    // the same prefix. The default router (origin id None) also owns legacy
    // unscoped origins.
    let ddm_current = rt
        .block_on(async { ddm.get_originated_tunnel_endpoints().await })?
        .into_inner()
        .into_iter()
        .filter(|x| x.overlay_prefix == *prefix && x.router_id == origin_id)
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

    update_dendrite(router, add.iter(), del.iter(), dpd, rt.clone(), log)?;

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
            router_id: origin_id,
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
