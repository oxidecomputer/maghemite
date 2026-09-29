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
use ddm::{
    BOUNDARY_SERVICES_VNI, add_tunnel_routes, remove_tunnel_routes,
    withdraw_tep_underlay_origin,
};
use ddm_api_types_versions::latest::net::TunnelOrigin;
use dendrite::link_is_up;
use log::mgl_log;
use mg_common::stats::MgLowerStats as Stats;
use oxnet::IpNet;
use platform::{Ddm, Dpd, SwitchZone};
use rdb::Rib;
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
    (db.id() != rdb::DEFAULT_ROUTER_ID).then(|| db.id().0)
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
/// withdrawn before returning. The loop runs on the calling thread, so
/// callers are responsible for running this function in a separate thread if
/// asynchronous execution is required. `routers` is every router's
/// database; the default router uses it to find switch tables that no router
/// holds.
#[allow(clippy::too_many_arguments)]
pub fn run(
    tep: Ipv6Addr, //tunnel endpoint address
    db: RouterDb,
    routers: rdb::Db,
    log: Logger,
    stats: Arc<Stats>,
    rt: Arc<tokio::runtime::Handle>,
    shutdown: Arc<AtomicBool>,
    dpd: &impl Dpd,
    ddm: &impl Ddm,
    sw: &impl SwitchZone,
) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return withdraw_all(tep, &db, &log, dpd, ddm, &rt);
        }

        let (tx, rx) = channel();

        // start the db watcher first so we catch any changes that may occur while
        // we're initializing
        db.watch(format!("{MG_LOWER_TAG}/{}", db.name()), tx);

        if let Err(e) = full_sync(
            tep,
            &db,
            &routers,
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
                        &routers,
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
    routers: &rdb::Db,
    log: &Logger,
    dpd: &impl Dpd,
    ddm: &impl Ddm,
    sw: &impl SwitchZone,
    _stats: &Arc<Stats>, //TODO(ry)
    rt: Arc<tokio::runtime::Handle>,
) -> Result<(), Error> {
    let rib_in = db.full_rib(None);
    let rib_loc = db.loc_rib(None);

    reconcile_switch_table(
        db.switch_index(),
        &rib_in,
        Some(tep),
        dpd,
        &rt,
        log,
    );
    if db.switch_index() == 0 {
        remove_dead_switch_tables(routers, dpd, &rt, log);
    }

    // Make sure our tunnel endpoint address is on the switch ASIC
    ensure_tep_addr(db.switch_index(), tep, dpd, rt.clone(), log);

    // Compute the bestpath for each prefix and synchronize the ASIC routing
    // tables with the chosen paths.
    for prefix in rib_in.keys() {
        sync_prefix(
            db.switch_index(),
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
fn withdraw_all(
    tep: Ipv6Addr,
    db: &RouterDb,
    log: &Logger,
    dpd: &impl Dpd,
    ddm: &impl Ddm,
    rt: &Arc<tokio::runtime::Handle>,
) {
    mgl_log!(log, info, "shutting down: withdrawing all platform state";);

    let nothing = HashSet::new();
    for prefix in db.full_rib(None).keys() {
        let current = match get_routes_for_prefix(
            db.switch_index(),
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
                continue;
            }
        };
        if let Err(e) = update_dendrite(
            db.switch_index(),
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
    // longer knows about (e.g. routes programmed before an mgd restart).
    reconcile_switch_table(db.switch_index(), &Rib::new(), None, dpd, rt, log);

    withdraw_tep_addr(db.switch_index(), tep, dpd, rt.clone(), log);

    // The TEP's underlay /64 was originated into ddm when the router's first
    // tunnel route landed (`ensure_tep_underlay_origin`); withdraw it so the
    // departed TEP stops being advertised over the underlay.
    withdraw_tep_underlay_origin(ddm, tep, rt, log);
}

/// Empty every switch table that no router holds: its router was deleted,
/// or mgd restarted and gave the router another index.
fn remove_dead_switch_tables(
    routers: &rdb::Db,
    dpd: &impl Dpd,
    rt: &Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    // Ask dpd before reading the live set: a router is in the live set
    // before its thread writes to its table, so a new router's table listed
    // here is never mistaken for a dead one.
    let tables = match rt.block_on(async { dpd.router_list().await }) {
        Ok(tables) => tables.into_inner(),
        Err(e) => {
            mgl_log!(log,
                error,
                "reconcile: failed to list switch tables: {e}";
                "error" => format!("{e}")
            );
            return;
        }
    };
    let live = routers.switch_indexes();
    for router in tables.into_iter().filter(|t| !live.contains(t)) {
        reconcile_switch_table(router, &Rib::new(), None, dpd, rt, log);
    }
}

/// Remove from a non-default switch table every route whose prefix is not
/// in `rib`, and every loopback other than `tep`. A router's mg-lower thread
/// is the only writer to its table, so anything else in it was left by an
/// earlier run (before an mgd restart, or by a router that held the same
/// index) and is stale. Table 0 is dendrite's shared default table, which
/// other components also write to, so it is never reconciled. Errors are
/// logged and skipped.
fn reconcile_switch_table(
    router: u8,
    rib: &Rib,
    tep: Option<Ipv6Addr>,
    dpd: &impl Dpd,
    rt: &Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    if router == 0 {
        return;
    }
    rt.block_on(async {
        match dpd.route_ipv4_list_full(router).await {
            Ok(routes) => {
                for r in routes {
                    if rib.contains_key(&r.cidr.into()) {
                        continue;
                    }
                    if let Err(e) =
                        dpd.route_ipv4_delete_prefix(router, &r.cidr).await
                    {
                        mgl_log!(log,
                            error,
                            "reconcile: failed to remove {}: {e}", r.cidr;
                            "error" => format!("{e}")
                        );
                    }
                }
            }
            Err(e) => mgl_log!(log,
                error,
                "reconcile: failed to list IPv4 routes: {e}";
                "error" => format!("{e}")
            ),
        }
        match dpd.route_ipv6_list_full(router).await {
            Ok(routes) => {
                for r in routes {
                    if rib.contains_key(&r.cidr.into()) {
                        continue;
                    }
                    if let Err(e) =
                        dpd.route_ipv6_delete_prefix(router, &r.cidr).await
                    {
                        mgl_log!(log,
                            error,
                            "reconcile: failed to remove {}: {e}", r.cidr;
                            "error" => format!("{e}")
                        );
                    }
                }
            }
            Err(e) => mgl_log!(log,
                error,
                "reconcile: failed to list IPv6 routes: {e}";
                "error" => format!("{e}")
            ),
        }
        match dpd.loopback_ipv6_list(router).await {
            Ok(entries) => {
                for addr in entries.into_inner().into_iter().map(|e| e.addr) {
                    if Some(addr) == tep {
                        continue;
                    }
                    if let Err(e) =
                        dpd.loopback_ipv6_delete(router, &addr).await
                    {
                        mgl_log!(log,
                            error,
                            "reconcile: failed to remove loopback {addr}: {e}";
                            "error" => format!("{e}")
                        );
                    }
                }
            }
            Err(e) => mgl_log!(log,
                error,
                "reconcile: failed to list loopbacks: {e}";
                "error" => format!("{e}")
            ),
        }
    });
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
            db.switch_index(),
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
    router: u8,
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
