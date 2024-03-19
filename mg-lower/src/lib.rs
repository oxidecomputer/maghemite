// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This is the Maghemite external networking lower half. Its responsible for
//! synchronizing information in a routing information base onto an underlying
//! routing platform. The only platform currently supported is Dendrite.

use crate::dendrite::{
    db_route_to_dendrite_route, new_dpd_client, update_dendrite, RouteHash,
};
use crate::error::Error;
use ddm::{
    add_tunnel_routes, new_ddm_client, remove_tunnel_routes,
    update_tunnel_endpoints,
};
use ddm_admin_client::Client as DdmClient;
use dendrite::ensure_tep_addr;
use dpd_client::Client as DpdClient;
use mg_common::stats::MgLowerStats as Stats;
use rdb::{ChangeSet, Db};
use slog::{error, info, Logger};
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
        let mut generation =
            match full_sync(tep, &db, &log, &dpd, &ddm, &stats, rt.clone()) {
                Ok(gen) => gen,
                Err(e) => {
                    error!(log, "initializing failed: {e}");
                    info!(log, "restarting sync loop in one second");
                    sleep(Duration::from_secs(1));
                    continue;
                }
            };

        // handle any changes that occur
        loop {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(change) => {
                    generation = match handle_change(
                        tep,
                        &db,
                        change,
                        &log,
                        &dpd,
                        &ddm,
                        generation,
                        &stats,
                        rt.clone(),
                    ) {
                        Ok(gen) => gen,
                        Err(e) => {
                            error!(log, "handling change failed: {e}");
                            info!(log, "restarting sync loop");
                            continue;
                        }
                    }
                }
                // if we've not received updates in the timeout interval, do a
                // full sync in case something has changed out from under us.
                Err(RecvTimeoutError::Timeout) => {
                    generation = match full_sync(
                        tep,
                        &db,
                        &log,
                        &dpd,
                        &ddm,
                        &stats,
                        rt.clone(),
                    ) {
                        Ok(gen) => gen,
                        Err(e) => {
                            error!(log, "initializing failed: {e}");
                            info!(log, "restarting sync loop in one second");
                            sleep(Duration::from_secs(1));
                            continue;
                        }
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
    stats: &Arc<Stats>,
    rt: Arc<tokio::runtime::Handle>,
) -> Result<u64, Error> {
    let generation = db.generation();

    let db_imported: Vec<rdb::Route4ImportKey> = db.effective_route_set();

    ensure_tep_addr(tep, dpd, rt.clone(), log);

    // announce tunnel endpoints via ddm
    update_tunnel_endpoints(tep, ddm, &db_imported, rt.clone(), log);

    // get all imported routes from db
    let imported: HashSet<RouteHash> = db_route_to_dendrite_route(
        db_imported,
        log,
        dpd,
        Some(stats),
        true,
        rt.clone(),
    );

    // get all routes created by mg-lower from dendrite
    let routes =
        rt.block_on(async { dpd.route_ipv4_list(None, None).await })?;

    let mut active: HashSet<RouteHash> = HashSet::new();
    for route in &routes.items {
        for target in &route.targets {
            if let dpd_client::types::RouteTarget::V4(t) = target {
                if t.tag == MG_LOWER_TAG {
                    if let Ok(rh) = RouteHash::new(
                        route.cidr,
                        t.port_id,
                        t.link_id,
                        t.tgt_ip.into(),
                    ) {
                        active.insert(rh);
                    }
                }
            }
        }
    }

    // determine what routes need to be added and deleted
    let to_add = imported.difference(&active);
    let to_del = active.difference(&imported);

    update_dendrite(to_add, to_del, dpd, rt, log)?;

    Ok(generation)
}

/// Synchronize a change set from the RIB to the underlying platform.
#[allow(clippy::too_many_arguments)]
fn handle_change(
    tep: Ipv6Addr, // tunnel endpoint address
    db: &Db,
    change: ChangeSet,
    log: &Logger,
    dpd: &DpdClient,
    ddm: &DdmClient,
    generation: u64,
    stats: &Arc<Stats>,
    rt: Arc<tokio::runtime::Handle>,
) -> Result<u64, Error> {
    info!(
        log,
        "mg-lower: handling rib change generation {} -> {}: {:#?}",
        generation,
        change.generation,
        change,
    );

    if change.generation > generation + 1 {
        return full_sync(tep, db, log, dpd, ddm, stats, rt.clone());
    }
    let to_add: Vec<rdb::Route4ImportKey> =
        change.import.added.clone().into_iter().collect();

    add_tunnel_routes(tep, ddm, &to_add, rt.clone(), log);
    let to_add = db_route_to_dendrite_route(
        to_add,
        log,
        dpd,
        Some(stats),
        true,
        rt.clone(),
    );

    let to_del: Vec<rdb::Route4ImportKey> =
        change.import.removed.clone().into_iter().collect();
    remove_tunnel_routes(tep, ddm, &to_del, rt.clone(), log);
    let to_del =
        db_route_to_dendrite_route(to_del, log, dpd, None, false, rt.clone());

    update_dendrite(to_add.iter(), to_del.iter(), dpd, rt.clone(), log)?;

    Ok(change.generation)
}
