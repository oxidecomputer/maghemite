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
use dpd_client::Client as DpdClient;
use rdb::{ChangeSet, Db};
use slog::{error, info, Logger};
use std::collections::HashSet;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

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
pub fn run(db: Db, log: Logger, rt: Arc<tokio::runtime::Handle>) {
    loop {
        let (tx, rx) = channel();

        // start the db watcher first so we catch any changes that may occur while
        // we're initializing
        db.watch(MG_LOWER_TAG.into(), tx);

        // initialize the underlying router with the current state
        let dpd = new_dpd_client(&log);
        let mut generation = match initialize(&db, &log, &dpd, rt.clone()) {
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
            match rx.recv() {
                Ok(change) => {
                    generation = match handle_change(
                        &db,
                        change,
                        &log,
                        &dpd,
                        generation,
                        rt.clone(),
                    ) {
                        Ok(gen) => gen,
                        Err(e) => {
                            error!(log, "handling change failed: {e}");
                            info!(log, "restarting sync loop");
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!(log, "mg-lower watch rx: {e}");
                }
            }
        }
    }
}

/// Initialize the underlying platform with a complete set of routes from the
/// RIB.
fn initialize(
    db: &Db,
    log: &Logger,
    dpd: &DpdClient,
    rt: Arc<tokio::runtime::Handle>,
) -> Result<u64, Error> {
    let generation = db.generation();

    // get all imported routes from db
    let imported: HashSet<RouteHash> =
        db_route_to_dendrite_route(db.get_imported4(), log, dpd);

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
fn handle_change(
    db: &Db,
    change: ChangeSet,
    log: &Logger,
    dpd: &DpdClient,
    generation: u64,
    rt: Arc<tokio::runtime::Handle>,
) -> Result<u64, Error> {
    if change.generation > generation + 1 {
        return initialize(db, log, dpd, rt.clone());
    }
    let to_add = change.import.added.clone().into_iter().collect();
    let to_add = db_route_to_dendrite_route(to_add, log, dpd);

    let to_del = change.import.removed.clone().into_iter().collect();
    let to_del = db_route_to_dendrite_route(to_del, log, dpd);

    update_dendrite(to_add.iter(), to_del.iter(), dpd, rt.clone(), log)?;

    Ok(change.generation)
}
