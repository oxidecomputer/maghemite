// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The reconciler for transit routers, which programs the switch ASIC via
//! dendrite. See [`crate::reconciler`] for the overall design.

use crate::db::Db;
use crate::dbg;
use crate::reconciler::{RECONCILE_INTERVAL, desired_underlay};
use ddm_lower::dendrite::DendriteBackend;
use ddm_lower::{InterfaceName, Route};
use slog::Logger;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddrV6;
use tokio::time::MissedTickBehavior;

/// Tag used in log entries where the state machines use an interface name.
const LOG_TAG: &str = "dendrite_reconciler";

/// The dendrite backend requires each batch to be for a single interface.
fn group_by_ifname(
    routes: impl IntoIterator<Item = Route>,
) -> impl Iterator<Item = Vec<Route>> {
    let mut groups: HashMap<InterfaceName, Vec<Route>> = HashMap::new();
    for r in routes {
        groups.entry(r.ifname.clone()).or_default().push(r);
    }
    groups.into_values()
}

/// A reconciler for transit routers that applies the desired underlay routes
/// from the database to the switch ASIC via dendrite.
pub struct DendriteReconciler {
    db: Db,
    backend: DendriteBackend,
    dpd_addr: SocketAddrV6,
    log: Logger,
}

impl DendriteReconciler {
    pub fn new(db: Db, dpd_addr: SocketAddrV6, log: Logger) -> Self {
        Self {
            db,
            backend: DendriteBackend::new(&log),
            dpd_addr,
            log,
        }
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.run())
    }

    async fn run(self) {
        let mut rx = self.db.watch();
        let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // The previous pass's desired state. Removals are computed against
        // this rather than against the dataplane, so the reconciler never
        // deletes routes it did not ask for.
        let mut last = HashSet::new();

        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                changed = rx.changed() => {
                    if changed.is_err() {
                        // The Db was dropped; nothing left to reconcile.
                        return;
                    }
                }
            }
            let desired = desired_underlay(&rx.borrow_and_update());
            last = self.reconcile(last, desired).await;
        }
    }

    /// Run one reconciliation pass. Awaiting the pass serializes
    /// reconciliation; the watch channel coalesces any changes that arrive
    /// meanwhile.
    ///
    /// Each pass removes the routes that dropped out of the desired state
    /// since the last pass, then re-applies the full desired set. Dendrite
    /// treats setting an identical route as a no-op, so the re-apply heals
    /// routes lost behind our back and retries failed applies. Errors are
    /// logged inside the backend and retried by the next pass.
    async fn reconcile(
        &self,
        last: HashSet<Route>,
        desired: HashSet<Route>,
    ) -> HashSet<Route> {
        let remove: Vec<Route> = last.difference(&desired).cloned().collect();

        dbg!(
            self.log,
            LOG_TAG,
            "pass: {} underlay desired, removing {}",
            desired.len(),
            remove.len(),
        );

        // Remove stale routes before re-applying the desired set: dendrite
        // removal is by prefix only, so removing a stale nexthop can take a
        // surviving one with it, and the re-apply below restores it.
        for routes in group_by_ifname(remove) {
            let _ = self
                .backend
                .remove_underlay_routes(self.dpd_addr, routes)
                .await;
        }
        for routes in group_by_ifname(desired.iter().cloned()) {
            let _ = self
                .backend
                .add_underlay_routes(self.dpd_addr, routes)
                .await;
        }

        desired
    }
}
