// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The reconciler for transit routers, which programs the switch ASIC via
//! dendrite. See [`crate::reconciler`] for the overall design.

use crate::db::Db;
use crate::reconciler::{
    RECONCILE_INTERVAL, ReconcilerTrigger, desired_underlay,
};
use crate::{dbg, inf};
use ddm_lower::Route;
use ddm_lower::dendrite::{DendriteBackend, Error as DendriteError};
use slog::Logger;
use std::collections::HashSet;
use std::net::SocketAddrV6;
use tokio::time::MissedTickBehavior;

/// Tag used in log entries where the state machines use an interface name.
const LOG_TAG: &str = "transit_reconciler";

/// The routes whose removal failed, which must be folded back into the next
/// pass's state so the removal is retried.
fn removal_retries(errors: Vec<DendriteError>) -> impl Iterator<Item = Route> {
    errors.into_iter().filter_map(|e| match e {
        DendriteError::RemoveRoute { route, .. } => Some(route),
        _ => None,
    })
}

/// A reconciler for transit routers that applies the desired underlay routes
/// from the database to the switch ASIC via dendrite.
pub struct TransitReconciler {
    db: Db,
    backend: DendriteBackend,
    log: Logger,
}

impl TransitReconciler {
    pub fn new(db: Db, dpd_addr: SocketAddrV6, log: Logger) -> Self {
        Self {
            db,
            backend: DendriteBackend::new(dpd_addr, &log),
            log,
        }
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.run())
    }

    async fn run(self) {
        let mut rx = self.db.watch();
        let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // The previous pass's desired state. Removals are computed against
        // this rather than against the dataplane, so the reconciler never
        // deletes routes it did not ask for.
        let mut last = HashSet::new();

        loop {
            let trigger = tokio::select! {
                _ = ticker.tick() => {
                    ReconcilerTrigger::Timeout

                }
                changed = rx.changed() => {
                    if changed.is_err() {
                        // The Db was dropped; nothing left to reconcile.
                        inf!(
                            self.log,
                            LOG_TAG,
                            "exiting due to db drop (shutdown)"
                        );
                        return;
                    }
                    ReconcilerTrigger::WatchNotification
                }
            };
            let desired = desired_underlay(&rx.borrow_and_update());
            last = self.reconcile(last, desired, trigger).await;
        }
    }

    /// Run one reconciliation pass.
    ///
    /// Awaiting the pass serializes reconciliation; the watch channel coalesces
    /// any changes that arrive meanwhile.
    ///
    /// Each pass removes the routes that dropped out of the desired state
    /// since the last pass, then re-applies the full desired set. Dendrite
    /// treats setting an identical route as a no-op, so the re-apply heals
    /// routes lost behind our back and retries failed adds. Routes whose
    /// removal fails are folded back into the returned state so the next
    /// pass retries the removal; without this they would leak into the
    /// dataplane forever.
    ///
    /// Note that if the process running the reconciler restarts, the previous
    /// desired state will be lost. This will leak routes that failed removal
    /// until the next restart of the machine. While unfortunate, this is a
    /// tradeoff for the lack of recording in the reconciler, and is better than
    /// the alternative of removing routes that are not owned by the reconciler,
    /// if we blindly deleted routes not in the current desired state.
    async fn reconcile(
        &self,
        last: HashSet<Route>,
        desired: HashSet<Route>,
        trigger: ReconcilerTrigger,
    ) -> HashSet<Route> {
        let remove: Vec<Route> = last.difference(&desired).cloned().collect();

        dbg!(
            self.log,
            LOG_TAG,
            "{} pass: {} underlay desired, removing {}",
            trigger,
            desired.len(),
            remove.len(),
        );

        let mut next = desired.clone();

        // Remove stale routes before re-applying the desired set.
        //
        // Since dendrite removal is by prefix only, if we add route before
        // removal, we'll remove it along with the routes we actually intended
        // to delete.
        if let Err(errors) = self.backend.remove_underlay_routes(remove).await {
            // We log this in the backend. No need to duplicate here,
            // although we may want to collect stats in the future.
            next.extend(removal_retries(errors));
        }

        // No need to track failures here, as we'll retry any adds that are
        // part of the desired state in the next reconciliation pass.
        let _ = self
            .backend
            .add_underlay_routes(desired.into_iter().collect())
            .await;

        next
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ddm_lower::InterfaceName;
    use pretty_assertions::assert_eq;

    fn route(dest: &str, gw: &str, ifname: &str) -> Route {
        Route {
            dest: dest.parse().unwrap(),
            gw: gw.parse().unwrap(),
            ifname: InterfaceName::new(ifname),
        }
    }

    #[test]
    fn test_removal_retries() {
        let r = route("fd00:1::/64", "fe80::1", "tfportrear0_0");
        let errors = vec![
            DendriteError::RemoveRoute {
                route: r.clone(),
                err: dpd_client::Error::InvalidRequest("test".to_string()),
            },
            DendriteError::InvalidPortPrefix(InterfaceName::new("igb0")),
        ];

        // Only failed removals are retried; other errors carry no route.
        let retries: Vec<Route> = removal_retries(errors).collect();
        assert_eq!(retries, vec![r]);

        assert_eq!(removal_retries(Vec::new()).count(), 0);
    }
}
