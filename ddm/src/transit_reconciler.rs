// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The reconciler for transit routers, which programs the switch ASIC via
//! dendrite. See [`crate::reconciler`] for the overall design.

use crate::db::Db;
use crate::dbg;
use crate::reconciler::{RECONCILE_INTERVAL, desired_underlay};
use ddm_lower::dendrite::{DendriteBackend, Error as DendriteError};
use ddm_lower::{InterfaceName, Route};
use slog::Logger;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddrV6;
use tokio::time::MissedTickBehavior;

/// Tag used in log entries where the state machines use an interface name.
const LOG_TAG: &str = "transit_reconciler";

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
    ) -> HashSet<Route> {
        let remove: Vec<Route> = last.difference(&desired).cloned().collect();

        dbg!(
            self.log,
            LOG_TAG,
            "pass: {} underlay desired, removing {}",
            desired.len(),
            remove.len(),
        );

        let mut next = desired.clone();

        // Remove stale routes before re-applying the desired set.
        //
        // Since dendrite removal is by prefix only, if we add route before
        // removal, we'll remove it along with the routes we actually intended
        // to delete.
        for routes in group_by_ifname(remove) {
            if let Err(errors) =
                self.backend.remove_underlay_routes(routes).await
            {
                // We log this in the backend. No need to duplicate here,
                // although we may want to collect stats in the future.
                next.extend(removal_retries(errors));
            }
        }
        for routes in group_by_ifname(desired.iter().cloned()) {
            // No need to track failures here, as we'll retry any adds that are
            // part of the desired state in the next reconciliation pass.
            let _ = self.backend.add_underlay_routes(routes).await;
        }

        next
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    fn route(dest: &str, gw: &str, ifname: &str) -> Route {
        Route {
            dest: dest.parse().unwrap(),
            gw: gw.parse().unwrap(),
            ifname: InterfaceName::new(ifname),
        }
    }

    #[test]
    fn test_group_by_ifname() {
        let r1 = route("fd00:1::/64", "fe80::1", "tfportrear0_0");
        let r2 = route("fd00:2::/64", "fe80::1", "tfportrear0_0");
        let r3 = route("fd00:3::/64", "fe80::2", "tfportrear1_0");

        let groups: Vec<Vec<Route>> =
            group_by_ifname([r1.clone(), r2.clone(), r3.clone()]).collect();

        // Each group holds exactly one interface (the invariant the dendrite
        // backend asserts on), and the groups partition the input.
        assert_eq!(groups.len(), 2);
        let mut all = Vec::new();
        for g in &groups {
            assert!(g.iter().all(|r| r.ifname == g[0].ifname));
            all.extend(g.iter().cloned());
        }
        all.sort_by_key(|r| r.dest.to_string());
        assert_eq!(all, vec![r1, r2, r3]);
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
