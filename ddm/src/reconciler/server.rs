// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The reconciler for server routers, which programs the illumos kernel and
//! OPTE. See [`crate::reconciler`] for the overall design.

use crate::db::{Db, DbData, effective_route_set};
use crate::reconciler::{
    RECONCILE_INTERVAL, ReconcilerTrigger, desired_underlay,
};
use crate::{dbg, inf};
use ddm_api_types::net::TunnelOrigin;
use ddm_lower::illumos::{Error as IllumosError, IllumosBackend};
use ddm_lower::{InterfaceName, Route};
use slog::Logger;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::time::MissedTickBehavior;

/// Tag used in log entries where the state machines use an interface name.
/// Also used as the pseudo interface name for OPTE tunnel route operations.
const LOG_TAG: &str = "server_reconciler";

/// The dataplane state implied by a [`DbData`] snapshot on a server router.
#[derive(Default, Clone)]
struct Desired {
    underlay: HashSet<Route>,
    tunnel: HashSet<TunnelOrigin>,
}

impl Desired {
    fn new(data: &DbData) -> Self {
        Self {
            underlay: desired_underlay(data),
            tunnel: effective_route_set(&data.imported_tunnel)
                .iter()
                .map(|r| r.origin)
                .collect(),
        }
    }
}

/// The routes whose removal failed, which must be folded back into the next
/// pass's state so the removal is retried.
fn removal_retries(errors: Vec<IllumosError>) -> impl Iterator<Item = Route> {
    errors.into_iter().filter_map(|e| match e {
        IllumosError::RemoveRoute { route, .. } => Some(route),
        _ => None,
    })
}

/// A reconciler for server routers that applies the desired underlay routes
/// from the database to the illumos kernel and the desired tunnel routes to
/// OPTE.
pub struct ServerReconciler {
    db: Db,
    // The libnet/OPTE calls are synchronous and run on the blocking pool.
    backend: Arc<IllumosBackend>,
    log: Logger,
}

impl ServerReconciler {
    pub fn new(db: Db, log: Logger) -> Self {
        Self {
            backend: Arc::new(IllumosBackend::new(&log)),
            db,
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

        // The previous pass's desired state.
        //
        // The dataplane has shared ownership, and routes are not only created
        // or removed by this reconciler. Removals are computed against
        // the reconciler's previous desired state rather than against the
        // dataplane, to prevent deletion of routes this reconciler did not
        // create (e.g. static kernel routes).
        let mut last = Desired::default();

        loop {
            let trigger = tokio::select! {
                _ = ticker.tick() => { ReconcilerTrigger::Timeout}
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
            let desired = Desired::new(&rx.borrow_and_update());
            last = self.reconcile(last, desired, trigger).await;
        }
    }

    /// Run one reconciliation pass.
    ///
    /// Awaiting the pass serializes reconciliation; the watch channel coalesces
    /// any changes that arrive meanwhile.
    ///
    /// Each pass removes the routes that dropped out of the desired state
    /// since the last pass, then re-applies the full desired set. The backend
    /// operations are idempotent (libnet ensures presence), so the re-apply
    /// heals routes lost behind our back and retries failed adds. Routes
    /// whose removal fails are folded back into the returned state so the
    /// next pass retries the removal; without this they would leak into the
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
        last: Desired,
        desired: Desired,
        trigger: ReconcilerTrigger,
    ) -> Desired {
        let underlay_remove: Vec<Route> = last
            .underlay
            .difference(&desired.underlay)
            .cloned()
            .collect();
        let tunnel_remove: HashSet<TunnelOrigin> =
            last.tunnel.difference(&desired.tunnel).copied().collect();

        dbg!(
            self.log,
            LOG_TAG,
            "{} pass: {} underlay / {} tunnel desired, removing {} / {}",
            trigger,
            desired.underlay.len(),
            desired.tunnel.len(),
            underlay_remove.len(),
            tunnel_remove.len(),
        );

        let backend = self.backend.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut next = desired.clone();

            if !underlay_remove.is_empty()
                && let Err(errors) =
                    backend.remove_underlay_routes(underlay_remove)
            {
                // We log this in the backend. No need to duplicate here,
                // although we may want to collect stats in the future.
                next.underlay.extend(removal_retries(errors));
            }
            // Add failures automatically get retried from the desired state on
            // next reconciliation. No need to track.
            let _ = backend.add_underlay_routes(
                desired.underlay.iter().cloned().collect(),
            );

            // Tunnel endpoints for one prefix are added and cleared
            // individually. We add before removing so that we never leave a
            // prefix without a TEP unnecessarily.
            if !desired.tunnel.is_empty() {
                // Add failures automatically get retried from the desired state
                // on next reconciliation. No need to track.
                let _ = backend.add_tunnel_routes(
                    InterfaceName::new(LOG_TAG),
                    &desired.tunnel,
                );
            }
            if !tunnel_remove.is_empty()
                && backend
                    .remove_tunnel_routes(
                        InterfaceName::new(LOG_TAG),
                        &tunnel_remove,
                    )
                    .is_err()
            {
                // OPTE clear errors do not identify which origins failed,
                // so retry the whole batch.
                next.tunnel.extend(tunnel_remove);
            }

            next
        })
        .await;

        // This workspace builds with panic=abort, so a panicking pass aborts
        // the whole process rather than surfacing here as a JoinError, and
        // nothing cancels the blocking task. The join can only fail while the
        // runtime is already shutting down.
        result.expect("reconcile pass failed")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_removal_retries() {
        let r = Route {
            dest: "fd00:1::/64".parse().unwrap(),
            gw: "fe80::1".parse().unwrap(),
            ifname: InterfaceName::new("cxgbe0"),
        };
        let errors = vec![
            IllumosError::RemoveRoute {
                route: r.clone(),
                err: libnet::route::Error::DoesNotExist,
            },
            // An add failure also carries a route, but add failures retry
            // from the desired state and must not be folded back in.
            IllumosError::AddRoute {
                route: Route {
                    dest: "fd00:2::/64".parse().unwrap(),
                    gw: "fe80::2".parse().unwrap(),
                    ifname: InterfaceName::new("cxgbe0"),
                },
                err: libnet::route::Error::Exists,
            },
        ];

        // Only failed removals are retried; other errors carry no route.
        let retries: Vec<Route> = removal_retries(errors).collect();
        assert_eq!(retries, vec![r]);

        assert_eq!(removal_retries(Vec::new()).count(), 0);
    }
}
