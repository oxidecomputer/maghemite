// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The reconciler for server routers, which programs the illumos kernel and
//! OPTE. See [`crate::reconciler`] for the overall design.

use crate::db::{Db, DbData, effective_route_set};
use crate::reconciler::{RECONCILE_INTERVAL, desired_underlay};
use crate::{dbg, err};
use ddm_api_types::net::TunnelOrigin;
use ddm_lower::illumos::IllumosBackend;
use ddm_lower::{InterfaceName, Route};
use slog::Logger;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::time::MissedTickBehavior;

/// Tag used in log entries where the state machines use an interface name.
/// Also used as the pseudo interface name for OPTE tunnel route operations.
const LOG_TAG: &str = "illumos_reconciler";

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

/// A reconciler for server routers that applies the desired underlay routes
/// from the database to the illumos kernel and the desired tunnel routes to
/// OPTE.
pub struct IllumosReconciler {
    db: Db,
    // The libnet/OPTE calls are synchronous and run on the blocking pool.
    backend: Arc<IllumosBackend>,
    log: Logger,
}

impl IllumosReconciler {
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
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // The previous pass's desired state. Removals are computed against
        // this rather than against the dataplane, so the reconciler never
        // deletes routes it did not ask for (e.g. static kernel routes).
        let mut last = Desired::default();

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
            let desired = Desired::new(&rx.borrow_and_update());
            last = self.reconcile(last, desired).await;
        }
    }

    /// Run one reconciliation pass. Awaiting the pass serializes
    /// reconciliation; the watch channel coalesces any changes that arrive
    /// meanwhile.
    ///
    /// Each pass removes the routes that dropped out of the desired state
    /// since the last pass, then re-applies the full desired set. The backend
    /// operations are idempotent (libnet ensures presence), so the re-apply
    /// heals routes lost behind our back and retries failed applies. Errors
    /// are logged inside the backend and retried by the next pass.
    async fn reconcile(&self, last: Desired, desired: Desired) -> Desired {
        let underlay_remove: Vec<Route> = last
            .underlay
            .difference(&desired.underlay)
            .cloned()
            .collect();

        dbg!(
            self.log,
            LOG_TAG,
            "pass: {} underlay / {} tunnel desired, removing {} / {}",
            desired.underlay.len(),
            desired.tunnel.len(),
            underlay_remove.len(),
            last.tunnel.difference(&desired.tunnel).count(),
        );

        let backend = self.backend.clone();
        let to_sync = desired.clone();
        let result = tokio::task::spawn_blocking(move || {
            if !underlay_remove.is_empty() {
                let _ = backend.remove_underlay_routes(underlay_remove);
            }
            let _ = backend
                .add_underlay_routes(to_sync.underlay.iter().cloned().collect());

            // Tunnel endpoints for one prefix are added and cleared
            // individually, so add before removing and a prefix whose
            // backup endpoint becomes effective is never left without
            // a TEP.
            if !to_sync.tunnel.is_empty() {
                let _ = backend.add_tunnel_routes(
                    InterfaceName::new(LOG_TAG),
                    &to_sync.tunnel,
                );
            }
            let tunnel_remove: HashSet<TunnelOrigin> = last
                .tunnel
                .difference(&to_sync.tunnel)
                .copied()
                .collect();
            if !tunnel_remove.is_empty() {
                let _ = backend.remove_tunnel_routes(
                    InterfaceName::new(LOG_TAG),
                    &tunnel_remove,
                );
            }
        })
        .await;
        if let Err(e) = result {
            err!(self.log, LOG_TAG, "reconcile pass failed: {e}");
        }
        desired
    }
}
