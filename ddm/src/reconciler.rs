// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! An asynchronous task that converges the forwarding dataplane onto the
//! desired state held in the [`Db`], using the platform backends in
//! `ddm-lower`. It wakes on every database change and on a periodic timer,
//! then applies the full desired state idempotently.

use crate::db::{Db, DbData, effective_route_set};
use crate::{dbg, err};
use ddm_api_types::db::RouterKind;
use ddm_api_types::net::TunnelOrigin;
use ddm_lower::dendrite::DendriteBackend;
use ddm_lower::illumos::IllumosBackend;
use ddm_lower::{InterfaceName, Route};
use slog::Logger;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::MissedTickBehavior;

/// The delay between reconciliation passes when the database is quiet.
///
/// The upstream reconcilers that feed this database (sled-agent, mg-lower) are
/// diff-based and make no writes in steady state. This timer is the only thing
/// that heals dataplane drift and retries failed applies.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// Tag used in log entries where the state machines use an interface name.
const LOG_TAG: &str = "reconciler";

enum Backend {
    /// Synchronous libnet/OPTE calls, run on the blocking pool.
    Illumos(Arc<IllumosBackend>),
    /// Native async dpd client calls.
    Dendrite {
        backend: DendriteBackend,
        dpd_addr: SocketAddrV6,
    },
}

// A reconciler that applies the desired state from the database to the
// illumos/opte and dendrite backends.
pub struct Reconciler {
    db: Db,
    backend: Backend,
    kind: RouterKind,
    log: Logger,
}

/// The dataplane state implied by a [`DbData`] snapshot.
#[derive(Default, Clone)]
struct Desired {
    underlay: HashSet<Route>,
    tunnel: HashSet<TunnelOrigin>,
}

impl Desired {
    fn new(data: &DbData, kind: RouterKind) -> Self {
        Self {
            // The db tracks imported routes per path, but the dataplane only
            // knows (destination, nexthop) vectors. The conversion drops the
            // path and the set collapses the duplicates.
            underlay: data
                .imported
                .iter()
                .map(|r| Route {
                    dest: r.destination,
                    gw: r.nexthop,
                    ifname: InterfaceName::new(r.ifname.clone()),
                })
                .collect(),

            // Tunnel routes are programmed into OPTE, which only servers
            // have. Transits keep them in the RIB for redistribution.
            tunnel: if kind == RouterKind::Server {
                effective_route_set(&data.imported_tunnel)
                    .iter()
                    .map(|r| r.origin)
                    .collect()
            } else {
                HashSet::new()
            },
        }
    }
}

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

impl Reconciler {
    pub fn new(
        db: Db,
        dpd: Option<SocketAddrV6>,
        kind: RouterKind,
        log: Logger,
    ) -> Self {
        let backend = match dpd {
            Some(dpd_addr) => Backend::Dendrite {
                backend: DendriteBackend::new(&log),
                dpd_addr,
            },
            None => Backend::Illumos(Arc::new(IllumosBackend::new(&log))),
        };
        Self {
            db,
            backend,
            kind,
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
            let desired = Desired::new(&rx.borrow_and_update(), self.kind);
            last = self.reconcile(last, desired).await;
        }
    }

    /// Run one reconciliation pass. Awaiting the pass serializes
    /// reconciliation; the watch channel coalesces any changes that arrive
    /// meanwhile.
    ///
    /// Each pass removes the underlay routes that dropped out of the desired
    /// state since the last pass, then re-applies the full desired set. The
    /// backend operations are idempotent (dendrite treats setting an
    /// identical route as a no-op and libnet ensures presence), so the
    /// re-apply heals routes lost behind our back and retries failed applies.
    /// Errors are logged inside the backends and retried by the next pass.
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

        match &self.backend {
            Backend::Dendrite { backend, dpd_addr } => {
                // Remove stale routes before re-applying the desired set:
                // dendrite removal is by prefix only, so removing a stale
                // nexthop can take a surviving one with it, and the re-apply
                // below restores it.
                for routes in group_by_ifname(underlay_remove) {
                    let _ =
                        backend.remove_underlay_routes(*dpd_addr, routes).await;
                }
                for routes in group_by_ifname(desired.underlay.iter().cloned())
                {
                    let _ =
                        backend.add_underlay_routes(*dpd_addr, routes).await;
                }
            }
            Backend::Illumos(backend) => {
                let backend = backend.clone();
                let kind = self.kind;
                let last = last.clone();
                let to_sync = desired.clone();
                let result = tokio::task::spawn_blocking(move || {
                    if !underlay_remove.is_empty() {
                        let _ = backend.remove_underlay_routes(underlay_remove);
                    }
                    let _ = backend.add_underlay_routes(
                        to_sync.underlay.iter().cloned().collect(),
                    );

                    if kind != RouterKind::Server {
                        return;
                    }
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
            }
        }
        desired
    }
}
