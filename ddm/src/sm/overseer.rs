// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{Config, Event, StateMachine};
use crate::db::Db;
use iddqd::IdOrdMap;
use mg_common::write_lock;
use slog::Logger;
use std::collections::BTreeMap;
use std::sync::mpsc::Sender;
use std::sync::{Arc, RwLock};

#[cfg(all(feature = "backend", target_os = "illumos"))]
use {
    super::{InterfaceState, SessionStats, SmContext},
    ddm_api_types::db::InterfaceLifetime,
    slog::{error, warn},
    std::collections::BTreeSet,
    std::sync::mpsc::channel,
};

/// Sole owner of every DDM state machine and the inter-FSM sender mesh.
///
/// The daemon holds the Overseer behind a single `Arc<RwLock<Overseer>>`.
/// Admin readers take the read lock. `apply` takes the write lock for the
/// entire reconcile, including signalling and joining departing FSMs. That
/// guarantees at most one FSM per interface exists at any time, even while
/// one is mid-teardown, and serializes concurrent applies.
///
/// Each state machine carries an [`ddm_api_types::db::InterfaceLifetime`].
/// Static machines come from the ddmd command line and live for the life of
/// the daemon. Dynamic machines are owned by `apply`, which reconciles only
/// that set, so a client that knows nothing about the static interfaces
/// cannot strip them. Every other Overseer accessor sees both kinds.
///
/// FSM threads never take the Overseer lock. They reach the mesh through the
/// shared `Arc` in [`super::SmContext::event_channels`], and they are free to
/// take the mesh read lock, database locks, and the `InterfaceState` mutex
/// while `apply` is joining them.
pub struct Overseer {
    machines: IdOrdMap<StateMachine>,
    mesh: Arc<RwLock<BTreeMap<String, Sender<Event>>>>,
    /// Only the illumos-only FSM factory (`add_state_machine`) reads this, but
    /// the daemon constructs an Overseer on every platform, so it exists
    /// (unread) elsewhere too.
    #[cfg_attr(
        not(all(feature = "backend", target_os = "illumos")),
        allow(dead_code)
    )]
    template: SmTemplate,
}

/// Daemon-wide inputs shared by every FSM's [`super::SmContext`]. See
/// [`Overseer::template`] for why these are unread off illumos.
#[cfg_attr(
    not(all(feature = "backend", target_os = "illumos")),
    allow(dead_code)
)]
struct SmTemplate {
    log: Logger,
    db: Db,
    rt: tokio::runtime::Handle,
    hostname: String,
    base_fsm_config: Config,
}

impl Overseer {
    pub fn new(
        log: Logger,
        db: Db,
        rt: tokio::runtime::Handle,
        hostname: String,
        base_fsm_config: Config,
    ) -> Self {
        Self {
            machines: IdOrdMap::new(),
            mesh: Arc::new(RwLock::new(BTreeMap::new())),
            template: SmTemplate {
                log,
                db,
                rt,
                hostname,
                base_fsm_config,
            },
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &StateMachine> {
        self.machines.iter()
    }

    /// Add and start the state machine for `ifname`.
    #[cfg(all(feature = "backend", target_os = "illumos"))]
    pub fn add_state_machine(
        &mut self,
        ifname: String,
        lifetime: InterfaceLifetime,
    ) {
        if self.machines.get(ifname.as_str()).is_some() {
            error!(self.template.log, "state machine {ifname} already exists");
            return;
        }

        let (tx, rx) = channel();
        let mut config = self.template.base_fsm_config.clone();
        config.if_name = ifname.clone();
        let ctx = SmContext {
            config,
            db: self.template.db.clone(),
            tx: tx.clone(),
            event_channels: self.mesh.clone(),
            rt: self.template.rt.clone(),
            hostname: self.template.hostname.clone(),
            iface: Arc::new(InterfaceState::default()),
            stats: Arc::new(SessionStats::default()),
            log: self.template.log.clone(),
        };

        write_lock!(self.mesh).insert(ifname, tx);
        let sm = StateMachine::spawn(ctx, lifetime, rx);
        assert!(self.machines.insert_unique(sm).is_ok());
    }

    /// Detach a state machine and its sender without stopping it.
    pub fn remove_state_machine(
        &mut self,
        ifname: &str,
    ) -> Option<StateMachine> {
        let machine = self.machines.remove(ifname)?;
        write_lock!(self.mesh).remove(ifname);
        Some(machine)
    }

    /// Reconcile the running dynamic FSMs with `desired`, including full
    /// teardown of dynamic FSMs that are no longer wanted. Static FSMs are
    /// never added or removed here; a static name in `desired` is ignored
    /// with a warning.
    ///
    /// The caller holds the Overseer write lock throughout this method, so
    /// readers stall for the teardown duration. The slow tail is DPD HTTP in
    /// `sys::remove_underlay_routes`, called by `close_session`.
    #[cfg(all(feature = "backend", target_os = "illumos"))]
    pub fn apply(&mut self, desired: BTreeSet<String>) {
        let current_dynamic = self
            .machines
            .iter()
            .filter(|sm| sm.lifetime == InterfaceLifetime::Dynamic)
            .map(|sm| sm.ctx.config.if_name.clone())
            .collect::<BTreeSet<_>>();
        let to_del = current_dynamic
            .difference(&desired)
            .cloned()
            .collect::<Vec<_>>();
        let to_add = desired
            .difference(&current_dynamic)
            .cloned()
            .collect::<Vec<_>>();
        let departing = to_del
            .iter()
            .filter_map(|name| self.remove_state_machine(name))
            .collect::<Vec<_>>();

        for name in to_add {
            // Anything already present but not dynamic is static.
            if self.machines.get(name.as_str()).is_some() {
                warn!(
                    self.template.log,
                    "ddm_apply: {name} is a static interface from the \
                     command line; ignoring it"
                );
                continue;
            }
            self.add_state_machine(name, InterfaceLifetime::Dynamic);
        }
        // Signal every departing FSM before joining any of them, so their
        // threads wake and tear down concurrently rather than one at a time.
        for sm in &departing {
            sm.signal_stop();
        }
        for sm in departing {
            sm.join();
        }
    }
}
