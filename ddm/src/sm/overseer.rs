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
    slog::error,
    std::collections::BTreeSet,
    std::sync::Mutex,
    std::sync::mpsc::channel,
};

/// Sole owner of every DDM state machine and the inter-FSM sender mesh.
///
/// Lives behind one `Arc<RwLock<Overseer>>`: admin readers take the read lock;
/// `apply` takes the write lock for the whole reconcile, including signalling
/// and joining departing FSMs, so at most one FSM per interface ever exists
/// (including ones mid-teardown) and concurrent applies are serialized. FSM
/// threads must never take this lock; they reach the mesh through the shared
/// `Arc` in [`SmContext::event_channels`]. FSM threads may take the mesh read
/// lock, database locks, and `InterfaceState` mutexes while `apply` joins them.
#[cfg_attr(
    not(all(feature = "backend", target_os = "illumos")),
    allow(dead_code)
)]
pub struct Overseer {
    log: Logger,
    db: Db,
    rt: tokio::runtime::Handle,
    hostname: String,
    base_fsm_config: Config,
    machines: IdOrdMap<StateMachine>,
    mesh: Arc<RwLock<BTreeMap<String, Sender<Event>>>>,
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
            log,
            db,
            rt,
            hostname,
            base_fsm_config,
            machines: IdOrdMap::new(),
            mesh: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &StateMachine> {
        self.machines.iter()
    }

    /// Update the hostname carried in path vectors by state machines started
    /// after this call. Running state machines keep the hostname they were
    /// started with.
    pub fn set_hostname(&mut self, hostname: String) {
        self.hostname = hostname;
    }

    /// Add and start the state machine for `ifname`.
    #[cfg(all(feature = "backend", target_os = "illumos"))]
    pub fn add_state_machine(&mut self, ifname: String) {
        if self.machines.get(ifname.as_str()).is_some() {
            error!(self.log, "state machine {ifname} already exists");
            return;
        }

        let (tx, rx) = channel();
        let mut config = self.base_fsm_config.clone();
        config.if_name = ifname.clone();
        let ctx = SmContext {
            config,
            db: self.db.clone(),
            tx: tx.clone(),
            event_channels: self.mesh.clone(),
            rt: self.rt.clone(),
            hostname: self.hostname.clone(),
            iface: Arc::new(InterfaceState {
                if_name: Mutex::new(ifname.clone()),
                ..Default::default()
            }),
            stats: Arc::new(SessionStats::default()),
            log: self.log.clone(),
        };

        write_lock!(self.mesh).insert(ifname, tx);
        let sm = StateMachine::spawn(ctx, rx);
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

    /// Reconcile the running FSMs with `desired`, including full teardown.
    ///
    /// The caller holds the Overseer write lock throughout this method, so
    /// readers stall for the teardown duration. The slow tail is DPD HTTP in
    /// `sys::remove_underlay_routes`, called by `close_session` and
    /// `sweep_interface`.
    #[cfg(all(feature = "backend", target_os = "illumos"))]
    pub fn apply(&mut self, desired: BTreeSet<String>) {
        let current = self
            .machines
            .iter()
            .map(|sm| sm.ctx.config.if_name.clone())
            .collect::<BTreeSet<_>>();
        let to_del = current.difference(&desired).cloned().collect::<Vec<_>>();
        let to_add = desired.difference(&current).cloned().collect::<Vec<_>>();
        let departing = to_del
            .iter()
            .filter_map(|name| self.remove_state_machine(name))
            .collect::<Vec<_>>();

        for name in to_add {
            self.add_state_machine(name);
        }
        for sm in &departing {
            sm.signal_stop();
        }
        for sm in departing {
            sm.join();
        }
    }
}
