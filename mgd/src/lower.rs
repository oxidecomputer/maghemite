// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Lifecycle management for per-router mg-lower threads.
//!
//! Each router gets one mg-lower thread that synchronizes its loc-RIB onto
//! the underlying platform (dendrite/ddm) using the router's own TEP address.
//! A thread is started when its router is created (or at daemon startup) and
//! stopped — withdrawing all the router's platform state — when the router
//! is torn down. On platforms without mg-lower support this is all a no-op.

use mg_common::lock;
use mg_common::stats::MgLowerStats;
use slog::Logger;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct LowerContext {
    handles: Mutex<BTreeMap<String, LowerHandle>>,
}

struct LowerHandle {
    shutdown: Arc<AtomicBool>,
    join: std::thread::JoinHandle<()>,
}

impl LowerContext {
    /// Start an mg-lower thread for this router if one is not already
    /// running. Must be called from within a tokio runtime.
    #[cfg(all(feature = "mg-lower", target_os = "illumos"))]
    pub fn ensure(
        &self,
        rdb: &rdb::RouterDb,
        log: &Logger,
        stats: &Arc<MgLowerStats>,
    ) {
        let mut handles = lock!(self.handles);
        if handles.contains_key(rdb.name()) {
            return;
        }
        let rdb = rdb.clone();
        let name = rdb.name().to_string();
        let log = log.clone();
        let stats = stats.clone();
        let rt = Arc::new(tokio::runtime::Handle::current());
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        let join = std::thread::Builder::new()
            .name(format!("mg-lower-{name}"))
            .spawn(move || {
                let dpd = mg_lower::ProductionDpd {
                    client: mg_lower::new_dpd_client(&log),
                    rid: rdb.switch_index(),
                };
                let ddm = mg_lower::ProductionDdm {
                    client: mg_lower::new_ddm_client(&log),
                };
                let sw = mg_lower::ProductionSwitchZone {};
                mg_lower::run(
                    rdb.tep(),
                    rdb,
                    log,
                    stats,
                    rt,
                    flag,
                    &dpd,
                    &ddm,
                    &sw,
                );
            })
            .expect("failed to start mg-lower");
        handles.insert(name, LowerHandle { shutdown, join });
    }

    #[cfg(not(all(feature = "mg-lower", target_os = "illumos")))]
    pub fn ensure(
        &self,
        _rdb: &rdb::RouterDb,
        _log: &Logger,
        _stats: &Arc<MgLowerStats>,
    ) {
    }

    /// Stop the router's mg-lower thread, waiting for it to withdraw the
    /// router's routes from the ASIC and its tunnel advertisements from ddm.
    pub async fn stop(&self, name: &str) {
        let handle = lock!(self.handles).remove(name);
        if let Some(handle) = handle {
            handle.shutdown.store(true, Ordering::Relaxed);
            // The thread polls the shutdown flag with a one second period
            // and then withdraws platform state, so join off the runtime.
            let _ =
                tokio::task::spawn_blocking(move || handle.join.join()).await;
        }
    }
}
