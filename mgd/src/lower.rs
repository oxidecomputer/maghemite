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
//!
//! Unit tests substitute a [`TestLower`] hook so router lifecycle code can be
//! exercised without a switch: no platform threads are started and the
//! hook records which routers were started and stopped.

use mg_common::lock;
use mg_common::stats::MgLowerStats;
use slog::Logger;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub struct LowerContext {
    handles: Mutex<BTreeMap<rdb::types::RouterId, LowerHandle>>,
    /// Test hook; `None` in production.
    #[cfg(test)]
    test: Option<Arc<TestLower>>,
}

impl Default for LowerContext {
    fn default() -> Self {
        Self {
            handles: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            test: None,
        }
    }
}

struct LowerHandle {
    shutdown: Arc<AtomicBool>,
    join: std::thread::JoinHandle<()>,
}

/// Recorded platform lifecycle for tests: which routers were started and
/// stopped.
#[cfg(test)]
pub(crate) struct TestLower {
    pub(crate) ensured: Mutex<Vec<String>>,
    pub(crate) stopped: Mutex<Vec<String>>,
}

#[cfg(test)]
impl Default for TestLower {
    fn default() -> Self {
        Self {
            ensured: Mutex::new(Vec::new()),
            stopped: Mutex::new(Vec::new()),
        }
    }
}

impl LowerContext {
    /// A context that never touches a platform; lifecycle calls are recorded
    /// in `hook`.
    #[cfg(test)]
    pub(crate) fn for_test(hook: Arc<TestLower>) -> Self {
        Self {
            handles: Mutex::new(BTreeMap::new()),
            test: Some(hook),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_hook(&self) -> Option<&Arc<TestLower>> {
        self.test.as_ref()
    }

    /// Start an mg-lower thread for this router if one is not already
    /// running. Must be called from within a tokio runtime.
    pub fn ensure(
        &self,
        db: &rdb::Db,
        rdb: &rdb::RouterDb,
        log: &Logger,
        stats: &Arc<MgLowerStats>,
    ) {
        #[cfg(test)]
        if let Some(hook) = &self.test {
            lock!(hook.ensured).push(rdb.name().to_string());
            return;
        }
        self.ensure_production(db, rdb, log, stats);
    }

    #[cfg(all(feature = "mg-lower", target_os = "illumos"))]
    fn ensure_production(
        &self,
        db: &rdb::Db,
        rdb: &rdb::RouterDb,
        log: &Logger,
        stats: &Arc<MgLowerStats>,
    ) {
        let mut handles = lock!(self.handles);
        if handles.contains_key(&rdb.id()) {
            return;
        }
        let db = db.clone();
        let rdb = rdb.clone();
        let id = rdb.id();
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
                };
                let ddm = mg_lower::ProductionDdm {
                    client: mg_lower::new_ddm_client(&log),
                };
                let sw = mg_lower::ProductionSwitchZone {};
                mg_lower::run(
                    rdb.tep(),
                    rdb,
                    db,
                    log,
                    stats,
                    rt,
                    flag,
                    &dpd,
                    &ddm,
                    &sw,
                )
            })
            .expect("failed to start mg-lower");
        handles.insert(id, LowerHandle { shutdown, join });
    }

    #[cfg(not(all(feature = "mg-lower", target_os = "illumos")))]
    fn ensure_production(
        &self,
        _db: &rdb::Db,
        _rdb: &rdb::RouterDb,
        _log: &Logger,
        _stats: &Arc<MgLowerStats>,
    ) {
    }

    /// Stop the router's mg-lower thread, waiting for it to withdraw the
    /// router's routes from the ASIC and its tunnel advertisements from ddm.
    pub async fn stop(&self, rdb: &rdb::RouterDb) {
        #[cfg(test)]
        if let Some(hook) = &self.test {
            lock!(hook.stopped).push(rdb.name().to_string());
            return;
        }
        let handle = lock!(self.handles).remove(&rdb.id());
        let Some(handle) = handle else {
            return;
        };
        handle.shutdown.store(true, Ordering::Relaxed);
        // The thread polls the shutdown flag with a one second period
        // and then withdraws platform state, so join off the runtime.
        let _ = tokio::task::spawn_blocking(move || handle.join.join()).await;
    }
}
