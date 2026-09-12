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
//! clean/dirty teardown and scrub outcomes come from the hook.

use mg_common::lock;
use mg_common::stats::MgLowerStats;
use slog::Logger;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub struct LowerContext {
    handles: Mutex<BTreeMap<String, LowerHandle>>,
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
    /// Resolves to mg-lower's report of whether dpd confirmed the router's
    /// switch table was left clean on shutdown.
    join: std::thread::JoinHandle<bool>,
}

/// Recorded platform lifecycle for tests: which routers were started and
/// stopped, and what dpd "reported" for teardown and scrub.
#[cfg(test)]
pub(crate) struct TestLower {
    /// Routers whose `stop` reports a dirty switch table (tombstoning its
    /// index), as when dpd is unreachable during teardown.
    pub(crate) dirty_on_stop: Mutex<std::collections::BTreeSet<String>>,
    /// Whether scrubbing a tombstoned table succeeds (dpd confirms it clean)
    /// and releases the index. Defaults to true.
    pub(crate) scrub_clean: Mutex<bool>,
    pub(crate) ensured: Mutex<Vec<String>>,
    pub(crate) stopped: Mutex<Vec<String>>,
}

#[cfg(test)]
impl Default for TestLower {
    fn default() -> Self {
        Self {
            dirty_on_stop: Mutex::new(std::collections::BTreeSet::new()),
            scrub_clean: Mutex::new(true),
            ensured: Mutex::new(Vec::new()),
            stopped: Mutex::new(Vec::new()),
        }
    }
}

impl LowerContext {
    /// A context that never touches a platform; lifecycle outcomes come from
    /// `hook`.
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
        rdb: &rdb::RouterDb,
        log: &Logger,
        stats: &Arc<MgLowerStats>,
    ) {
        #[cfg(test)]
        if let Some(hook) = &self.test {
            lock!(hook.ensured).push(rdb.name().to_string());
            return;
        }
        self.ensure_production(rdb, log, stats);
    }

    #[cfg(all(feature = "mg-lower", target_os = "illumos"))]
    fn ensure_production(
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
                )
            })
            .expect("failed to start mg-lower");
        handles.insert(name, LowerHandle { shutdown, join });
    }

    #[cfg(not(all(feature = "mg-lower", target_os = "illumos")))]
    fn ensure_production(
        &self,
        _rdb: &rdb::RouterDb,
        _log: &Logger,
        _stats: &Arc<MgLowerStats>,
    ) {
    }

    /// Stop the router's mg-lower thread, waiting for it to withdraw the
    /// router's routes from the ASIC and its tunnel advertisements from ddm.
    ///
    /// Returns true when dpd confirmed the router's switch table was left
    /// clean (or when there was no thread, i.e. nothing was ever
    /// programmed). On false, the router's switch table index must not be
    /// reused: keep it tombstoned and retry the cleanup later.
    pub async fn stop(&self, name: &str) -> bool {
        #[cfg(test)]
        if let Some(hook) = &self.test {
            lock!(hook.stopped).push(name.to_string());
            return !lock!(hook.dirty_on_stop).contains(name);
        }
        let handle = lock!(self.handles).remove(name);
        let Some(handle) = handle else {
            return true;
        };
        handle.shutdown.store(true, Ordering::Relaxed);
        // The thread polls the shutdown flag with a one second period
        // and then withdraws platform state, so join off the runtime.
        tokio::task::spawn_blocking(move || handle.join.join())
            .await
            .map(|joined| joined.unwrap_or(false))
            .unwrap_or(false)
    }

    /// Retry cleanup for tombstoned switch table indexes: scrub each
    /// departed router's table and release the index once dpd confirms the
    /// table is clean. Failures are logged; the tombstone stays for the
    /// next attempt.
    pub async fn scrub_orphaned_switch_indexes(
        &self,
        db: &rdb::Db,
        log: &Logger,
    ) {
        let orphans = match db.orphaned_switch_indexes() {
            Ok(orphans) => orphans,
            Err(e) => {
                slog::warn!(log, "failed to list switch index tombstones: {e}");
                return;
            }
        };
        for (id, index) in orphans {
            let clean = self.scrub_switch_table(id, index, log).await;
            if clean {
                match db.release_switch_index(&id) {
                    Ok(()) => slog::info!(
                        log,
                        "switch table {index} of departed router {id} \
                         confirmed clean; index released"
                    ),
                    Err(e) => slog::warn!(
                        log,
                        "failed to release switch index {index} of departed \
                         router {id}: {e}"
                    ),
                }
            } else {
                slog::warn!(
                    log,
                    "switch table {index} of departed router {id} is not \
                     confirmed clean; keeping its index tombstoned"
                );
            }
        }
    }

    /// Scrub one tombstoned table; true when dpd confirmed it clean.
    async fn scrub_switch_table(
        &self,
        id: rdb::types::RouterId,
        index: u8,
        log: &Logger,
    ) -> bool {
        #[cfg(test)]
        if let Some(hook) = &self.test {
            let _ = (id, index, log);
            return *lock!(hook.scrub_clean);
        }
        Self::scrub_switch_table_production(id, index, log).await
    }

    #[cfg(all(feature = "mg-lower", target_os = "illumos"))]
    async fn scrub_switch_table_production(
        id: rdb::types::RouterId,
        index: u8,
        log: &Logger,
    ) -> bool {
        let rt = Arc::new(tokio::runtime::Handle::current());
        let scrub_log = log.clone();
        tokio::task::spawn_blocking(move || {
            let dpd = mg_lower::ProductionDpd {
                client: mg_lower::new_dpd_client(&scrub_log),
                rid: index,
            };
            mg_lower::scrub_switch_table(id, &dpd, &rt, &scrub_log)
        })
        .await
        .unwrap_or(false)
    }

    /// Without a lower half nothing is ever programmed into a switch, so
    /// tombstoned indexes can be released directly.
    #[cfg(not(all(feature = "mg-lower", target_os = "illumos")))]
    async fn scrub_switch_table_production(
        _id: rdb::types::RouterId,
        _index: u8,
        _log: &Logger,
    ) -> bool {
        true
    }
}
