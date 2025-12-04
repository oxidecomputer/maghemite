// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! [Reverse Path Forwarding][RPF] (RPF) verification for multicast routing.
//!
//! RPF verification ensures that multicast packets arrive from the expected
//! upstream direction, preventing loops in multicast distribution trees.
//! See [RFD 488] for the overall multicast routing design.
//!
//! This module provides an optimized RPF implementation using Oxide's
//! [poptrie] implementation for O(1) longest-prefix matching (LPM), with a lazy
//! rebuild strategy and fallback to linear scan during rebuilds. RPF lookups
//! happen frequently during multicast route installation and unicast RIB
//! changes, requiring LPM against the unicast RIB.
//!
//! ## (S,G) vs (*,G) Routes
//!
//! RPF verification only applies to (S,G) routes where a specific source
//! address is known. The source address is looked up in the unicast RIB to
//! find the expected upstream neighbor(s).
//!
//! (*,G) routes have no source address to verify, so RPF is skipped entirely
//! and routes are directly "installed."
//!
//! ## Revalidator Integration
//!
//! The RPF revalidator (spawned in `db.rs`) listens for rebuild events and
//! re-checks (S,G) routes when unicast RIB changes. Lock ordering:
//!
//! 1. Revalidator reads unicast RIB (`rib4_loc`/`rib6_loc`)
//! 2. Revalidator writes MRIB (`mrib_in`/`mrib_loc`)
//!
//! This matches the lock order in `mrib/mod.rs`. RPF lookups hold at most one
//! lock at a time: they try poptrie first (read lock), release it, then fall
//! back to linear scan (RIB lock) if needed. No path holds both locks.
//!
//! ## Lock Poisoning
//!
//! The poptrie cache uses asymmetric poison handling:
//!
//! - **Write side** (background rebuild thread): Panics on poison via
//!   `write_lock!`.
//!
//! - **Read side**: Uses `.ok()` for graceful fallback to linear
//!   scan if the cache is poisoned. This avoids crashing during RPF checks
//!   while the linear scan fallback remains intact.
//!
//! Once an `RwLock` is poisoned, it **cannot be unpoisoned**.
//! Subsequent rebuild attempts will also panic on `write_lock!`, so the cache
//! remains permanently disabled. Reads continue to work via the
//! linear-scan fallback, keeping the system functional until SMF restarts the
//! daemon (which is the normal recovery path here).
//!
//! ## Threading Model
//!
//! Poptrie cache rebuilds run in short-lived, named background threads
//! ("rpf-poptrie-v4"/"rpf-poptrie-v6"). These threads are fire-and-forget:
//! we deliberately drop their `JoinHandle`s. If a rebuild thread panics, the
//! cache is simply not updated and RPF verification transparently falls back
//! to the linear-scan path until the next successful rebuild.
//!
//! [RPF]: https://datatracker.ietf.org/doc/html/rfc5110
//! [RFD 488]: https://rfd.shared.oxide.computer/rfd/0488
//! [poptrie]: https://conferences.sigcomm.org/sigcomm/2015/pdf/papers/p57.pdf

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use poptrie::Poptrie;
use slog::{Logger, debug, error};

use mg_common::{lock, write_lock};

use crate::bestpath::bestpaths;
use crate::db::{Rib4, Rib6};
use crate::types::{Path, Prefix, PrefixContains};
use crate::{Prefix4, Prefix6};

/// Default interval for periodic RPF revalidation sweeps.
pub const DEFAULT_REVALIDATION_INTERVAL: Duration = Duration::from_secs(60);

/// Event emitted when RPF revalidation is needed.
///
/// This is emitted when a poptrie rebuild completes, or when a rebuild
/// request was rate-limited but multicast RPF revalidation should still
/// proceed using the linear-scan fallback.
///
/// The optional prefix ([`Prefix4`]/[`Prefix6`]) indicates which unicast route
/// changed, enabling targeted (S,G) revalidation. If `None`, a full sweep is
/// performed.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RebuildEvent {
    /// IPv4 unicast routing changed. If a prefix is provided, only (S,G)
    /// routes with sources matching that prefix need revalidation.
    V4(Option<Prefix4>),
    /// IPv6 unicast routing changed. If a prefix is provided, only (S,G)
    /// routes with sources matching that prefix need revalidation.
    V6(Option<Prefix6>),
}

impl RebuildEvent {
    /// Convert to a full-sweep event (no specific prefix).
    ///
    /// Used when multiple prefixes may have changed during pending rebuilds.
    fn to_full_sweep(self) -> Self {
        match self {
            Self::V4(_) => Self::V4(None),
            Self::V6(_) => Self::V6(None),
        }
    }

    /// Check if a source address is potentially affected by this event.
    ///
    /// Returns true if the source falls within the changed prefix (targeted),
    /// or if no specific prefix is provided (full sweep).
    pub(crate) fn matches_source(&self, source: IpAddr) -> bool {
        match (source, self) {
            (src, RebuildEvent::V4(Some(prefix))) => {
                Prefix::V4(*prefix).contains(src).is_some()
            }
            (src, RebuildEvent::V6(Some(prefix))) => {
                Prefix::V6(*prefix).contains(src).is_some()
            }
            // No specific prefix = full sweep for this AF
            (IpAddr::V4(_), RebuildEvent::V4(None)) => true,
            (IpAddr::V6(_), RebuildEvent::V6(None)) => true,
            // Wrong AF = skip
            (IpAddr::V4(_), RebuildEvent::V6(_)) => false,
            (IpAddr::V6(_), RebuildEvent::V4(_)) => false,
        }
    }
}

/// Set of paths for a prefix, stored in the poptrie cache.
///
/// We store full [`Path`] objects (not just nexthops) so that we can apply
/// bestpath selection at lookup time. This ensures consistent behavior
/// between the poptrie fast path and linear scan fallback, regardless of
/// the configured fanout value.
pub(crate) type CachedPaths = BTreeSet<Path>;

/// State machine for coordinating poptrie rebuilds.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RebuildState {
    /// No rebuild in progress.
    Idle = 0,
    /// Rebuild thread is running.
    Running = 1,
    /// Rebuild thread is running and more changes arrived.
    RunningPending = 2,
}

/// Coordinator for poptrie rebuild threads.
///
/// Provides atomic state transitions to prevent race conditions where
/// pending work could be missed between checking the pending flag and
/// releasing the in-progress lock.
#[derive(Debug)]
struct RebuildCoordinator(AtomicU8);

impl RebuildCoordinator {
    /// Create a new coordinator in the idle state.
    fn new() -> Self {
        Self(AtomicU8::new(RebuildState::Idle as u8))
    }

    /// Try to start a rebuild. Returns `true` if this thread should do work.
    ///
    /// Atomically transitions `Idle → Running`.
    fn try_start(&self) -> bool {
        self.0
            .compare_exchange(
                RebuildState::Idle as u8,
                RebuildState::Running as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Signal that more work arrived while a rebuild is in progress.
    ///
    /// Atomically transitions `Running → RunningPending`. If already
    /// `RunningPending` or `Idle`, this is a no-op.
    fn signal_pending(&self) {
        // Only transition Running → RunningPending
        let _ = self.0.compare_exchange(
            RebuildState::Running as u8,
            RebuildState::RunningPending as u8,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }

    /// Check if more work is pending and atomically clear the pending flag.
    ///
    /// Returns `true` if we should continue working (previously `RunningPending`).
    /// Atomically transitions `RunningPending → Running`.
    fn check_pending(&self) -> bool {
        self.0
            .compare_exchange(
                RebuildState::RunningPending as u8,
                RebuildState::Running as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Mark the rebuild as complete.
    ///
    /// Transitions to `Idle`. Should only be called by the rebuild thread.
    fn finish(&self) {
        self.0.store(RebuildState::Idle as u8, Ordering::Release);
    }
}

/// Scope guard to mark rebuild as finished on drop.
///
/// This ensures the coordinator transitions to `Idle` even if the rebuild
/// thread panics, preventing deadlock.
struct RebuildGuard(Arc<RebuildCoordinator>);

impl Drop for RebuildGuard {
    fn drop(&mut self) {
        self.0.finish();
    }
}

/// Address-family related rebuild job.
///
/// Encapsulates the RIB source and cache destination for a poptrie rebuild,
/// allowing the rebuild logic to be shared between IPv4 and IPv6.
enum RebuildJob {
    V4 {
        rib: Arc<Mutex<Rib4>>,
        cache: Arc<RwLock<Option<Poptrie<CachedPaths>>>>,
    },
    V6 {
        rib: Arc<Mutex<Rib6>>,
        cache: Arc<RwLock<Option<Poptrie<CachedPaths>>>>,
    },
}

impl RebuildJob {
    /// Take a snapshot of the RIB and build a fresh poptrie cache.
    fn rebuild(&self) {
        match self {
            Self::V4 { rib, cache } => {
                let snapshot = {
                    let r = lock!(rib);
                    RpfTable::snapshot_rib(&r, |p| {
                        (u32::from(p.value), p.length)
                    })
                };
                let mut table = poptrie::Ipv4RoutingTable::default();
                for (addr, len, paths) in snapshot {
                    table.insert((addr, len), paths);
                }
                *write_lock!(cache) = Some(Poptrie::from(table));
            }
            Self::V6 { rib, cache } => {
                let snapshot = {
                    let r = lock!(rib);
                    RpfTable::snapshot_rib(&r, |p| {
                        (u128::from(p.value), p.length)
                    })
                };
                let mut table = poptrie::Ipv6RoutingTable::default();
                for (addr, len, paths) in snapshot {
                    table.insert((addr, len), paths);
                }
                *write_lock!(cache) = Some(Poptrie::from(table));
            }
        }
    }

    /// Thread name for debugging.
    fn thread_name(&self) -> &'static str {
        match self {
            Self::V4 { .. } => "rpf-poptrie-v4",
            Self::V6 { .. } => "rpf-poptrie-v6",
        }
    }
}

/// RPF verification table using poptrie for O(1) LPM (longest-prefix matching).
///
/// This table maintains a poptrie-based cache of the RIB for fast RPF lookups.
/// The cache is rebuilt asynchronously in the background when triggered, with
/// rate limiting to avoid excessive rebuilds. Falls back to linear scan during
/// rebuilds or if poptrie is unavailable.
///
/// The poptrie stores full [`Path`] objects (not just nexthops) so that
/// bestpath selection can be applied at lookup time. This ensures consistent
/// RPF verification behavior regardless of whether poptrie or linear scan is
/// used.
#[derive(Clone)]
pub(crate) struct RpfTable {
    /// IPv4 poptrie cache.
    cache_v4: Arc<RwLock<Option<Poptrie<CachedPaths>>>>,
    /// IPv6 poptrie cache.
    cache_v6: Arc<RwLock<Option<Poptrie<CachedPaths>>>>,
    /// Last rebuild completion time for rate limiting.
    ///
    /// Shared between v4 and v6 rebuilds. During route updates
    /// affecting both address families, this prevents simultaneous
    /// rebuilds and spreads the CPU load. The fallback is a linear scan.
    last_rebuild: Arc<Mutex<Option<Instant>>>,
    /// Configurable minimum interval between rebuilds (milliseconds).
    rebuild_interval_ms: Arc<AtomicU64>,
    /// Optional notifier for rebuild-complete events.
    rebuild_notifier: Arc<Mutex<Option<mpsc::Sender<RebuildEvent>>>>,
    /// Coordinator for IPv4 poptrie rebuilds.
    rebuild_v4: Arc<RebuildCoordinator>,
    /// Coordinator for IPv6 poptrie rebuilds.
    rebuild_v6: Arc<RebuildCoordinator>,
    /// Logger for error reporting.
    log: Logger,
}

impl RpfTable {
    /// Default minimum time between rebuilds (milliseconds).
    const DEFAULT_REBUILD_INTERVAL_MS: u64 = 1000;

    /// Create a new empty RPF table with default rebuild interval.
    pub fn new(log: Logger) -> Self {
        Self {
            cache_v4: Arc::new(RwLock::new(None)),
            cache_v6: Arc::new(RwLock::new(None)),
            last_rebuild: Arc::new(Mutex::new(None)),
            rebuild_interval_ms: Arc::new(AtomicU64::new(
                Self::DEFAULT_REBUILD_INTERVAL_MS,
            )),
            rebuild_notifier: Arc::new(Mutex::new(None)),
            rebuild_v4: Arc::new(RebuildCoordinator::new()),
            rebuild_v6: Arc::new(RebuildCoordinator::new()),
            log,
        }
    }

    /// Set the minimum interval between rebuilds.
    pub fn set_rebuild_interval(&self, interval: Duration) {
        self.rebuild_interval_ms
            .store(interval.as_millis() as u64, Ordering::Relaxed);
    }

    /// Check if enough time has passed since the last rebuild.
    /// Returns `true` if rebuild should proceed, `false` if rate limited.
    fn check_rate_limit(&self) -> bool {
        let min_interval_ms = self.rebuild_interval_ms.load(Ordering::Relaxed);
        let min_interval = Duration::from_millis(min_interval_ms);

        if let Ok(last) = self.last_rebuild.lock()
            && let Some(last_instant) = *last
            && last_instant.elapsed() < min_interval
        {
            return false; // Skip rebuild, too soon
        }
        true
    }

    /// Send a rebuild event notification if configured.
    fn notify(&self, event: RebuildEvent) {
        if let Ok(guard) = self.rebuild_notifier.lock()
            && let Some(tx) = &*guard
            && tx.send(event).is_err()
        {
            debug!(self.log, "rpf revalidator not running");
        }
    }

    /// Snapshot a RIB for poptrie rebuild.
    ///
    /// Extracts (addr_bits, prefix_len, paths) tuples from the RIB.
    /// The `to_bits` closure converts the prefix to address bits.
    fn snapshot_rib<P, A, F>(
        rib: &BTreeMap<P, BTreeSet<Path>>,
        to_bits: F,
    ) -> Vec<(A, u8, BTreeSet<Path>)>
    where
        F: Fn(&P) -> (A, u8),
    {
        rib.iter()
            .filter(|(_, paths)| !paths.is_empty())
            .map(|(prefix, paths)| {
                let (bits, len) = to_bits(prefix);
                (bits, len, paths.clone())
            })
            .collect()
    }

    /// Install a notifier to be called on rebuild completion.
    pub fn set_rebuild_notifier(&self, tx: mpsc::Sender<RebuildEvent>) {
        if let Ok(mut guard) = self.rebuild_notifier.lock() {
            *guard = Some(tx);
        }
    }

    /// Spawn a background thread to execute a rebuild job.
    ///
    /// This is the shared implementation for both IPv4 and IPv6 rebuilds.
    /// The job encapsulates the address-family-specific parts (RIB, cache),
    /// while this method handles the shared logic (coordinator, timing, notify).
    ///
    /// The `event` parameter is used for targeted revalidation: if we complete
    /// without looping, we send the original prefix so only affected (S,G)
    /// routes are re-checked. If pending changes caused us to loop, we send
    /// a full-sweep event (`None` prefix) since multiple prefixes may have
    /// changed.
    fn spawn_rebuild(
        &self,
        job: RebuildJob,
        coordinator: Arc<RebuildCoordinator>,
        event: RebuildEvent,
    ) {
        let last_rebuild = self.last_rebuild.clone();
        let notifier = self.rebuild_notifier.clone();
        let log = self.log.clone();
        let thread_name = job.thread_name().to_string();
        let thread_coord = Arc::clone(&coordinator);

        if let Err(e) =
            thread::Builder::new()
                .name(thread_name.clone())
                .spawn(move || {
                    let _guard = RebuildGuard(Arc::clone(&thread_coord));

                    // Track whether we looped due to pending changes.
                    let mut looped = false;

                    // Loop while there are pending rebuilds. This ensures we
                    // capture all RIB changes that occurred during the rebuild.
                    loop {
                        job.rebuild();

                        if let Ok(mut last) = last_rebuild.lock() {
                            *last = Some(Instant::now());
                        }

                        // Atomically check if more changes arrived during rebuild.
                        // If so, loop again to capture them.
                        if !thread_coord.check_pending() {
                            break;
                        }
                        looped = true;
                    }

                    // Notify revalidator. If we looped, multiple prefixes may
                    // have changed so we send a full-sweep event.
                    if let Ok(guard) = notifier.lock()
                        && let Some(tx) = &*guard
                    {
                        let final_event =
                            if looped { event.to_full_sweep() } else { event };
                        let _ = tx.send(final_event);
                    }
                })
        {
            error!(log, "failed to spawn {thread_name}: {e}");
            coordinator.finish();
            self.notify(event);
        }
    }

    /// Trigger a background rebuild of the IPv4 RPF cache.
    ///
    /// The RIB snapshot is taken lazily in the background thread, reducing
    /// lock contention during RIB updates.
    ///
    /// The `changed_prefix` ([`Prefix4`]) parameter enables targeted
    /// revalidation: only (S,G) routes whose source falls within this prefix
    /// need RPF re-checking.
    ///
    /// This trigger is rate limited based on configured interval. Only one
    /// rebuild can be in progress at a time per address family.
    pub fn trigger_rebuild_v4(
        &self,
        rib4_loc: Arc<Mutex<Rib4>>,
        changed_prefix: Option<Prefix4>,
    ) {
        if !self.check_rate_limit() {
            // Clear cache to force linear-scan fallback until next rebuild.
            // This ensures lookups use fresh RIB data rather than stale cache.
            if let Ok(mut guard) = self.cache_v4.write() {
                *guard = None;
            }
            self.notify(RebuildEvent::V4(changed_prefix));
            return;
        }

        if !self.rebuild_v4.try_start() {
            self.rebuild_v4.signal_pending();
            return;
        }

        let job = RebuildJob::V4 {
            rib: rib4_loc,
            cache: self.cache_v4.clone(),
        };

        self.spawn_rebuild(
            job,
            Arc::clone(&self.rebuild_v4),
            RebuildEvent::V4(changed_prefix),
        );
    }

    /// Trigger a background rebuild of the IPv6 RPF cache.
    ///
    /// The RIB snapshot is taken lazily in the background thread, reducing
    /// lock contention during RIB updates.
    ///
    /// The `changed_prefix` ([`Prefix6`]) parameter enables targeted
    /// revalidation: only (S,G) routes whose source falls within this prefix
    /// need RPF re-checking.
    ///
    /// This trigger is rate limited based on configured interval. Only one
    /// rebuild can be in progress at a time per address family.
    pub fn trigger_rebuild_v6(
        &self,
        rib6_loc: Arc<Mutex<Rib6>>,
        changed_prefix: Option<Prefix6>,
    ) {
        if !self.check_rate_limit() {
            // Clear cache to force linear-scan fallback until next rebuild.
            // This ensures lookups use fresh RIB data rather than stale cache.
            if let Ok(mut guard) = self.cache_v6.write() {
                *guard = None;
            }
            self.notify(RebuildEvent::V6(changed_prefix));
            return;
        }

        if !self.rebuild_v6.try_start() {
            self.rebuild_v6.signal_pending();
            return;
        }

        let job = RebuildJob::V6 {
            rib: rib6_loc,
            cache: self.cache_v6.clone(),
        };

        self.spawn_rebuild(
            job,
            Arc::clone(&self.rebuild_v6),
            RebuildEvent::V6(changed_prefix),
        );
    }

    /// Look up the RPF neighbor for a multicast source address.
    ///
    /// Returns the best nexthop from the unicast RIB for reaching the source,
    /// which is the valid RPF neighbor for (S,G) routes. Returns `None` if
    /// no route exists for the source.
    ///
    /// Uses poptrie for O(1) lookup with linear scan fallback.
    pub fn lookup(
        &self,
        source: IpAddr,
        rib4_loc: &Arc<Mutex<Rib4>>,
        rib6_loc: &Arc<Mutex<Rib6>>,
        fanout: usize,
    ) -> Option<IpAddr> {
        // Try poptrie lookup first
        let cached_paths = match source {
            IpAddr::V4(addr) => self.cache_v4.read().ok().and_then(|cache| {
                cache.as_ref().and_then(|pt| pt.match_v4(u32::from(addr)))
            }),
            IpAddr::V6(addr) => self.cache_v6.read().ok().and_then(|cache| {
                cache.as_ref().and_then(|pt| pt.match_v6(u128::from(addr)))
            }),
        };

        if let Some(paths) = cached_paths {
            return Self::get_rpf_neighbor(&paths, fanout);
        }

        // Fallback to linear scan
        match source {
            IpAddr::V4(addr) => Self::lookup_v4(addr, rib4_loc, fanout),
            IpAddr::V6(addr) => Self::lookup_v6(addr, rib6_loc, fanout),
        }
    }

    /// IPv4 RPF lookup (linear scan fallback when poptrie unavailable).
    ///
    /// This O(n) scan is acceptable for deployments where the
    /// unicast RIB is small.
    fn lookup_v4(
        source: Ipv4Addr,
        rib4_loc: &Arc<Mutex<Rib4>>,
        fanout: usize,
    ) -> Option<IpAddr> {
        let rib = rib4_loc.lock().ok()?;

        // Find best matching prefix (longest-prefix match)
        let mut best_paths: Option<&BTreeSet<Path>> = None;
        let mut best_len = 0u8;

        let source_bits = u32::from(source);
        for (prefix, paths) in rib.iter() {
            let prefix_bits = u32::from(prefix.value);
            let mask = if prefix.length == 0 {
                0
            } else {
                !0u32 << (32 - prefix.length)
            };
            if (prefix_bits & mask) == (source_bits & mask)
                && prefix.length > best_len
            {
                best_len = prefix.length;
                best_paths = Some(paths);
            }
        }

        best_paths.and_then(|paths| Self::get_rpf_neighbor(paths, fanout))
    }

    /// IPv6 RPF lookup (linear scan fallback when poptrie unavailable).
    ///
    /// This O(n) scan is acceptable for deployments where the
    /// unicast RIB is small.
    fn lookup_v6(
        source: Ipv6Addr,
        rib6_loc: &Arc<Mutex<Rib6>>,
        fanout: usize,
    ) -> Option<IpAddr> {
        let rib = rib6_loc.lock().ok()?;

        // Find best matching prefix (longest-prefix match)
        let mut best_paths: Option<&BTreeSet<Path>> = None;
        let mut best_len = 0u8;

        let source_bits = u128::from(source);
        for (prefix, paths) in rib.iter() {
            let prefix_bits = u128::from(prefix.value);
            let mask = if prefix.length == 0 {
                0
            } else {
                !0u128 << (128 - prefix.length)
            };
            if (prefix_bits & mask) == (source_bits & mask)
                && prefix.length > best_len
            {
                best_len = prefix.length;
                best_paths = Some(paths);
            }
        }

        best_paths.and_then(|paths| Self::get_rpf_neighbor(paths, fanout))
    }

    /// Extract the RPF neighbor from a set of paths.
    ///
    /// For fanout == 1, returns the single bestpath nexthop.
    /// For fanout > 1, returns the first active nexthop. All paths in loc-rib
    /// are valid ECMP paths (already bestpath-selected), so any one suffices
    /// for RPF verification.
    fn get_rpf_neighbor(
        paths: &BTreeSet<Path>,
        fanout: usize,
    ) -> Option<IpAddr> {
        let active_paths: BTreeSet<Path> =
            paths.iter().filter(|p| !p.shutdown).cloned().collect();

        if active_paths.is_empty() {
            return None;
        }

        if fanout == 1 {
            bestpaths(&active_paths, 1)
                .and_then(|selected| selected.iter().next().map(|p| p.nexthop))
        } else {
            active_paths.iter().next().map(|p| p.nexthop)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use mg_common::log::*;

    use crate::{DEFAULT_RIB_PRIORITY_BGP, DEFAULT_RIB_PRIORITY_STATIC};

    /// Helper to create empty Rib4 for tests
    fn empty_rib4() -> Arc<Mutex<Rib4>> {
        Arc::new(Mutex::new(BTreeMap::new()))
    }

    /// Helper to create empty Rib6 for tests
    fn empty_rib6() -> Arc<Mutex<Rib6>> {
        Arc::new(Mutex::new(BTreeMap::new()))
    }

    /// Extract nexthops from paths (filters out shutdown paths).
    fn nexthops_from_paths(paths: &BTreeSet<Path>) -> BTreeSet<IpAddr> {
        paths
            .iter()
            .filter(|p| !p.shutdown)
            .map(|p| p.nexthop)
            .collect()
    }

    #[test]
    fn test_nexthops_from_paths() {
        let mut paths = BTreeSet::new();
        let path1 = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };
        let path2 = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };
        paths.insert(path1);
        paths.insert(path2);

        let next_hops = nexthops_from_paths(&paths);
        assert_eq!(next_hops.len(), 2);
        assert!(next_hops.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(next_hops.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));
        assert!(!next_hops.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3))));
    }

    #[test]
    fn test_rpf_table_linear_scan() {
        let mut rib4_inner: Rib4 = BTreeMap::new();
        let prefix: Prefix4 = "192.0.2.0/24".parse().unwrap();

        let mut paths = BTreeSet::new();
        let path = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };
        paths.insert(path);
        rib4_inner.insert(prefix, paths);

        let rib4_loc = Arc::new(Mutex::new(rib4_inner));
        let rib6_loc = empty_rib6();
        let log = init_file_logger("rpf_linear_scan.log");
        let rpf_table = RpfTable::new(log);

        // Without poptrie cache, should use linear scan
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        let expected = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(
            rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1),
            Some(expected)
        );
    }

    #[test]
    fn test_rpf_table_with_poptrie() {
        let mut rib4_inner: Rib4 = BTreeMap::new();
        let prefix: Prefix4 = "192.0.2.0/24".parse().unwrap();

        let mut paths = BTreeSet::new();
        let path = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };
        paths.insert(path);
        rib4_inner.insert(prefix, paths.clone());

        let rib4_loc = Arc::new(Mutex::new(rib4_inner));
        let rib6_loc = empty_rib6();

        let log = init_file_logger("rpf_poptrie.log");
        let rpf_table = RpfTable::new(log);
        rpf_table.trigger_rebuild_v4(Arc::clone(&rib4_loc), None);

        // Wait for rebuild to complete
        crate::test::wait_for(
            || rpf_table.cache_v4.read().unwrap().is_some(),
            crate::test::TEST_TIMEOUT,
            "poptrie v4 rebuild timed out",
        );

        // Should now use poptrie cache
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        let expected = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(
            rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1),
            Some(expected)
        );
    }

    #[test]
    fn test_rpf_table_shutdown_paths() {
        // Test that shutdown paths are filtered out
        let mut rib4_inner: Rib4 = BTreeMap::new();
        let prefix: Prefix4 = "192.0.2.0/24".parse().unwrap();

        let mut paths = BTreeSet::new();
        // Active path
        let active_path = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            rib_priority: 10,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };
        // Shutdown path
        let shutdown_path = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            rib_priority: 20,
            shutdown: true,
            bgp: None,
            vlan_id: None,
        };
        paths.insert(active_path);
        paths.insert(shutdown_path);
        rib4_inner.insert(prefix, paths);

        let log = init_file_logger("rpf_shutdown.log");
        let rpf_table = RpfTable::new(log);
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        let rib4_loc = Arc::new(Mutex::new(rib4_inner));
        let rib6_loc = empty_rib6();
        let active_neighbor = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

        // Linear scan should return active path, not shutdown
        assert_eq!(
            rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1),
            Some(active_neighbor)
        );

        // Rebuild poptrie and test again
        rpf_table.trigger_rebuild_v4(Arc::clone(&rib4_loc), None);
        crate::test::wait_for(
            || rpf_table.cache_v4.read().unwrap().is_some(),
            crate::test::TEST_TIMEOUT,
            "poptrie v4 rebuild timed out",
        );

        // Poptrie should also return active path
        assert_eq!(
            rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1),
            Some(active_neighbor)
        );
    }

    #[test]
    fn test_rpf_table_all_shutdown() {
        // Test that a prefix with ALL paths shutdown returns None
        let mut rib4_inner: Rib4 = BTreeMap::new();
        let prefix: Prefix4 = "192.0.2.0/24".parse().unwrap();

        let mut paths = BTreeSet::new();
        let shutdown_path = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            rib_priority: 1,
            shutdown: true,
            bgp: None,
            vlan_id: None,
        };
        paths.insert(shutdown_path);
        rib4_inner.insert(prefix, paths);

        let log = init_file_logger("rpf_all_shutdown.log");
        let rpf_table = RpfTable::new(log);
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        let rib4_loc = Arc::new(Mutex::new(rib4_inner));
        let rib6_loc = empty_rib6();

        // Linear scan - should return `None` (all paths shutdown)
        assert_eq!(rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1), None);

        // Rebuild poptrie
        rpf_table.trigger_rebuild_v4(Arc::clone(&rib4_loc), None);
        crate::test::wait_for(
            || rpf_table.cache_v4.read().unwrap().is_some(),
            crate::test::TEST_TIMEOUT,
            "poptrie v4 rebuild timed out",
        );

        // Poptrie finds the route but all paths shutdown, still `None`
        assert_eq!(rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1), None);
    }

    #[test]
    fn test_rpf_ecmp_different_priorities() {
        // Test that bestpath selection prefers lower rib_priority

        let mut rib4_inner: Rib4 = BTreeMap::new();
        let prefix: Prefix4 = "192.0.2.0/24".parse().unwrap();

        // Static route (priority 1)
        let static_nexthop = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let static_path = Path {
            nexthop: static_nexthop,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };

        // BGP route (priority 20)
        let bgp_nexthop = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let bgp_path = Path {
            nexthop: bgp_nexthop,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };

        let mut paths = BTreeSet::new();
        paths.insert(static_path);
        paths.insert(bgp_path);
        rib4_inner.insert(prefix, paths);

        let log = init_file_logger("rpf_ecmp_priority.log");
        let rpf_table = RpfTable::new(log);
        let rib4_loc = Arc::new(Mutex::new(rib4_inner));
        let rib6_loc = empty_rib6();
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));

        // fanout=1: returns static (best priority)
        assert_eq!(
            rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1),
            Some(static_nexthop)
        );

        rpf_table.trigger_rebuild_v4(Arc::clone(&rib4_loc), None);
        crate::test::wait_for(
            || rpf_table.cache_v4.read().unwrap().is_some(),
            crate::test::TEST_TIMEOUT,
            "poptrie v4 rebuild timed out",
        );

        // Same with poptrie
        assert_eq!(
            rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1),
            Some(static_nexthop)
        );
    }

    #[test]
    fn test_rpf_table_linear_scan_v6() {
        let mut rib6_inner: Rib6 = BTreeMap::new();
        let prefix: Prefix6 = "2001:db8::/32".parse().unwrap();

        let mut paths = BTreeSet::new();
        let path = Path {
            nexthop: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };
        paths.insert(path);
        rib6_inner.insert(prefix, paths);

        let rib4_loc = empty_rib4();
        let rib6_loc = Arc::new(Mutex::new(rib6_inner));
        let log = init_file_logger("rpf_linear_scan_v6.log");
        let rpf_table = RpfTable::new(log);

        // Without poptrie cache, should use linear scan
        let source =
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50));
        let expected = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1),
            Some(expected)
        );
    }

    #[test]
    fn test_rpf_table_with_poptrie_v6() {
        let mut rib6_inner: Rib6 = BTreeMap::new();
        let prefix: Prefix6 = "2001:db8::/32".parse().unwrap();

        let mut paths = BTreeSet::new();
        let path = Path {
            nexthop: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };
        paths.insert(path);
        rib6_inner.insert(prefix, paths.clone());

        let rib4_loc = empty_rib4();
        let rib6_loc = Arc::new(Mutex::new(rib6_inner));

        let log = init_file_logger("rpf_poptrie_v6.log");
        let rpf_table = RpfTable::new(log);
        rpf_table.trigger_rebuild_v6(Arc::clone(&rib6_loc), None);

        // Wait for rebuild to complete
        crate::test::wait_for(
            || rpf_table.cache_v6.read().unwrap().is_some(),
            crate::test::TEST_TIMEOUT,
            "poptrie v6 rebuild timed out",
        );

        // Should now use poptrie cache
        let source =
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50));
        let expected = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1),
            Some(expected)
        );
    }

    #[test]
    fn test_rpf_lpm() {
        // Test longest-prefix match -> the more specific route wins
        let mut rib4_inner: Rib4 = BTreeMap::new();

        // Less specific: 192.0.2.0/24 -> nexthop1
        let prefix_24: Prefix4 = "192.0.2.0/24".parse().unwrap();
        let nexthop1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let mut paths1 = BTreeSet::new();
        paths1.insert(Path {
            nexthop: nexthop1,
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        });
        rib4_inner.insert(prefix_24, paths1);

        // More specific: 192.0.2.128/25 -> nexthop2
        let prefix_25: Prefix4 = "192.0.2.128/25".parse().unwrap();
        let nexthop2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let mut paths2 = BTreeSet::new();
        paths2.insert(Path {
            nexthop: nexthop2,
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        });
        rib4_inner.insert(prefix_25, paths2);

        let log = init_file_logger("rpf_lpm.log");
        let rpf_table = RpfTable::new(log);
        let rib4_loc = Arc::new(Mutex::new(rib4_inner.clone()));
        let rib6_loc = empty_rib6();

        // Source in /25 should match more specific route
        let source_in_25 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
        assert_eq!(
            rpf_table.lookup(source_in_25, &rib4_loc, &rib6_loc, 1),
            Some(nexthop2)
        );

        // Source in /24 but not /25 should match less specific route
        let source_in_24 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        assert_eq!(
            rpf_table.lookup(source_in_24, &rib4_loc, &rib6_loc, 1),
            Some(nexthop1)
        );

        // Test with poptrie too
        rpf_table.trigger_rebuild_v4(Arc::clone(&rib4_loc), None);
        crate::test::wait_for(
            || rpf_table.cache_v4.read().unwrap().is_some(),
            crate::test::TEST_TIMEOUT,
            "poptrie v4 rebuild timed out",
        );

        assert_eq!(
            rpf_table.lookup(source_in_25, &rib4_loc, &rib6_loc, 1),
            Some(nexthop2)
        );
        assert_eq!(
            rpf_table.lookup(source_in_24, &rib4_loc, &rib6_loc, 1),
            Some(nexthop1)
        );
    }

    #[test]
    fn test_rpf_ecmp_v6() {
        // Test IPv6 ECMP: lookup returns one of the equal-priority paths
        let mut rib6_inner: Rib6 = BTreeMap::new();
        let prefix: Prefix6 = "2001:db8::/32".parse().unwrap();

        let nexthop1 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let nexthop2 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));

        let path1 = Path {
            nexthop: nexthop1,
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };
        let path2 = Path {
            nexthop: nexthop2,
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };

        let mut paths = BTreeSet::new();
        paths.insert(path1);
        paths.insert(path2);
        rib6_inner.insert(prefix, paths);

        let log = init_file_logger("rpf_ecmp_v6.log");
        let rpf_table = RpfTable::new(log);
        let rib4_loc = empty_rib4();
        let rib6_loc = Arc::new(Mutex::new(rib6_inner));
        let source =
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 50));

        // fanout=1: returns one of the equal-priority paths
        let result = rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1);
        assert!(
            result == Some(nexthop1) || result == Some(nexthop2),
            "expected one of the ECMP nexthops"
        );
    }
}
