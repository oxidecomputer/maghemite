// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! [Reverse Path Forwarding][RPF] (RPF) verification for multicast routing.
//!
//! RPF verification ensures that multicast packets arrive from the expected
//! upstream direction, preventing loops in multicast distribution trees.
//! See [RFD 488] for the overall multicast routing design.
//!
//! This module provides an optimized RPF implementation using Oxide's
//! [poptrie] implementation for O(1) longest-prefix matching (LPM), with
//! asynchronous cache rebuilds and fallback to linear scan while the cache
//! is absent. RPF lookups happen frequently during multicast route
//! installation and unicast RIB changes, requiring LPM against the unicast
//! RIB.
//!
//! ## Why a Cache
//!
//! The two sides of the cache run at different frequencies. Lookups run at
//! group-membership frequency: (S,G) installation and removal follow dynamic
//! join/leave activity, both explicit and implicit (instance lifecycle and
//! placement), so there is no quiescent period to absorb slower lookups.
//! Rebuilds run at unicast-event frequency, which is episodic and settles
//! after convergence. With the cache, lookups stay O(1) and never contend with
//! unicast RIB writers, while LPM directly against the `BTreeMap` RIB would pay
//! up to address-width ordered probes under the RIB mutex on every group event
//! and revalidation sweep.
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
//! ## Rebuild Worker
//!
//! A single long-lived worker thread ("rpf-rebuild") owns all poptrie
//! rebuilds. Triggers merge their request into a shared pending slot (one
//! per address family, so memory use is bounded regardless of trigger
//! volume) and wake the worker through a bounded channel. The worker waits
//! one coalescing window, takes the pending work, snapshots the RIB while
//! holding its lock (deriving the compact `RpfNexthops` payload in the same
//! pass), builds the poptrie outside the lock, installs that snapshot, and
//! notifies the revalidator.
//!
//! Because this is the only rebuild worker, snapshots are installed in
//! capture order (i.e. an older build cannot overwrite a newer one). A trigger
//! that arrives during a build remains in the pending slot, so the worker
//! takes a newer snapshot on its next pass. Installing each completed
//! snapshot lets the cache advance during sustained route churn. After
//! updates quiesce, the final pending rebuild converges to the current RIB.
//! The cache therefore provides eventual consistency rather than being
//! guaranteed fresh at every instant.
//!
//! The cached payload is `RpfNexthops`, nexthops derived at build time,
//! rather than full path sets. Poptrie clones the payload on every match,
//! so caching derived nexthops keeps lookups allocation-free and makes
//! rebuilds cheaper.
//!
//! ## Lock Poisoning
//!
//! Cache writes never panic. If the cache `RwLock` is poisoned, the writer
//! heals it (`clear_poison`) and installs the new value, since the cache is
//! replaced wholesale and cannot expose a broken invariant. Readers use
//! `.ok()` and fall back to linear scan.
//!
//! [RPF]: https://datatracker.ietf.org/doc/html/rfc5110
//! [RFD 488]: https://rfd.shared.oxide.computer/rfd/0488
//! [poptrie]: https://conferences.sigcomm.org/sigcomm/2015/pdf/papers/p57.pdf

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, mpsc};
use std::thread;
use std::time::Duration;

use poptrie::Poptrie;
use slog::{Logger, debug, error};

use mg_common::lock;

use crate::bestpath::bestpaths;
use crate::rib::{Rib4, Rib6};
use mg_api_types::rdb::path::Path;
use oxnet::{Ipv4Net, Ipv6Net};

/// Default interval for periodic RPF revalidation sweeps.
pub const DEFAULT_REVALIDATION_INTERVAL: Duration = Duration::from_secs(60);

/// Monotonic generation number for the RPF caches.
///
/// Modeled on `omicron_common::api::external::Generation`, used here for
/// optimistic concurrency control over RPF derivations. Purely in-process,
/// so the database-driven i64 range restriction and serialization of the
/// original do not apply.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Generation(u64);

/// Shared counter producing [`Generation`] values.
///
/// Advanced by the rebuild worker each time a cache swap makes new lookup
/// results observable. A caller that snapshots the generation before a
/// lookup and observes the same generation after applying the result knows
/// no swap (and thus no revalidator pass it could clobber) intervened.
#[derive(Default)]
pub(crate) struct GenerationCounter(AtomicU64);

impl GenerationCounter {
    pub(crate) fn current(&self) -> Generation {
        Generation(self.0.load(Ordering::Acquire))
    }

    fn advance(&self) {
        self.0.fetch_add(1, Ordering::Release);
    }
}

/// Event emitted when RPF revalidation is needed.
///
/// This is emitted when a poptrie rebuild completes, or when the rebuild
/// worker is unavailable and multicast RPF revalidation should proceed
/// using the linear-scan fallback.
///
/// The optional prefix ([`Ipv4Net`]/[`Ipv6Net`]) indicates which unicast route
/// changed, enabling targeted (S,G) revalidation. If `None`, a full sweep is
/// performed.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RebuildEvent {
    /// IPv4 unicast routing changed. If a prefix is provided, only (S,G)
    /// routes with sources matching that prefix need revalidation.
    V4(Option<Ipv4Net>),
    /// IPv6 unicast routing changed. If a prefix is provided, only (S,G)
    /// routes with sources matching that prefix need revalidation.
    V6(Option<Ipv6Net>),
}

impl RebuildEvent {
    /// Check if a source address is potentially affected by this event.
    ///
    /// Returns true if the source falls within the changed prefix (targeted),
    /// or if no specific prefix is provided (full sweep).
    pub(crate) fn matches_source(&self, source: IpAddr) -> bool {
        match (source, self) {
            (IpAddr::V4(src), RebuildEvent::V4(Some(prefix))) => {
                prefix.contains(src)
            }
            (IpAddr::V6(src), RebuildEvent::V6(Some(prefix))) => {
                prefix.contains(src)
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

/// Nexthops derived from a prefix's path set at cache-build time.
///
/// Both fanout interpretations are precomputed because the RPF neighbor
/// depends on the fanout configured at lookup time. Caching derived
/// nexthops instead of full [`Path`] sets keeps poptrie lookups
/// allocation-free (poptrie clones the payload on every match) and makes
/// rebuilds cheaper.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RpfNexthops {
    /// Bestpath-selected nexthop (fanout == 1 semantics).
    best: Option<IpAddr>,
    /// One representative active nexthop for fanout > 1.
    ///
    /// RPF records a single upstream neighbor even when the loc-RIB contains
    /// multiple ECMP paths.
    first_active: Option<IpAddr>,
}

impl RpfNexthops {
    /// Derive cached nexthops from a prefix's path set.
    ///
    /// Delegates to [`RpfTable::get_rpf_neighbor`] for both fanout
    /// interpretations so the cached results match the linear-scan
    /// fallback by construction.
    fn from_paths(paths: &BTreeSet<Path>) -> Self {
        Self {
            best: RpfTable::get_rpf_neighbor(paths, 1),
            first_active: RpfTable::get_rpf_neighbor(paths, 2),
        }
    }

    /// Select the nexthop for the given fanout.
    fn for_fanout(&self, fanout: usize) -> Option<IpAddr> {
        if fanout == 1 {
            self.best
        } else {
            self.first_active
        }
    }
}

/// Coalesced pending rebuild work, shared between trigger sites and the
/// rebuild worker.
///
/// One slot per address family bounds memory regardless of trigger
/// volume. Each slot carries the RIB handle so the worker can snapshot at
/// build time, and the changed prefix (if any) for targeted revalidation.
#[derive(Default)]
struct Pending {
    v4: Option<(Arc<Mutex<Rib4>>, Option<Ipv4Net>)>,
    v6: Option<(Arc<Mutex<Rib6>>, Option<Ipv6Net>)>,
}

impl Pending {
    /// Fold an IPv4 request into the pending slot.
    ///
    /// Requests with distinct changed prefixes coalesce into a full sweep
    /// (`None`), since a single targeted revalidation can no longer cover
    /// them.
    fn merge_v4(&mut self, rib: Arc<Mutex<Rib4>>, prefix: Option<Ipv4Net>) {
        let prefix = match self.v4.take() {
            Some((_, existing)) if existing != prefix => None,
            _ => prefix,
        };
        self.v4 = Some((rib, prefix));
    }

    /// Fold an IPv6 request into the pending slot.
    ///
    /// Requests with distinct changed prefixes coalesce into a full sweep
    /// (`None`), since a single targeted revalidation can no longer cover
    /// them.
    fn merge_v6(&mut self, rib: Arc<Mutex<Rib6>>, prefix: Option<Ipv6Net>) {
        let prefix = match self.v6.take() {
            Some((_, existing)) if existing != prefix => None,
            _ => prefix,
        };
        self.v6 = Some((rib, prefix));
    }

    fn is_empty(&self) -> bool {
        self.v4.is_none() && self.v6.is_none()
    }
}

/// Lock the shared pending slot, healing a poisoned lock.
///
/// [`Pending`] carries no invariants across its fields, so recovering the
/// data from a poisoned lock is safe. This must not panic: it runs on
/// trigger paths.
fn lock_pending(pending: &Mutex<Pending>) -> MutexGuard<'_, Pending> {
    match pending.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Store a cache value, healing a poisoned lock if needed.
///
/// The cache is replaced wholesale, so poisoning cannot expose a broken
/// invariant. This must not panic: it also runs on trigger fallback paths.
fn store_cache(
    cache: &RwLock<Option<Poptrie<RpfNexthops>>>,
    value: Option<Poptrie<RpfNexthops>>,
) {
    match cache.write() {
        Ok(mut guard) => *guard = value,
        Err(poisoned) => {
            cache.clear_poison();
            *poisoned.into_inner() = value;
        }
    }
}

/// The long-lived worker that owns all poptrie rebuilds.
///
/// A single worker serves both address families, serializing rebuilds and
/// spreading CPU load when both families change at once. The worker exits
/// when every [`RpfTable`] clone (and thus the send side of its wakeup
/// channel) has been dropped.
struct RebuildWorker {
    cache_v4: Arc<RwLock<Option<Poptrie<RpfNexthops>>>>,
    cache_v6: Arc<RwLock<Option<Poptrie<RpfNexthops>>>>,
    pending: Arc<Mutex<Pending>>,
    notifier: Arc<Mutex<Option<mpsc::Sender<RebuildEvent>>>>,
    generation: Arc<GenerationCounter>,
}

impl RebuildWorker {
    /// Fixed window for coalescing RPF rebuild requests.
    ///
    /// Before taking pending work, the worker waits one fixed window.
    /// Requests arriving during that window merge into the pending rebuild
    /// without restarting the wait, so bursty route changes pack into one
    /// rebuild while sustained triggers cannot postpone rebuilding
    /// indefinitely.
    const COALESCE_WINDOW: Duration = Duration::from_millis(10);

    fn run(self, rx: mpsc::Receiver<()>) {
        // A recv error means every sender (each `RpfTable` clone) is gone.
        while rx.recv().is_ok() {
            loop {
                thread::sleep(Self::COALESCE_WINDOW);
                // Extra wakeups drained here (or observed as an immediate
                // outer recv) only cost a noop pass.
                while rx.try_recv().is_ok() {}
                let work = std::mem::take(&mut *lock_pending(&self.pending));
                if work.is_empty() {
                    break;
                }

                if let Some((rib, prefix)) = work.v4 {
                    self.rebuild_v4(&rib, prefix);
                }
                if let Some((rib, prefix)) = work.v6 {
                    self.rebuild_v6(&rib, prefix);
                }
            }
        }
    }

    /// Rebuild the IPv4 cache once.
    fn rebuild_v4(
        &self,
        rib: &Arc<Mutex<Rib4>>,
        changed_prefix: Option<Ipv4Net>,
    ) {
        let snapshot = {
            let r = lock!(rib);
            RpfTable::snapshot_rib(&r, |p| (p.addr().octets(), p.width()))
        };
        // Build the poptrie outside the RIB lock.
        let mut table = poptrie::Ipv4RoutingTable::default();
        for (addr, len, nexthops) in snapshot {
            table.insert((addr, len), nexthops);
        }
        store_cache(&self.cache_v4, Some(Poptrie::from(table)));
        // Advance before notifying so any revalidator pass triggered by
        // this swap is observable through the generation check.
        self.generation.advance();
        self.notify(RebuildEvent::V4(changed_prefix));
    }

    /// Rebuild the IPv6 cache once.
    fn rebuild_v6(
        &self,
        rib: &Arc<Mutex<Rib6>>,
        changed_prefix: Option<Ipv6Net>,
    ) {
        let snapshot = {
            let r = lock!(rib);
            RpfTable::snapshot_rib(&r, |p| (p.addr().octets(), p.width()))
        };
        // Build the poptrie outside the RIB lock.
        let mut table = poptrie::Ipv6RoutingTable::default();
        for (addr, len, nexthops) in snapshot {
            table.insert((addr, len), nexthops);
        }
        store_cache(&self.cache_v6, Some(Poptrie::from(table)));
        // Advance before notifying so any revalidator pass triggered by
        // this swap is observable through the generation check.
        self.generation.advance();
        self.notify(RebuildEvent::V6(changed_prefix));
    }

    /// Send a rebuild event notification if a revalidator is installed.
    fn notify(&self, event: RebuildEvent) {
        if let Ok(guard) = self.notifier.lock()
            && let Some(tx) = &*guard
        {
            let _ = tx.send(event);
        }
    }
}

/// RPF verification table using poptrie for O(1) LPM (longest-prefix matching).
///
/// This table maintains a poptrie-based cache of the RIB for fast RPF
/// lookups, rebuilt asynchronously by a dedicated worker thread (see the
/// module docs). Lookups fall back to a linear scan of the live RIB while
/// the cache is absent.
///
/// The poptrie stores [`RpfNexthops`] derived at build time via the same
/// selection logic as the linear-scan fallback, so RPF verification
/// behavior is consistent across both paths.
#[derive(Clone)]
pub(crate) struct RpfTable {
    /// IPv4 poptrie cache.
    cache_v4: Arc<RwLock<Option<Poptrie<RpfNexthops>>>>,
    /// IPv6 poptrie cache.
    cache_v6: Arc<RwLock<Option<Poptrie<RpfNexthops>>>>,
    /// Pending rebuild work shared with the worker.
    pending: Arc<Mutex<Pending>>,
    /// Send side of the worker's wakeup channel.
    wake_tx: mpsc::SyncSender<()>,
    /// Optional notifier for rebuild-complete events.
    rebuild_notifier: Arc<Mutex<Option<mpsc::Sender<RebuildEvent>>>>,
    /// Cache generation, advanced on every swap that changes lookup results.
    generation: Arc<GenerationCounter>,
    /// Logger for error reporting.
    log: Logger,
}

impl RpfTable {
    /// Create a new empty RPF table and spawn its rebuild worker.
    pub fn new(log: Logger) -> Self {
        let cache_v4 = Arc::new(RwLock::new(None));
        let cache_v6 = Arc::new(RwLock::new(None));
        let pending = Arc::new(Mutex::new(Pending::default()));
        let rebuild_notifier = Arc::new(Mutex::new(None));
        let generation = Arc::new(GenerationCounter::default());

        let (wake_tx, rx) = mpsc::sync_channel(1);
        let worker = RebuildWorker {
            cache_v4: Arc::clone(&cache_v4),
            cache_v6: Arc::clone(&cache_v6),
            pending: Arc::clone(&pending),
            notifier: Arc::clone(&rebuild_notifier),
            generation: Arc::clone(&generation),
        };
        // If the spawn fails, the receiver is dropped and triggers fall
        // back to clearing the cache, so lookups linear-scan the live RIB.
        if let Err(e) = thread::Builder::new()
            .name("rpf-rebuild".to_string())
            .spawn(move || worker.run(rx))
        {
            error!(log, "failed to spawn rpf-rebuild worker: {e}");
        }

        Self {
            cache_v4,
            cache_v6,
            pending,
            wake_tx,
            rebuild_notifier,
            generation,
            log,
        }
    }

    /// Current cache generation for optimistic concurrency over derivations.
    pub(crate) fn generation(&self) -> Generation {
        self.generation.current()
    }

    /// Request a targeted revalidation pass for routes sourced at `source`.
    ///
    /// Used when an optimistic derivation exhausts its inline retry budget
    /// under sustained cache churn. The revalidator re-derives from the
    /// then-current cache, correcting any stale result the caller may have
    /// applied.
    ///
    /// This returns whether the request reached a running revalidator. On
    /// `false`, no corrective pass is coming and the caller must converge on
    /// its own.
    pub(crate) fn request_revalidation(&self, source: IpAddr) -> bool {
        let event = match source {
            IpAddr::V4(addr) => {
                RebuildEvent::V4(Some(Ipv4Net::new_unchecked(addr, 32)))
            }
            IpAddr::V6(addr) => {
                RebuildEvent::V6(Some(Ipv6Net::new_unchecked(addr, 128)))
            }
        };
        self.notify(event)
    }

    /// Wake the rebuild worker through its bounded channel.
    ///
    /// Returns `false` if the worker is unavailable because it failed to
    /// spawn or exited, in which case the caller must handle the fallback.
    fn wake_worker(&self) -> bool {
        match self.wake_tx.try_send(()) {
            Ok(()) | Err(mpsc::TrySendError::Full(())) => true,
            Err(mpsc::TrySendError::Disconnected(())) => false,
        }
    }

    /// Send a rebuild event notification if configured.
    ///
    /// Returns whether the event reached a revalidator.
    fn notify(&self, event: RebuildEvent) -> bool {
        if let Ok(guard) = self.rebuild_notifier.lock()
            && let Some(tx) = &*guard
        {
            if tx.send(event).is_ok() {
                return true;
            }
            debug!(self.log, "rpf revalidator not running");
        }
        false
    }

    /// Snapshot a RIB for poptrie rebuild.
    ///
    /// Extracts (addr_bits, prefix_len, [`RpfNexthops`]) tuples from the
    /// RIB, deriving the compact nexthop payload in the same pass so full
    /// path sets are never cloned. The `to_bits` closure converts the
    /// prefix to address bits.
    fn snapshot_rib<P, A, F>(
        rib: &BTreeMap<P, BTreeSet<Path>>,
        to_bits: F,
    ) -> Vec<(A, u8, RpfNexthops)>
    where
        F: Fn(&P) -> (A, u8),
    {
        rib.iter()
            .filter(|(_, paths)| !paths.is_empty())
            .map(|(prefix, paths)| {
                let (bits, len) = to_bits(prefix);
                (bits, len, RpfNexthops::from_paths(paths))
            })
            .collect()
    }

    /// Install a notifier to be called on rebuild completion.
    pub fn set_rebuild_notifier(&self, tx: mpsc::Sender<RebuildEvent>) {
        if let Ok(mut guard) = self.rebuild_notifier.lock() {
            *guard = Some(tx);
        }
    }

    /// Trigger a background rebuild of the IPv4 RPF cache.
    ///
    /// Pending work is merged before the worker is woken. A request arriving
    /// during a build remains pending for the worker's next pass.
    ///
    /// The `changed_prefix` ([`Ipv4Net`]) parameter enables targeted
    /// revalidation: only (S,G) routes whose source falls within this prefix
    /// need RPF re-checking.
    pub fn trigger_rebuild_v4(
        &self,
        rib4_loc: Arc<Mutex<Rib4>>,
        changed_prefix: Option<Ipv4Net>,
    ) {
        lock_pending(&self.pending).merge_v4(rib4_loc, changed_prefix);
        if !self.wake_worker() {
            // The worker is unavailable.
            // Clear the cache so lookups fall back to a linear scan of
            // the live RIB, and notify the revalidator directly.
            debug!(self.log, "rpf rebuild worker not running");
            store_cache(&self.cache_v4, None);
            self.generation.advance();
            self.notify(RebuildEvent::V4(changed_prefix));
        }
    }

    /// Trigger a background rebuild of the IPv6 RPF cache.
    ///
    /// Pending work is merged before the worker is woken. A request arriving
    /// during a build remains pending for the worker's next pass.
    ///
    /// The `changed_prefix` ([`Ipv6Net`]) parameter enables targeted
    /// revalidation: only (S,G) routes whose source falls within this prefix
    /// need RPF re-checking.
    pub fn trigger_rebuild_v6(
        &self,
        rib6_loc: Arc<Mutex<Rib6>>,
        changed_prefix: Option<Ipv6Net>,
    ) {
        lock_pending(&self.pending).merge_v6(rib6_loc, changed_prefix);
        if !self.wake_worker() {
            // The worker is unavailable.
            // Clear the cache so lookups fall back to a linear scan of
            // the live RIB, and notify the revalidator directly.
            debug!(self.log, "rpf rebuild worker not running");
            store_cache(&self.cache_v6, None);
            self.generation.advance();
            self.notify(RebuildEvent::V6(changed_prefix));
        }
    }

    /// Look up the RPF neighbor for a multicast source address.
    ///
    /// Returns the best nexthop from the unicast RIB for reaching the source,
    /// which is the valid RPF neighbor for (S,G) routes. Returns `None` if
    /// no route with an active path exists for the source.
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
        let cached = match source {
            IpAddr::V4(addr) => self.cache_v4.read().ok().and_then(|cache| {
                cache.as_ref().and_then(|pt| pt.match_v4(u32::from(addr)))
            }),
            IpAddr::V6(addr) => self.cache_v6.read().ok().and_then(|cache| {
                cache.as_ref().and_then(|pt| pt.match_v6(u128::from(addr)))
            }),
        };

        if let Some(nexthops) = cached {
            return nexthops.for_fanout(fanout);
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

        // Find best matching prefix (longest-prefix match). The first match
        // is accepted regardless of width so a default route (/0) can serve
        // as the RPF match of last resort.
        let mut best_paths: Option<&BTreeSet<Path>> = None;
        let mut best_len = 0u8;

        for (prefix, paths) in rib.iter() {
            if prefix.contains(source)
                && (best_paths.is_none() || prefix.width() > best_len)
            {
                best_len = prefix.width();
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

        // Find best matching prefix (longest-prefix match). The first match
        // is accepted regardless of width so a default route (/0) can serve
        // as the RPF match of last resort.
        let mut best_paths: Option<&BTreeSet<Path>> = None;
        let mut best_len = 0u8;

        for (prefix, paths) in rib.iter() {
            if prefix.contains(source)
                && (best_paths.is_none() || prefix.width() > best_len)
            {
                best_len = prefix.width();
                best_paths = Some(paths);
            }
        }

        best_paths.and_then(|paths| Self::get_rpf_neighbor(paths, fanout))
    }

    /// Extract the RPF neighbor from a set of paths.
    ///
    /// For fanout == 1, returns the single bestpath nexthop.
    /// For fanout > 1, returns one representative active nexthop. RPF records
    /// a single upstream neighbor rather than the full ECMP set. The loc-RIB
    /// paths are already bestpath-selected as equal-cost, so any active
    /// member is valid.
    ///
    /// Returns `None` when no active path exists. This deviates from
    /// [`bestpaths`], which selects among shutdown paths when no active
    /// path exists: a shutdown path is never a valid RPF neighbor.
    fn get_rpf_neighbor(
        paths: &BTreeSet<Path>,
        fanout: usize,
    ) -> Option<IpAddr> {
        let first_active = paths.iter().find(|p| !p.shutdown)?;

        if fanout == 1 {
            // With an active path present, bestpaths selects among active
            // paths only, so passing the full set matches selection over
            // the active subset without cloning it.
            bestpaths(paths, 1)
                .and_then(|selected| selected.iter().next().map(|p| p.nexthop))
        } else {
            Some(first_active.nexthop)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use mg_common::log::*;
    use mg_common::test::DEFAULT_INTERVAL;
    use mg_common::wait_for;

    use crate::test::TEST_WAIT_ITERATIONS;
    use mg_api_types::rdb::{
        DEFAULT_RIB_PRIORITY_BGP, DEFAULT_RIB_PRIORITY_STATIC,
    };

    /// Helper to create empty Rib4 for tests
    fn empty_rib4() -> Arc<Mutex<Rib4>> {
        Arc::new(Mutex::new(BTreeMap::new()))
    }

    /// Helper to create empty Rib6 for tests
    fn empty_rib6() -> Arc<Mutex<Rib6>> {
        Arc::new(Mutex::new(BTreeMap::new()))
    }

    #[test]
    fn pending_widens_distinct_prefixes() {
        let rib4 = empty_rib4();
        let first: Ipv4Net = "192.0.2.0/24".parse().unwrap();
        let second: Ipv4Net = "198.51.100.0/24".parse().unwrap();
        let mut pending = Pending::default();

        pending.merge_v4(Arc::clone(&rib4), Some(first));
        pending.merge_v4(Arc::clone(&rib4), Some(first));
        assert_eq!(pending.v4.as_ref().unwrap().1, Some(first));

        pending.merge_v4(Arc::clone(&rib4), Some(second));
        assert_eq!(pending.v4.as_ref().unwrap().1, None);

        // A full sweep remains sticky when later targeted work arrives.
        pending.merge_v4(rib4, Some(first));
        assert_eq!(pending.v4.as_ref().unwrap().1, None);
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
            nexthop_interface: None,
        };
        let path2 = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
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
        let prefix: Ipv4Net = "192.0.2.0/24".parse().unwrap();

        let mut paths = BTreeSet::new();
        let path = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
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
    fn test_rpf_default_route_linear_scan() {
        // A source reachable only through a default route must still resolve
        // an RPF neighbor. The /0 match is the match of last resort. This
        // pins the linear-scan fallback only, which runs whenever the poptrie
        // cache is absent (e.g., at startup before the first rebuild
        // completes).
        let mut rib4_inner: Rib4 = BTreeMap::new();
        let prefix: Ipv4Net = "0.0.0.0/0".parse().unwrap();
        let mut paths = BTreeSet::new();
        paths.insert(Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
        });
        rib4_inner.insert(prefix, paths);

        let mut rib6_inner: Rib6 = BTreeMap::new();
        let prefix6: Ipv6Net = "::/0".parse().unwrap();
        let mut paths6 = BTreeSet::new();
        paths6.insert(Path {
            nexthop: IpAddr::V6("fd00::1".parse().unwrap()),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
        });
        rib6_inner.insert(prefix6, paths6);

        let rib4_loc = Arc::new(Mutex::new(rib4_inner));
        let rib6_loc = Arc::new(Mutex::new(rib6_inner));
        let log = init_file_logger("rpf_default_route.log");
        let rpf_table = RpfTable::new(log);

        let source = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let expected = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(
            rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1),
            Some(expected)
        );

        let source6 = IpAddr::V6("2001:db8::7".parse().unwrap());
        let expected6 = IpAddr::V6("fd00::1".parse().unwrap());
        assert_eq!(
            rpf_table.lookup(source6, &rib4_loc, &rib6_loc, 1),
            Some(expected6)
        );
    }

    #[test]
    fn test_rpf_table_with_poptrie() {
        let mut rib4_inner: Rib4 = BTreeMap::new();
        let prefix: Ipv4Net = "192.0.2.0/24".parse().unwrap();

        let mut paths = BTreeSet::new();
        let path = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
        };
        paths.insert(path);
        rib4_inner.insert(prefix, paths.clone());

        let rib4_loc = Arc::new(Mutex::new(rib4_inner));
        let rib6_loc = empty_rib6();

        let log = init_file_logger("rpf_poptrie.log");
        let rpf_table = RpfTable::new(log);
        rpf_table.trigger_rebuild_v4(Arc::clone(&rib4_loc), None);

        // Wait for rebuild to complete
        wait_for!(
            rpf_table.cache_v4.read().unwrap().is_some(),
            DEFAULT_INTERVAL,
            TEST_WAIT_ITERATIONS,
            "poptrie v4 rebuild timed out"
        );

        // Should now use poptrie cache
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
        let expected = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(
            rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1),
            Some(expected)
        );
    }

    /// Every cache swap advances the generation. `Db::update_mrib_loc`'s
    /// post-apply generation check relies on this to detect a racing
    /// revalidator pass.
    #[test]
    fn generation_advances_on_each_rebuild() {
        let prefix: Ipv4Net = "192.0.2.0/24".parse().unwrap();
        let path = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
        };
        let rib4_loc = Arc::new(Mutex::new(BTreeMap::from([(
            prefix,
            BTreeSet::from([path]),
        )])));

        let log = init_file_logger("rpf_generation.log");
        let rpf_table = RpfTable::new(log);
        let (tx, rx) = mpsc::channel();
        rpf_table.set_rebuild_notifier(tx);

        let before = rpf_table.generation();
        rpf_table.trigger_rebuild_v4(Arc::clone(&rib4_loc), Some(prefix));
        rx.recv_timeout(Duration::from_secs(10))
            .expect("rebuild notification");
        let after = rpf_table.generation();
        assert_ne!(after, before, "cache swap must advance the generation");

        rpf_table.trigger_rebuild_v4(Arc::clone(&rib4_loc), None);
        rx.recv_timeout(Duration::from_secs(10))
            .expect("second rebuild notification");
        assert_ne!(
            rpf_table.generation(),
            after,
            "each swap advances the generation"
        );
    }

    #[test]
    fn rapid_rebuilds_converge() {
        let prefix: Ipv4Net = "192.0.2.0/24".parse().unwrap();
        let path = |last| Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, last)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
        };
        let rib4_loc = Arc::new(Mutex::new(BTreeMap::from([(
            prefix,
            BTreeSet::from([path(1)]),
        )])));
        let source = Ipv4Addr::new(192, 0, 2, 50);
        let log = init_file_logger("rpf_rapid_rebuilds.log");
        let rpf_table = RpfTable::new(log);

        rpf_table.trigger_rebuild_v4(Arc::clone(&rib4_loc), Some(prefix));
        wait_for!(
            rpf_table
                .cache_v4
                .read()
                .unwrap()
                .as_ref()
                .and_then(|cache| cache.match_v4(u32::from(source)))
                .and_then(|nexthops| nexthops.for_fanout(1))
                == Some(path(1).nexthop),
            DEFAULT_INTERVAL,
            TEST_WAIT_ITERATIONS,
            "initial poptrie rebuild timed out"
        );

        for last in 2..=5 {
            rib4_loc
                .lock()
                .unwrap()
                .insert(prefix, BTreeSet::from([path(last)]));
            rpf_table.trigger_rebuild_v4(Arc::clone(&rib4_loc), Some(prefix));
        }

        wait_for!(
            rpf_table
                .cache_v4
                .read()
                .unwrap()
                .as_ref()
                .and_then(|cache| cache.match_v4(u32::from(source)))
                .and_then(|nexthops| nexthops.for_fanout(1))
                == Some(path(5).nexthop),
            DEFAULT_INTERVAL,
            TEST_WAIT_ITERATIONS,
            "poptrie did not converge to the latest RIB snapshot"
        );
    }

    #[test]
    fn test_rpf_table_shutdown_paths() {
        // Test that shutdown paths are filtered out
        let mut rib4_inner: Rib4 = BTreeMap::new();
        let prefix: Ipv4Net = "192.0.2.0/24".parse().unwrap();

        let mut paths = BTreeSet::new();
        // Active path
        let active_path = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            rib_priority: 10,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
        };
        // Shutdown path
        let shutdown_path = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            rib_priority: 20,
            shutdown: true,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
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
        wait_for!(
            rpf_table.cache_v4.read().unwrap().is_some(),
            DEFAULT_INTERVAL,
            TEST_WAIT_ITERATIONS,
            "poptrie v4 rebuild timed out"
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
        let prefix: Ipv4Net = "192.0.2.0/24".parse().unwrap();

        let mut paths = BTreeSet::new();
        let shutdown_path = Path {
            nexthop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            rib_priority: 1,
            shutdown: true,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
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
        wait_for!(
            rpf_table.cache_v4.read().unwrap().is_some(),
            DEFAULT_INTERVAL,
            TEST_WAIT_ITERATIONS,
            "poptrie v4 rebuild timed out"
        );

        // Poptrie finds the route but all paths shutdown, still `None`
        assert_eq!(rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1), None);
    }

    #[test]
    fn test_rpf_ecmp_different_priorities() {
        // Test that bestpath selection prefers lower rib_priority

        let mut rib4_inner: Rib4 = BTreeMap::new();
        let prefix: Ipv4Net = "192.0.2.0/24".parse().unwrap();

        // Static route (priority 1)
        let static_nexthop = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let static_path = Path {
            nexthop: static_nexthop,
            rib_priority: DEFAULT_RIB_PRIORITY_STATIC,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
        };

        // BGP route (priority 20)
        let bgp_nexthop = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let bgp_path = Path {
            nexthop: bgp_nexthop,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
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
        wait_for!(
            rpf_table.cache_v4.read().unwrap().is_some(),
            DEFAULT_INTERVAL,
            TEST_WAIT_ITERATIONS,
            "poptrie v4 rebuild timed out"
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
        let prefix: Ipv6Net = "2001:db8::/32".parse().unwrap();

        let mut paths = BTreeSet::new();
        let path = Path {
            nexthop: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
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
        let prefix: Ipv6Net = "2001:db8::/32".parse().unwrap();

        let mut paths = BTreeSet::new();
        let path = Path {
            nexthop: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
        };
        paths.insert(path);
        rib6_inner.insert(prefix, paths.clone());

        let rib4_loc = empty_rib4();
        let rib6_loc = Arc::new(Mutex::new(rib6_inner));

        let log = init_file_logger("rpf_poptrie_v6.log");
        let rpf_table = RpfTable::new(log);
        rpf_table.trigger_rebuild_v6(Arc::clone(&rib6_loc), None);

        // Wait for rebuild to complete
        wait_for!(
            rpf_table.cache_v6.read().unwrap().is_some(),
            DEFAULT_INTERVAL,
            TEST_WAIT_ITERATIONS,
            "poptrie v6 rebuild timed out"
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
        let prefix_24: Ipv4Net = "192.0.2.0/24".parse().unwrap();
        let nexthop1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let mut paths1 = BTreeSet::new();
        paths1.insert(Path {
            nexthop: nexthop1,
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
        });
        rib4_inner.insert(prefix_24, paths1);

        // More specific: 192.0.2.128/25 -> nexthop2
        let prefix_25: Ipv4Net = "192.0.2.128/25".parse().unwrap();
        let nexthop2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let mut paths2 = BTreeSet::new();
        paths2.insert(Path {
            nexthop: nexthop2,
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
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
        wait_for!(
            rpf_table.cache_v4.read().unwrap().is_some(),
            DEFAULT_INTERVAL,
            TEST_WAIT_ITERATIONS,
            "poptrie v4 rebuild timed out"
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
        let prefix: Ipv6Net = "2001:db8::/32".parse().unwrap();

        let nexthop1 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let nexthop2 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));

        let path1 = Path {
            nexthop: nexthop1,
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
        };
        let path2 = Path {
            nexthop: nexthop2,
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
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

    #[test]
    fn test_rpf_v6_with_nexthop_interface() {
        // RPF with link-local nexthops and interface binding
        // (BGP unnumbered underlay for multicast).
        //
        // This verifies both linear scan and poptrie paths return the correct
        // nexthop.
        let mut rib6_inner: Rib6 = BTreeMap::new();
        let prefix: Ipv6Net = "2001:db8:1::/48".parse().unwrap();

        let nexthop = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let path = Path {
            nexthop,
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: Some("qsfp0".to_string()),
        };

        let mut paths = BTreeSet::new();
        paths.insert(path);
        rib6_inner.insert(prefix, paths);

        let log = init_file_logger("rpf_v6_interface.log");
        let rpf_table = RpfTable::new(log);
        let rib4_loc = empty_rib4();
        let rib6_loc = Arc::new(Mutex::new(rib6_inner));

        let source =
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 100));

        // Linear scan
        assert_eq!(
            rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1),
            Some(nexthop),
        );

        // Poptrie
        rpf_table.trigger_rebuild_v6(Arc::clone(&rib6_loc), None);
        wait_for!(
            rpf_table.cache_v6.read().unwrap().is_some(),
            DEFAULT_INTERVAL,
            TEST_WAIT_ITERATIONS,
            "poptrie v6 rebuild timed out"
        );

        assert_eq!(
            rpf_table.lookup(source, &rib4_loc, &rib6_loc, 1),
            Some(nexthop),
        );
    }

    #[test]
    fn test_rpf_v6_lpm() {
        const NEXTHOP1: IpAddr =
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xff, 0, 0, 0, 0, 1));
        const NEXTHOP2: IpAddr =
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xff, 0, 0, 0, 0, 2));

        let mut rib6_inner: Rib6 = BTreeMap::new();

        // Less specific: 2001:db8::/32 -> NEXTHOP1
        let prefix_32: Ipv6Net = "2001:db8::/32".parse().unwrap();
        let mut paths1 = BTreeSet::new();
        paths1.insert(Path {
            nexthop: NEXTHOP1,
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
        });
        rib6_inner.insert(prefix_32, paths1);

        // More specific: 2001:db8:1::/48 -> NEXTHOP2
        let prefix_48: Ipv6Net = "2001:db8:1::/48".parse().unwrap();
        let mut paths2 = BTreeSet::new();
        paths2.insert(Path {
            nexthop: NEXTHOP2,
            rib_priority: 1,
            shutdown: false,
            bgp: None,
            vlan_id: None,
            nexthop_interface: None,
        });
        rib6_inner.insert(prefix_48, paths2);

        let log = init_file_logger("rpf_v6_lpm.log");
        let rpf_table = RpfTable::new(log);
        let rib4_loc = empty_rib4();
        let rib6_loc = Arc::new(Mutex::new(rib6_inner));

        // Source in /48 should match more specific route
        let source_in_48 =
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 50));
        assert_eq!(
            rpf_table.lookup(source_in_48, &rib4_loc, &rib6_loc, 1),
            Some(NEXTHOP2)
        );

        // Source in /32 but not /48 should match less specific route
        let source_in_32 =
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 50));
        assert_eq!(
            rpf_table.lookup(source_in_32, &rib4_loc, &rib6_loc, 1),
            Some(NEXTHOP1)
        );
    }
}
