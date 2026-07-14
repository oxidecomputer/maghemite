// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::NewUnnumberedInterfaceError;
use crate::bgp::{BgpUnnumbered, BgpUnnumberedInterface};
use crate::error::UnnumberedError;
use crate::interface::{InterfaceMap, UnnumberedInterface};
use mg_common::lock;
use mg_common::thread::ManagedThread;
use ndp::Ipv6NetworkInterface;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use slog::{Logger, crit, info, o, warn};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    num::NonZeroU32,
    sync::{
        Arc, Mutex,
        mpsc::{
            Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel,
        },
    },
    thread,
    time::{Duration, Instant},
};

pub const MOD_UNNUMBERED_MANAGER: &str = "unnumbered manager";

/// How often to poll for interface availability changes.
const INTERFACE_POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum AddNeighborError {
    #[error("system interface error: {0}")]
    Interface(#[from] network_interface::Error),

    #[error("unnumbered interface error: {0}")]
    UnnumberedInterface(#[from] NewUnnumberedInterfaceError),
}

pub struct UnnumberedManager {
    log: Logger,
    /// Interfaces currently active for unnumbered operation.
    active_interfaces: Arc<Mutex<InterfaceMap>>,

    /// Interfaces configured for unnumbered operation.
    ///
    /// This records admin configuration across interface runtime flaps.
    /// Pending interfaces are derived from configured interfaces that do not
    /// currently have active router-discovery runtime.
    configured_interfaces: Arc<Mutex<HashMap<String, u16>>>,

    /// Wakes the monitor thread when configuration changes. Buffer size 1:
    /// if a wake token is already pending the monitor has yet to run and
    /// will observe this change too, so a full buffer needs no new token.
    ///
    /// None means no monitor thread exists by construction (tests), where
    /// reconciliation is driven manually. The manager's Drop impl takes the
    /// sender to disconnect the channel, ending the monitor loop before
    /// ManagedThread's drop joins the thread.
    monitor_tx: Option<SyncSender<()>>,

    /// Managed thread for interface monitoring.
    /// Stored to ensure automatic cleanup on drop - the ManagedThread's Drop
    /// impl will join the thread.
    monitor_thread: Arc<ManagedThread>,
}

impl UnnumberedManager {
    pub fn new(log: Logger) -> Arc<Self> {
        let log = log.new(o!(
            "module" => MOD_UNNUMBERED_MANAGER,
        ));

        let monitor_thread = Arc::new(ManagedThread::new());
        let active_interfaces = Arc::new(Mutex::new(InterfaceMap::new()));
        let configured_interfaces = Arc::new(Mutex::new(HashMap::new()));
        let (monitor_tx, monitor_rx) = sync_channel(1);

        let manager = Arc::new(Self {
            log: log.clone(),
            active_interfaces: Arc::clone(&active_interfaces),
            configured_interfaces: Arc::clone(&configured_interfaces),
            monitor_tx: Some(monitor_tx),
            monitor_thread: Arc::clone(&monitor_thread),
        });

        // Spawn and register the interface monitor thread. Dropping the
        // manager disconnects the wake channel, which ends the monitor
        // loop; the ManagedThread then joins the thread.
        let handle = thread::Builder::new()
            .name("unnumbered-interface-monitor".to_string())
            .spawn(move || {
                Self::run_interface_monitor(
                    log,
                    active_interfaces,
                    configured_interfaces,
                    monitor_rx,
                );
            })
            .expect("failed to spawn interface monitor thread");
        monitor_thread.start(handle);

        manager
    }

    #[cfg(test)]
    fn new_test() -> Arc<Self> {
        Arc::new(Self {
            log: Logger::root(slog::Discard, o!()),
            active_interfaces: Arc::new(Mutex::new(InterfaceMap::new())),
            configured_interfaces: Arc::new(Mutex::new(HashMap::new())),
            // No monitor thread; tests drive reconciliation manually.
            monitor_tx: None,
            monitor_thread: Arc::new(ManagedThread::new()),
        })
    }

    /// Main loop for the interface monitor thread.
    ///
    /// This thread periodically checks for interface availability changes:
    /// - Pending interfaces that have become available (need NDP activation)
    /// - Active interfaces that have been removed (need NDP deactivation)
    ///
    /// Uses batched interface checking: a single call to `NetworkInterface::show()`
    /// per poll cycle, regardless of how many interfaces are being monitored.
    ///
    /// Exits when `monitor_rx` disconnects, which happens when the manager
    /// (holding the sender) is dropped.
    fn run_interface_monitor(
        log: Logger,
        active_interfaces: Arc<Mutex<InterfaceMap>>,
        configured_interfaces: Arc<Mutex<HashMap<String, u16>>>,
        monitor_rx: Receiver<()>,
    ) {
        info!(log, "interface monitor started");

        loop {
            // Check if there's any work to do
            let has_configured = !lock!(configured_interfaces).is_empty();
            let has_active = !lock!(active_interfaces).is_empty();

            if has_configured || has_active {
                // Get all system interfaces once (single syscall)
                match Self::get_available_interfaces(&log) {
                    Ok(available) => {
                        Self::reconcile_interfaces(
                            &log,
                            &active_interfaces,
                            &configured_interfaces,
                            &available,
                        );
                    }
                    Err(e) => {
                        warn!(
                            log,
                            "failed to enumerate system interfaces";
                            "error" => %e,
                        );
                    }
                }
            }

            // Sleep until woken by a config change, the poll interval
            // elapsing, or the manager being dropped (disconnecting the
            // channel). A token sent while we were reconciling above is
            // buffered and returns immediately, so wakes cannot be lost.
            match monitor_rx.recv_timeout(INTERFACE_POLL_INTERVAL) {
                Ok(()) | Err(RecvTimeoutError::Timeout) => (),
                Err(RecvTimeoutError::Disconnected) => {
                    info!(log, "interface monitor shutting down");
                    break;
                }
            }
        }

        info!(log, "interface monitor exited");
    }

    /// Get the interfaces that are available for NDP.
    ///
    /// An interface is considered available if it exists on the system and
    /// has an IPv6 link-local address configured.
    fn get_available_interfaces(
        log: &Logger,
    ) -> Result<HashMap<String, Ipv6NetworkInterface>, network_interface::Error>
    {
        let interfaces = NetworkInterface::show()?;

        let mut available = HashMap::new();
        for iface in interfaces {
            let Some(addr) = iface.addr else {
                continue;
            };
            let IpAddr::V6(ip) = addr.ip() else {
                continue;
            };
            if !ip.is_unicast_link_local() {
                continue;
            }

            let ifx = Ipv6NetworkInterface {
                name: iface.name,
                ip,
                scope_id: match NonZeroU32::new(iface.index) {
                    Some(scope_id) => scope_id,
                    None => continue,
                },
            };
            if let Some(previous) =
                available.insert(ifx.name.clone(), ifx.clone())
            {
                warn!(
                    log,
                    "more than 1 link local address for interface";
                    "interface" => ifx.name.as_str(),
                    "using" => ifx.ip.to_string(),
                    "also found" => previous.ip.to_string(),
                );
            }
        }

        Ok(available)
    }

    fn reconcile_interfaces(
        log: &Logger,
        active_interfaces: &Mutex<InterfaceMap>,
        configured_interfaces: &Mutex<HashMap<String, u16>>,
        available: &HashMap<String, Ipv6NetworkInterface>,
    ) {
        Self::reconcile_interfaces_with_activator(
            log,
            active_interfaces,
            configured_interfaces,
            available,
            |ifx, router_lifetime| {
                Self::start_interface_runtime(log, ifx, router_lifetime)
            },
        );
    }

    fn reconcile_interfaces_with_activator<F, E>(
        log: &Logger,
        active_interfaces: &Mutex<InterfaceMap>,
        configured_interfaces: &Mutex<HashMap<String, u16>>,
        available: &HashMap<String, Ipv6NetworkInterface>,
        activate: F,
    ) where
        F: Fn(&Ipv6NetworkInterface, u16) -> Result<UnnumberedInterface, E>,
        E: std::fmt::Display,
    {
        let mut to_deactivate = Vec::new();

        {
            let configured = lock!(configured_interfaces);
            let active = lock!(active_interfaces);

            for active_ifx in active.iter() {
                let interface_name = active_ifx.name();
                let Some(router_lifetime) = configured.get(interface_name)
                else {
                    to_deactivate.push(interface_name.to_string());
                    continue;
                };

                let Some(ifx) = available.get(interface_name) else {
                    to_deactivate.push(interface_name.to_string());
                    continue;
                };

                if active_ifx.scope_id() != ifx.scope_id
                    || active_ifx.local_address() != ifx.ip
                {
                    to_deactivate.push(interface_name.to_string());
                } else if active_ifx.tx_router_lifetime() != *router_lifetime {
                    active_ifx.set_tx_router_lifetime(*router_lifetime);
                }
            }
        }

        for interface_name in to_deactivate {
            Self::remove_interface_runtime(
                log,
                active_interfaces,
                &interface_name,
            );
        }

        // Reconciliation runs from a single snapshot of configured interfaces.
        // Mutations made after this snapshot are picked up by the next pass
        // rather than re-checked around activation; this keeps the reconciler
        // eventually consistent and avoids holding manager locks while runtime
        // threads are started.
        let configured: Vec<_> = lock!(configured_interfaces)
            .iter()
            .map(|(interface_name, router_lifetime)| {
                (interface_name.clone(), *router_lifetime)
            })
            .collect();

        for (interface_name, router_lifetime) in configured {
            if let Some(ifx) = available.get(&interface_name) {
                if lock!(active_interfaces).contains_name(&interface_name) {
                    continue;
                }

                info!(
                    log,
                    "interface became available, activating NDP";
                    "interface" => ifx.name.as_str(),
                );

                match activate(ifx, router_lifetime) {
                    Ok(active) => {
                        // Bind any displaced interfaces so their drop (which
                        // joins router-discovery threads) happens after the
                        // lock is released. Displacement is believed
                        // unreachable here (names are pre-filtered and stale
                        // scope-id holders are deactivated earlier in this
                        // pass), but joining under the lock would stall
                        // connection dispatch if that ever changed.
                        let displaced =
                            lock!(active_interfaces).insert_overwrite(active);
                        drop(displaced);
                    }
                    Err(e) => {
                        warn!(
                            log,
                            "failed to activate interface";
                            "interface" => ifx.name.as_str(),
                            "error" => e.to_string(),
                        );
                    }
                }
            }
        }
    }

    fn start_interface_runtime(
        log: &Logger,
        ifx: &Ipv6NetworkInterface,
        router_lifetime: u16,
    ) -> Result<UnnumberedInterface, AddNeighborError> {
        UnnumberedInterface::new(ifx.clone(), router_lifetime, log.clone())
            .map_err(AddNeighborError::from)
    }

    /// Remove an interface runtime.
    ///
    /// This removes the interface from the active interface map.
    fn remove_interface_runtime(
        log: &Logger,
        active_interfaces: &Mutex<InterfaceMap>,
        interface_name: &str,
    ) {
        info!(
            log,
            "deactivating NDP runtime";
            "interface" => interface_name,
        );

        // Clean up active interface state. Dropping the interface also drops
        // its router-discovery thread handles.
        let _removed = lock!(active_interfaces).remove_by_name(interface_name);
    }

    /// Configure NDP peer discovery on an interface.
    ///
    /// Runtime setup is handled asynchronously by the monitor thread, which
    /// reconciles configured interfaces with currently available system
    /// interfaces.
    ///
    /// BGP session creation is handled separately by the caller.
    ///
    /// If the interface doesn't exist yet, this is not an error. The caller
    /// should still create the BGP session, which will wait for the interface
    /// to become available.
    pub fn configure_interface(
        self: &Arc<Self>,
        interface: impl AsRef<str>,
        router_lifetime: u16,
    ) -> Result<(), AddNeighborError> {
        let interface_str = interface.as_ref();

        lock!(self.configured_interfaces)
            .insert(interface_str.to_string(), router_lifetime);

        info!(
            self.log,
            "interface configured for NDP peer discovery";
            "interface" => interface_str,
        );

        // Wake the monitor thread since there's new or updated work. A full
        // buffer means a wake is already pending and this change will be
        // observed by it. A disconnected channel means the monitor thread
        // exited while the manager is still alive — the loop only exits on
        // sender disconnect, so this indicates the monitor panicked and the
        // configuration just recorded will never be reconciled. A None
        // sender means no monitor exists by construction (tests) and the
        // caller drives reconciliation itself.
        if let Some(tx) = &self.monitor_tx
            && let Err(TrySendError::Disconnected(())) = tx.try_send(())
        {
            crit!(
                self.log,
                "interface monitor thread is gone; \
                 unnumbered interface reconciliation is not running";
                "interface" => interface_str,
            );
        }

        Ok(())
    }

    /// Remove NDP peer discovery configuration for an interface.
    ///
    /// This drops any active runtime and removes configuration so the
    /// monitor will not reactivate the interface.
    ///
    /// BGP session deletion is handled separately by the caller.
    pub fn unconfigure_interface(
        self: &Arc<Self>,
        interface: impl AsRef<str>,
    ) -> Result<(), network_interface::Error> {
        let interface_str = interface.as_ref();

        // Remove configuration so the monitor will not reactivate it.
        lock!(self.configured_interfaces).remove(interface_str);

        // Remove from active if it was active. Dropping the interface also
        // drops its router-discovery thread handles, which joins threads
        // that sleep in multi-second intervals — bind the removed value so
        // the drop (and joins) happen after the lock is released, not as a
        // statement temporary while the guard is still held.
        let removed =
            lock!(self.active_interfaces).remove_by_name(interface_str);
        drop(removed);

        info!(
            self.log,
            "interface unregistered from NDP peer discovery";
            "interface" => interface_str,
        );

        Ok(())
    }

    /// Get the currently discovered neighbor for an interface.
    ///
    /// Returns the peer's link-local IPv6 address if a neighbor has been
    /// discovered via NDP, or None if no neighbor is present. The scope is
    /// owned by the interface state, not by the discovered neighbor.
    ///
    /// This is used by SessionRunner to actively query for peer addresses
    /// when attempting connections on unnumbered interfaces.
    ///
    /// # Arguments
    /// * `interface` - The interface name (e.g., "eth0")
    ///
    /// # Returns
    /// * `Ok(Some(Ipv6Addr))` - Neighbor discovered on this interface
    /// * `Ok(None)` - No neighbor discovered or interface not ready
    /// * `Err(network_interface::Error)` - Failed to enumerate interfaces
    pub fn get_neighbor_by_interface(
        &self,
        interface: impl AsRef<str>,
    ) -> Result<Option<Ipv6Addr>, network_interface::Error> {
        Ok(lock!(self.active_interfaces)
            .get_by_name(interface.as_ref())
            .and_then(|ifx| ifx.discovered_neighbor()))
    }

    /// Get the interface name for a given IPv6 scope_id.
    ///
    /// This is used by Dispatcher to route incoming link-local connections
    /// to the correct unnumbered session based on the scope_id in the peer
    /// address.
    ///
    /// # Arguments
    /// * `scope_id` - The IPv6 scope_id (interface index)
    ///
    /// # Returns
    /// * `Some(interface_name)` - Interface found for this scope_id
    /// * `None` - No interface registered with this scope_id
    pub fn get_interface_for_scope(&self, scope_id: u32) -> Option<String> {
        let scope_id = NonZeroU32::new(scope_id)?;
        lock!(self.active_interfaces)
            .get_by_scope_id(scope_id)
            .map(|ifx| ifx.name().to_string())
    }
}

impl Drop for UnnumberedManager {
    fn drop(&mut self) {
        // Disconnect the wake channel so the monitor loop exits before
        // `monitor_thread`'s field drop joins the thread. Drop bodies run
        // before automatic field drops, so this ordering is guaranteed
        // regardless of field declaration order.
        self.monitor_tx = None;
    }
}

// =========================================================================
// BgpUnnumbered Trait Implementation
// =========================================================================
// Provides the interface for Dispatcher to query interface mappings
impl BgpUnnumbered for UnnumberedManager {
    fn get_active_interface_by_scope(
        &self,
        scope_id: u32,
    ) -> Result<Option<BgpUnnumberedInterface>, UnnumberedError> {
        let Some(scope_id) = NonZeroU32::new(scope_id) else {
            return Ok(None);
        };

        Ok(lock!(self.active_interfaces)
            .get_by_scope_id(scope_id)
            .map(|ifx| BgpUnnumberedInterface {
                interface: ifx.name().to_string(),
                scope_id: ifx.scope_id().get(),
                discovered_neighbor: ifx.discovered_neighbor(),
            }))
    }

    fn get_active_interface(
        &self,
        interface: &str,
    ) -> Result<Option<BgpUnnumberedInterface>, UnnumberedError> {
        Ok(lock!(self.active_interfaces)
            .get_by_name(interface)
            .map(|ifx| BgpUnnumberedInterface {
                interface: ifx.name().to_string(),
                scope_id: ifx.scope_id().get(),
                discovered_neighbor: ifx.discovered_neighbor(),
            }))
    }
}

impl UnnumberedManager {
    /// Get the current state of unnumbered NDP interface tracking.
    ///
    /// Returns information about the monitor thread, pending interfaces,
    /// and active interfaces.
    pub fn get_manager_state(&self) -> UnnumberedManagerState {
        UnnumberedManagerState {
            monitor_running: self.monitor_thread.is_running(),
            pending_interfaces: self.get_pending_interfaces(),
            active_interfaces: lock!(self.active_interfaces)
                .iter()
                .map(|ifx| ifx.name().to_string())
                .collect(),
        }
    }

    /// Get all interfaces that are configured but not yet available on the system.
    pub fn get_pending_interfaces(&self) -> Vec<PendingInterfaceInfo> {
        let configured = lock!(self.configured_interfaces);
        let active = lock!(self.active_interfaces);
        configured
            .iter()
            .filter(|(name, _)| !active.contains_name(name))
            .map(|(name, router_lifetime)| PendingInterfaceInfo {
                interface: name.clone(),
                router_lifetime: *router_lifetime,
            })
            .collect()
    }

    /// List all active unnumbered interfaces with detailed NDP state.
    ///
    /// Returns a list of interfaces managed by this unnumbered manager,
    /// including full peer advertisement information with timestamps.
    pub fn list_interfaces(&self) -> Vec<UnnumberedInterfaceInfo> {
        lock!(self.active_interfaces)
            .iter()
            .map(|ifx| UnnumberedInterfaceInfo {
                interface: ifx.name().to_string(),
                local_address: ifx.local_address(),
                scope_id: ifx.scope_id().get(),
                router_lifetime: ifx.tx_router_lifetime(),
                peer_state: ifx
                    .discovered_neighbor_info()
                    .map(DiscoveredRouterState::from),
                runtime_state: ifx.get_runtime_state(),
            })
            .collect()
    }

    /// Get detailed NDP state for a specific interface.
    ///
    /// Returns detailed information about peer discovery including timestamps,
    /// RA parameters, and expiry status.
    ///
    /// Returns None if the interface is not active for unnumbered operation.
    pub fn get_interface_detail(
        &self,
        interface_name: &str,
    ) -> Result<Option<InterfaceDetail>, network_interface::Error> {
        Ok(lock!(self.active_interfaces)
            .get_by_name(interface_name)
            .map(|ifx| InterfaceDetail {
                local_address: ifx.local_address(),
                scope_id: ifx.scope_id().get(),
                router_lifetime: ifx.tx_router_lifetime(),
                peer_state: ifx
                    .discovered_neighbor_info()
                    .map(DiscoveredRouterState::from),
                runtime_state: ifx.get_runtime_state(),
            }))
    }
}

/// Information about an active unnumbered interface with NDP state.
#[derive(Debug, Clone)]
pub struct UnnumberedInterfaceInfo {
    pub interface: String,
    pub local_address: Ipv6Addr,
    pub scope_id: u32,
    pub router_lifetime: u16,
    pub peer_state: Option<DiscoveredRouterState>,
    pub runtime_state: ndp::RouterDiscoveryRuntimeState,
}

/// Detailed NDP state for a specific interface
#[derive(Debug, Clone)]
pub struct InterfaceDetail {
    pub local_address: Ipv6Addr,
    pub scope_id: u32,
    pub router_lifetime: u16,
    pub peer_state: Option<DiscoveredRouterState>,
    pub runtime_state: ndp::RouterDiscoveryRuntimeState,
}

/// Detailed discovered router state
#[derive(Debug, Clone)]
pub struct DiscoveredRouterState {
    pub address: Ipv6Addr,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub effective_reachable_time: Duration,
    pub retrans_timer: u32,
    pub expired: bool,
}

impl From<ndp::RouterAdvertisementInfo> for DiscoveredRouterState {
    fn from(info: ndp::RouterAdvertisementInfo) -> Self {
        let ndp::RouterAdvertisementInfo {
            address,
            first_seen,
            last_seen,
            router_lifetime,
            reachable_time,
            effective_reachable_time,
            retrans_timer,
            expired,
        } = info;
        Self {
            address,
            first_seen,
            last_seen,
            router_lifetime,
            reachable_time,
            effective_reachable_time,
            retrans_timer,
            expired,
        }
    }
}

impl From<&DiscoveredRouterState>
    for Option<mg_api_types::unnumbered::DiscoveredRouter>
{
    /// The API represents an expired discovery entry as an absent peer, so
    /// expired state converts to None.
    fn from(state: &DiscoveredRouterState) -> Self {
        let &DiscoveredRouterState {
            address,
            first_seen,
            last_seen,
            router_lifetime,
            reachable_time,
            effective_reachable_time,
            retrans_timer,
            expired,
        } = state;
        if expired {
            return None;
        }
        let now = Instant::now();
        Some(mg_api_types::unnumbered::DiscoveredRouter {
            address,
            time_since_discovered: now.duration_since(first_seen),
            time_since_last_rx: now.duration_since(last_seen),
            effective_reachable_time,
            router_lifetime,
            reachable_time,
            retrans_timer,
        })
    }
}

/// Information about a pending interface (configured but not yet on system)
#[derive(Debug, Clone)]
pub struct PendingInterfaceInfo {
    pub interface: String,
    pub router_lifetime: u16,
}

/// Overall unnumbered NDP interface tracking state.
#[derive(Debug, Clone)]
pub struct UnnumberedManagerState {
    pub monitor_running: bool,
    pub pending_interfaces: Vec<PendingInterfaceInfo>,
    pub active_interfaces: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link_local(n: u16) -> Ipv6Addr {
        format!("fe80::{n}").parse().unwrap()
    }

    fn discovered_router_state(expired: bool) -> DiscoveredRouterState {
        let now = Instant::now();
        DiscoveredRouterState {
            address: link_local(1),
            first_seen: now - Duration::from_secs(60),
            last_seen: now - Duration::from_secs(1),
            router_lifetime: 42,
            reachable_time: 5000,
            effective_reachable_time: Duration::from_secs(42),
            retrans_timer: 1000,
            expired,
        }
    }

    #[test]
    fn expired_discovered_router_converts_to_absent_api_peer() {
        let state = discovered_router_state(true);
        let peer: Option<mg_api_types::unnumbered::DiscoveredRouter> =
            (&state).into();
        assert!(peer.is_none());
    }

    #[test]
    fn live_discovered_router_converts_to_api_peer() {
        let state = discovered_router_state(false);
        let peer: Option<mg_api_types::unnumbered::DiscoveredRouter> =
            (&state).into();
        let peer = peer.expect("live state should convert to a peer");

        assert_eq!(peer.address, link_local(1));
        assert_eq!(peer.effective_reachable_time, Duration::from_secs(42));
        assert_eq!(peer.router_lifetime, 42);
        assert_eq!(peer.reachable_time, 5000);
        assert_eq!(peer.retrans_timer, 1000);
        // Elapsed durations are measured against Instant::now(), so bound
        // them rather than asserting exact values.
        assert!(peer.time_since_discovered >= Duration::from_secs(60));
        assert!(peer.time_since_last_rx >= Duration::from_secs(1));
        assert!(peer.time_since_discovered > peer.time_since_last_rx);
    }

    fn manual_interface(
        name: &str,
        addr: Ipv6Addr,
        scope_id: u32,
        router_lifetime: u16,
    ) -> UnnumberedInterface {
        UnnumberedInterface::new_manual(name, addr, scope_id, router_lifetime)
            .unwrap()
    }

    fn available_interface(
        name: &str,
        addr: Ipv6Addr,
        index: u32,
    ) -> Ipv6NetworkInterface {
        Ipv6NetworkInterface {
            name: name.to_string(),
            ip: addr,
            scope_id: NonZeroU32::new(index).unwrap(),
        }
    }

    fn reconcile_test(
        manager: &UnnumberedManager,
        available: &HashMap<String, Ipv6NetworkInterface>,
    ) {
        UnnumberedManager::reconcile_interfaces_with_activator(
            &manager.log,
            &manager.active_interfaces,
            &manager.configured_interfaces,
            available,
            |ifx, router_lifetime| {
                UnnumberedInterface::new_manual(
                    ifx.name.clone(),
                    ifx.ip,
                    ifx.scope_id.get(),
                    router_lifetime,
                )
            },
        );
    }

    #[test]
    fn drop_releases_manager() {
        let manager = UnnumberedManager::new(Logger::root(slog::Discard, o!()));
        let weak = std::sync::Arc::downgrade(&manager);

        drop(manager);

        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn real_manager_runs_monitor_and_drop_joins_it() {
        // Unlike new_test, this spawns the real monitor thread.
        let manager = UnnumberedManager::new(Logger::root(slog::Discard, o!()));
        assert!(manager.get_manager_state().monitor_running);

        // Dropping the manager disconnects the wake channel; the monitor
        // must observe it and exit so the ManagedThread join completes.
        // A regression here (e.g. the loop no longer exiting on channel
        // disconnect) hangs this test rather than passing silently.
        drop(manager);
    }

    #[test]
    fn active_interface_drives_manager_queries_and_bgp_trait() {
        let manager = UnnumberedManager::new_test();
        let interface = manual_interface("eth0", link_local(1), 7, 123);
        let neighbor = link_local(2);
        interface.record_router_advertisement(
            ndp::Icmp6RouterAdvertisement {
                lifetime: 42,
                reachable_time: 5000,
                retrans_timer: 1000,
                ..Default::default()
            },
            neighbor,
        );
        lock!(manager.active_interfaces).insert_overwrite(interface);

        assert_eq!(manager.get_interface_for_scope(7), Some("eth0".into()));
        assert_eq!(manager.get_interface_for_scope(0), None);
        assert_eq!(manager.get_interface_for_scope(8), None);
        assert_eq!(
            BgpUnnumbered::get_active_interface_by_scope(&*manager, 7).unwrap(),
            Some(BgpUnnumberedInterface {
                interface: "eth0".into(),
                scope_id: 7,
                discovered_neighbor: Some(neighbor),
            })
        );

        let discovered = manager
            .get_neighbor_by_interface("eth0")
            .unwrap()
            .expect("neighbor should be discovered");
        assert_eq!(discovered, neighbor);
        assert_eq!(
            BgpUnnumbered::get_active_interface(&*manager, "eth0").unwrap(),
            Some(BgpUnnumberedInterface {
                interface: "eth0".into(),
                scope_id: 7,
                discovered_neighbor: Some(neighbor),
            })
        );
        assert!(manager.get_neighbor_by_interface("eth1").unwrap().is_none());

        let listed = manager.list_interfaces();
        assert_eq!(listed.len(), 1);
        let listed = &listed[0];
        assert_eq!(listed.interface, "eth0");
        assert_eq!(listed.local_address, link_local(1));
        assert_eq!(listed.scope_id, 7);
        assert_eq!(listed.router_lifetime, 123);
        assert!(listed.runtime_state.tx_running);
        assert!(listed.runtime_state.rx_running);
        let peer = listed.peer_state.as_ref().unwrap();
        assert_eq!(peer.address, neighbor);
        assert_eq!(peer.router_lifetime, 42);
        assert_eq!(peer.reachable_time, 5000);
        assert_eq!(peer.retrans_timer, 1000);
        assert!(!peer.expired);

        let detail = manager
            .get_interface_detail("eth0")
            .unwrap()
            .expect("active interface should have detail");
        assert_eq!(detail.local_address, link_local(1));
        assert_eq!(detail.scope_id, 7);
        assert_eq!(detail.router_lifetime, 123);
        assert!(detail.peer_state.is_some());
        assert!(manager.get_interface_detail("eth1").unwrap().is_none());
    }

    #[test]
    fn pending_interface_derivation() {
        let manager = UnnumberedManager::new_test();
        lock!(manager.configured_interfaces).insert("eth0".into(), 30);
        lock!(manager.configured_interfaces).insert("eth1".into(), 60);
        lock!(manager.active_interfaces).insert_overwrite(manual_interface(
            "eth1",
            link_local(1),
            7,
            60,
        ));

        let pending = manager.get_pending_interfaces();

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].interface, "eth0");
        assert_eq!(pending[0].router_lifetime, 30);
    }

    #[test]
    fn runtime_unaffected_by_lifetime_change() {
        let manager = UnnumberedManager::new_test();
        lock!(manager.configured_interfaces).insert("eth0".into(), 60);
        let interface = manual_interface("eth0", link_local(1), 7, 30);
        let neighbor = link_local(2);
        interface.record_router_advertisement(
            ndp::Icmp6RouterAdvertisement::default(),
            neighbor,
        );
        lock!(manager.active_interfaces).insert_overwrite(interface);
        let available = HashMap::from([(
            "eth0".to_string(),
            available_interface("eth0", link_local(1), 7),
        )]);

        reconcile_test(&manager, &available);

        let active = lock!(manager.active_interfaces);
        let interface = active.get_by_name("eth0").unwrap();
        assert_eq!(interface.tx_router_lifetime(), 60);
        assert_eq!(interface.discovered_neighbor(), Some(neighbor));
    }

    #[test]
    fn configured_interface_reactivates_after_flap() {
        let manager = UnnumberedManager::new_test();
        lock!(manager.configured_interfaces).insert("eth0".into(), 30);
        lock!(manager.active_interfaces).insert_overwrite(manual_interface(
            "eth0",
            link_local(1),
            7,
            30,
        ));

        reconcile_test(&manager, &HashMap::new());

        assert_eq!(manager.get_interface_for_scope(7), None);
        let pending = manager.get_pending_interfaces();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].interface, "eth0");

        let available = HashMap::from([(
            "eth0".to_string(),
            available_interface("eth0", link_local(1), 7),
        )]);
        reconcile_test(&manager, &available);

        assert!(manager.get_pending_interfaces().is_empty());
        assert_eq!(manager.get_interface_for_scope(7), Some("eth0".into()));
    }

    #[test]
    fn scope_change_restarts_runtime() {
        let manager = UnnumberedManager::new_test();
        lock!(manager.configured_interfaces).insert("eth0".into(), 30);
        let interface = manual_interface("eth0", link_local(1), 7, 30);
        interface.record_router_advertisement(
            ndp::Icmp6RouterAdvertisement::default(),
            link_local(2),
        );
        lock!(manager.active_interfaces).insert_overwrite(interface);
        let available = HashMap::from([(
            "eth0".to_string(),
            available_interface("eth0", link_local(1), 8),
        )]);

        reconcile_test(&manager, &available);

        assert_eq!(manager.get_interface_for_scope(7), None);
        assert_eq!(manager.get_interface_for_scope(8), Some("eth0".into()));
        let detail = manager.get_interface_detail("eth0").unwrap().unwrap();
        assert_eq!(detail.scope_id, 8);
        assert!(detail.peer_state.is_none());
    }

    #[test]
    fn addr_change_restarts_runtime() {
        let manager = UnnumberedManager::new_test();
        lock!(manager.configured_interfaces).insert("eth0".into(), 30);
        let interface = manual_interface("eth0", link_local(1), 7, 30);
        interface.record_router_advertisement(
            ndp::Icmp6RouterAdvertisement::default(),
            link_local(2),
        );
        lock!(manager.active_interfaces).insert_overwrite(interface);
        let available = HashMap::from([(
            "eth0".to_string(),
            available_interface("eth0", link_local(99), 7),
        )]);

        reconcile_test(&manager, &available);

        let detail = manager.get_interface_detail("eth0").unwrap().unwrap();
        assert_eq!(detail.local_address, link_local(99));
        assert_eq!(detail.scope_id, 7);
        assert!(detail.peer_state.is_none());
    }

    #[test]
    fn reconciler_retains_unchanged_interface() {
        let manager = UnnumberedManager::new_test();
        lock!(manager.configured_interfaces).insert("eth0".into(), 30);
        let interface = manual_interface("eth0", link_local(1), 7, 30);
        let neighbor = link_local(2);
        interface.record_router_advertisement(
            ndp::Icmp6RouterAdvertisement::default(),
            neighbor,
        );
        lock!(manager.active_interfaces).insert_overwrite(interface);
        let available = HashMap::from([(
            "eth0".to_string(),
            available_interface("eth0", link_local(1), 7),
        )]);

        reconcile_test(&manager, &available);

        assert_eq!(
            manager.get_neighbor_by_interface("eth0").unwrap(),
            Some(neighbor),
        );
    }

    #[test]
    fn failed_reactivation_leaves_interface_pending() {
        let manager = UnnumberedManager::new_test();
        lock!(manager.configured_interfaces).insert("eth0".into(), 30);
        lock!(manager.active_interfaces).insert_overwrite(manual_interface(
            "eth0",
            link_local(1),
            7,
            30,
        ));
        let available = HashMap::from([(
            "eth0".to_string(),
            available_interface("eth0", link_local(1), 8),
        )]);

        UnnumberedManager::reconcile_interfaces_with_activator(
            &manager.log,
            &manager.active_interfaces,
            &manager.configured_interfaces,
            &available,
            |_ifx,
             _router_lifetime|
             -> Result<UnnumberedInterface, &'static str> {
                Err("activation failed")
            },
        );

        assert_eq!(manager.get_interface_for_scope(7), None);
        assert!(
            lock!(manager.active_interfaces)
                .get_by_name("eth0")
                .is_none()
        );
        let pending = manager.get_pending_interfaces();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].interface, "eth0");

        reconcile_test(&manager, &available);
        assert_eq!(manager.get_interface_for_scope(8), Some("eth0".into()));
    }

    #[test]
    fn unconfigure_interface_clears_pending_and_active_state() {
        let manager = UnnumberedManager::new_test();
        lock!(manager.configured_interfaces).insert("eth0".into(), 30);
        lock!(manager.active_interfaces).insert_overwrite(manual_interface(
            "eth0",
            link_local(1),
            7,
            123,
        ));

        manager.unconfigure_interface("eth0").unwrap();

        assert!(lock!(manager.configured_interfaces).is_empty());
        assert!(
            lock!(manager.active_interfaces)
                .get_by_name("eth0")
                .is_none()
        );
        assert_eq!(manager.get_interface_for_scope(7), None);
        assert!(manager.get_neighbor_by_interface("eth0").unwrap().is_none());

        let state = manager.get_manager_state();
        assert!(!state.monitor_running);
        assert!(state.pending_interfaces.is_empty());
        assert!(state.active_interfaces.is_empty());
    }
}
