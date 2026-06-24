// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::NewUnnumberedInterfaceError;
use crate::bgp::{BgpUnnumbered, NdpNeighbor};
use crate::error::UnnumberedError;
use crate::interface::{InterfaceMap, UnnumberedInterface};
use mg_common::lock;
use mg_common::thread::ManagedThread;
use ndp::Ipv6NetworkInterface;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use slog::{Logger, info, o, warn};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
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

    /// Interfaces that are configured but not yet available on the system.
    /// When an interface appears, it will be moved to active and router
    /// discovery will be started.
    pending_interfaces: Arc<Mutex<HashMap<String, u16>>>,

    /// Managed thread for interface monitoring.
    /// Stored to ensure automatic cleanup on drop - the ManagedThread's Drop
    /// impl will signal shutdown and join the thread.
    monitor_thread: Arc<ManagedThread>,

    /// Condvar to wake the monitor thread when work is added
    monitor_condvar: Arc<Condvar>,
    monitor_mutex: Arc<Mutex<()>>,
}

impl UnnumberedManager {
    pub fn new(log: Logger) -> Arc<Self> {
        let log = log.new(o!(
            "module" => MOD_UNNUMBERED_MANAGER,
        ));

        // Create the managed thread and get its dropped flag before constructing
        // the manager, so we can pass the flag to the thread function.
        let monitor_thread = Arc::new(ManagedThread::new());
        let dropped = monitor_thread.dropped_flag();
        let active_interfaces = Arc::new(Mutex::new(InterfaceMap::new()));
        let pending_interfaces = Arc::new(Mutex::new(HashMap::new()));
        let monitor_condvar = Arc::new(Condvar::new());
        let monitor_mutex = Arc::new(Mutex::new(()));

        let manager = Arc::new(Self {
            log: log.clone(),
            active_interfaces: Arc::clone(&active_interfaces),
            pending_interfaces: Arc::clone(&pending_interfaces),
            monitor_thread: Arc::clone(&monitor_thread),
            monitor_condvar: Arc::clone(&monitor_condvar),
            monitor_mutex: Arc::clone(&monitor_mutex),
        });

        // Spawn and register the interface monitor thread.
        // The ManagedThread will automatically signal shutdown and join the
        // thread when the manager is dropped.
        let handle = thread::Builder::new()
            .name("unnumbered-interface-monitor".to_string())
            .spawn(move || {
                Self::run_interface_monitor(
                    log,
                    active_interfaces,
                    pending_interfaces,
                    monitor_condvar,
                    monitor_mutex,
                    dropped,
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
            pending_interfaces: Arc::new(Mutex::new(HashMap::new())),
            monitor_thread: Arc::new(ManagedThread::new()),
            monitor_condvar: Arc::new(Condvar::new()),
            monitor_mutex: Arc::new(Mutex::new(())),
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
    /// The `dropped` flag is set by the ManagedThread when the manager is dropped,
    /// signaling this thread to exit.
    fn run_interface_monitor(
        log: Logger,
        active_interfaces: Arc<Mutex<InterfaceMap>>,
        pending_interfaces: Arc<Mutex<HashMap<String, u16>>>,
        monitor_condvar: Arc<Condvar>,
        monitor_mutex: Arc<Mutex<()>>,
        dropped: Arc<AtomicBool>,
    ) {
        info!(log, "interface monitor started");

        loop {
            // Check for shutdown (set by ManagedThread::drop)
            if dropped.load(Ordering::Relaxed) {
                info!(log, "interface monitor shutting down");
                break;
            }

            // Check if there's any work to do
            let has_pending = !lock!(pending_interfaces).is_empty();
            let has_active = !lock!(active_interfaces).is_empty();

            if has_pending || has_active {
                // Get all system interfaces once (single syscall)
                match Self::get_available_interfaces(&log) {
                    Ok(available) => {
                        // Check for interfaces that have appeared
                        Self::check_pending_interfaces(
                            &log,
                            &active_interfaces,
                            &pending_interfaces,
                            &available,
                        );

                        // Check for interfaces that have been removed
                        Self::check_active_interfaces(
                            &log,
                            &active_interfaces,
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

            // Wait for the poll interval or until woken up
            let guard = lock!(monitor_mutex);
            let _result = monitor_condvar.wait_timeout_while(
                guard,
                INTERFACE_POLL_INTERVAL,
                |_| !dropped.load(Ordering::Relaxed),
            );
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
                index: iface.index,
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

    /// Check pending interfaces to see if any have become available.
    ///
    /// Takes a pre-computed set of available interfaces to avoid repeated syscalls.
    fn check_pending_interfaces(
        log: &Logger,
        active_interfaces: &Mutex<InterfaceMap>,
        pending_interfaces: &Mutex<HashMap<String, u16>>,
        available: &HashMap<String, Ipv6NetworkInterface>,
    ) {
        let mut pending = lock!(pending_interfaces);
        let mut to_activate = Vec::new();

        // Find interfaces that are now available
        for (interface_name, router_lifetime) in pending.iter() {
            if let Some(ifx) = available.get(interface_name) {
                to_activate.push((ifx.clone(), *router_lifetime));
            }
        }

        // Remove from pending and activate
        for (ifx, router_lifetime) in to_activate {
            pending.remove(&ifx.name);

            info!(
                log,
                "interface became available, activating NDP";
                "interface" => ifx.name.as_str(),
            );

            if let Err(e) = Self::activate_resolved_interface(
                log,
                active_interfaces,
                &ifx,
                router_lifetime,
            ) {
                warn!(
                    log,
                    "failed to activate interface";
                    "interface" => ifx.name.as_str(),
                    "error" => e.to_string(),
                );
                // Re-add to pending so we try again later.
                pending.insert(ifx.name.clone(), router_lifetime);
            } else {
                info!(
                    log,
                    "interface activated for NDP";
                    "interface" => ifx.name.as_str(),
                    "scope_id" => ifx.index,
                    "local_addr" => ifx.ip.to_string(),
                );
            }
        }
    }

    /// Check active interfaces to see if any have been removed.
    ///
    /// Takes a pre-computed set of available interfaces to avoid repeated syscalls.
    fn check_active_interfaces(
        log: &Logger,
        active_interfaces: &Mutex<InterfaceMap>,
        available: &HashMap<String, Ipv6NetworkInterface>,
    ) {
        let to_deactivate: Vec<String> = lock!(active_interfaces)
            .iter()
            .filter(|interface| !available.contains_key(interface.name()))
            .map(|interface| interface.name().to_string())
            .collect();

        // Remove from active and deactivate
        for interface_name in to_deactivate {
            Self::deactivate_interface(log, active_interfaces, &interface_name);
        }
    }

    /// Activate an already-resolved interface.
    ///
    /// This starts router discovery for the interface and records it as active
    /// for unnumbered lookups.
    fn activate_resolved_interface(
        log: &Logger,
        active_interfaces: &Mutex<InterfaceMap>,
        ifx: &Ipv6NetworkInterface,
        router_lifetime: u16,
    ) -> Result<(), AddNeighborError> {
        let active = UnnumberedInterface::new(
            ifx.clone(),
            router_lifetime,
            log.clone(),
        )?;
        lock!(active_interfaces).insert_overwrite(active);
        Ok(())
    }

    /// Deactivate an interface that has been removed.
    ///
    /// This removes the interface from the active interface map.
    fn deactivate_interface(
        log: &Logger,
        active_interfaces: &Mutex<InterfaceMap>,
        interface_name: &str,
    ) {
        info!(
            log,
            "interface removed, deactivating NDP";
            "interface" => interface_name,
        );

        // Clean up active interface state. Dropping the interface also drops
        // its router-discovery thread handles.
        lock!(active_interfaces).remove_by_name(interface_name);
    }

    /// Register an interface for NDP peer discovery.
    ///
    /// This method only handles NDP-related setup:
    /// - Resolves the interface to get its IPv6 link-local address
    /// - Starts router discovery for the interface
    /// - Records the interface as active for unnumbered lookups
    ///
    /// BGP session creation is handled separately by the caller.
    ///
    /// If the interface doesn't exist yet, this is not an error - the interface
    /// will be added to a pending list and registered when it appears. The
    /// caller should still create the BGP session, which will wait for the
    /// interface to become available.
    pub fn add_interface(
        self: &Arc<Self>,
        interface: impl AsRef<str>,
        router_lifetime: u16,
    ) -> Result<(), AddNeighborError> {
        let interface_str = interface.as_ref();

        // Try to get the interface. If it does not exist or is not ready for
        // unnumbered operation yet, add it to the pending list.
        match Self::get_interface(interface_str, &self.log)? {
            Some(ifx) => {
                Self::activate_resolved_interface(
                    &self.log,
                    &self.active_interfaces,
                    &ifx,
                    router_lifetime,
                )?;

                info!(
                    self.log,
                    "interface registered for NDP peer discovery";
                    "interface" => interface_str,
                    "scope_id" => ifx.index,
                    "local_addr" => ifx.ip.to_string(),
                );
            }
            None => {
                // Interface not ready - add to pending list. The monitor
                // thread will activate it when it appears and has a link-local
                // IPv6 address.
                info!(
                    self.log,
                    "interface not currently available, adding to pending";
                    "interface" => interface_str,
                );

                lock!(self.pending_interfaces)
                    .insert(interface_str.to_string(), router_lifetime);

                // Wake up the monitor thread since there's new work
                self.monitor_condvar.notify_one();
            }
        };

        Ok(())
    }

    /// Unregister an interface from NDP peer discovery.
    ///
    /// This method only handles NDP-related cleanup:
    /// - Drops the active interface and its router-discovery thread handles
    /// - Removes from pending/active tracking
    ///
    /// BGP session deletion is handled separately by the caller.
    pub fn remove_interface(
        self: &Arc<Self>,
        interface: impl AsRef<str>,
    ) -> Result<(), network_interface::Error> {
        let interface_str = interface.as_ref();

        // Remove from pending if it was waiting to be activated
        lock!(self.pending_interfaces).remove(interface_str);

        // Remove from active if it was active. Dropping the interface also
        // drops its router-discovery thread handles.
        lock!(self.active_interfaces).remove_by_name(interface_str);

        info!(
            self.log,
            "interface unregistered from NDP peer discovery";
            "interface" => interface_str,
        );

        Ok(())
    }

    // =========================================================================
    // Unnumbered/NDP Query Interface
    // =========================================================================
    // These methods provide the query interface for BGP session and dispatcher
    // code to access current unnumbered/NDP state without triggering session
    // management.

    /// Get the currently discovered neighbor for an interface.
    ///
    /// Returns the peer's link-local IPv6 address and scope_id if a neighbor
    /// has been discovered via NDP, or None if no neighbor is present.
    ///
    /// This is used by SessionRunner to actively query for peer addresses
    /// when attempting connections on unnumbered interfaces.
    ///
    /// # Arguments
    /// * `interface` - The interface name (e.g., "eth0")
    ///
    /// # Returns
    /// * `Ok(Some(NdpNeighbor))` - Neighbor discovered on this interface
    /// * `Ok(None)` - No neighbor discovered or interface not ready
    /// * `Err(network_interface::Error)` - Failed to enumerate interfaces
    pub fn get_neighbor_by_interface(
        &self,
        interface: impl AsRef<str>,
    ) -> Result<Option<NdpNeighbor>, network_interface::Error> {
        Ok(lock!(self.active_interfaces)
            .get_by_name(interface.as_ref())
            .and_then(|ifx| {
                ifx.discovered_neighbor().map(|addr| NdpNeighbor {
                    addr,
                    scope_id: ifx.scope_id().get(),
                })
            }))
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

    /// Validate that a peer address matches the discovered neighbor for an interface.
    ///
    /// This is used by SessionRunner to validate incoming connections on
    /// unnumbered interfaces, ensuring the connection is from the expected
    /// NDP-discovered neighbor.
    ///
    /// # Arguments
    /// * `interface` - The interface name
    /// * `peer` - The peer address to validate
    ///
    /// # Returns
    /// * `true` - Peer matches the discovered neighbor for this interface
    /// * `false` - Peer does not match or no neighbor discovered
    ///
    /// Note: Currently unused as validation happens via Dispatcher routing.
    /// Available for future explicit validation scenarios.
    #[allow(dead_code)]
    pub fn validate_peer_for_interface(
        &self,
        interface: impl AsRef<str>,
        peer: SocketAddr,
    ) -> bool {
        // Get discovered neighbor for interface
        if let Ok(Some(discovered)) = self.get_neighbor_by_interface(interface)
        {
            // Compare IP addresses (ignore port/flowinfo/scope_id differences)
            IpAddr::V6(discovered.addr) == peer.ip()
        } else {
            false
        }
    }

    fn get_interface(
        name: &str,
        log: &Logger,
    ) -> Result<Option<Ipv6NetworkInterface>, network_interface::Error> {
        let candidates: Vec<_> = NetworkInterface::show()?
            .into_iter()
            .filter(|x| x.name == name)
            .collect();

        if candidates.is_empty() {
            return Ok(None);
        }

        let mut local: Vec<_> = candidates
            .into_iter()
            .filter_map(|x| x.addr.map(|addr| (addr, x.index)))
            .filter_map(|(addr, idx)| match addr.ip() {
                IpAddr::V6(ip) if ip.is_unicast_link_local() => Some((ip, idx)),
                _ => None,
            })
            .collect();

        let Some((addr, index)) = local.pop() else {
            return Ok(None);
        };

        if !local.is_empty() {
            warn!(
                log,
                "more than 1 link local address for interface";
                "using" => addr.to_string(),
                "also found" => local
                    .into_iter()
                    .map(|x| x.0.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }

        Ok(Some(Ipv6NetworkInterface {
            name: name.to_owned(),
            ip: addr,
            index,
        }))
    }
}

impl Drop for UnnumberedManager {
    fn drop(&mut self) {
        let _guard = lock!(self.monitor_mutex);
        self.monitor_thread
            .dropped_flag()
            .store(true, Ordering::Relaxed);
        self.monitor_condvar.notify_one();
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
    ) -> Result<Option<String>, UnnumberedError> {
        Ok(Self::get_interface_for_scope(self, scope_id))
    }

    fn get_discovered_ndp_neighbor(
        &self,
        interface: &str,
    ) -> Result<Option<NdpNeighbor>, UnnumberedError> {
        Self::get_neighbor_by_interface(self, interface).map_err(|e| {
            UnnumberedError::ResolutionFailed {
                interface: interface.to_string(),
                reason: e.to_string(),
            }
        })
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
        lock!(self.pending_interfaces)
            .iter()
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

/// Detailed discovered router state with full RA information
#[derive(Debug, Clone)]
pub struct DiscoveredRouterState {
    pub address: Ipv6Addr,
    pub first_seen: std::time::Instant,
    pub when: std::time::Instant,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub expired: bool,
}

impl From<ndp::RouterAdvertisementInfo> for DiscoveredRouterState {
    fn from(info: ndp::RouterAdvertisementInfo) -> Self {
        Self {
            address: info.address,
            first_seen: info.first_seen,
            when: info.last_seen,
            router_lifetime: info.router_lifetime,
            reachable_time: info.reachable_time,
            retrans_timer: info.retrans_timer,
            expired: info.expired,
        }
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

    fn manual_interface(
        name: &str,
        addr: Ipv6Addr,
        scope_id: u32,
        router_lifetime: u16,
    ) -> UnnumberedInterface {
        UnnumberedInterface::new_manual(name, addr, scope_id, router_lifetime)
            .unwrap()
    }

    #[test]
    fn drop_releases_manager() {
        let manager = UnnumberedManager::new(Logger::root(slog::Discard, o!()));
        let weak = std::sync::Arc::downgrade(&manager);

        drop(manager);

        assert!(weak.upgrade().is_none());
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
            Some("eth0".into())
        );

        let discovered = manager
            .get_neighbor_by_interface("eth0")
            .unwrap()
            .expect("neighbor should be discovered");
        assert_eq!(discovered.addr, neighbor);
        assert_eq!(discovered.scope_id, 7);
        assert_eq!(
            BgpUnnumbered::get_discovered_ndp_neighbor(&*manager, "eth0")
                .unwrap()
                .map(|n| (n.addr, n.scope_id)),
            Some((neighbor, 7))
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
    fn remove_interface_clears_pending_and_active_state() {
        let manager = UnnumberedManager::new_test();
        lock!(manager.pending_interfaces).insert("eth0".into(), 30);
        lock!(manager.active_interfaces).insert_overwrite(manual_interface(
            "eth0",
            link_local(1),
            7,
            123,
        ));

        manager.remove_interface("eth0").unwrap();

        assert!(lock!(manager.pending_interfaces).is_empty());
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
