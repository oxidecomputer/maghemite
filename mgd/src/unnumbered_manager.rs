// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use bgp::{
    connection_tcp::BgpConnectionTcp, router::Router, session::SessionRunner,
    unnumbered::NdpNeighbor,
};
use mg_common::lock;
use mg_common::thread::ManagedThread;
use ndp::{Ipv6NetworkInterface, NdpManager, NewInterfaceNdpManagerError};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use slog::{Logger, o, warn};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv6Addr, SocketAddr},
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

/// Configuration for a pending interface (configured but not yet available)
#[derive(Debug, Clone)]
struct PendingInterfaceConfig {
    router_lifetime: u16,
}

pub struct UnnumberedManagerNdp {
    routers: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
    ndp_mgr: Arc<NdpManager>,
    /// Maps scope_id (interface index) to interface name for Dispatcher routing
    interface_scope_map: Mutex<HashMap<u32, String>>,
    log: Logger,

    // =========================================================================
    // Interface monitoring state
    // =========================================================================
    /// Interfaces that are configured but not yet available on the system.
    /// When an interface appears, it will be moved to active and registered
    /// with the NDP manager.
    pending_interfaces: Mutex<HashMap<String, PendingInterfaceConfig>>,

    /// Interfaces that are currently active (registered with NDP manager).
    /// Used to detect when an interface is removed from the system.
    active_interfaces: Mutex<HashSet<String>>,

    /// Managed thread for interface monitoring.
    /// Stored to ensure automatic cleanup on drop - the ManagedThread's Drop
    /// impl will signal shutdown and join the thread.
    _monitor_thread: Arc<ManagedThread>,

    /// Condvar to wake the monitor thread when work is added
    monitor_condvar: Condvar,
    monitor_mutex: Mutex<()>,
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveNeighborError {
    #[error("No such interface")]
    NoSuchInterface,
    #[error("Interface has no IPv6 link local address")]
    NotIpv6Interface,
    #[error("Could not get system interfaces: {0}")]
    System(#[from] network_interface::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum AddNeighborError {
    #[error("resolve neighbor error: {0}")]
    Resolve(#[from] ResolveNeighborError),

    #[error("add interface error: {0}")]
    NdpManager(#[from] NewInterfaceNdpManagerError),
}

impl UnnumberedManagerNdp {
    pub fn new(
        routers: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
        log: Logger,
    ) -> Arc<Self> {
        let log = log.new(o!(
            "component" => crate::COMPONENT_MGD,
            "unit" => crate::UNIT_DAEMON,
            "module" => MOD_UNNUMBERED_MANAGER,
        ));

        // Create the managed thread and get its dropped flag before constructing
        // the manager, so we can pass the flag to the thread function.
        let monitor_thread = Arc::new(ManagedThread::new());
        let dropped = monitor_thread.dropped_flag();

        let manager = Arc::new(Self {
            routers,
            interface_scope_map: Mutex::new(HashMap::default()),
            ndp_mgr: NdpManager::new(log.clone()),
            log,
            pending_interfaces: Mutex::new(HashMap::new()),
            active_interfaces: Mutex::new(HashSet::new()),
            _monitor_thread: Arc::clone(&monitor_thread),
            monitor_condvar: Condvar::new(),
            monitor_mutex: Mutex::new(()),
        });

        // Spawn and register the interface monitor thread.
        // The ManagedThread will automatically signal shutdown and join the
        // thread when the manager is dropped.
        let monitor_manager = Arc::clone(&manager);
        let handle = thread::Builder::new()
            .name("unnumbered-interface-monitor".to_string())
            .spawn(move || {
                monitor_manager.run_interface_monitor(dropped);
            })
            .expect("failed to spawn interface monitor thread");
        monitor_thread.start(handle);

        manager
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
    fn run_interface_monitor(&self, dropped: Arc<AtomicBool>) {
        slog::info!(self.log, "interface monitor started");

        loop {
            // Check for shutdown (set by ManagedThread::drop)
            if dropped.load(Ordering::Relaxed) {
                slog::info!(self.log, "interface monitor shutting down");
                break;
            }

            // Check if there's any work to do
            let has_pending = !lock!(self.pending_interfaces).is_empty();
            let has_active = !lock!(self.active_interfaces).is_empty();

            if has_pending || has_active {
                // Get all system interfaces once (single syscall)
                match Self::get_available_interfaces() {
                    Ok(available) => {
                        // Check for interfaces that have appeared
                        self.check_pending_interfaces(&available);

                        // Check for interfaces that have been removed
                        self.check_active_interfaces(&available);
                    }
                    Err(e) => {
                        slog::warn!(
                            self.log,
                            "failed to enumerate system interfaces";
                            "error" => %e,
                        );
                    }
                }
            }

            // Wait for the poll interval or until woken up
            let guard = lock!(self.monitor_mutex);
            let _result = self
                .monitor_condvar
                .wait_timeout(guard, INTERFACE_POLL_INTERVAL);
        }

        slog::info!(self.log, "interface monitor exited");
    }

    /// Get the set of interface names that are available for NDP.
    ///
    /// An interface is considered available if it exists on the system and
    /// has an IPv6 link-local address configured.
    fn get_available_interfaces()
    -> Result<HashSet<String>, network_interface::Error> {
        let interfaces = NetworkInterface::show()?;

        Ok(interfaces
            .into_iter()
            .filter(|iface| {
                iface
                    .addr
                    .map(|addr| {
                        matches!(addr.ip(), IpAddr::V6(ip) if ip.is_unicast_link_local())
                    })
                    .unwrap_or(false)
            })
            .map(|iface| iface.name)
            .collect())
    }

    /// Check pending interfaces to see if any have become available.
    ///
    /// Takes a pre-computed set of available interfaces to avoid repeated syscalls.
    fn check_pending_interfaces(&self, available: &HashSet<String>) {
        let mut pending = lock!(self.pending_interfaces);
        let mut to_activate = Vec::new();

        // Find interfaces that are now available
        for (interface_name, config) in pending.iter() {
            if available.contains(interface_name) {
                to_activate.push((interface_name.clone(), config.clone()));
            }
        }

        // Remove from pending and activate
        for (interface_name, config) in to_activate {
            pending.remove(&interface_name);
            drop(pending); // Release lock before activation

            self.activate_interface(&interface_name, config.router_lifetime);

            pending = lock!(self.pending_interfaces);
        }
    }

    /// Check active interfaces to see if any have been removed.
    ///
    /// Takes a pre-computed set of available interfaces to avoid repeated syscalls.
    fn check_active_interfaces(&self, available: &HashSet<String>) {
        let mut active = lock!(self.active_interfaces);
        let mut to_deactivate = Vec::new();

        // Find interfaces that are no longer available
        for interface_name in active.iter() {
            if !available.contains(interface_name) {
                to_deactivate.push(interface_name.clone());
            }
        }

        // Remove from active and deactivate
        for interface_name in to_deactivate {
            active.remove(&interface_name);
            drop(active); // Release lock before deactivation

            self.deactivate_interface(&interface_name);

            active = lock!(self.active_interfaces);
        }
    }

    /// Activate an interface that has become available.
    ///
    /// This registers the interface with the NDP manager for peer discovery.
    fn activate_interface(&self, interface_name: &str, router_lifetime: u16) {
        slog::info!(
            self.log,
            "interface became available, activating NDP";
            "interface" => interface_name,
        );

        match Self::get_interface(interface_name, &self.log) {
            Ok(ifx) => {
                // Add interface to NDP manager for peer discovery
                if let Err(e) =
                    self.ndp_mgr.add_interface(ifx.clone(), router_lifetime)
                {
                    slog::warn!(
                        self.log,
                        "failed to add interface to NDP manager";
                        "interface" => interface_name,
                        "error" => e.to_string(),
                    );
                    return;
                }

                // Store scope_id mapping for Dispatcher routing
                lock!(self.interface_scope_map)
                    .insert(ifx.index, ifx.name.clone());

                // Track as active
                lock!(self.active_interfaces)
                    .insert(interface_name.to_string());

                slog::info!(
                    self.log,
                    "interface activated for NDP";
                    "interface" => interface_name,
                    "scope_id" => ifx.index,
                    "local_addr" => ifx.ip.to_string(),
                );
            }
            Err(e) => {
                // Race condition - interface disappeared between check and activation
                slog::warn!(
                    self.log,
                    "interface disappeared during activation";
                    "interface" => interface_name,
                    "error" => e.to_string(),
                );
                // Re-add to pending so we try again later
                lock!(self.pending_interfaces).insert(
                    interface_name.to_string(),
                    PendingInterfaceConfig { router_lifetime },
                );
            }
        }
    }

    /// Deactivate an interface that has been removed.
    ///
    /// This removes the interface from the NDP manager and cleans up mappings.
    fn deactivate_interface(&self, interface_name: &str) {
        slog::info!(
            self.log,
            "interface removed, deactivating NDP";
            "interface" => interface_name,
        );

        // Try to get interface info for NDP manager removal
        // (may fail if interface is already gone)
        if let Ok(ifx) = Self::get_interface(interface_name, &self.log) {
            self.ndp_mgr.remove_interface(ifx);
        }

        // Clean up scope mapping by searching for interface name
        let mut scope_map = lock!(self.interface_scope_map);
        if let Some((&scope_id, _)) = scope_map
            .iter()
            .find(|(_, name)| name.as_str() == interface_name)
        {
            scope_map.remove(&scope_id);
        }
    }

    /// Register an interface for NDP peer discovery.
    ///
    /// This method only handles NDP-related setup:
    /// - Resolves the interface to get its IPv6 link-local address
    /// - Registers the interface with the NDP manager for peer discovery
    /// - Stores the scope_id -> interface mapping for Dispatcher routing
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

        // Try to get the interface - this can fail if the interface doesn't exist
        // or isn't configured properly
        match Self::get_interface(interface_str, &self.log) {
            Ok(ifx) => {
                // Add interface to NDP manager for peer discovery
                self.ndp_mgr.add_interface(ifx.clone(), router_lifetime)?;

                // Store scope_id mapping for Dispatcher routing
                lock!(self.interface_scope_map)
                    .insert(ifx.index, ifx.name.clone());

                // Track as active
                lock!(self.active_interfaces).insert(interface_str.to_string());

                slog::info!(
                    self.log,
                    "interface registered for NDP peer discovery";
                    "interface" => interface_str,
                    "scope_id" => ifx.index,
                    "local_addr" => ifx.ip.to_string(),
                );
            }
            Err(e) => {
                // Interface not found - add to pending list.
                // The monitor thread will activate it when it appears.
                slog::info!(
                    self.log,
                    "interface not currently available, adding to pending";
                    "interface" => interface_str,
                    "error" => e.to_string(),
                );

                lock!(self.pending_interfaces).insert(
                    interface_str.to_string(),
                    PendingInterfaceConfig { router_lifetime },
                );

                // Wake up the monitor thread since there's new work
                self.monitor_condvar.notify_one();
            }
        };

        Ok(())
    }

    /// Unregister an interface from NDP peer discovery.
    ///
    /// This method only handles NDP-related cleanup:
    /// - Removes the interface from the NDP manager
    /// - Removes the scope_id -> interface mapping
    /// - Removes from pending/active tracking
    ///
    /// BGP session deletion is handled separately by the caller.
    pub fn remove_interface(
        self: &Arc<Self>,
        interface: impl AsRef<str>,
    ) -> Result<(), ResolveNeighborError> {
        let interface_str = interface.as_ref();

        // Remove from pending if it was waiting to be activated
        lock!(self.pending_interfaces).remove(interface_str);

        // Remove from active tracking
        lock!(self.active_interfaces).remove(interface_str);

        // Remove from NDP manager if interface exists
        if let Ok(ifx) = Self::get_interface(interface_str, &self.log) {
            self.ndp_mgr.remove_interface(ifx);
        }

        // Clean up scope mapping by searching for interface name.
        // This works whether or not the interface still exists in the system.
        let mut scope_map = lock!(self.interface_scope_map);
        if let Some((&scope_id, _)) = scope_map
            .iter()
            .find(|(_, name)| name.as_str() == interface_str)
        {
            scope_map.remove(&scope_id);
        }

        slog::info!(
            self.log,
            "interface unregistered from NDP peer discovery";
            "interface" => interface_str,
        );

        Ok(())
    }

    pub fn get_neighbor_session(
        self: &Arc<Self>,
        asn: u32,
        interface: impl AsRef<str>,
    ) -> Result<
        Option<Arc<SessionRunner<BgpConnectionTcp>>>,
        ResolveNeighborError,
    > {
        if let Some(rtr) = lock!(self.routers).get(&asn)
            && let Some(session) = rtr.get_session(interface.as_ref())
        {
            return Ok(Some(session));
        };
        Ok(None)
    }

    // =========================================================================
    // NDP Query Interface
    // =========================================================================
    // These methods provide the query interface for SessionRunner and Dispatcher
    // to access current NDP state without triggering session management.
    //
    // Currently, SessionRunner uses neighbor_cell for passive updates (updated by
    // the run loop when NDP discovers peers). These methods are available for
    // future active query scenarios.

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
    /// * `Ok(None)` - No neighbor discovered yet
    /// * `Err(ResolveNeighborError)` - Interface not found or not IPv6
    pub fn get_neighbor_by_interface(
        &self,
        interface: impl AsRef<str>,
    ) -> Result<Option<NdpNeighbor>, ResolveNeighborError> {
        let ifx = Self::get_interface(interface.as_ref(), &self.log)?;

        Ok(self.ndp_mgr.get_peer(&ifx).map(|peer_addr| NdpNeighbor {
            addr: peer_addr,
            scope_id: ifx.index,
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
        lock!(self.interface_scope_map).get(&scope_id).cloned()
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
    ) -> Result<Ipv6NetworkInterface, ResolveNeighborError> {
        let candidates: Vec<_> = NetworkInterface::show()?
            .into_iter()
            .filter(|x| x.name == name)
            .collect();

        if candidates.is_empty() {
            return Err(ResolveNeighborError::NoSuchInterface);
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
            return Err(ResolveNeighborError::NotIpv6Interface);
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

        Ok(Ipv6NetworkInterface {
            name: name.to_owned(),
            ip: addr,
            index,
        })
    }
}

// =========================================================================
// UnnumberedManager Trait Implementation
// =========================================================================
// Provides the interface for Dispatcher to query interface mappings
impl bgp::unnumbered::UnnumberedManager for UnnumberedManagerNdp {
    fn interface_is_active(&self, interface: &str) -> bool {
        // Delegate to the existing implementation
        Self::get_interface(interface, &self.log).is_ok()
    }

    fn get_interface_by_scope(&self, scope_id: u32) -> Option<String> {
        // Delegate to the existing implementation
        Self::get_interface_for_scope(self, scope_id)
    }

    fn get_neighbor_by_interface(
        &self,
        interface: &str,
    ) -> Result<
        Option<bgp::unnumbered::NdpNeighbor>,
        bgp::unnumbered::UnnumberedError,
    > {
        // Delegate to the existing implementation
        Self::get_neighbor_by_interface(self, interface).map_err(|e| match e {
            ResolveNeighborError::NoSuchInterface => {
                bgp::unnumbered::UnnumberedError::InterfaceNotFound(
                    interface.to_string(),
                )
            }
            ResolveNeighborError::NotIpv6Interface => {
                bgp::unnumbered::UnnumberedError::NotIpv6(interface.to_string())
            }
            ResolveNeighborError::System(sys_err) => {
                bgp::unnumbered::UnnumberedError::ResolutionFailed {
                    interface: interface.to_string(),
                    reason: sys_err.to_string(),
                }
            }
        })
    }
}

impl UnnumberedManagerNdp {
    /// List all NDP-managed interfaces with detailed discovery state.
    ///
    /// Returns a list of interfaces managed by this unnumbered manager,
    /// including full peer advertisement information with timestamps.
    ///
    /// The caller should filter by ASN based on which neighbors are configured
    /// for unnumbered BGP sessions.
    pub fn list_ndp_interfaces(&self) -> Vec<ManagedInterfaceInfo> {
        // Get detailed interface information from NDP manager
        let detailed_interfaces = self.ndp_mgr.list_interfaces_detailed();

        // Filter to only interfaces we're managing for BGP unnumbered
        let scope_map = lock!(self.interface_scope_map);

        detailed_interfaces
            .into_iter()
            .filter_map(|info| {
                // Only include interfaces in our scope map
                if !scope_map.contains_key(&info.interface.index) {
                    return None;
                }

                let peer_state =
                    info.discovered_peer.as_ref().map(|detail| NdpPeerState {
                        address: detail.address,
                        first_seen: detail.first_seen,
                        when: detail.when,
                        router_lifetime: detail.router_lifetime,
                        reachable_time: detail.reachable_time,
                        retrans_timer: detail.retrans_timer,
                        expired: detail.expired,
                    });

                Some(ManagedInterfaceInfo {
                    interface: info.interface.name,
                    local_address: info.interface.ip,
                    scope_id: info.interface.index,
                    peer_state,
                })
            })
            .collect()
    }

    /// Get detailed NDP state for a specific interface.
    ///
    /// Returns detailed information about peer discovery including timestamps,
    /// RA parameters, and expiry status.
    ///
    /// Returns None if the interface is not managed by NDP.
    pub fn get_ndp_interface_detail(
        &self,
        interface_name: &str,
    ) -> Result<Option<InterfaceDetail>, ResolveNeighborError> {
        let ifx = Self::get_interface(interface_name, &self.log)?;

        // Check if we're managing this interface
        if !lock!(self.interface_scope_map).contains_key(&ifx.index) {
            return Ok(None);
        }

        // Get detailed peer information from NDP manager
        let peer_state =
            self.ndp_mgr
                .get_peer_detail(&ifx)
                .map(|detail| NdpPeerState {
                    address: detail.address,
                    first_seen: detail.first_seen,
                    when: detail.when,
                    router_lifetime: detail.router_lifetime,
                    reachable_time: detail.reachable_time,
                    retrans_timer: detail.retrans_timer,
                    expired: detail.expired,
                });

        Ok(Some(InterfaceDetail {
            local_address: ifx.ip,
            scope_id: ifx.index,
            peer_state,
        }))
    }
}

/// Information about a managed interface with NDP state
#[derive(Debug, Clone)]
pub struct ManagedInterfaceInfo {
    pub interface: String,
    pub local_address: Ipv6Addr,
    pub scope_id: u32,
    pub peer_state: Option<NdpPeerState>,
}

/// Detailed NDP state for a specific interface
#[derive(Debug, Clone)]
pub struct InterfaceDetail {
    pub local_address: Ipv6Addr,
    pub scope_id: u32,
    pub peer_state: Option<NdpPeerState>,
}

/// Detailed NDP peer state with full RA information
#[derive(Debug, Clone)]
pub struct NdpPeerState {
    pub address: Ipv6Addr,
    pub first_seen: std::time::Instant,
    pub when: std::time::Instant,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub expired: bool,
}
