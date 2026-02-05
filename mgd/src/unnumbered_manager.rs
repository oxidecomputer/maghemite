// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use bgp::{
    connection_tcp::BgpConnectionTcp, router::Router, session::SessionRunner,
    unnumbered::NdpNeighbor,
};
use mg_common::lock;
use ndp::{Ipv6NetworkInterface, NdpManager, NewInterfaceNdpManagerError};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use slog::{Logger, o, warn};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
};

pub const MOD_UNNUMBERED_MANAGER: &str = "unnumbered manager";

pub struct UnnumberedManagerNdp {
    routers: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
    ndp_mgr: Arc<NdpManager>,
    /// Maps scope_id (interface index) to interface name for Dispatcher routing
    interface_scope_map: Mutex<HashMap<u32, String>>,
    log: Logger,
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

        Arc::new(Self {
            routers,
            interface_scope_map: Mutex::new(HashMap::default()),
            ndp_mgr: NdpManager::new(log.clone()),
            log,
        })
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
    /// will be registered when it appears. The caller should still create the
    /// BGP session, which will wait for the interface to become available.
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
            }
            Err(e) => {
                // Interface not found - that's OK, it may appear later.
                // The BGP session (created by caller) will wait for it.
                slog::info!(
                    self.log,
                    "interface not currently available for NDP setup";
                    "interface" => interface_str,
                    "error" => e.to_string(),
                );
            }
        };

        Ok(())
    }

    /// Unregister an interface from NDP peer discovery.
    ///
    /// This method only handles NDP-related cleanup:
    /// - Removes the interface from the NDP manager
    /// - Removes the scope_id -> interface mapping
    ///
    /// BGP session deletion is handled separately by the caller.
    pub fn remove_interface(
        self: &Arc<Self>,
        interface: impl AsRef<str>,
    ) -> Result<(), ResolveNeighborError> {
        let interface_str = interface.as_ref();

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
