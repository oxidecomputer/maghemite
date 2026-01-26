// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use bgp::{
    connection_tcp::BgpConnectionTcp,
    params::UnnumberedNeighbor,
    router::Router,
    session::{SessionInfo, SessionRunner},
};
use mg_common::lock;
use ndp::{Ipv6NetworkInterface, NdpManager, NewInterfaceNdpManagerError};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use slog::{Logger, error, o, warn};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{Arc, Mutex, mpsc::channel},
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

    pub fn add_neighbor(
        self: &Arc<Self>,
        asn: u32,
        interface: impl AsRef<str>,
        info: SessionInfo,
        nbr: UnnumberedNeighbor,
    ) -> Result<(), AddNeighborError> {
        let ifx = Self::get_interface(interface.as_ref(), &self.log)?;

        // Add interface to NDP manager for peer discovery
        self.ndp_mgr
            .add_interface(ifx.clone(), nbr.act_as_a_default_ipv6_router)?;

        // Store scope_id mapping for Dispatcher routing
        lock!(self.interface_scope_map).insert(ifx.index, ifx.name.clone());

        // Create unnumbered session immediately
        let router_guard = lock!(self.routers);
        if let Some(router) = router_guard.get(&asn) {
            let (event_tx, event_rx) = channel();

            // Create peer config with placeholder address
            let placeholder_host =
                SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, ifx.index);

            if let Err(e) = router.ensure_unnumbered_session(
                ifx.name.clone(),
                nbr.to_peer_config(placeholder_host),
                None,
                event_tx.clone(),
                event_rx,
                info,
                self.clone(), // Pass unnumbered manager for active NDP queries
            ) {
                error!(
                    self.log,
                    "error creating unnumbered session";
                    "error" => e.to_string(),
                    "interface" => &nbr.interface,
                );
                return Err(AddNeighborError::Resolve(
                    ResolveNeighborError::NoSuchInterface,
                ));
            }
        } else {
            warn!(
                self.log,
                "session configured for asn {}, but no router is running", asn
            );
        }

        Ok(())
    }

    pub fn remove_neighbor(
        self: &Arc<Self>,
        _asn: u32,
        interface: impl AsRef<str>,
    ) -> Result<(), ResolveNeighborError> {
        let ifx = Self::get_interface(interface.as_ref(), &self.log)?;

        // Remove interface from NDP manager
        self.ndp_mgr.remove_interface(ifx.clone());

        // Nexthop cleanup happens automatically via path removal

        // Remove scope mapping
        lock!(self.interface_scope_map).remove(&ifx.index);

        Ok(())
    }
    pub fn get_neighbor_addr(
        self: &Arc<Self>,
        interface: impl AsRef<str>,
    ) -> Result<Option<Ipv6Addr>, ResolveNeighborError> {
        let ifx = Self::get_interface(interface.as_ref(), &self.log)?;
        Ok(self.ndp_mgr.get_peer(&ifx))
    }

    pub fn get_neighbor_session(
        self: &Arc<Self>,
        asn: u32,
        interface: impl AsRef<str>,
    ) -> Result<
        Option<Arc<SessionRunner<BgpConnectionTcp>>>,
        ResolveNeighborError,
    > {
        if let Some(addr) = self.get_neighbor_addr(interface)?
            && let Some(rtr) = lock!(self.routers).get(&asn)
            && let Some(session) = rtr.get_session(addr)
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
    /// Returns the peer's link-local SocketAddr (with scope_id set) if a neighbor
    /// has been discovered via NDP, or None if no neighbor is present.
    ///
    /// This is used by SessionRunner to actively query for peer addresses
    /// when attempting connections on unnumbered interfaces.
    ///
    /// # Arguments
    /// * `interface` - The interface name (e.g., "eth0")
    ///
    /// # Returns
    /// * `Ok(Some(SocketAddr))` - Neighbor discovered at this address
    /// * `Ok(None)` - No neighbor discovered yet
    /// * `Err(ResolveNeighborError)` - Interface not found or not IPv6
    pub fn get_neighbor_for_interface(
        &self,
        interface: impl AsRef<str>,
    ) -> Result<Option<SocketAddr>, ResolveNeighborError> {
        let ifx = Self::get_interface(interface.as_ref(), &self.log)?;

        if let Some(peer_addr) = self.ndp_mgr.get_peer(&ifx) {
            // Construct SocketAddr with scope_id from interface index
            let socket_addr = SocketAddr::V6(SocketAddrV6::new(
                peer_addr, 179, // BGP port
                0,   // flowinfo
                ifx.index,
            ));
            Ok(Some(socket_addr))
        } else {
            Ok(None)
        }
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
        if let Ok(Some(discovered)) = self.get_neighbor_for_interface(interface)
        {
            // Compare IP addresses (ignore port/flowinfo/scope_id differences)
            discovered.ip() == peer.ip()
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
    fn get_interface_for_scope(&self, scope_id: u32) -> Option<String> {
        // Delegate to the existing implementation
        Self::get_interface_for_scope(self, scope_id)
    }

    fn get_neighbor_for_interface(
        &self,
        interface: &str,
    ) -> Result<Option<SocketAddr>, Box<dyn std::error::Error>> {
        // Delegate to the existing implementation
        Self::get_neighbor_for_interface(self, interface)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}
