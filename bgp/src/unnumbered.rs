// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

/// Error type for UnnumberedManager operations.
#[derive(Debug, Clone)]
pub enum UnnumberedError {
    /// Interface not found on the system
    InterfaceNotFound(String),
    /// Interface exists but is not IPv6
    NotIpv6(String),
    /// Other interface resolution error
    ResolutionFailed { interface: String, reason: String },
}

impl fmt::Display for UnnumberedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InterfaceNotFound(iface) => {
                write!(f, "interface '{}' not found", iface)
            }
            Self::NotIpv6(iface) => {
                write!(f, "interface '{}' is not IPv6", iface)
            }
            Self::ResolutionFailed { interface, reason } => {
                write!(
                    f,
                    "failed to resolve interface '{}': {}",
                    interface, reason
                )
            }
        }
    }
}

impl std::error::Error for UnnumberedError {}

/// NDP neighbor information returned by the unnumbered manager.
///
/// Contains the discovered peer's link-local IPv6 address and the interface
/// index (scope_id) needed to construct a properly scoped socket address.
/// The port is intentionally not included - the caller supplies the port per
/// the configuration for the BGP neighbor.
#[derive(Debug, Clone, Copy)]
pub struct NdpNeighbor {
    pub addr: Ipv6Addr,
    pub scope_id: u32,
}

impl NdpNeighbor {
    /// Convert to a SocketAddr with the specified port.
    pub fn to_socket_addr(&self, port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(self.addr, port, 0, self.scope_id))
    }
}

/// Trait for managing unnumbered BGP sessions via NDP neighbor discovery.
///
/// This trait provides the interface between BGP and the external NDP/neighbor
/// discovery system, enabling:
/// - Dispatcher to route incoming link-local connections to the correct session
/// - SessionRunner to query for discovered peer addresses on unnumbered interfaces
pub trait UnnumberedManager: Send + Sync {
    /// Check if an interface is known to the unnumbered manager.
    ///
    /// This is used by SessionRunner to query for interface presence.
    ///
    /// # Arguments
    /// * `interface` - Interface name to query for
    ///
    /// # Returns
    /// * `true` - Interface is present the system
    /// * `false` - Interface is not present on the system
    fn interface_is_active(&self, interface: &str) -> bool;

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
    fn get_interface_by_scope(&self, scope_id: u32) -> Option<String>;

    /// Get the currently discovered neighbor for an interface.
    ///
    /// This is used by SessionRunner to actively query for peer addresses
    /// when attempting connections on unnumbered interfaces. Returns the
    /// neighbor's IPv6 address and scope_id; the caller constructs the
    /// full SocketAddr using the peer's configured port.
    ///
    /// # Arguments
    /// * `interface` - The interface name (e.g., "eth0")
    ///
    /// # Returns
    /// * `Ok(Some(NdpNeighbor))` - Neighbor discovered on this interface
    /// * `Ok(None)` - No neighbor discovered yet
    /// * `Err(UnnumberedError)` - Interface not found or not IPv6
    fn get_neighbor_by_interface(
        &self,
        interface: &str,
    ) -> Result<Option<NdpNeighbor>, UnnumberedError>;
}
