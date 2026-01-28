// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::SocketAddr;

/// Trait for managing unnumbered BGP sessions via NDP neighbor discovery.
///
/// This trait provides the interface between BGP and the external NDP/neighbor
/// discovery system, enabling:
/// - Dispatcher to route incoming link-local connections to the correct session
/// - SessionRunner to query for discovered peer addresses on unnumbered interfaces
pub trait UnnumberedManager: Send + Sync {
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
    fn get_interface_for_scope(&self, scope_id: u32) -> Option<String>;

    /// Get the currently discovered neighbor for an interface.
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
    /// * `Err` - Interface not found or not IPv6
    fn get_neighbor_for_interface(
        &self,
        interface: &str,
    ) -> Result<Option<SocketAddr>, Box<dyn std::error::Error>>;
}
