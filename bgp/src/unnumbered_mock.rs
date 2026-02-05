// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Mock implementation of UnnumberedManager for testing.
//!
//! This module provides a controllable NDP state simulator that allows tests to:
//! - Simulate peer discovery on interfaces
//! - Trigger peer expiry
//! - Map scope_id to interface names (for Dispatcher routing)
//! - Verify SessionRunner queries NDP state correctly
//!
//! ## Configuration vs System Presence
//!
//! The mock distinguishes between two concepts:
//! - **Configured**: Interface has a BGP session configured (scope_map entry)
//! - **System presence**: Interface exists on the system (discoveries map entry)
//!
//! This allows testing scenarios where:
//! - Interface is configured but doesn't exist yet
//! - Interface appears after session is configured
//! - Interface is removed while session is established

use crate::unnumbered::{NdpNeighbor, UnnumberedError, UnnumberedManager};
use mg_common::lock;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};

/// Mock implementation of UnnumberedManager for testing.
///
/// This simulates the UnnumberedManagerNdp's interface,
/// allowing tests to control when peers are discovered, expired, and
/// how scope_id maps to interface names.
///
/// The mock tracks two separate concepts:
/// - `scope_map`: Interface configuration (scope_id → interface name mapping)
/// - `discoveries`: Interface system presence (interface → discovered peer)
#[derive(Clone)]
pub struct UnnumberedManagerMock {
    /// Map from interface name to discovered peer address.
    /// Presence in this map indicates the interface exists on the system.
    /// None value means no peer discovered yet or peer has expired.
    discoveries: Arc<Mutex<HashMap<String, Option<Ipv6Addr>>>>,

    /// Map from scope_id to interface name.
    /// Used by Dispatcher to route incoming link-local connections.
    scope_map: Arc<Mutex<HashMap<u32, String>>>,

    /// Reverse map from interface name to scope_id.
    /// Maintained alongside scope_map for efficient lookup.
    interface_to_scope: Arc<Mutex<HashMap<String, u32>>>,
}

impl UnnumberedManagerMock {
    /// Create a new mock UnnumberedManager.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            discoveries: Arc::new(Mutex::new(HashMap::new())),
            scope_map: Arc::new(Mutex::new(HashMap::new())),
            interface_to_scope: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    // =========================================================================
    // Configuration Methods (scope_map)
    // =========================================================================

    /// Configure an interface with a scope_id mapping.
    ///
    /// This establishes the scope_id → interface name mapping used by Dispatcher
    /// to route incoming connections. Does NOT add the interface to the system.
    ///
    /// Use `add_system_interface()` separately to simulate the interface
    /// appearing on the system.
    pub fn configure_interface(&self, interface: String, scope_id: u32) {
        lock!(self.scope_map).insert(scope_id, interface.clone());
        lock!(self.interface_to_scope).insert(interface, scope_id);
    }

    /// Remove interface configuration.
    ///
    /// Removes the scope_id → interface mapping. Does NOT affect system presence.
    pub fn unconfigure_interface(&self, interface: &str) -> Option<u32> {
        let scope_id = lock!(self.interface_to_scope).remove(interface)?;
        lock!(self.scope_map).remove(&scope_id);
        Some(scope_id)
    }

    // =========================================================================
    // System Presence Methods (discoveries)
    // =========================================================================

    /// Add an interface to the system.
    ///
    /// This simulates the interface appearing on the system (e.g., link comes up).
    /// The interface starts with no discovered peer.
    ///
    /// After calling this, `interface_is_active()` will return `true` for this interface.
    pub fn add_system_interface(&self, interface: &str) {
        lock!(self.discoveries).insert(interface.to_string(), None);
    }

    /// Remove an interface from the system.
    ///
    /// This simulates the interface disappearing from the system (e.g., link goes
    /// down, interface deleted). Does NOT affect configuration (scope_map).
    ///
    /// After calling this, `interface_is_active()` will return `false` for this interface.
    pub fn remove_system_interface(&self, interface: &str) {
        lock!(self.discoveries).remove(interface);
    }

    // =========================================================================
    // Convenience Methods
    // =========================================================================

    /// Register an interface with a scope_id (convenience method).
    ///
    /// This is equivalent to calling both `configure_interface()` and
    /// `add_system_interface()`. Useful for tests that don't need to test
    /// the "interface not present" scenario.
    pub fn register_interface(&self, interface: String, scope_id: u32) {
        self.configure_interface(interface.clone(), scope_id);
        self.add_system_interface(&interface);
    }

    /// Unregister an interface completely (convenience method).
    ///
    /// Removes the interface from both configuration (scope_map) and system
    /// presence (discoveries).
    pub fn unregister_interface(&self, interface: &str) -> Option<u32> {
        self.remove_system_interface(interface);
        self.unconfigure_interface(interface)
    }

    /// Simulate NDP discovering a peer on an interface.
    ///
    /// # Arguments
    /// * `interface` - The interface name
    /// * `peer_addr` - The discovered peer's link-local IPv6 address
    ///
    /// # Returns
    /// `Ok(())` if interface is registered, `Err(())` if not.
    #[allow(clippy::result_unit_err)]
    pub fn discover_peer(
        &self,
        interface: &str,
        peer_addr: Ipv6Addr,
    ) -> Result<(), ()> {
        let mut discoveries = lock!(self.discoveries);
        if let Some(entry) = discoveries.get_mut(interface) {
            *entry = Some(peer_addr);
            Ok(())
        } else {
            Err(())
        }
    }

    /// Simulate NDP peer expiring on an interface.
    ///
    /// # Returns
    /// `Ok(previous_peer)` if interface was registered, `Err(())` if not.
    #[allow(clippy::result_unit_err)]
    pub fn expire_peer(&self, interface: &str) -> Result<Option<Ipv6Addr>, ()> {
        let mut discoveries = lock!(self.discoveries);
        if let Some(entry) = discoveries.get_mut(interface) {
            Ok(entry.take())
        } else {
            Err(())
        }
    }

    /// Get the currently discovered peer for an interface.
    ///
    /// Returns `None` if no peer has been discovered or if the peer has expired.
    pub fn get_neighbor(&self, interface: &str) -> Option<NdpNeighbor> {
        let addr = lock!(self.discoveries)
            .get(interface)
            .and_then(|opt| *opt)?;
        let scope_id = *lock!(self.interface_to_scope).get(interface)?;
        Some(NdpNeighbor { addr, scope_id })
    }

    /// Get the interface name for a given scope_id.
    ///
    /// This simulates querying `UnnumberedManagerNdp::get_interface_for_scope()`.
    /// Used by Dispatcher to route incoming link-local connections.
    pub fn get_interface_for_scope(&self, scope_id: u32) -> Option<String> {
        lock!(self.scope_map).get(&scope_id).cloned()
    }

    /// Get all registered interfaces.
    ///
    /// Returns a list of (interface_name, scope_id, discovered_peer).
    pub fn get_all_interfaces(&self) -> Vec<(String, u32, Option<Ipv6Addr>)> {
        let discoveries = lock!(self.discoveries);
        let interface_to_scope = lock!(self.interface_to_scope);

        discoveries
            .iter()
            .filter_map(|(iface, peer)| {
                let scope_id = interface_to_scope.get(iface)?;
                Some((iface.clone(), *scope_id, *peer))
            })
            .collect()
    }
}

/// Implement UnnumberedManager trait for use in tests.
///
/// This allows UnnumberedManagerMock to be used as the unnumbered_manager parameter
/// when creating unnumbered BGP sessions in tests.
impl UnnumberedManager for UnnumberedManagerMock {
    fn interface_is_active(&self, interface: &str) -> bool {
        lock!(self.discoveries).contains_key(interface)
    }

    fn get_interface_by_scope(&self, scope_id: u32) -> Option<String> {
        Self::get_interface_for_scope(self, scope_id)
    }

    fn get_neighbor_by_interface(
        &self,
        interface: &str,
    ) -> Result<Option<NdpNeighbor>, UnnumberedError> {
        if !lock!(self.discoveries).contains_key(interface) {
            return Err(UnnumberedError::InterfaceNotFound(
                interface.to_string(),
            ));
        }

        // Use get_neighbor which handles the NdpNeighbor construction
        Ok(self.get_neighbor(interface))
    }
}
