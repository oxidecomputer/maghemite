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
//! ## Three-Phase Interface Lifecycle
//!
//! The mock distinguishes between three concepts that model the real system:
//!
//! 1. **Configured**: Interface has a BGP session configured (scope_map entry)
//!    - Set via `configure_interface()`
//!
//! 2. **System presence**: Interface exists on the system (system_interfaces entry)
//!    - Set via `add_system_interface()`
//!
//! 3. **NDP initialized**: NDP tx/rx loops are running for this interface
//!    - Set via `activate_ndp()` (must be called after interface appears)
//!    - In real system: happens when interface is detected by monitor thread
//!
//! ## Why NDP Initialization Matters
//!
//! In the real `UnnumberedManagerNdp`:
//! - When `add_interface()` is called and interface doesn't exist, NDP loops
//!   are NOT started
//! - A monitor thread polls for interface appearance and calls `activate_interface()`
//! - Only after NDP is activated can peer discovery occur
//!
//! Tests that skip `activate_ndp()` after `add_system_interface()` will fail
//! to discover peers, which correctly models the system behavior.
//!
//! ## Testing Scenarios
//!
//! - Interface configured before it exists: `configure_interface()` first,
//!   then later `add_system_interface()` + `activate_ndp()`
//! - Interface exists at configuration time: `register_interface()` does all three
//! - Interface removed while session established: `remove_system_interface()`

use crate::unnumbered::{NdpNeighbor, UnnumberedError, UnnumberedManager};
use mg_common::lock;
use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};

/// Mock implementation of UnnumberedManager for testing.
///
/// This simulates the UnnumberedManagerNdp's interface,
/// allowing tests to control when peers are discovered, expired, and
/// how scope_id maps to interface names.
///
/// The mock tracks three separate concepts:
/// - `scope_map`: Interface configuration (scope_id → interface name mapping)
/// - `system_interfaces`: Interfaces present on the system
/// - `ndp_initialized`: Interfaces with NDP tx/rx loops running
/// - `discoveries`: Discovered peer addresses (only works if NDP initialized)
#[derive(Clone)]
pub struct UnnumberedManagerMock {
    /// Map from interface name to discovered peer address.
    /// None value means no peer discovered yet or peer has expired.
    /// NOTE: Peer discovery only works if interface is in `ndp_initialized`.
    discoveries: Arc<Mutex<HashMap<String, Option<Ipv6Addr>>>>,

    /// Map from scope_id to interface name.
    /// Used by Dispatcher to route incoming link-local connections.
    scope_map: Arc<Mutex<HashMap<u32, String>>>,

    /// Reverse map from interface name to scope_id.
    /// Maintained alongside scope_map for efficient lookup.
    interface_to_scope: Arc<Mutex<HashMap<String, u32>>>,

    /// Interfaces that exist on the system (link up).
    /// Presence here means `interface_is_active()` returns true.
    system_interfaces: Arc<Mutex<HashSet<String>>>,

    /// Interfaces that have NDP tx/rx loops initialized.
    /// This models the real system where NDP must be activated before
    /// peer discovery can occur. In the real system, this is done by
    /// the monitor thread when it detects an interface has appeared.
    ndp_initialized: Arc<Mutex<HashSet<String>>>,
}

impl UnnumberedManagerMock {
    /// Create a new mock UnnumberedManager.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            discoveries: Arc::new(Mutex::new(HashMap::new())),
            scope_map: Arc::new(Mutex::new(HashMap::new())),
            interface_to_scope: Arc::new(Mutex::new(HashMap::new())),
            system_interfaces: Arc::new(Mutex::new(HashSet::new())),
            ndp_initialized: Arc::new(Mutex::new(HashSet::new())),
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
    // System Presence Methods
    // =========================================================================

    /// Add an interface to the system.
    ///
    /// This simulates the interface appearing on the system (e.g., link comes up).
    /// After calling this, `interface_is_active()` will return `true`.
    ///
    /// **Important**: This does NOT activate NDP. You must call `activate_ndp()`
    /// separately to simulate what the monitor thread does in the real system.
    /// Without `activate_ndp()`, peer discovery will fail.
    pub fn add_system_interface(&self, interface: &str) {
        lock!(self.system_interfaces).insert(interface.to_string());
    }

    /// Remove an interface from the system.
    ///
    /// This simulates the interface disappearing from the system (e.g., link goes
    /// down, interface deleted). Does NOT affect configuration (scope_map).
    ///
    /// Also removes NDP initialization and any discovered peer for this interface.
    ///
    /// After calling this, `interface_is_active()` will return `false`.
    pub fn remove_system_interface(&self, interface: &str) {
        lock!(self.system_interfaces).remove(interface);
        lock!(self.ndp_initialized).remove(interface);
        lock!(self.discoveries).remove(interface);
    }

    // =========================================================================
    // NDP Initialization Methods
    // =========================================================================

    /// Activate NDP for an interface.
    ///
    /// This simulates the monitor thread detecting an interface has appeared
    /// and starting NDP tx/rx loops for it. In the real system, this is done
    /// by `UnnumberedManagerNdp::activate_interface()`.
    ///
    /// **Preconditions**:
    /// - Interface must be configured (via `configure_interface()`)
    /// - Interface must be on system (via `add_system_interface()`)
    ///
    /// After calling this, peer discovery will work for this interface.
    ///
    /// # Returns
    /// - `Ok(())` if NDP was activated
    /// - `Err(reason)` if preconditions not met
    pub fn activate_ndp(&self, interface: &str) -> Result<(), &'static str> {
        // Check interface is on system
        if !lock!(self.system_interfaces).contains(interface) {
            return Err("interface not on system");
        }

        // Check interface is configured
        if !lock!(self.interface_to_scope).contains_key(interface) {
            return Err("interface not configured");
        }

        // Initialize NDP and prepare for peer discovery
        lock!(self.ndp_initialized).insert(interface.to_string());
        // Initialize discoveries entry (no peer yet)
        lock!(self.discoveries).insert(interface.to_string(), None);

        Ok(())
    }

    /// Deactivate NDP for an interface.
    ///
    /// This simulates the monitor thread detecting an interface has been removed
    /// and stopping NDP tx/rx loops. Clears any discovered peer.
    pub fn deactivate_ndp(&self, interface: &str) {
        lock!(self.ndp_initialized).remove(interface);
        lock!(self.discoveries).remove(interface);
    }

    /// Check if NDP is initialized for an interface.
    pub fn is_ndp_initialized(&self, interface: &str) -> bool {
        lock!(self.ndp_initialized).contains(interface)
    }

    // =========================================================================
    // Convenience Methods
    // =========================================================================

    /// Register an interface with a scope_id (convenience method).
    ///
    /// This is equivalent to calling `configure_interface()`, `add_system_interface()`,
    /// and `activate_ndp()`. Useful for tests that don't need to test
    /// the "interface not present" or "NDP not initialized" scenarios.
    pub fn register_interface(&self, interface: String, scope_id: u32) {
        self.configure_interface(interface.clone(), scope_id);
        self.add_system_interface(&interface);
        self.activate_ndp(&interface)
            .expect("activate_ndp should succeed after configure + add_system");
    }

    /// Unregister an interface completely (convenience method).
    ///
    /// Removes the interface from configuration, system presence, NDP state,
    /// and discoveries.
    pub fn unregister_interface(&self, interface: &str) -> Option<u32> {
        self.remove_system_interface(interface);
        self.unconfigure_interface(interface)
    }

    /// Simulate NDP discovering a peer on an interface.
    ///
    /// This models receiving a Router Advertisement from a peer. In the real
    /// system, this can only happen if NDP tx/rx loops are running.
    ///
    /// # Arguments
    /// * `interface` - The interface name
    /// * `peer_addr` - The discovered peer's link-local IPv6 address
    ///
    /// # Returns
    /// - `Ok(())` if peer was discovered
    /// - `Err("ndp not initialized")` if NDP is not activated for this interface
    /// - `Err("interface not on system")` if interface doesn't exist
    pub fn discover_peer(
        &self,
        interface: &str,
        peer_addr: Ipv6Addr,
    ) -> Result<(), &'static str> {
        // NDP must be initialized to receive Router Advertisements
        if !lock!(self.ndp_initialized).contains(interface) {
            return Err("ndp not initialized");
        }

        let mut discoveries = lock!(self.discoveries);
        if let Some(entry) = discoveries.get_mut(interface) {
            *entry = Some(peer_addr);
            Ok(())
        } else {
            Err("interface not in discoveries")
        }
    }

    /// Simulate NDP peer expiring on an interface.
    ///
    /// This models a Router Advertisement timing out. Can only happen if NDP
    /// is initialized for the interface.
    ///
    /// # Returns
    /// - `Ok(previous_peer)` if expiry was processed
    /// - `Err("ndp not initialized")` if NDP is not activated
    pub fn expire_peer(
        &self,
        interface: &str,
    ) -> Result<Option<Ipv6Addr>, &'static str> {
        // NDP must be initialized
        if !lock!(self.ndp_initialized).contains(interface) {
            return Err("ndp not initialized");
        }

        let mut discoveries = lock!(self.discoveries);
        if let Some(entry) = discoveries.get_mut(interface) {
            Ok(entry.take())
        } else {
            Err("interface not in discoveries")
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
        // Interface is active if it exists on the system
        lock!(self.system_interfaces).contains(interface)
    }

    fn get_interface_by_scope(&self, scope_id: u32) -> Option<String> {
        Self::get_interface_for_scope(self, scope_id)
    }

    fn get_neighbor_by_interface(
        &self,
        interface: &str,
    ) -> Result<Option<NdpNeighbor>, UnnumberedError> {
        // Must be on system
        if !lock!(self.system_interfaces).contains(interface) {
            return Err(UnnumberedError::InterfaceNotFound(
                interface.to_string(),
            ));
        }

        // If NDP not initialized, we can't have discovered a neighbor
        if !lock!(self.ndp_initialized).contains(interface) {
            // Interface exists but NDP not running - return None (no neighbor)
            return Ok(None);
        }

        // Use get_neighbor which handles the NdpNeighbor construction
        Ok(self.get_neighbor(interface))
    }
}
