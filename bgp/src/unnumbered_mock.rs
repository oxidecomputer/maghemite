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

use crate::unnumbered::UnnumberedManager;
use mg_common::lock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// Mock implementation of UnnumberedManager for testing.
///
/// This simulates the UnnumberedManagerNdp's interface,
/// allowing tests to control when peers are discovered, expired, and
/// how scope_id maps to interface names.
#[derive(Clone)]
pub struct UnnumberedManagerMock {
    /// Map from interface name to discovered peer address.
    /// None means no peer discovered yet or peer has expired.
    discoveries: Arc<Mutex<HashMap<String, Option<SocketAddr>>>>,

    /// Map from scope_id to interface name.
    /// Used by Dispatcher to route incoming link-local connections.
    scope_map: Arc<Mutex<HashMap<u32, String>>>,
}

impl UnnumberedManagerMock {
    /// Create a new mock UnnumberedManager.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            discoveries: Arc::new(Mutex::new(HashMap::new())),
            scope_map: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Register an interface with a scope_id.
    ///
    /// This simulates adding an interface to the NDP manager.
    /// The interface starts with no discovered peer.
    pub fn register_interface(&self, interface: String, scope_id: u32) {
        lock!(self.discoveries).insert(interface.clone(), None);
        lock!(self.scope_map).insert(scope_id, interface);
    }

    /// Unregister an interface.
    ///
    /// This simulates removing an interface from the NDP manager.
    pub fn unregister_interface(&self, interface: &str) -> Option<u32> {
        lock!(self.discoveries).remove(interface);

        // Find and remove the scope_id mapping
        let mut scope_map = lock!(self.scope_map);
        let scope_id = scope_map
            .iter()
            .find(|(_, iface)| iface.as_str() == interface)
            .map(|(id, _)| *id);

        if let Some(id) = scope_id {
            scope_map.remove(&id);
        }

        scope_id
    }

    /// Simulate NDP discovering a peer on an interface.
    ///
    /// # Arguments
    /// * `interface` - The interface name
    /// * `peer` - The discovered peer address (should be link-local with scope_id set)
    ///
    /// # Returns
    /// `Ok(())` if interface is registered, `Err(())` if not.
    #[allow(clippy::result_unit_err)]
    pub fn discover_peer(
        &self,
        interface: &str,
        peer: SocketAddr,
    ) -> Result<(), ()> {
        let mut discoveries = lock!(self.discoveries);
        if let Some(entry) = discoveries.get_mut(interface) {
            *entry = Some(peer);
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
    pub fn expire_peer(
        &self,
        interface: &str,
    ) -> Result<Option<SocketAddr>, ()> {
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
    /// This simulates querying `UnnumberedManagerNdp::get_neighbor_for_interface()`.
    pub fn get_neighbor(&self, interface: &str) -> Option<SocketAddr> {
        lock!(self.discoveries).get(interface).and_then(|opt| *opt)
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
    pub fn get_all_interfaces(&self) -> Vec<(String, u32, Option<SocketAddr>)> {
        let discoveries = lock!(self.discoveries);
        let scope_map = lock!(self.scope_map);

        discoveries
            .iter()
            .filter_map(|(iface, peer)| {
                // Find scope_id for this interface
                scope_map
                    .iter()
                    .find(|(_, i)| i.as_str() == iface)
                    .map(|(scope_id, _)| (iface.clone(), *scope_id, *peer))
            })
            .collect()
    }
}

/// Implement UnnumberedManager trait for use in tests.
///
/// This allows UnnumberedManagerMock to be used as the unnumbered_manager parameter
/// when creating unnumbered BGP sessions in tests.
impl UnnumberedManager for UnnumberedManagerMock {
    fn get_interface_for_scope(&self, scope_id: u32) -> Option<String> {
        Self::get_interface_for_scope(self, scope_id)
    }

    fn get_neighbor_for_interface(
        &self,
        interface: &str,
    ) -> Result<Option<std::net::SocketAddr>, Box<dyn std::error::Error>> {
        // UnnumberedManagerMock returns None for unregistered interfaces,
        // but UnnumberedManager expects an error for invalid interfaces
        let discoveries = lock!(self.discoveries);
        if discoveries.contains_key(interface) {
            Ok(discoveries.get(interface).and_then(|opt| *opt))
        } else {
            Err(format!("Interface '{}' not registered", interface).into())
        }
    }
}
