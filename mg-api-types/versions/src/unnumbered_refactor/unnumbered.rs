// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v5;

/// Selector for unnumbered interface queries.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct UnnumberedInterfaceSelector {
    /// Interface name
    pub interface: String,
}

/// Runtime state for router discovery on an interface.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct RouterDiscoveryRuntimeState {
    /// Whether the TX loop is running
    pub tx_running: bool,
    /// Whether the RX loop is running
    pub rx_running: bool,
}

/// Unnumbered manager state showing overall health and interface status.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct UnnumberedManagerState {
    /// Whether the interface monitor thread is running
    pub monitor_running: bool,
    /// Interfaces configured but not yet available on the system
    pub pending_interfaces: Vec<PendingUnnumberedInterface>,
    /// Interfaces currently active for unnumbered operation
    pub active_interfaces: Vec<String>,
}

/// Information about a pending unnumbered interface.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct PendingUnnumberedInterface {
    /// Interface name
    pub interface: String,
    /// Configured router lifetime (seconds)
    pub router_lifetime: u16,
}

/// Unnumbered state for an interface.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct UnnumberedInterface {
    /// Interface name (e.g., "qsfp0")
    pub interface: String,
    /// Local IPv6 link-local address
    pub local_address: Ipv6Addr,
    /// IPv6 scope ID (interface index)
    pub scope_id: u32,
    /// Router lifetime advertised by this router (seconds)
    pub router_lifetime: u16,
    /// Information about discovered peer (if any, including expired)
    pub discovered_peer: Option<DiscoveredRouter>,
    /// Runtime state for router discovery on this interface
    pub runtime_state: RouterDiscoveryRuntimeState,
}

/// Information about a router discovered through router advertisements.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct DiscoveredRouter {
    /// Router IPv6 address
    pub address: Ipv6Addr,
    /// When the router was first discovered (ISO 8601 timestamp)
    pub discovered_at: String,
    /// When the most recent Router Advertisement was received (ISO 8601
    /// timestamp)
    pub last_advertisement: String,
    /// Router lifetime from RA (seconds)
    pub router_lifetime: u16,
    /// Reachable time from RA (milliseconds)
    pub reachable_time: u32,
    /// Retransmit timer from RA (milliseconds)
    pub retrans_timer: u32,
    /// Whether the discovered router entry has expired
    pub expired: bool,
    /// Time until expiry (human-readable), or None if already expired
    pub time_until_expiry: Option<String>,
}

impl From<PendingUnnumberedInterface> for v5::ndp::NdpPendingInterface {
    fn from(interface: PendingUnnumberedInterface) -> Self {
        Self {
            interface: interface.interface,
            router_lifetime: interface.router_lifetime,
        }
    }
}

impl From<DiscoveredRouter> for v5::ndp::NdpPeer {
    fn from(router: DiscoveredRouter) -> Self {
        Self {
            address: router.address,
            discovered_at: router.discovered_at,
            last_advertisement: router.last_advertisement,
            router_lifetime: router.router_lifetime,
            reachable_time: router.reachable_time,
            retrans_timer: router.retrans_timer,
            expired: router.expired,
            time_until_expiry: router.time_until_expiry,
        }
    }
}

impl From<UnnumberedManagerState> for v5::ndp::NdpManagerState {
    fn from(state: UnnumberedManagerState) -> Self {
        Self {
            monitor_thread_running: state.monitor_running,
            pending_interfaces: state
                .pending_interfaces
                .into_iter()
                .map(Into::into)
                .collect(),
            active_interfaces: state.active_interfaces,
        }
    }
}

impl From<RouterDiscoveryRuntimeState> for v5::ndp::NdpThreadState {
    fn from(state: RouterDiscoveryRuntimeState) -> Self {
        Self {
            tx_running: state.tx_running,
            rx_running: state.rx_running,
        }
    }
}

impl From<UnnumberedInterface> for v5::ndp::NdpInterface {
    fn from(interface: UnnumberedInterface) -> Self {
        Self {
            interface: interface.interface,
            local_address: interface.local_address,
            scope_id: interface.scope_id,
            router_lifetime: interface.router_lifetime,
            discovered_peer: interface.discovered_peer.map(Into::into),
            thread_state: Some(interface.runtime_state.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link_local(n: u16) -> Ipv6Addr {
        format!("fe80::{n}").parse().unwrap()
    }

    #[test]
    fn manager_state_downgrades_to_legacy_ndp_shape() {
        let state = UnnumberedManagerState {
            monitor_running: true,
            pending_interfaces: vec![PendingUnnumberedInterface {
                interface: "eth0".into(),
                router_lifetime: 30,
            }],
            active_interfaces: vec!["eth1".into()],
        };

        let legacy: v5::ndp::NdpManagerState = state.into();

        assert!(legacy.monitor_thread_running);
        assert_eq!(legacy.pending_interfaces.len(), 1);
        assert_eq!(legacy.pending_interfaces[0].interface, "eth0");
        assert_eq!(legacy.pending_interfaces[0].router_lifetime, 30);
        assert_eq!(legacy.active_interfaces, vec!["eth1".to_string()]);
    }

    #[test]
    fn interface_downgrades_to_legacy_ndp_shape() {
        let interface = UnnumberedInterface {
            interface: "eth0".into(),
            local_address: link_local(1),
            scope_id: 7,
            router_lifetime: 123,
            discovered_peer: Some(DiscoveredRouter {
                address: link_local(2),
                discovered_at: "2026-06-24T12:00:00Z".into(),
                last_advertisement: "2026-06-24T12:00:01Z".into(),
                router_lifetime: 42,
                reachable_time: 5000,
                retrans_timer: 1000,
                expired: false,
                time_until_expiry: Some("41s".into()),
            }),
            runtime_state: RouterDiscoveryRuntimeState {
                tx_running: true,
                rx_running: false,
            },
        };

        let legacy: v5::ndp::NdpInterface = interface.into();

        assert_eq!(legacy.interface, "eth0");
        assert_eq!(legacy.local_address, link_local(1));
        assert_eq!(legacy.scope_id, 7);
        assert_eq!(legacy.router_lifetime, 123);
        let peer = legacy.discovered_peer.unwrap();
        assert_eq!(peer.address, link_local(2));
        assert_eq!(peer.discovered_at, "2026-06-24T12:00:00Z");
        assert_eq!(peer.last_advertisement, "2026-06-24T12:00:01Z");
        assert_eq!(peer.router_lifetime, 42);
        assert_eq!(peer.reachable_time, 5000);
        assert_eq!(peer.retrans_timer, 1000);
        assert!(!peer.expired);
        assert_eq!(peer.time_until_expiry.as_deref(), Some("41s"));
        let thread_state = legacy.thread_state.unwrap();
        assert!(thread_state.tx_running);
        assert!(!thread_state.rx_running);
    }

    #[test]
    fn interface_without_discovered_router_downgrades_to_none_peer() {
        let interface = UnnumberedInterface {
            interface: "eth0".into(),
            local_address: link_local(1),
            scope_id: 7,
            router_lifetime: 123,
            discovered_peer: None,
            runtime_state: RouterDiscoveryRuntimeState {
                tx_running: true,
                rx_running: true,
            },
        };

        let legacy: v5::ndp::NdpInterface = interface.into();

        assert!(legacy.discovered_peer.is_none());
        assert!(legacy.thread_state.is_some());
    }
}
