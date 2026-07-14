// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
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
    /// Status of every interface configured for unnumbered operation,
    /// keyed by interface name.
    pub interfaces: BTreeMap<String, UnnumberedInterfaceStatus>,
}

/// Status of an interface configured for unnumbered operation.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub enum UnnumberedInterfaceStatus {
    /// Configured but not yet available on the system.
    Pending {
        /// Configured router lifetime (seconds)
        router_lifetime: u16,
    },
    /// Active for unnumbered operation.
    Active {
        /// Local IPv6 link-local address
        local_address: Ipv6Addr,
        /// IPv6 scope ID (interface index)
        scope_id: u32,
        /// Router lifetime advertised by this router (seconds)
        router_lifetime: u16,
        /// Information about the discovered peer. None if no peer has been
        /// discovered or the discovered entry has expired.
        discovered_peer: Option<DiscoveredRouter>,
        /// Runtime state for router discovery on this interface
        runtime_state: RouterDiscoveryRuntimeState,
    },
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
    /// Information about the discovered peer. None if no peer has been
    /// discovered or the discovered entry has expired.
    pub discovered_peer: Option<DiscoveredRouter>,
    /// Runtime state for router discovery on this interface
    pub runtime_state: RouterDiscoveryRuntimeState,
}

/// Information about a router discovered through router advertisements.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct DiscoveredRouter {
    /// Router IPv6 address
    pub address: Ipv6Addr,
    /// Time elapsed since the router was first discovered
    pub time_since_discovered: Duration,
    /// Time elapsed since the most recent Router Advertisement was received
    pub time_since_last_rx: Duration,
    /// Effective reachable time governing expiry of this entry
    pub effective_reachable_time: Duration,
    /// Router lifetime from RA (seconds)
    pub router_lifetime: u16,
    /// Reachable time from RA (milliseconds)
    pub reachable_time: u32,
    /// Retransmit timer from RA (milliseconds)
    pub retrans_timer: u32,
}

impl From<DiscoveredRouter> for v5::ndp::NdpPeer {
    fn from(router: DiscoveredRouter) -> Self {
        // The legacy API reported wall-clock ISO 8601 timestamps and a
        // human-readable time-until-expiry. Expired peers never reach this
        // conversion — they are represented as a missing discovered_peer —
        // so `expired` is always false here.
        let to_iso8601 = |elapsed: Duration| {
            chrono::Duration::from_std(elapsed)
                .ok()
                .and_then(|d| Utc::now().checked_sub_signed(d))
                .unwrap_or(DateTime::<Utc>::MIN_UTC)
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        };
        let time_until_expiry = router.time_until_expiration();
        Self {
            address: router.address,
            discovered_at: to_iso8601(router.time_since_discovered),
            last_advertisement: to_iso8601(router.time_since_last_rx),
            router_lifetime: router.router_lifetime,
            reachable_time: router.reachable_time,
            retrans_timer: router.retrans_timer,
            expired: false,
            time_until_expiry: Some(client_common::format_duration_human(
                time_until_expiry,
            )),
        }
    }
}

impl From<UnnumberedManagerState> for v5::ndp::NdpManagerState {
    fn from(state: UnnumberedManagerState) -> Self {
        // The legacy API split the interface map into separate pending and
        // active lists.
        let mut pending_interfaces = Vec::new();
        let mut active_interfaces = Vec::new();
        for (interface, status) in state.interfaces {
            match status {
                UnnumberedInterfaceStatus::Pending { router_lifetime } => {
                    pending_interfaces.push(v5::ndp::NdpPendingInterface {
                        interface,
                        router_lifetime,
                    });
                }
                UnnumberedInterfaceStatus::Active { .. } => {
                    active_interfaces.push(interface);
                }
            }
        }
        Self {
            monitor_thread_running: state.monitor_running,
            pending_interfaces,
            active_interfaces,
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
            interfaces: BTreeMap::from([
                (
                    "eth0".to_string(),
                    UnnumberedInterfaceStatus::Pending {
                        router_lifetime: 30,
                    },
                ),
                (
                    "eth1".to_string(),
                    UnnumberedInterfaceStatus::Active {
                        local_address: link_local(1),
                        scope_id: 7,
                        router_lifetime: 123,
                        discovered_peer: None,
                        runtime_state: RouterDiscoveryRuntimeState {
                            tx_running: true,
                            rx_running: true,
                        },
                    },
                ),
            ]),
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
                time_since_discovered: Duration::from_secs(60),
                time_since_last_rx: Duration::from_secs(1),
                effective_reachable_time: Duration::from_secs(42),
                router_lifetime: 42,
                reachable_time: 5000,
                retrans_timer: 1000,
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
        // Timestamps are derived from Utc::now() minus the elapsed
        // durations, so just check they parse as RFC 3339 and are ordered.
        let discovered_at: DateTime<Utc> = peer.discovered_at.parse().unwrap();
        let last_advertisement: DateTime<Utc> =
            peer.last_advertisement.parse().unwrap();
        assert!(discovered_at < last_advertisement);
        assert_eq!(peer.router_lifetime, 42);
        assert_eq!(peer.reachable_time, 5000);
        assert_eq!(peer.retrans_timer, 1000);
        assert!(!peer.expired);
        assert_eq!(peer.time_until_expiry.as_deref(), Some("41s 0ms"));
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
