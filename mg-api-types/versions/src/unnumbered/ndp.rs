// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Selector for NDP interface queries
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NdpInterfaceSelector {
    /// ASN of the router
    pub asn: u32,
    /// Interface name
    pub interface: String,
}

/// NDP manager state showing overall health and interface status
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NdpManagerState {
    /// Whether the interface monitor thread is running
    pub monitor_thread_running: bool,
    /// Interfaces configured but not yet available on the system
    pub pending_interfaces: Vec<NdpPendingInterface>,
    /// Interfaces currently active in NDP (available on system)
    pub active_interfaces: Vec<String>,
}

/// Information about a pending NDP interface
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NdpPendingInterface {
    /// Interface name
    pub interface: String,
    /// Configured router lifetime (seconds)
    pub router_lifetime: u16,
}

/// Thread state for NDP rx/tx loops on an interface
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NdpThreadState {
    /// Whether the TX loop thread is running
    pub tx_running: bool,
    /// Whether the RX loop thread is running
    pub rx_running: bool,
}

/// NDP state for an interface
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NdpInterface {
    /// Interface name (e.g., "qsfp0")
    pub interface: String,
    /// Local IPv6 link-local address
    pub local_address: Ipv6Addr,
    /// IPv6 scope ID (interface index)
    pub scope_id: u32,
    /// Router lifetime advertised by this router (seconds)
    pub router_lifetime: u16,
    /// Information about discovered peer (if any, including expired)
    pub discovered_peer: Option<NdpPeer>,
    /// Thread state for rx/tx loops (None if interface not active in NDP)
    pub thread_state: Option<NdpThreadState>,
}

/// Information about a discovered NDP peer
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NdpPeer {
    /// Peer IPv6 address
    pub address: Ipv6Addr,
    /// When the peer was first discovered (ISO 8601 timestamp)
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
    /// Whether the peer entry has expired
    pub expired: bool,
    /// Time until expiry (human-readable), or None if already expired
    pub time_until_expiry: Option<String>,
}
