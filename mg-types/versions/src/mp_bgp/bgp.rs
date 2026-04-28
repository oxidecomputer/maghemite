// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bgp_types_versions::v4::messages::Afi;
use rdb_types_versions::v1::prefix::Prefix;
use rdb_types_versions::v4::policy::{
    ImportExportPolicy4, ImportExportPolicy6,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;

/// V2 API neighbor reset operations with per-AF support
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub enum NeighborResetOp {
    /// Hard reset - closes TCP connection and restarts session
    Hard,
    /// Soft inbound reset - sends route refresh for specified AF(s)
    /// None means all negotiated AFs
    SoftInbound(Option<Afi>),
    /// Soft outbound reset - re-advertises routes for specified AF(s)
    /// None means all negotiated AFs
    SoftOutbound(Option<Afi>),
}

impl From<v1::bgp::NeighborResetOp> for NeighborResetOp {
    fn from(op: v1::bgp::NeighborResetOp) -> Self {
        match op {
            v1::bgp::NeighborResetOp::Hard => NeighborResetOp::Hard,
            v1::bgp::NeighborResetOp::SoftInbound => {
                NeighborResetOp::SoftInbound(Some(Afi::Ipv4))
            }
            v1::bgp::NeighborResetOp::SoftOutbound => {
                NeighborResetOp::SoftOutbound(Some(Afi::Ipv4))
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NeighborResetRequest {
    pub asn: u32,
    pub addr: IpAddr,
    pub op: NeighborResetOp,
}

impl From<v1::bgp::NeighborResetRequest> for NeighborResetRequest {
    fn from(req: v1::bgp::NeighborResetRequest) -> Self {
        Self {
            asn: req.asn,
            addr: req.addr,
            op: req.op.into(),
        }
    }
}

/// Jitter range with minimum and maximum multiplier values.
/// When applied to a timer, the timer duration is multiplied by a random value
/// within [min, max] to help break synchronization patterns.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct JitterRange {
    /// Minimum jitter multiplier (typically 0.75 or similar)
    pub min: f64,
    /// Maximum jitter multiplier (typically 1.0 or similar)
    pub max: f64,
}

impl std::str::FromStr for JitterRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() != 2 {
            return Err(
                "jitter range must be in format 'min,max' (e.g., '0.75,1.0')"
                    .to_string(),
            );
        }
        let min = parts[0].trim().parse::<f64>().map_err(|_| {
            format!("min value '{}' is not a valid float", parts[0].trim())
        })?;
        let max = parts[1].trim().parse::<f64>().map_err(|_| {
            format!("max value '{}' is not a valid float", parts[1].trim())
        })?;
        Ok(JitterRange { min, max })
    }
}

/// Per-address-family configuration for IPv4 Unicast
#[derive(
    Debug, Default, Clone, Deserialize, Serialize, JsonSchema, PartialEq,
)]
pub struct Ipv4UnicastConfig {
    pub nexthop: Option<IpAddr>,
    pub import_policy: ImportExportPolicy4,
    pub export_policy: ImportExportPolicy4,
}

/// Per-address-family configuration for IPv6 Unicast
#[derive(
    Debug, Default, Clone, Deserialize, Serialize, JsonSchema, PartialEq,
)]
pub struct Ipv6UnicastConfig {
    pub nexthop: Option<IpAddr>,
    pub import_policy: ImportExportPolicy6,
    pub export_policy: ImportExportPolicy6,
}

/// BGP peer parameters for v4-v6 API (lacks src_addr/src_port).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[schemars(rename = "BgpPeerParameters")]
pub struct BgpPeerParameters {
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub passive: bool,
    pub remote_asn: Option<u32>,
    pub min_ttl: Option<u8>,
    pub md5_auth_key: Option<String>,
    pub multi_exit_discriminator: Option<u32>,
    pub communities: Vec<u32>,
    pub local_pref: Option<u32>,
    pub enforce_first_as: bool,
    pub vlan_id: Option<u16>,
    pub ipv4_unicast: Option<Ipv4UnicastConfig>,
    pub ipv6_unicast: Option<Ipv6UnicastConfig>,
    pub deterministic_collision_resolution: bool,
    pub idle_hold_jitter: Option<JitterRange>,
    pub connect_retry_jitter: Option<JitterRange>,
}

/// BGP peer config for v4-v6 API (lacks src_addr/src_port).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[schemars(rename = "BgpPeerConfig")]
pub struct BgpPeerConfig {
    pub host: SocketAddr,
    pub name: String,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

/// Neighbor configuration for v4-v6 API (lacks src_addr/src_port).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[schemars(rename = "Neighbor")]
pub struct Neighbor {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub host: SocketAddr,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

/// Unnumbered BGP peer config for v4-v6 API (lacks src_addr/src_port).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[schemars(rename = "UnnumberedBgpPeerConfig")]
pub struct UnnumberedBgpPeerConfig {
    pub interface: String,
    pub name: String,
    pub router_lifetime: u16,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

/// Apply request for v4-v6 API (lacks src_addr/src_port in peer configs).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[schemars(rename = "ApplyRequest")]
pub struct ApplyRequest {
    pub asn: u32,
    pub originate: Vec<Prefix>,
    pub checker: Option<v1::bgp::CheckerSource>,
    pub shaper: Option<v1::bgp::ShaperSource>,
    pub peers: HashMap<String, Vec<BgpPeerConfig>>,
    #[serde(default)]
    pub unnumbered_peers: HashMap<String, Vec<UnnumberedBgpPeerConfig>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct DynamicTimerInfo {
    pub configured: Duration,
    pub negotiated: Duration,
    pub remaining: Duration,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AfiSafi {
    pub(crate) afi: u16,
    pub(crate) safi: u8,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub enum BgpCapability {
    MultiprotocolExtensions(AfiSafi),
    RouteRefresh,
    FourOctetAsn(u32),
    AddPath { elements: Vec<AfiSafi> },
    Unknown(u8),
}

/// Timer information for static (non-negotiated) timers
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct StaticTimerInfo {
    pub configured: Duration,
    pub remaining: Duration,
}

/// Session-level counters that persist across connection changes
/// These serve as aggregate counters across all connections for the session
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PeerCounters {
    // FSM Counters
    pub connection_retries: u64,
    pub active_connections_accepted: u64,
    pub active_connections_declined: u64,
    pub passive_connections_accepted: u64,
    pub passive_connections_declined: u64,
    pub transitions_to_idle: u64,
    pub transitions_to_connect: u64,
    pub transitions_to_active: u64,
    pub transitions_to_open_sent: u64,
    pub transitions_to_open_confirm: u64,
    pub transitions_to_connection_collision: u64,
    pub transitions_to_session_setup: u64,
    pub transitions_to_established: u64,
    pub hold_timer_expirations: u64,
    pub idle_hold_timer_expirations: u64,

    // NLRI counters
    pub prefixes_advertised: u64,
    pub prefixes_imported: u64,

    // Message counters
    pub keepalives_sent: u64,
    pub keepalives_received: u64,
    pub route_refresh_sent: u64,
    pub route_refresh_received: u64,
    pub opens_sent: u64,
    pub opens_received: u64,
    pub notifications_sent: u64,
    pub notifications_received: u64,
    pub updates_sent: u64,
    pub updates_received: u64,

    // Message error counters
    pub unexpected_update_message: u64,
    pub unexpected_keepalive_message: u64,
    pub unexpected_open_message: u64,
    pub unexpected_route_refresh_message: u64,
    pub unexpected_notification_message: u64,
    pub update_nexhop_missing: u64,
    pub open_handle_failures: u64,
    pub unnegotiated_address_family: u64,

    // Send failure counters
    pub notification_send_failure: u64,
    pub open_send_failure: u64,
    pub keepalive_send_failure: u64,
    pub route_refresh_send_failure: u64,
    pub update_send_failure: u64,

    // Connection failure counters
    pub tcp_connection_failure: u64,
    pub md5_auth_failures: u64,
    pub connector_panics: u64,
}
