// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    config::PeerConfig,
    messages::{AddPathElement, Afi, Capability},
    session::{FsmStateKind, SessionCounters, SessionInfo},
};
use rdb::{
    ImportExportPolicy4, ImportExportPolicy6, ImportExportPolicyV1,
    PolicyAction, Prefix4, Prefix6,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    sync::atomic::Ordering,
    time::Duration,
};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Router {
    /// Autonomous system number for this router
    pub asn: u32,

    /// Id for this router
    pub id: u32,

    /// Listening address <addr>:<port>
    pub listen: String,

    /// Gracefully shut this router down.
    pub graceful_shutdown: bool,
}

/// V1 API neighbor reset operations (backwards compatibility)
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[schemars(rename = "NeighborResetOp")]
pub enum NeighborResetOpV1 {
    Hard,
    SoftInbound,
    SoftOutbound,
}

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

impl From<NeighborResetOpV1> for NeighborResetOp {
    fn from(op: NeighborResetOpV1) -> Self {
        match op {
            NeighborResetOpV1::Hard => NeighborResetOp::Hard,
            NeighborResetOpV1::SoftInbound => {
                NeighborResetOp::SoftInbound(Some(Afi::Ipv4))
            }
            NeighborResetOpV1::SoftOutbound => {
                NeighborResetOp::SoftOutbound(Some(Afi::Ipv4))
            }
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

/// Timer configuration extracted from SessionInfo.
/// This is a lightweight value type that can be cloned and passed without locks.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TimerConfig {
    pub connect_retry_time: Duration,
    pub keepalive_time: Duration,
    pub hold_time: Duration,
    pub idle_hold_time: Duration,
    pub delay_open_time: Duration,
    pub resolution: Duration,
    pub connect_retry_jitter: Option<JitterRange>,
    pub idle_hold_jitter: Option<JitterRange>,
}

impl TimerConfig {
    /// Extract timer config from SessionInfo without holding lock
    pub fn from_session_info(session: &SessionInfo) -> Self {
        Self {
            connect_retry_time: session.connect_retry_time,
            keepalive_time: session.keepalive_time,
            hold_time: session.hold_time,
            idle_hold_time: session.idle_hold_time,
            delay_open_time: session.delay_open_time,
            resolution: session.resolution,
            connect_retry_jitter: session.connect_retry_jitter,
            idle_hold_jitter: session.idle_hold_jitter,
        }
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

/// Neighbor configuration with explicit per-address-family enablement (v3 API)
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct Neighbor {
    pub asn: u32,
    pub name: String,
    pub host: SocketAddr,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub group: String,
    pub passive: bool,
    pub remote_asn: Option<u32>,
    pub min_ttl: Option<u8>,
    pub md5_auth_key: Option<String>,
    pub multi_exit_discriminator: Option<u32>,
    pub communities: Vec<u32>,
    pub local_pref: Option<u32>,
    pub enforce_first_as: bool,
    /// IPv4 Unicast address family configuration (None = disabled)
    pub ipv4_unicast: Option<Ipv4UnicastConfig>,
    /// IPv6 Unicast address family configuration (None = disabled)
    pub ipv6_unicast: Option<Ipv6UnicastConfig>,
    pub vlan_id: Option<u16>,
    pub connect_retry_jitter: Option<JitterRange>,
    pub idle_hold_jitter: Option<JitterRange>,
    pub deterministic_collision_resolution: bool,
}

impl Neighbor {
    /// Validate that at least one address family is enabled
    pub fn validate_address_families(&self) -> Result<(), String> {
        if self.ipv4_unicast.is_none() && self.ipv6_unicast.is_none() {
            return Err("at least one address family must be enabled".into());
        }
        Ok(())
    }

    /// Validate nexthop address family matches configured address families.
    /// Initially strict: IPv4 nexthop requires IPv4, IPv6 requires IPv6.
    /// Can be relaxed in future for Extended Next-Hop (RFC 5549).
    ///
    /// Additionally validates cross-AF scenarios:
    /// - IPv4 Unicast enabled for IPv6 peer requires configured IPv4 nexthop
    /// - IPv6 Unicast enabled for IPv4 peer requires configured IPv6 nexthop
    pub fn validate_nexthop(&self) -> Result<(), String> {
        if let Some(cfg) = &self.ipv4_unicast {
            if let Some(nh) = cfg.nexthop {
                if !nh.is_ipv4() {
                    return Err(format!(
                        "IPv4 unicast nexthop must be IPv4 address, got {}",
                        nh
                    ));
                }
            } else if self.host.is_ipv6() {
                return Err(
                    "IPv4 Unicast enabled for IPv6 peer requires configured IPv4 nexthop"
                        .into(),
                );
            }
        }

        if let Some(cfg) = &self.ipv6_unicast {
            if let Some(nh) = cfg.nexthop {
                if !nh.is_ipv6() {
                    return Err(format!(
                        "IPv6 unicast nexthop must be IPv6 address, got {}",
                        nh
                    ));
                }
            } else if !self.host.is_ipv6() {
                return Err(
                    "IPv6 Unicast enabled for IPv4 peer requires configured IPv6 nexthop"
                        .into(),
                );
            }
        }

        Ok(())
    }
}

/// Legacy neighbor configuration (v1/v2 API compatibility)
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct NeighborV1 {
    pub asn: u32,
    pub name: String,
    pub host: SocketAddr,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub group: String,
    pub passive: bool,
    pub remote_asn: Option<u32>,
    pub min_ttl: Option<u8>,
    pub md5_auth_key: Option<String>,
    pub multi_exit_discriminator: Option<u32>,
    pub communities: Vec<u32>,
    pub local_pref: Option<u32>,
    pub enforce_first_as: bool,
    pub allow_import: ImportExportPolicyV1,
    pub allow_export: ImportExportPolicyV1,
    pub vlan_id: Option<u16>,
}

impl From<Neighbor> for PeerConfig {
    fn from(rq: Neighbor) -> Self {
        Self {
            name: rq.name.clone(),
            group: rq.group.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
        }
    }
}

impl From<NeighborV1> for PeerConfig {
    fn from(rq: NeighborV1) -> Self {
        Self {
            name: rq.name.clone(),
            group: rq.group.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
        }
    }
}

impl NeighborV1 {
    pub fn from_bgp_peer_config_v1(
        asn: u32,
        group: String,
        rq: BgpPeerConfigV1,
    ) -> Self {
        Self {
            asn,
            remote_asn: rq.remote_asn,
            min_ttl: rq.min_ttl,
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
            passive: rq.passive,
            group: group.clone(),
            md5_auth_key: rq.md5_auth_key,
            multi_exit_discriminator: rq.multi_exit_discriminator,
            communities: rq.communities,
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            allow_import: rq.allow_import,
            allow_export: rq.allow_export,
            vlan_id: rq.vlan_id,
        }
    }

    pub fn from_rdb_neighbor_info(asn: u32, rq: &rdb::BgpNeighborInfo) -> Self {
        Self {
            asn,
            remote_asn: rq.remote_asn,
            min_ttl: rq.min_ttl,
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
            passive: rq.passive,
            group: rq.group.clone(),
            md5_auth_key: rq.md5_auth_key.clone(),
            multi_exit_discriminator: rq.multi_exit_discriminator,
            communities: rq.communities.clone(),
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            // Combine per-AF policies into legacy format for API compatibility
            allow_import: ImportExportPolicyV1::from_per_af_policies(
                &rq.allow_import4,
                &rq.allow_import6,
            ),
            allow_export: ImportExportPolicyV1::from_per_af_policies(
                &rq.allow_export4,
                &rq.allow_export6,
            ),
            vlan_id: rq.vlan_id,
        }
    }
}

impl Neighbor {
    /// Create a Neighbor from a BgpPeerConfig.
    ///
    /// Uses the `ipv4_enabled` and `ipv6_enabled` flags from the config to
    /// determine which address families are enabled.
    pub fn from_bgp_peer_config(
        asn: u32,
        group: String,
        rq: BgpPeerConfig,
    ) -> Self {
        Self {
            asn,
            remote_asn: rq.remote_asn,
            min_ttl: rq.min_ttl,
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
            passive: rq.passive,
            group: group.clone(),
            md5_auth_key: rq.md5_auth_key,
            multi_exit_discriminator: rq.multi_exit_discriminator,
            communities: rq.communities,
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            ipv4_unicast: rq.ipv4_unicast,
            ipv6_unicast: rq.ipv6_unicast,
            vlan_id: rq.vlan_id,
            connect_retry_jitter: rq.connect_retry_jitter,
            idle_hold_jitter: rq.idle_hold_jitter,
            deterministic_collision_resolution: rq
                .deterministic_collision_resolution,
        }
    }

    pub fn from_rdb_neighbor_info(asn: u32, rq: &rdb::BgpNeighborInfo) -> Self {
        // Use explicit enablement flags from the database
        let ipv4_unicast = if rq.ipv4_enabled {
            Some(Ipv4UnicastConfig {
                nexthop: rq.nexthop4,
                import_policy: rq.allow_import4.clone(),
                export_policy: rq.allow_export4.clone(),
            })
        } else {
            None
        };

        let ipv6_unicast = if rq.ipv6_enabled {
            Some(Ipv6UnicastConfig {
                nexthop: rq.nexthop6,
                import_policy: rq.allow_import6.clone(),
                export_policy: rq.allow_export6.clone(),
            })
        } else {
            None
        };

        Self {
            asn,
            remote_asn: rq.remote_asn,
            min_ttl: rq.min_ttl,
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
            passive: rq.passive,
            group: rq.group.clone(),
            md5_auth_key: rq.md5_auth_key.clone(),
            multi_exit_discriminator: rq.multi_exit_discriminator,
            communities: rq.communities.clone(),
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            ipv4_unicast,
            ipv6_unicast,
            vlan_id: rq.vlan_id,
            connect_retry_jitter: Some(JitterRange {
                min: 0.75,
                max: 1.0,
            }),
            idle_hold_jitter: None,
            deterministic_collision_resolution: false,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddExportPolicyRequest {
    /// ASN of the router to apply the export policy to.
    pub asn: u32,

    /// Address of the peer to apply this policy to.
    pub addr: IpAddr,

    /// Prefix this policy applies to.
    pub prefix: Prefix4,

    /// Priority of the policy, higher value is higher priority.
    pub priority: u16,

    /// The policy action to apply.
    pub action: PolicyAction,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Origin4 {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Origin6 {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix6>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Withdraw4Request {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GracefulShutdownRequest {
    /// ASN of the router to gracefully shut down.
    pub asn: u32,
    /// Set whether or not graceful shutdown is initiated from this router.
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetOriginated4Request {
    /// ASN of the router to get originated prefixes from.
    pub asn: u32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetRoutersRequest {}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetRouersResponse {
    pub router: Vec<RouterInfo>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RouterInfo {
    pub asn: u32,
    pub peers: BTreeMap<IpAddr, PeerInfoV2>,
    pub graceful_shutdown: bool,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[schemars(rename = "DynamicTimerInfo")]
pub struct DynamicTimerInfoV1 {
    pub configured: Duration,
    pub negotiated: Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct DynamicTimerInfo {
    pub configured: Duration,
    pub negotiated: Duration,
    pub remaining: Duration,
}

/// Timer information for static (non-negotiated) timers
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct StaticTimerInfo {
    pub configured: Duration,
    pub remaining: Duration,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PeerTimers {
    pub hold: DynamicTimerInfo,
    pub keepalive: DynamicTimerInfo,
    pub connect_retry: StaticTimerInfo,
    pub connect_retry_jitter: Option<JitterRange>,
    pub idle_hold: StaticTimerInfo,
    pub idle_hold_jitter: Option<JitterRange>,
    pub delay_open: StaticTimerInfo,
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

impl From<&SessionCounters> for PeerCounters {
    fn from(value: &SessionCounters) -> Self {
        Self {
            connection_retries: value
                .connection_retries
                .load(Ordering::Relaxed),
            active_connections_accepted: value
                .active_connections_accepted
                .load(Ordering::Relaxed),
            active_connections_declined: value
                .active_connections_declined
                .load(Ordering::Relaxed),
            passive_connections_accepted: value
                .passive_connections_accepted
                .load(Ordering::Relaxed),
            passive_connections_declined: value
                .passive_connections_declined
                .load(Ordering::Relaxed),
            transitions_to_idle: value
                .transitions_to_idle
                .load(Ordering::Relaxed),
            transitions_to_connect: value
                .transitions_to_connect
                .load(Ordering::Relaxed),
            transitions_to_active: value
                .transitions_to_active
                .load(Ordering::Relaxed),
            transitions_to_open_sent: value
                .transitions_to_open_sent
                .load(Ordering::Relaxed),
            transitions_to_open_confirm: value
                .transitions_to_open_confirm
                .load(Ordering::Relaxed),
            transitions_to_connection_collision: value
                .transitions_to_connection_collision
                .load(Ordering::Relaxed),
            transitions_to_session_setup: value
                .transitions_to_session_setup
                .load(Ordering::Relaxed),
            transitions_to_established: value
                .transitions_to_established
                .load(Ordering::Relaxed),
            hold_timer_expirations: value
                .hold_timer_expirations
                .load(Ordering::Relaxed),
            idle_hold_timer_expirations: value
                .idle_hold_timer_expirations
                .load(Ordering::Relaxed),
            prefixes_advertised: value
                .prefixes_advertised
                .load(Ordering::Relaxed),
            prefixes_imported: value.prefixes_imported.load(Ordering::Relaxed),
            keepalives_sent: value.keepalives_sent.load(Ordering::Relaxed),
            keepalives_received: value
                .keepalives_received
                .load(Ordering::Relaxed),
            route_refresh_sent: value
                .route_refresh_sent
                .load(Ordering::Relaxed),
            route_refresh_received: value
                .route_refresh_received
                .load(Ordering::Relaxed),
            opens_sent: value.opens_sent.load(Ordering::Relaxed),
            opens_received: value.opens_received.load(Ordering::Relaxed),
            notifications_sent: value
                .notifications_sent
                .load(Ordering::Relaxed),
            notifications_received: value
                .notifications_received
                .load(Ordering::Relaxed),
            updates_sent: value.updates_sent.load(Ordering::Relaxed),
            updates_received: value.updates_received.load(Ordering::Relaxed),
            unexpected_update_message: value
                .unexpected_update_message
                .load(Ordering::Relaxed),
            unexpected_keepalive_message: value
                .unexpected_keepalive_message
                .load(Ordering::Relaxed),
            unexpected_open_message: value
                .unexpected_open_message
                .load(Ordering::Relaxed),
            unexpected_route_refresh_message: value
                .unexpected_route_refresh_message
                .load(Ordering::Relaxed),
            unexpected_notification_message: value
                .unexpected_notification_message
                .load(Ordering::Relaxed),
            update_nexhop_missing: value
                .update_nexhop_missing
                .load(Ordering::Relaxed),
            open_handle_failures: value
                .open_handle_failures
                .load(Ordering::Relaxed),
            unnegotiated_address_family: value
                .unnegotiated_address_family
                .load(Ordering::Relaxed),
            notification_send_failure: value
                .notification_send_failure
                .load(Ordering::Relaxed),
            open_send_failure: value.open_send_failure.load(Ordering::Relaxed),
            keepalive_send_failure: value
                .keepalive_send_failure
                .load(Ordering::Relaxed),
            route_refresh_send_failure: value
                .route_refresh_send_failure
                .load(Ordering::Relaxed),
            update_send_failure: value
                .update_send_failure
                .load(Ordering::Relaxed),
            tcp_connection_failure: value
                .tcp_connection_failure
                .load(Ordering::Relaxed),
            md5_auth_failures: value.md5_auth_failures.load(Ordering::Relaxed),
            connector_panics: value.connector_panics.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AfiSafi {
    afi: u16,
    safi: u8,
}

impl From<&AddPathElement> for AfiSafi {
    fn from(value: &AddPathElement) -> Self {
        Self {
            afi: value.afi,
            safi: value.safi,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub enum BgpCapability {
    MultiprotocolExtensions(AfiSafi),
    RouteRefresh,
    FourOctetAsn(u32),
    AddPath { elements: Vec<AfiSafi> },
    Unknown(u8),
}

impl From<&Capability> for BgpCapability {
    fn from(value: &Capability) -> Self {
        match value {
            Capability::MultiprotocolExtensions { afi, safi } => {
                BgpCapability::MultiprotocolExtensions(AfiSafi {
                    afi: *afi,
                    safi: *safi,
                })
            }
            Capability::RouteRefresh {} => BgpCapability::RouteRefresh,
            Capability::FourOctetAs { asn } => {
                BgpCapability::FourOctetAsn(*asn)
            }
            Capability::AddPath { elements } => BgpCapability::AddPath {
                elements: elements.iter().map(AfiSafi::from).collect(),
            },
            c => BgpCapability::Unknown(c.code() as u8),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PeerInfo {
    pub name: String,
    pub peer_group: String,
    pub fsm_state: FsmStateKind,
    pub fsm_state_duration: Duration,
    pub asn: Option<u32>,
    pub id: Option<u32>,
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub local_tcp_port: u16,
    pub remote_tcp_port: u16,
    pub received_capabilities: Vec<BgpCapability>,
    pub timers: PeerTimers,
    pub counters: PeerCounters,
    pub ipv4_unicast: Ipv4UnicastConfig,
    pub ipv6_unicast: Ipv6UnicastConfig,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct CheckerSource {
    pub asn: u32,
    pub code: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct ShaperSource {
    pub asn: u32,
    pub code: String,
}

/// Apply changes to an ASN (v1/v2 API - legacy format).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[schemars(rename = "ApplyRequest")]
pub struct ApplyRequestV1 {
    /// ASN to apply changes to.
    pub asn: u32,
    /// Complete set of prefixes to originate. Any active prefixes not in this
    /// list will be removed. All prefixes in this list are ensured to be in
    /// the originating set.
    pub originate: Vec<Prefix4>,

    /// Checker rhai code to apply to ingress open and update messages.
    pub checker: Option<CheckerSource>,

    /// Checker rhai code to apply to egress open and update messages.
    pub shaper: Option<ShaperSource>,

    /// Lists of peers indexed by peer group. Set's within a peer group key are
    /// a total set. For example, the value
    ///
    /// ```text
    /// {"foo": [a, b, d]}
    /// ```
    /// Means that the peer group "foo" only contains the peers `a`, `b` and
    /// `d`. If there is a peer `c` currently in the peer group "foo", it will
    /// be removed.
    pub peers: HashMap<String, Vec<BgpPeerConfigV1>>,
}

/// BGP peer configuration for v1/v2 API (legacy format with combined import/export).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[schemars(rename = "BgpPeerConfig")]
pub struct BgpPeerConfigV1 {
    pub host: SocketAddr,
    pub name: String,
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
    pub allow_import: ImportExportPolicyV1,
    pub allow_export: ImportExportPolicyV1,
    pub vlan_id: Option<u16>,
}

/// BGP peer configuration (current version with per-address-family policies).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct BgpPeerConfig {
    pub host: SocketAddr,
    pub name: String,
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
    /// IPv4 Unicast address family configuration (None = disabled)
    pub ipv4_unicast: Option<Ipv4UnicastConfig>,
    /// IPv6 Unicast address family configuration (None = disabled)
    pub ipv6_unicast: Option<Ipv6UnicastConfig>,
    pub vlan_id: Option<u16>,
    /// Jitter range for connect_retry timer. When used, the connect_retry timer
    /// is multiplied by a random value within the (min, max) range supplied.
    /// Useful to help break repeated synchronization of connection collisions.
    pub connect_retry_jitter: Option<JitterRange>,
    /// Jitter range for idle hold timer. When used, the idle hold timer is
    /// multiplied by a random value within the (min, max) range supplied.
    /// Useful to help break repeated synchronization of connection collisions.
    pub idle_hold_jitter: Option<JitterRange>,
    /// Enable deterministic collision resolution in Established state.
    /// When true, uses BGP-ID comparison per RFC 4271 §6.8 for collision
    /// resolution even when one connection is already in Established state.
    /// When false, Established connection always wins (timing-based resolution).
    pub deterministic_collision_resolution: bool,
}

impl From<BgpPeerConfigV1> for BgpPeerConfig {
    fn from(cfg: BgpPeerConfigV1) -> Self {
        // Legacy BgpPeerConfigV1 is IPv4-only
        Self {
            host: cfg.host,
            name: cfg.name,
            hold_time: cfg.hold_time,
            idle_hold_time: cfg.idle_hold_time,
            delay_open: cfg.delay_open,
            connect_retry: cfg.connect_retry,
            keepalive: cfg.keepalive,
            resolution: cfg.resolution,
            passive: cfg.passive,
            remote_asn: cfg.remote_asn,
            min_ttl: cfg.min_ttl,
            md5_auth_key: cfg.md5_auth_key,
            multi_exit_discriminator: cfg.multi_exit_discriminator,
            communities: cfg.communities,
            local_pref: cfg.local_pref,
            enforce_first_as: cfg.enforce_first_as,
            ipv4_unicast: Some(Ipv4UnicastConfig {
                nexthop: None,
                import_policy: cfg.allow_import.as_ipv4_policy(),
                export_policy: cfg.allow_export.as_ipv4_policy(),
            }),
            ipv6_unicast: None,
            vlan_id: cfg.vlan_id,
            connect_retry_jitter: Some(JitterRange {
                min: 0.75,
                max: 1.0,
            }),
            idle_hold_jitter: None,
            deterministic_collision_resolution: false,
        }
    }
}

pub enum PolicySource {
    Checker(String),
    Shaper(String),
}

pub enum PolicyKind {
    Checker,
    Shaper,
}

// ============================================================================
// API Compatibility Types (VERSION_INITIAL / v1.0.0)
// ============================================================================
// These types maintain backward compatibility with the INITIAL API version.
// FsmStateKindV1 lacks the ConnectionCollision state added in VERSION_IPV6_BASIC.
// Used exclusively for API responses via /bgp/status/neighbors endpoint (v1).
// Never used internally - always convert from current types at API boundary.
//
// Delete these types when VERSION_INITIAL is retired.

/// Simplified representation of a BGP state without having to carry a
/// connection. This does not include the ConnectionCollision state for
/// backwards comptability with the initial release of the versioned dropshot
/// API.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema,
)]
#[schemars(rename = "FsmStateKind")]
pub enum FsmStateKindV1 {
    /// Initial state. Refuse all incomming BGP connections. No resources
    /// allocated to peer.
    Idle,

    /// Waiting for the TCP connection to be completed.
    Connect,

    /// Trying to acquire peer by listening for and accepting a TCP connection.
    Active,

    /// Waiting for open message from peer.
    OpenSent,

    /// Waiting for keepalive or notification from peer.
    OpenConfirm,

    /// Sync up with peers.
    SessionSetup,

    /// Able to exchange update, notification and keepliave messages with peers.
    Established,
}

impl From<FsmStateKind> for FsmStateKindV1 {
    fn from(kind: FsmStateKind) -> Self {
        match kind {
            FsmStateKind::Idle => FsmStateKindV1::Idle,
            FsmStateKind::Connect => FsmStateKindV1::Connect,
            FsmStateKind::Active => FsmStateKindV1::Active,
            FsmStateKind::OpenSent => FsmStateKindV1::OpenSent,
            FsmStateKind::OpenConfirm => FsmStateKindV1::OpenConfirm,
            // We convert ConnectionCollision to OpenSent, because one
            // connection is always in OpenSent for the duration of
            // the colliison (unless we've already transitioned out of
            // ConnectionCollision), so this is technically correct, even if
            // it's only correct from the perspective of just one connection.
            FsmStateKind::ConnectionCollision => FsmStateKindV1::OpenSent,
            FsmStateKind::SessionSetup => FsmStateKindV1::SessionSetup,
            FsmStateKind::Established => FsmStateKindV1::Established,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[schemars(rename = "PeerInfo")]
pub struct PeerInfoV1 {
    pub state: FsmStateKindV1,
    pub asn: Option<u32>,
    pub duration_millis: u64,
    pub timers: PeerTimersV1,
}

impl From<PeerInfoV2> for PeerInfoV1 {
    fn from(info: PeerInfoV2) -> Self {
        Self {
            state: FsmStateKindV1::from(info.state),
            asn: info.asn,
            duration_millis: info.duration_millis,
            timers: info.timers,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[schemars(rename = "PeerInfo")]
pub struct PeerInfoV2 {
    pub state: FsmStateKind,
    pub asn: Option<u32>,
    pub duration_millis: u64,
    pub timers: PeerTimersV1,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[schemars(rename = "PeerTimers")]
pub struct PeerTimersV1 {
    pub hold: DynamicTimerInfoV1,
    pub keepalive: DynamicTimerInfoV1,
}

// ============================================================================
// API Types for VERSION_MP_BGP / v3.0.0
// ============================================================================
// These types are for the v3+ API with per-address-family import/export policies.

/// Apply changes to an ASN (current version with per-AF policies).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct ApplyRequest {
    /// ASN to apply changes to.
    pub asn: u32,
    /// Complete set of prefixes to originate.
    pub originate: Vec<Prefix4>,
    /// Checker rhai code to apply to ingress open and update messages.
    pub checker: Option<CheckerSource>,
    /// Checker rhai code to apply to egress open and update messages.
    pub shaper: Option<ShaperSource>,
    /// Lists of peers indexed by peer group.
    pub peers: HashMap<String, Vec<BgpPeerConfig>>,
}

impl From<ApplyRequestV1> for ApplyRequest {
    fn from(req: ApplyRequestV1) -> Self {
        Self {
            asn: req.asn,
            originate: req.originate,
            checker: req.checker,
            shaper: req.shaper,
            peers: req
                .peers
                .into_iter()
                .map(|(k, v)| {
                    (k, v.into_iter().map(BgpPeerConfig::from).collect())
                })
                .collect(),
        }
    }
}
