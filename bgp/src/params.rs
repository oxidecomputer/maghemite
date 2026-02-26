// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    config::PeerConfig,
    messages::{AddPathElement, Afi, Capability},
    session::{FsmStateKind, SessionCounters, SessionInfo},
};
use rdb::{
    Dscp, ImportExportPolicy4, ImportExportPolicy6, ImportExportPolicyV1,
    PolicyAction, Prefix, Prefix4, Prefix6,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr, SocketAddrV6},
    num::NonZeroU8,
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

impl Ipv4UnicastConfig {
    fn new(
        enabled: bool,
        nexthop: Option<IpAddr>,
        import_policy: ImportExportPolicy4,
        export_policy: ImportExportPolicy4,
    ) -> Option<Self> {
        if enabled {
            Some(Self {
                nexthop,
                import_policy,
                export_policy,
            })
        } else {
            None
        }
    }
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

impl Ipv6UnicastConfig {
    fn new(
        enabled: bool,
        nexthop: Option<IpAddr>,
        import_policy: ImportExportPolicy6,
        export_policy: ImportExportPolicy6,
    ) -> Option<Self> {
        if enabled {
            Some(Self {
                nexthop,
                import_policy,
                export_policy,
            })
        } else {
            None
        }
    }
}

/// Neighbor configuration with explicit per-address-family enablement (v3 API)
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct Neighbor {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub host: SocketAddr,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

impl Neighbor {
    /// Validate that at least one address family is enabled
    pub fn validate_address_families(&self) -> Result<(), String> {
        self.parameters.validate_address_families()
    }
}

impl UnnumberedNeighbor {
    /// Validate that at least one address family is enabled
    pub fn validate_address_families(&self) -> Result<(), String> {
        self.parameters.validate_address_families()
    }
}

/// Legacy neighbor configuration (v1/v2 API compatibility)
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct NeighborV1 {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub host: SocketAddr,
    #[serde(flatten)]
    pub parameters: BgpPeerParametersV1,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct UnnumberedNeighbor {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub interface: String,
    pub act_as_a_default_ipv6_router: u16,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

impl From<Neighbor> for PeerConfig {
    fn from(rq: Neighbor) -> Self {
        Self {
            name: rq.name.clone(),
            group: rq.group.clone(),
            host: rq.host,
            hold_time: rq.parameters.hold_time,
            idle_hold_time: rq.parameters.idle_hold_time,
            delay_open: rq.parameters.delay_open,
            connect_retry: rq.parameters.connect_retry,
            keepalive: rq.parameters.keepalive,
            resolution: rq.parameters.resolution,
        }
    }
}

impl From<NeighborV1> for PeerConfig {
    fn from(rq: NeighborV1) -> Self {
        Self {
            name: rq.name.clone(),
            group: rq.group.clone(),
            host: rq.host,
            hold_time: rq.parameters.hold_time,
            idle_hold_time: rq.parameters.idle_hold_time,
            delay_open: rq.parameters.delay_open,
            connect_retry: rq.parameters.connect_retry,
            keepalive: rq.parameters.keepalive,
            resolution: rq.parameters.resolution,
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
            group: group.clone(),
            host: rq.host,
            name: rq.name.clone(),
            parameters: rq.parameters.clone(),
        }
    }

    pub fn from_rdb_neighbor_info(asn: u32, rq: &rdb::BgpNeighborInfo) -> Self {
        Self {
            asn,
            group: rq.group.clone(),
            name: rq.name.clone(),
            host: rq.host,
            parameters: BgpPeerParametersV1 {
                remote_asn: rq.parameters.remote_asn,
                min_ttl: rq.parameters.min_ttl,
                hold_time: rq.parameters.hold_time,
                idle_hold_time: rq.parameters.idle_hold_time,
                delay_open: rq.parameters.delay_open,
                connect_retry: rq.parameters.connect_retry,
                keepalive: rq.parameters.keepalive,
                resolution: rq.parameters.resolution,
                passive: rq.parameters.passive,
                md5_auth_key: rq.parameters.md5_auth_key.clone(),
                multi_exit_discriminator: rq
                    .parameters
                    .multi_exit_discriminator,
                communities: rq.parameters.communities.clone(),
                local_pref: rq.parameters.local_pref,
                enforce_first_as: rq.parameters.enforce_first_as,
                allow_import: ImportExportPolicyV1::from_per_af_policies(
                    &rq.parameters.allow_import4,
                    &rq.parameters.allow_import6,
                ),
                allow_export: ImportExportPolicyV1::from_per_af_policies(
                    &rq.parameters.allow_export4,
                    &rq.parameters.allow_export6,
                ),
                vlan_id: rq.parameters.vlan_id,
            },
        }
    }
}

impl UnnumberedNeighbor {
    pub fn from_bgp_peer_config(
        asn: u32,
        group: String,
        rq: UnnumberedBgpPeerConfig,
    ) -> Self {
        Self {
            asn,
            group: group.clone(),
            interface: rq.interface.clone(),
            name: rq.name.clone(),
            act_as_a_default_ipv6_router: rq.router_lifetime,
            parameters: rq.parameters.clone(),
        }
    }

    pub fn to_peer_config(&self, addr: SocketAddrV6) -> PeerConfig {
        PeerConfig {
            name: self.name.clone(),
            host: addr.into(),
            group: self.group.clone(),
            hold_time: self.parameters.hold_time,
            idle_hold_time: self.parameters.idle_hold_time,
            delay_open: self.parameters.delay_open,
            connect_retry: self.parameters.connect_retry,
            keepalive: self.parameters.keepalive,
            resolution: self.parameters.resolution,
        }
    }

    pub fn from_rdb_neighbor_info(
        asn: u32,
        rq: &rdb::BgpUnnumberedNeighborInfo,
    ) -> Self {
        Self {
            asn,
            group: rq.group.clone(),
            name: rq.name.clone(),
            interface: rq.interface.clone(),
            act_as_a_default_ipv6_router: rq.router_lifetime,
            parameters: BgpPeerParameters {
                remote_asn: rq.parameters.remote_asn,
                min_ttl: rq
                    .parameters
                    .min_ttl
                    .and_then(NonZeroU8::new),
                hold_time: rq.parameters.hold_time,
                idle_hold_time: rq.parameters.idle_hold_time,
                delay_open: rq.parameters.delay_open,
                connect_retry: rq.parameters.connect_retry,
                keepalive: rq.parameters.keepalive,
                resolution: rq.parameters.resolution,
                passive: rq.parameters.passive,
                md5_auth_key: rq.parameters.md5_auth_key.clone(),
                multi_exit_discriminator: rq
                    .parameters
                    .multi_exit_discriminator,
                communities: rq.parameters.communities.clone(),
                local_pref: rq.parameters.local_pref,
                enforce_first_as: rq.parameters.enforce_first_as,
                vlan_id: rq.parameters.vlan_id,
                ipv4_unicast: Ipv4UnicastConfig::new(
                    rq.parameters.ipv4_enabled,
                    rq.parameters.nexthop4,
                    rq.parameters.allow_import4.clone(),
                    rq.parameters.allow_export4.clone(),
                ),
                ipv6_unicast: Ipv6UnicastConfig::new(
                    rq.parameters.ipv6_enabled,
                    rq.parameters.nexthop6,
                    rq.parameters.allow_import6.clone(),
                    rq.parameters.allow_export6.clone(),
                ),
                deterministic_collision_resolution: false,
                idle_hold_jitter: None,
                connect_retry_jitter: Some(JitterRange {
                    min: 0.75,
                    max: 1.0,
                }),
                dscp: rq.parameters.dscp,
            },
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
            name: rq.name.clone(),
            host: rq.host,
            group: group.clone(),
            parameters: rq.parameters.clone(),
        }
    }

    pub fn from_rdb_neighbor_info(asn: u32, rq: &rdb::BgpNeighborInfo) -> Self {
        Self {
            asn,
            name: rq.name.clone(),
            host: rq.host,
            group: rq.group.clone(),
            parameters: BgpPeerParameters {
                remote_asn: rq.parameters.remote_asn,
                min_ttl: rq
                    .parameters
                    .min_ttl
                    .and_then(NonZeroU8::new),
                hold_time: rq.parameters.hold_time,
                idle_hold_time: rq.parameters.idle_hold_time,
                delay_open: rq.parameters.delay_open,
                connect_retry: rq.parameters.connect_retry,
                keepalive: rq.parameters.keepalive,
                resolution: rq.parameters.resolution,
                passive: rq.parameters.passive,
                md5_auth_key: rq.parameters.md5_auth_key.clone(),
                multi_exit_discriminator: rq
                    .parameters
                    .multi_exit_discriminator,
                communities: rq.parameters.communities.clone(),
                local_pref: rq.parameters.local_pref,
                enforce_first_as: rq.parameters.enforce_first_as,
                ipv4_unicast: Ipv4UnicastConfig::new(
                    rq.parameters.ipv4_enabled,
                    rq.parameters.nexthop4,
                    rq.parameters.allow_import4.clone(),
                    rq.parameters.allow_export4.clone(),
                ),
                ipv6_unicast: Ipv6UnicastConfig::new(
                    rq.parameters.ipv6_enabled,
                    rq.parameters.nexthop6,
                    rq.parameters.allow_import6.clone(),
                    rq.parameters.allow_export6.clone(),
                ),
                vlan_id: rq.parameters.vlan_id,
                connect_retry_jitter: Some(JitterRange {
                    min: 0.75,
                    max: 1.0,
                }),
                idle_hold_jitter: None,
                deterministic_collision_resolution: false,
                dscp: rq.parameters.dscp,
            },
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

/// Reason for the most recent session reset.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum ResetReason {
    AdministrativeReset,
    AdministrativeShutdown,
    HoldTimerExpired,
    FsmError,
    ConnectionRejected,
    CollisionResolution,
    IoError,
    ParseError,
    NotificationReceived,
}

/// Information about the most recent session reset.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FsmResetRecord {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub reason: ResetReason,
}

/// A record of a BGP notification message with a timestamp.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NotificationRecord {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub notification: crate::messages::NotificationMessage,
}

/// Session-level counters (v5-v6 API: aggregate NLRI, no reset_count).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[schemars(rename = "PeerCounters")]
pub struct PeerCountersV1 {
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

impl From<&SessionCounters> for PeerCountersV1 {
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
                .ipv4_prefixes_advertised
                .load(Ordering::Relaxed)
                + value.ipv6_prefixes_advertised.load(Ordering::Relaxed),
            prefixes_imported: value
                .ipv4_prefixes_imported
                .load(Ordering::Relaxed)
                + value.ipv6_prefixes_imported.load(Ordering::Relaxed),
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

/// Peer info for v5-v6 API (aggregate NLRI counters, no reset/notification).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[schemars(rename = "PeerInfo")]
pub struct PeerInfoV3 {
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
    pub counters: PeerCountersV1,
    pub ipv4_unicast: Ipv4UnicastConfig,
    pub ipv6_unicast: Ipv6UnicastConfig,
}

/// Session-level counters with per-AFI NLRI gauges (v7+ API).
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

    // Per-AFI NLRI gauge counters
    pub ipv4_prefixes_advertised: u64,
    pub ipv4_prefixes_imported: u64,
    pub ipv6_prefixes_advertised: u64,
    pub ipv6_prefixes_imported: u64,

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
    pub updates_treated_as_withdraw: u64,

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

    // Reset counter
    pub reset_count: u64,
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
            ipv4_prefixes_advertised: value
                .ipv4_prefixes_advertised
                .load(Ordering::Relaxed),
            ipv4_prefixes_imported: value
                .ipv4_prefixes_imported
                .load(Ordering::Relaxed),
            ipv6_prefixes_advertised: value
                .ipv6_prefixes_advertised
                .load(Ordering::Relaxed),
            ipv6_prefixes_imported: value
                .ipv6_prefixes_imported
                .load(Ordering::Relaxed),
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
            updates_treated_as_withdraw: value
                .updates_treated_as_withdraw
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
            reset_count: value.reset_count.load(Ordering::Relaxed),
        }
    }
}

/// Peer info for v7+ API (per-AFI counters, reset/notification tracking).
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
    pub last_reset: Option<FsmResetRecord>,
    pub last_notification_sent: Option<NotificationRecord>,
    pub last_notification_received: Option<NotificationRecord>,
}

impl From<PeerInfo> for PeerInfoV3 {
    fn from(info: PeerInfo) -> Self {
        Self {
            name: info.name,
            peer_group: info.peer_group,
            fsm_state: info.fsm_state,
            fsm_state_duration: info.fsm_state_duration,
            asn: info.asn,
            id: info.id,
            local_ip: info.local_ip,
            remote_ip: info.remote_ip,
            local_tcp_port: info.local_tcp_port,
            remote_tcp_port: info.remote_tcp_port,
            received_capabilities: info.received_capabilities,
            timers: info.timers,
            counters: PeerCountersV1 {
                connection_retries: info.counters.connection_retries,
                active_connections_accepted: info
                    .counters
                    .active_connections_accepted,
                active_connections_declined: info
                    .counters
                    .active_connections_declined,
                passive_connections_accepted: info
                    .counters
                    .passive_connections_accepted,
                passive_connections_declined: info
                    .counters
                    .passive_connections_declined,
                transitions_to_idle: info.counters.transitions_to_idle,
                transitions_to_connect: info.counters.transitions_to_connect,
                transitions_to_active: info.counters.transitions_to_active,
                transitions_to_open_sent: info
                    .counters
                    .transitions_to_open_sent,
                transitions_to_open_confirm: info
                    .counters
                    .transitions_to_open_confirm,
                transitions_to_connection_collision: info
                    .counters
                    .transitions_to_connection_collision,
                transitions_to_session_setup: info
                    .counters
                    .transitions_to_session_setup,
                transitions_to_established: info
                    .counters
                    .transitions_to_established,
                hold_timer_expirations: info.counters.hold_timer_expirations,
                idle_hold_timer_expirations: info
                    .counters
                    .idle_hold_timer_expirations,
                prefixes_advertised: info.counters.ipv4_prefixes_advertised
                    + info.counters.ipv6_prefixes_advertised,
                prefixes_imported: info.counters.ipv4_prefixes_imported
                    + info.counters.ipv6_prefixes_imported,
                keepalives_sent: info.counters.keepalives_sent,
                keepalives_received: info.counters.keepalives_received,
                route_refresh_sent: info.counters.route_refresh_sent,
                route_refresh_received: info.counters.route_refresh_received,
                opens_sent: info.counters.opens_sent,
                opens_received: info.counters.opens_received,
                notifications_sent: info.counters.notifications_sent,
                notifications_received: info.counters.notifications_received,
                updates_sent: info.counters.updates_sent,
                updates_received: info.counters.updates_received,
                unexpected_update_message: info
                    .counters
                    .unexpected_update_message,
                unexpected_keepalive_message: info
                    .counters
                    .unexpected_keepalive_message,
                unexpected_open_message: info.counters.unexpected_open_message,
                unexpected_route_refresh_message: info
                    .counters
                    .unexpected_route_refresh_message,
                unexpected_notification_message: info
                    .counters
                    .unexpected_notification_message,
                update_nexhop_missing: info.counters.update_nexhop_missing,
                open_handle_failures: info.counters.open_handle_failures,
                unnegotiated_address_family: info
                    .counters
                    .unnegotiated_address_family,
                notification_send_failure: info
                    .counters
                    .notification_send_failure,
                open_send_failure: info.counters.open_send_failure,
                keepalive_send_failure: info.counters.keepalive_send_failure,
                route_refresh_send_failure: info
                    .counters
                    .route_refresh_send_failure,
                update_send_failure: info.counters.update_send_failure,
                tcp_connection_failure: info.counters.tcp_connection_failure,
                md5_auth_failures: info.counters.md5_auth_failures,
                connector_panics: info.counters.connector_panics,
            },
            ipv4_unicast: info.ipv4_unicast,
            ipv6_unicast: info.ipv6_unicast,
        }
    }
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
    #[serde(flatten)]
    pub parameters: BgpPeerParametersV1,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct BgpPeerConfig {
    pub host: SocketAddr,
    pub name: String,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct UnnumberedBgpPeerConfig {
    pub interface: String,
    pub name: String,
    pub router_lifetime: u16,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct BgpPeerParameters {
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub passive: bool,
    pub remote_asn: Option<u32>,
    pub min_ttl: Option<NonZeroU8>,
    pub md5_auth_key: Option<String>,
    pub multi_exit_discriminator: Option<u32>,
    pub communities: Vec<u32>,
    pub local_pref: Option<u32>,
    pub enforce_first_as: bool,
    pub vlan_id: Option<u16>,

    // new stuff after v1
    /// IPv4 Unicast address family configuration (None = disabled)
    pub ipv4_unicast: Option<Ipv4UnicastConfig>,
    /// IPv6 Unicast address family configuration (None = disabled)
    pub ipv6_unicast: Option<Ipv6UnicastConfig>,
    /// Enable deterministic collision resolution in Established state.
    /// When true, uses BGP-ID comparison per RFC 4271 §6.8 for collision
    /// resolution even when one connection is already in Established state.
    /// When false, Established connection always wins (timing-based resolution).
    pub deterministic_collision_resolution: bool,
    /// Jitter range for idle hold timer. When used, the idle hold timer is
    /// multiplied by a random value within the (min, max) range supplied.
    /// Useful to help break repeated synchronization of connection collisions.
    pub idle_hold_jitter: Option<JitterRange>,
    /// Jitter range for connect_retry timer. When used, the connect_retry timer
    /// is multiplied by a random value within the (min, max) range supplied.
    /// Useful to help break repeated synchronization of connection collisions.
    pub connect_retry_jitter: Option<JitterRange>,
    /// DSCP value for BGP TCP connections (0-63).
    /// RFC 4271 Appendix E recommends CS6 (48) for BGP traffic.
    /// Default: CS6 (48).
    #[serde(default)]
    pub dscp: Dscp,
}

impl BgpPeerParameters {
    /// Validate that at least one address family is enabled
    pub fn validate_address_families(&self) -> Result<(), String> {
        if self.ipv4_unicast.is_none() && self.ipv6_unicast.is_none() {
            return Err("at least one address family must be enabled".into());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct BgpPeerParametersV1 {
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

impl From<BgpPeerConfigV1> for BgpPeerConfig {
    fn from(cfg: BgpPeerConfigV1) -> Self {
        // Legacy BgpPeerConfigV1 is IPv4-only
        Self {
            host: cfg.host,
            name: cfg.name,
            parameters: BgpPeerParameters {
                hold_time: cfg.parameters.hold_time,
                idle_hold_time: cfg.parameters.idle_hold_time,
                delay_open: cfg.parameters.delay_open,
                connect_retry: cfg.parameters.connect_retry,
                keepalive: cfg.parameters.keepalive,
                resolution: cfg.parameters.resolution,
                passive: cfg.parameters.passive,
                remote_asn: cfg.parameters.remote_asn,
                min_ttl: cfg
                    .parameters
                    .min_ttl
                    .and_then(NonZeroU8::new),
                md5_auth_key: cfg.parameters.md5_auth_key,
                multi_exit_discriminator: cfg
                    .parameters
                    .multi_exit_discriminator,
                communities: cfg.parameters.communities,
                local_pref: cfg.parameters.local_pref,
                enforce_first_as: cfg.parameters.enforce_first_as,
                ipv4_unicast: Some(Ipv4UnicastConfig {
                    nexthop: None,
                    import_policy: cfg.parameters.allow_import.as_ipv4_policy(),
                    export_policy: cfg.parameters.allow_export.as_ipv4_policy(),
                }),
                ipv6_unicast: None,
                vlan_id: cfg.parameters.vlan_id,
                connect_retry_jitter: Some(JitterRange {
                    min: 0.75,
                    max: 1.0,
                }),
                idle_hold_jitter: None,
                deterministic_collision_resolution: false,
                dscp: Dscp::default(),
            },
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
// API Compatibility Types (VERSION_MP_BGP..VERSION_EXTENDED_NH_STATIC)
// ============================================================================
// These types represent the v3-v6 API format (per-AF config, no DSCP).
// Used for API versions between VERSION_MP_BGP and
// VERSION_EXTENDED_NH_STATIC.
// Delete when VERSION_EXTENDED_NH_STATIC is the minimum supported version.

/// BGP peer parameters for v3-v6 API (per-AF config, no DSCP).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[schemars(rename = "BgpPeerParameters")]
pub struct BgpPeerParametersV2 {
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

impl From<BgpPeerParameters> for BgpPeerParametersV2 {
    fn from(p: BgpPeerParameters) -> Self {
        Self {
            hold_time: p.hold_time,
            idle_hold_time: p.idle_hold_time,
            delay_open: p.delay_open,
            connect_retry: p.connect_retry,
            keepalive: p.keepalive,
            resolution: p.resolution,
            passive: p.passive,
            remote_asn: p.remote_asn,
            min_ttl: p.min_ttl.map(NonZeroU8::get),
            md5_auth_key: p.md5_auth_key,
            multi_exit_discriminator: p.multi_exit_discriminator,
            communities: p.communities,
            local_pref: p.local_pref,
            enforce_first_as: p.enforce_first_as,
            vlan_id: p.vlan_id,
            ipv4_unicast: p.ipv4_unicast,
            ipv6_unicast: p.ipv6_unicast,
            deterministic_collision_resolution: p
                .deterministic_collision_resolution,
            idle_hold_jitter: p.idle_hold_jitter,
            connect_retry_jitter: p.connect_retry_jitter,
        }
    }
}

impl From<BgpPeerParametersV2> for BgpPeerParameters {
    fn from(p: BgpPeerParametersV2) -> Self {
        Self {
            hold_time: p.hold_time,
            idle_hold_time: p.idle_hold_time,
            delay_open: p.delay_open,
            connect_retry: p.connect_retry,
            keepalive: p.keepalive,
            resolution: p.resolution,
            passive: p.passive,
            remote_asn: p.remote_asn,
            min_ttl: p.min_ttl.and_then(NonZeroU8::new),
            md5_auth_key: p.md5_auth_key,
            multi_exit_discriminator: p.multi_exit_discriminator,
            communities: p.communities,
            local_pref: p.local_pref,
            enforce_first_as: p.enforce_first_as,
            vlan_id: p.vlan_id,
            ipv4_unicast: p.ipv4_unicast,
            ipv6_unicast: p.ipv6_unicast,
            deterministic_collision_resolution: p
                .deterministic_collision_resolution,
            idle_hold_jitter: p.idle_hold_jitter,
            connect_retry_jitter: p.connect_retry_jitter,
            dscp: Dscp::default(),
        }
    }
}

/// BGP peer config for v3-v6 API (no DSCP).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[schemars(rename = "BgpPeerConfig")]
pub struct BgpPeerConfigV2 {
    pub host: SocketAddr,
    pub name: String,
    #[serde(flatten)]
    pub parameters: BgpPeerParametersV2,
}

impl From<BgpPeerConfig> for BgpPeerConfigV2 {
    fn from(c: BgpPeerConfig) -> Self {
        Self {
            host: c.host,
            name: c.name,
            parameters: c.parameters.into(),
        }
    }
}

impl From<BgpPeerConfigV2> for BgpPeerConfig {
    fn from(c: BgpPeerConfigV2) -> Self {
        Self {
            host: c.host,
            name: c.name,
            parameters: c.parameters.into(),
        }
    }
}

/// Neighbor configuration for v3-v6 API (no DSCP).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[schemars(rename = "Neighbor")]
pub struct NeighborV2 {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub host: SocketAddr,
    #[serde(flatten)]
    pub parameters: BgpPeerParametersV2,
}

impl From<Neighbor> for NeighborV2 {
    fn from(n: Neighbor) -> Self {
        Self {
            asn: n.asn,
            name: n.name,
            group: n.group,
            host: n.host,
            parameters: n.parameters.into(),
        }
    }
}

impl From<NeighborV2> for Neighbor {
    fn from(n: NeighborV2) -> Self {
        Self {
            asn: n.asn,
            name: n.name,
            group: n.group,
            host: n.host,
            parameters: n.parameters.into(),
        }
    }
}

/// Unnumbered BGP peer config for v5-v6 API (no DSCP).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[schemars(rename = "UnnumberedBgpPeerConfig")]
pub struct UnnumberedBgpPeerConfigV1 {
    pub interface: String,
    pub name: String,
    pub router_lifetime: u16,
    #[serde(flatten)]
    pub parameters: BgpPeerParametersV2,
}

impl From<UnnumberedBgpPeerConfig> for UnnumberedBgpPeerConfigV1 {
    fn from(c: UnnumberedBgpPeerConfig) -> Self {
        Self {
            interface: c.interface,
            name: c.name,
            router_lifetime: c.router_lifetime,
            parameters: c.parameters.into(),
        }
    }
}

impl From<UnnumberedBgpPeerConfigV1> for UnnumberedBgpPeerConfig {
    fn from(c: UnnumberedBgpPeerConfigV1) -> Self {
        Self {
            interface: c.interface,
            name: c.name,
            router_lifetime: c.router_lifetime,
            parameters: c.parameters.into(),
        }
    }
}

/// Unnumbered neighbor configuration for v5-v6 API (no DSCP).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[schemars(rename = "UnnumberedNeighbor")]
pub struct UnnumberedNeighborV1 {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub interface: String,
    pub act_as_a_default_ipv6_router: u16,
    #[serde(flatten)]
    pub parameters: BgpPeerParametersV2,
}

impl From<UnnumberedNeighbor> for UnnumberedNeighborV1 {
    fn from(n: UnnumberedNeighbor) -> Self {
        Self {
            asn: n.asn,
            name: n.name,
            group: n.group,
            interface: n.interface,
            act_as_a_default_ipv6_router: n.act_as_a_default_ipv6_router,
            parameters: n.parameters.into(),
        }
    }
}

impl From<UnnumberedNeighborV1> for UnnumberedNeighbor {
    fn from(n: UnnumberedNeighborV1) -> Self {
        Self {
            asn: n.asn,
            name: n.name,
            group: n.group,
            interface: n.interface,
            act_as_a_default_ipv6_router: n.act_as_a_default_ipv6_router,
            parameters: n.parameters.into(),
        }
    }
}

/// Apply request for v3-v6 API (no DSCP).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[schemars(rename = "ApplyRequest")]
pub struct ApplyRequestV2 {
    pub asn: u32,
    pub originate: Vec<Prefix>,
    pub checker: Option<CheckerSource>,
    pub shaper: Option<ShaperSource>,
    pub peers: HashMap<String, Vec<BgpPeerConfigV2>>,
    #[serde(default)]
    pub unnumbered_peers: HashMap<String, Vec<UnnumberedBgpPeerConfigV1>>,
}

impl From<ApplyRequest> for ApplyRequestV2 {
    fn from(r: ApplyRequest) -> Self {
        Self {
            asn: r.asn,
            originate: r.originate,
            checker: r.checker,
            shaper: r.shaper,
            peers: r
                .peers
                .into_iter()
                .map(|(k, v)| {
                    (k, v.into_iter().map(BgpPeerConfigV2::from).collect())
                })
                .collect(),
            unnumbered_peers: r
                .unnumbered_peers
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        v.into_iter()
                            .map(UnnumberedBgpPeerConfigV1::from)
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

impl From<ApplyRequestV2> for ApplyRequest {
    fn from(r: ApplyRequestV2) -> Self {
        Self {
            asn: r.asn,
            originate: r.originate,
            checker: r.checker,
            shaper: r.shaper,
            peers: r
                .peers
                .into_iter()
                .map(|(k, v)| {
                    (k, v.into_iter().map(BgpPeerConfig::from).collect())
                })
                .collect(),
            unnumbered_peers: r
                .unnumbered_peers
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        v.into_iter()
                            .map(UnnumberedBgpPeerConfig::from)
                            .collect(),
                    )
                })
                .collect(),
        }
    }
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
    pub originate: Vec<Prefix>,
    /// Checker rhai code to apply to ingress open and update messages.
    pub checker: Option<CheckerSource>,
    /// Checker rhai code to apply to egress open and update messages.
    pub shaper: Option<ShaperSource>,
    /// Lists of peers indexed by peer group.
    pub peers: HashMap<String, Vec<BgpPeerConfig>>,
    /// Lists of unnumbered peers indexed by peer group.
    #[serde(default)]
    pub unnumbered_peers: HashMap<String, Vec<UnnumberedBgpPeerConfig>>,
}

impl From<ApplyRequestV1> for ApplyRequest {
    fn from(req: ApplyRequestV1) -> Self {
        Self {
            asn: req.asn,
            originate: req.originate.iter().map(|p| Prefix::V4(*p)).collect(),
            checker: req.checker,
            shaper: req.shaper,
            peers: req
                .peers
                .into_iter()
                .map(|(k, v)| {
                    (k, v.into_iter().map(BgpPeerConfig::from).collect())
                })
                .collect(),
            unnumbered_peers: HashMap::default(),
        }
    }
}
