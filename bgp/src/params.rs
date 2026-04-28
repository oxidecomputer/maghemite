// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    config::PeerConfig,
    messages::{AddPathElement, Capability, CapabilityCode},
    session::{FsmStateKind, SessionCounters, SessionInfo},
};
use mg_types_versions::v1::bgp as v1_bgp;
use mg_types_versions::v4::bgp as v4_bgp;
use mg_types_versions::v5::bgp as v5_bgp;
use mg_types_versions::v8::bgp as v8_bgp;
use rdb::{
    ImportExportPolicy4, ImportExportPolicy6, PolicyAction, Prefix4, Prefix6,
};
use rdb_types_versions::v1::policy::ImportExportPolicy;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddrV6},
    sync::atomic::Ordering,
    time::Duration,
};

// ----- Versioned BGP-config families re-exported from mg-types-versions -----
//
// Migrated to mg-types-versions in RFD 619 Phase 2d sub-chunk 6a. These
// re-exports preserve the existing `bgp::params::*` public surface so
// internal Bgp callers don't have to change.
pub use v1_bgp::ApplyRequest as ApplyRequestV1;
pub use v1_bgp::BgpPeerConfig as BgpPeerConfigV1;
pub use v1_bgp::BgpPeerParameters as BgpPeerParametersV1;
pub use v1_bgp::CheckerSource;
pub use v1_bgp::Neighbor as NeighborV1;
pub use v1_bgp::NeighborResetOp as NeighborResetOpV1;
pub use v1_bgp::ShaperSource;
pub use v4_bgp::ApplyRequest as ApplyRequestV6;
pub use v4_bgp::BgpPeerConfig as BgpPeerConfigV6;
pub use v4_bgp::BgpPeerParameters as BgpPeerParametersV6;
pub use v4_bgp::Ipv4UnicastConfig;
pub use v4_bgp::Ipv6UnicastConfig;
pub use v4_bgp::JitterRange;
pub use v4_bgp::Neighbor as NeighborV6;
pub use v4_bgp::NeighborResetOp;
pub use v4_bgp::UnnumberedBgpPeerConfig as UnnumberedBgpPeerConfigV6;
pub use v5_bgp::UnnumberedNeighbor as UnnumberedNeighborV6;
pub use v8_bgp::ApplyRequest;
pub use v8_bgp::BgpPeerConfig;
pub use v8_bgp::BgpPeerParameters;
pub use v8_bgp::Neighbor;
pub use v8_bgp::UnnumberedBgpPeerConfig;
pub use v8_bgp::UnnumberedNeighbor;

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

// ----- PeerConfig boundary conversions -----
//
// `PeerConfig` is bgp-internal (non-published). Boundary conversions live
// here as inherent `From` impls since `PeerConfig` is local to bgp.

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

// ----- Boundary helpers (free fns; non-published rdb input types) -----

/// Construct a `NeighborV1` from an rdb `BgpNeighborInfo`.
pub fn neighbor_v1_from_rdb_neighbor_info(
    asn: u32,
    rq: &rdb::BgpNeighborInfo,
) -> NeighborV1 {
    NeighborV1 {
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
            multi_exit_discriminator: rq.parameters.multi_exit_discriminator,
            communities: rq.parameters.communities.clone(),
            local_pref: rq.parameters.local_pref,
            enforce_first_as: rq.parameters.enforce_first_as,
            allow_import: ImportExportPolicy::from_per_af_policies(
                &rq.parameters.allow_import4,
                &rq.parameters.allow_import6,
            ),
            allow_export: ImportExportPolicy::from_per_af_policies(
                &rq.parameters.allow_export4,
                &rq.parameters.allow_export6,
            ),
            vlan_id: rq.parameters.vlan_id,
        },
    }
}

/// Construct a `NeighborV1` from a v1 `BgpPeerConfig`.
pub fn neighbor_v1_from_bgp_peer_config_v1(
    asn: u32,
    group: String,
    rq: BgpPeerConfigV1,
) -> NeighborV1 {
    NeighborV1 {
        asn,
        group: group.clone(),
        host: rq.host,
        name: rq.name.clone(),
        parameters: rq.parameters.clone(),
    }
}

/// Construct a latest `Neighbor` from an rdb `BgpNeighborInfo`.
pub fn neighbor_from_rdb_neighbor_info(
    asn: u32,
    rq: &rdb::BgpNeighborInfo,
) -> Neighbor {
    Neighbor {
        asn,
        name: rq.name.clone(),
        host: rq.host,
        group: rq.group.clone(),
        parameters: BgpPeerParameters {
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
            multi_exit_discriminator: rq.parameters.multi_exit_discriminator,
            communities: rq.parameters.communities.clone(),
            local_pref: rq.parameters.local_pref,
            enforce_first_as: rq.parameters.enforce_first_as,
            ipv4_unicast: ipv4_unicast_config_new(
                rq.parameters.ipv4_enabled,
                rq.parameters.nexthop4,
                rq.parameters.allow_import4.clone(),
                rq.parameters.allow_export4.clone(),
            ),
            ipv6_unicast: ipv6_unicast_config_new(
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
            src_addr: rq.parameters.src_addr,
            src_port: rq.parameters.src_port,
        },
    }
}

/// Construct a latest `Neighbor` from a latest `BgpPeerConfig`.
pub fn neighbor_from_bgp_peer_config(
    asn: u32,
    group: String,
    rq: BgpPeerConfig,
) -> Neighbor {
    Neighbor {
        asn,
        name: rq.name.clone(),
        host: rq.host,
        group: group.clone(),
        parameters: rq.parameters.clone(),
    }
}

/// Construct an `UnnumberedNeighbor` from a latest `UnnumberedBgpPeerConfig`.
pub fn unnumbered_neighbor_from_bgp_peer_config(
    asn: u32,
    group: String,
    rq: UnnumberedBgpPeerConfig,
) -> UnnumberedNeighbor {
    UnnumberedNeighbor {
        asn,
        group: group.clone(),
        interface: rq.interface.clone(),
        name: rq.name.clone(),
        act_as_a_default_ipv6_router: rq.router_lifetime,
        parameters: rq.parameters.clone(),
    }
}

/// Construct a `PeerConfig` from an `UnnumberedNeighbor` (uses the supplied
/// IPv6 link-local socket address as the connection target).
pub fn unnumbered_neighbor_to_peer_config(
    n: &UnnumberedNeighbor,
    addr: SocketAddrV6,
) -> PeerConfig {
    PeerConfig {
        name: n.name.clone(),
        host: addr.into(),
        group: n.group.clone(),
        hold_time: n.parameters.hold_time,
        idle_hold_time: n.parameters.idle_hold_time,
        delay_open: n.parameters.delay_open,
        connect_retry: n.parameters.connect_retry,
        keepalive: n.parameters.keepalive,
        resolution: n.parameters.resolution,
    }
}

/// Construct an `UnnumberedNeighbor` from an rdb `BgpUnnumberedNeighborInfo`.
pub fn unnumbered_neighbor_from_rdb_neighbor_info(
    asn: u32,
    rq: &rdb::BgpUnnumberedNeighborInfo,
) -> UnnumberedNeighbor {
    UnnumberedNeighbor {
        asn,
        group: rq.group.clone(),
        name: rq.name.clone(),
        interface: rq.interface.clone(),
        act_as_a_default_ipv6_router: rq.router_lifetime,
        parameters: BgpPeerParameters {
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
            multi_exit_discriminator: rq.parameters.multi_exit_discriminator,
            communities: rq.parameters.communities.clone(),
            local_pref: rq.parameters.local_pref,
            enforce_first_as: rq.parameters.enforce_first_as,
            vlan_id: rq.parameters.vlan_id,
            ipv4_unicast: ipv4_unicast_config_new(
                rq.parameters.ipv4_enabled,
                rq.parameters.nexthop4,
                rq.parameters.allow_import4.clone(),
                rq.parameters.allow_export4.clone(),
            ),
            ipv6_unicast: ipv6_unicast_config_new(
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
            src_addr: rq.parameters.src_addr,
            src_port: rq.parameters.src_port,
        },
    }
}

fn ipv4_unicast_config_new(
    enabled: bool,
    nexthop: Option<IpAddr>,
    import_policy: ImportExportPolicy4,
    export_policy: ImportExportPolicy4,
) -> Option<Ipv4UnicastConfig> {
    if enabled {
        Some(Ipv4UnicastConfig {
            nexthop,
            import_policy,
            export_policy,
        })
    } else {
        None
    }
}

fn ipv6_unicast_config_new(
    enabled: bool,
    nexthop: Option<IpAddr>,
    import_policy: ImportExportPolicy6,
    export_policy: ImportExportPolicy6,
) -> Option<Ipv6UnicastConfig> {
    if enabled {
        Some(Ipv6UnicastConfig {
            nexthop,
            import_policy,
            export_policy,
        })
    } else {
        None
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

/// Free-fn replacement for `From<&Capability> for BgpCapability`. The `From`
/// impl will be reabsorbed in mg-types-versions when `BgpCapability` migrates
/// in Chunk 6; until then, the impl cannot live here (orphan rule, since
/// `Capability` now lives in `bgp-types-versions`).
pub fn bgp_capability_from(value: &Capability) -> BgpCapability {
    match value {
        Capability::MultiprotocolExtensions { afi, safi } => {
            BgpCapability::MultiprotocolExtensions(AfiSafi {
                afi: *afi,
                safi: *safi,
            })
        }
        Capability::RouteRefresh {} => BgpCapability::RouteRefresh,
        Capability::FourOctetAs { asn } => BgpCapability::FourOctetAsn(*asn),
        Capability::AddPath { elements } => BgpCapability::AddPath {
            elements: elements.iter().map(AfiSafi::from).collect(),
        },
        c => BgpCapability::Unknown(CapabilityCode::from(c.clone()) as u8),
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
