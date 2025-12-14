// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::config::PeerConfig;
use crate::session::FsmStateKind;
use rdb::{
    ImportExportPolicy, ImportExportPolicy4, ImportExportPolicy6, PolicyAction,
    Prefix4, Prefix6,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
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

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub enum NeighborResetOp {
    Hard,
    SoftInbound,
    SoftOutbound,
}

/// Per-address-family configuration for IPv4 Unicast
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct Ipv4UnicastConfig {
    pub import_policy: ImportExportPolicy4,
    pub export_policy: ImportExportPolicy4,
}

/// Per-address-family configuration for IPv6 Unicast
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct Ipv6UnicastConfig {
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
}

impl Neighbor {
    /// Validate that at least one address family is enabled
    pub fn validate(&self) -> Result<(), String> {
        if self.ipv4_unicast.is_none() && self.ipv6_unicast.is_none() {
            return Err("at least one address family must be enabled".into());
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
    pub allow_import: ImportExportPolicy,
    pub allow_export: ImportExportPolicy,
    pub vlan_id: Option<u16>,
}

impl From<Neighbor> for PeerConfig {
    fn from(rq: Neighbor) -> Self {
        Self {
            name: rq.name.clone(),
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
            allow_import: ImportExportPolicy::from_per_af_policies(
                &rq.allow_import4,
                &rq.allow_import6,
            ),
            allow_export: ImportExportPolicy::from_per_af_policies(
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
        let ipv4_unicast = if rq.ipv4_enabled {
            Some(Ipv4UnicastConfig {
                import_policy: rq.allow_import4,
                export_policy: rq.allow_export4,
            })
        } else {
            None
        };

        let ipv6_unicast = if rq.ipv6_enabled {
            Some(Ipv6UnicastConfig {
                import_policy: rq.allow_import6,
                export_policy: rq.allow_export6,
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
            group: group.clone(),
            md5_auth_key: rq.md5_auth_key,
            multi_exit_discriminator: rq.multi_exit_discriminator,
            communities: rq.communities,
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            ipv4_unicast,
            ipv6_unicast,
            vlan_id: rq.vlan_id,
        }
    }

    pub fn from_rdb_neighbor_info(asn: u32, rq: &rdb::BgpNeighborInfo) -> Self {
        // Use explicit enablement flags from the database
        let ipv4_unicast = if rq.ipv4_enabled {
            Some(Ipv4UnicastConfig {
                import_policy: rq.allow_import4.clone(),
                export_policy: rq.allow_export4.clone(),
            })
        } else {
            None
        };

        let ipv6_unicast = if rq.ipv6_enabled {
            Some(Ipv6UnicastConfig {
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
    pub peers: BTreeMap<IpAddr, PeerInfo>,
    pub graceful_shutdown: bool,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DynamicTimerInfo {
    pub configured: Duration,
    pub negotiated: Duration,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PeerTimers {
    pub hold: DynamicTimerInfo,
    pub keepalive: DynamicTimerInfo,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PeerInfo {
    pub state: FsmStateKind,
    pub asn: Option<u32>,
    pub duration_millis: u64,
    pub timers: PeerTimers,
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
    pub allow_import: ImportExportPolicy,
    pub allow_export: ImportExportPolicy,
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
    /// Whether IPv4 unicast is enabled for this peer.
    pub ipv4_enabled: bool,
    /// Whether IPv6 unicast is enabled for this peer.
    pub ipv6_enabled: bool,
    /// Per-address-family import policy for IPv4 routes (only used if ipv4_enabled).
    #[serde(default)]
    pub allow_import4: ImportExportPolicy4,
    /// Per-address-family export policy for IPv4 routes (only used if ipv4_enabled).
    #[serde(default)]
    pub allow_export4: ImportExportPolicy4,
    /// Per-address-family import policy for IPv6 routes (only used if ipv6_enabled).
    #[serde(default)]
    pub allow_import6: ImportExportPolicy6,
    /// Per-address-family export policy for IPv6 routes (only used if ipv6_enabled).
    #[serde(default)]
    pub allow_export6: ImportExportPolicy6,
    pub vlan_id: Option<u16>,
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
            ipv4_enabled: true,
            ipv6_enabled: false,
            allow_import4: cfg.allow_import.as_ipv4_policy(),
            allow_export4: cfg.allow_export.as_ipv4_policy(),
            allow_import6: ImportExportPolicy6::NoFiltering,
            allow_export6: ImportExportPolicy6::NoFiltering,
            vlan_id: cfg.vlan_id,
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
pub struct PeerInfoV1 {
    pub state: FsmStateKindV1,
    pub asn: Option<u32>,
    pub duration_millis: u64,
    pub timers: PeerTimers,
}

impl From<PeerInfo> for PeerInfoV1 {
    fn from(info: PeerInfo) -> Self {
        Self {
            state: FsmStateKindV1::from(info.state),
            asn: info.asn,
            duration_millis: info.duration_millis,
            timers: info.timers,
        }
    }
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
