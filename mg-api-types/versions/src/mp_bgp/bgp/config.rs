// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;

use super::messages::Afi;
use crate::v1::rdb::prefix::Prefix;
use crate::v2::bgp::session::FsmStateKind;

use super::policy::ImportExportPolicy4;
use super::policy::ImportExportPolicy6;
use super::session::MessageHistory;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

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

impl From<v1::bgp::config::NeighborResetOp> for NeighborResetOp {
    fn from(op: v1::bgp::config::NeighborResetOp) -> Self {
        match op {
            v1::bgp::config::NeighborResetOp::Hard => NeighborResetOp::Hard,
            v1::bgp::config::NeighborResetOp::SoftInbound => {
                NeighborResetOp::SoftInbound(Some(Afi::Ipv4))
            }
            v1::bgp::config::NeighborResetOp::SoftOutbound => {
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

impl From<v1::bgp::config::NeighborResetRequest> for NeighborResetRequest {
    fn from(req: v1::bgp::config::NeighborResetRequest) -> Self {
        Self {
            asn: req.asn,
            addr: req.addr,
            op: req.op.into(),
        }
    }
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponse {
    pub by_peer: HashMap<IpAddr, MessageHistory>,
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
pub struct BgpPeerConfig {
    pub host: SocketAddr,
    pub name: String,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

/// Neighbor configuration for v4-v6 API (lacks src_addr/src_port).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
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
pub struct UnnumberedBgpPeerConfig {
    pub interface: String,
    pub name: String,
    pub router_lifetime: u16,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

/// Apply request for v4-v6 API (lacks src_addr/src_port in peer configs).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct ApplyRequest {
    pub asn: u32,
    pub originate: Vec<Prefix>,
    pub checker: Option<v1::bgp::config::CheckerSource>,
    pub shaper: Option<v1::bgp::config::ShaperSource>,
    pub peers: HashMap<String, Vec<BgpPeerConfig>>,
    #[serde(default)]
    pub unnumbered_peers: HashMap<String, Vec<UnnumberedBgpPeerConfig>>,
}

// ----- v1 (initial, frozen) <-> v4 upgrades/downgrades -----

impl From<v1::bgp::config::BgpPeerParameters> for BgpPeerParameters {
    fn from(p: v1::bgp::config::BgpPeerParameters) -> Self {
        let v1::bgp::config::BgpPeerParameters {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive,
            remote_asn,
            min_ttl,
            md5_auth_key,
            multi_exit_discriminator,
            communities,
            local_pref,
            enforce_first_as,
            allow_import,
            allow_export,
            vlan_id,
        } = p;
        Self {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive,
            remote_asn,
            min_ttl,
            md5_auth_key,
            multi_exit_discriminator,
            communities,
            local_pref,
            enforce_first_as,
            vlan_id,
            ipv4_unicast: Some(Ipv4UnicastConfig {
                nexthop: None,
                import_policy: ImportExportPolicy4::from(allow_import),
                export_policy: ImportExportPolicy4::from(allow_export),
            }),
            ipv6_unicast: None,
            deterministic_collision_resolution: false,
            idle_hold_jitter: None,
            connect_retry_jitter: Some(JitterRange {
                min: 0.75,
                max: 1.0,
            }),
        }
    }
}

impl From<v1::bgp::config::BgpPeerConfig> for BgpPeerConfig {
    fn from(cfg: v1::bgp::config::BgpPeerConfig) -> Self {
        let v1::bgp::config::BgpPeerConfig {
            host,
            name,
            parameters,
        } = cfg;
        Self {
            host,
            name,
            parameters: parameters.into(),
        }
    }
}

impl From<v1::bgp::config::Neighbor> for Neighbor {
    fn from(n: v1::bgp::config::Neighbor) -> Self {
        let v1::bgp::config::Neighbor {
            asn,
            name,
            group,
            host,
            parameters,
        } = n;
        Self {
            asn,
            name,
            group,
            host,
            parameters: parameters.into(),
        }
    }
}

impl From<v1::bgp::config::ApplyRequest> for ApplyRequest {
    fn from(req: v1::bgp::config::ApplyRequest) -> Self {
        let v1::bgp::config::ApplyRequest {
            asn,
            originate,
            checker,
            shaper,
            peers,
        } = req;
        Self {
            asn,
            originate: originate.into_iter().map(Prefix::V4).collect(),
            checker,
            shaper,
            peers: peers
                .into_iter()
                .map(|(group, peers)| {
                    (
                        group,
                        peers.into_iter().map(BgpPeerConfig::from).collect(),
                    )
                })
                .collect(),
            unnumbered_peers: HashMap::default(),
        }
    }
}

impl TryFrom<BgpPeerParameters> for v1::bgp::config::BgpPeerParameters {
    type Error = &'static str;

    fn try_from(p: BgpPeerParameters) -> Result<Self, Self::Error> {
        let BgpPeerParameters {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive,
            remote_asn,
            min_ttl,
            md5_auth_key,
            multi_exit_discriminator,
            communities,
            local_pref,
            enforce_first_as,
            vlan_id,
            ipv4_unicast,
            ipv6_unicast,
            deterministic_collision_resolution: _,
            idle_hold_jitter: _,
            connect_retry_jitter: _,
        } = p;

        if ipv6_unicast.is_some() {
            return Err("v1 BGP neighbors cannot represent IPv6 unicast");
        }
        let Some(Ipv4UnicastConfig {
            nexthop: _,
            import_policy,
            export_policy,
        }) = ipv4_unicast
        else {
            return Err("v1 BGP neighbors require IPv4 unicast");
        };

        Ok(Self {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive,
            remote_asn,
            min_ttl,
            md5_auth_key,
            multi_exit_discriminator,
            communities,
            local_pref,
            enforce_first_as,
            allow_import:
                v1::bgp::policy::ImportExportPolicy::from_per_af_policies(
                    &import_policy,
                    &ImportExportPolicy6::NoFiltering,
                ),
            allow_export:
                v1::bgp::policy::ImportExportPolicy::from_per_af_policies(
                    &export_policy,
                    &ImportExportPolicy6::NoFiltering,
                ),
            vlan_id,
        })
    }
}

impl TryFrom<BgpPeerConfig> for v1::bgp::config::BgpPeerConfig {
    type Error = &'static str;

    fn try_from(cfg: BgpPeerConfig) -> Result<Self, Self::Error> {
        let BgpPeerConfig {
            host,
            name,
            parameters,
        } = cfg;
        if !host.ip().is_ipv4() {
            return Err("v1 BGP neighbors cannot represent IPv6 peers");
        }
        Ok(Self {
            host,
            name,
            parameters: parameters.try_into()?,
        })
    }
}

impl TryFrom<Neighbor> for v1::bgp::config::Neighbor {
    type Error = &'static str;

    fn try_from(n: Neighbor) -> Result<Self, Self::Error> {
        let Neighbor {
            asn,
            name,
            group,
            host,
            parameters,
        } = n;
        if !host.ip().is_ipv4() {
            return Err("v1 BGP neighbors cannot represent IPv6 peers");
        }
        Ok(Self {
            asn,
            name,
            group,
            host,
            parameters: parameters.try_into()?,
        })
    }
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

// ----- AfiSafi / BgpCapability conversions from v1 wire messages -----

impl From<&crate::v1::bgp::messages::AddPathElement> for AfiSafi {
    fn from(value: &crate::v1::bgp::messages::AddPathElement) -> Self {
        let crate::v1::bgp::messages::AddPathElement {
            afi,
            safi,
            // send_receive is wire-protocol metadata that does not
            // belong on the schema-published AfiSafi shape.
            send_receive: _,
        } = value.clone();
        Self { afi, safi }
    }
}

impl From<&crate::v1::bgp::messages::Capability> for BgpCapability {
    fn from(value: &crate::v1::bgp::messages::Capability) -> Self {
        // BgpCapability has structured variants only for capabilities
        // we actively implement (MultiprotocolExtensions, RouteRefresh,
        // FourOctetAsn, AddPath). The remaining v1 Capability variants
        // are deliberately collapsed into BgpCapability::Unknown(code)
        // because there is no meaningful structured representation for
        // them today — most are RFC-listed but not yet implemented in
        // bgp.
        //
        // The match below names every v1 Capability variant explicitly
        // rather than using a wildcard arm, so that adding a new v1
        // variant fails to compile here. That forces a deliberate
        // decision: add a structured BgpCapability variant for it, or
        // route it to Unknown like the others.
        use crate::v1::bgp::messages::Capability;
        use crate::v1::bgp::messages::CapabilityCode;
        match value {
            Capability::MultiprotocolExtensions { afi, safi } => {
                Self::MultiprotocolExtensions(AfiSafi {
                    afi: *afi,
                    safi: *safi,
                })
            }
            Capability::RouteRefresh {} => Self::RouteRefresh,
            Capability::FourOctetAs { asn } => Self::FourOctetAsn(*asn),
            Capability::AddPath { elements } => Self::AddPath {
                elements: elements
                    .iter()
                    .map(|e| AfiSafi {
                        afi: e.afi,
                        safi: e.safi,
                    })
                    .collect(),
            },
            // Capabilities without a structured BgpCapability shape.
            c @ (Capability::OutboundRouteFiltering {}
            | Capability::MultipleRoutesToDestination {}
            | Capability::ExtendedNextHopEncoding { .. }
            | Capability::BGPExtendedMessage {}
            | Capability::BgpSec {}
            | Capability::MultipleLabels {}
            | Capability::BgpRole {}
            | Capability::GracefulRestart {}
            | Capability::DynamicCapability {}
            | Capability::MultisessionBgp {}
            | Capability::EnhancedRouteRefresh {}
            | Capability::LongLivedGracefulRestart {}
            | Capability::RoutingPolicyDistribution {}
            | Capability::Fqdn {}
            | Capability::PrestandardRouteRefresh {}
            | Capability::PrestandardOrfAndPd {}
            | Capability::PrestandardOutboundRouteFiltering {}
            | Capability::PrestandardMultisession {}
            | Capability::PrestandardFqdn {}
            | Capability::PrestandardOperationalMessage {}
            | Capability::Experimental { .. }
            | Capability::Unassigned { .. }
            | Capability::Reserved { .. }) => {
                Self::Unknown(CapabilityCode::from(c.clone()) as u8)
            }
        }
    }
}
