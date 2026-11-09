// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use oxnet::IpNet;
use oxnet::SocketAddrJson;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::messages::Afi;
use super::policy::ImportExportPolicy4;
use super::policy::ImportExportPolicy6;
use super::session::FsmStateKind;
use crate::{v1, v4, v5, v11};

/// V2 API neighbor reset operations with per-AF support
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
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

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NeighborResetRequest {
    pub asn: u32,
    pub addr: IpAddr,
    pub op: NeighborResetOp,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct UnnumberedNeighborResetRequest {
    pub asn: u32,
    pub interface: String,
    pub op: NeighborResetOp,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum BgpCapability {
    MultiprotocolExtensions(v4::bgp::config::AfiSafi),
    RouteRefresh,
    FourOctetAsn(u32),
    AddPath {
        elements: Vec<v4::bgp::config::AfiSafi>,
    },
    Unknown(u8),
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
    pub idle_hold_jitter: Option<v4::bgp::config::JitterRange>,
    /// Jitter range for connect_retry timer. When used, the connect_retry timer
    /// is multiplied by a random value within the (min, max) range supplied.
    /// Useful to help break repeated synchronization of connection collisions.
    pub connect_retry_jitter: Option<v4::bgp::config::JitterRange>,
    /// Source IP address to bind when establishing outbound TCP connections.
    /// None means the system selects the source address.
    pub src_addr: Option<IpAddr>,
    /// Source TCP port to bind when establishing outbound TCP connections.
    /// None means the system selects the source port.
    pub src_port: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct BgpPeerConfig {
    pub host: SocketAddrJson,
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

/// Neighbor configuration with explicit per-address-family enablement (v3 API)
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct Neighbor {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub host: SocketAddrJson,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
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

/// Apply changes to an ASN (current version with per-AF policies).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct ApplyRequest {
    /// ASN to apply changes to.
    pub asn: u32,
    /// Complete set of prefixes to originate.
    pub originate: Vec<IpNet>,
    /// Checker rhai code to apply to ingress open and update messages.
    pub checker: Option<v1::bgp::config::CheckerSource>,
    /// Checker rhai code to apply to egress open and update messages.
    pub shaper: Option<v1::bgp::config::ShaperSource>,
    /// Lists of peers indexed by peer group.
    pub peers: HashMap<String, Vec<BgpPeerConfig>>,
    /// Lists of unnumbered peers indexed by peer group.
    #[serde(default)]
    pub unnumbered_peers: HashMap<String, Vec<UnnumberedBgpPeerConfig>>,
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
    pub timers: v4::bgp::config::PeerTimers,
    pub counters: v4::bgp::config::PeerCounters,
    pub ipv4_unicast: Ipv4UnicastConfig,
    pub ipv6_unicast: Ipv6UnicastConfig,
}

impl From<v4::bgp::config::NeighborResetOp> for NeighborResetOp {
    fn from(old: v4::bgp::config::NeighborResetOp) -> Self {
        match old {
            v4::bgp::config::NeighborResetOp::Hard => Self::Hard,
            v4::bgp::config::NeighborResetOp::SoftInbound(afi) => {
                Self::SoftInbound(afi.map(Afi::from))
            }
            v4::bgp::config::NeighborResetOp::SoftOutbound(afi) => {
                Self::SoftOutbound(afi.map(Afi::from))
            }
        }
    }
}

impl From<v4::bgp::config::NeighborResetRequest> for NeighborResetRequest {
    fn from(old: v4::bgp::config::NeighborResetRequest) -> Self {
        let v4::bgp::config::NeighborResetRequest { asn, addr, op } = old;
        Self {
            asn,
            addr,
            op: op.into(),
        }
    }
}

impl From<v5::bgp::config::UnnumberedNeighborResetRequest>
    for UnnumberedNeighborResetRequest
{
    fn from(old: v5::bgp::config::UnnumberedNeighborResetRequest) -> Self {
        let v5::bgp::config::UnnumberedNeighborResetRequest {
            asn,
            interface,
            op,
        } = old;
        Self {
            asn,
            interface,
            op: op.into(),
        }
    }
}

impl From<BgpCapability> for v4::bgp::config::BgpCapability {
    fn from(new: BgpCapability) -> Self {
        match new {
            BgpCapability::MultiprotocolExtensions(afi_safi) => {
                Self::MultiprotocolExtensions(afi_safi)
            }
            BgpCapability::RouteRefresh => Self::RouteRefresh,
            BgpCapability::FourOctetAsn(asn) => Self::FourOctetAsn(asn),
            BgpCapability::AddPath { elements } => Self::AddPath { elements },
            BgpCapability::Unknown(code) => Self::Unknown(code),
        }
    }
}

impl From<v11::bgp::config::Ipv4UnicastConfig> for Ipv4UnicastConfig {
    fn from(old: v11::bgp::config::Ipv4UnicastConfig) -> Self {
        let v11::bgp::config::Ipv4UnicastConfig {
            nexthop,
            import_policy,
            export_policy,
        } = old;
        Self {
            nexthop,
            import_policy: import_policy.into(),
            export_policy: export_policy.into(),
        }
    }
}

impl From<Ipv4UnicastConfig> for v11::bgp::config::Ipv4UnicastConfig {
    fn from(new: Ipv4UnicastConfig) -> Self {
        let Ipv4UnicastConfig {
            nexthop,
            import_policy,
            export_policy,
        } = new;
        Self {
            nexthop,
            import_policy: import_policy.into(),
            export_policy: export_policy.into(),
        }
    }
}

impl From<v11::bgp::config::Ipv6UnicastConfig> for Ipv6UnicastConfig {
    fn from(old: v11::bgp::config::Ipv6UnicastConfig) -> Self {
        let v11::bgp::config::Ipv6UnicastConfig {
            nexthop,
            import_policy,
            export_policy,
        } = old;
        Self {
            nexthop,
            import_policy: import_policy.into(),
            export_policy: export_policy.into(),
        }
    }
}

impl From<Ipv6UnicastConfig> for v11::bgp::config::Ipv6UnicastConfig {
    fn from(new: Ipv6UnicastConfig) -> Self {
        let Ipv6UnicastConfig {
            nexthop,
            import_policy,
            export_policy,
        } = new;
        Self {
            nexthop,
            import_policy: import_policy.into(),
            export_policy: export_policy.into(),
        }
    }
}

impl From<v11::bgp::config::BgpPeerParameters> for BgpPeerParameters {
    fn from(old: v11::bgp::config::BgpPeerParameters) -> Self {
        let v11::bgp::config::BgpPeerParameters {
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
            deterministic_collision_resolution,
            idle_hold_jitter,
            connect_retry_jitter,
            src_addr,
            src_port,
        } = old;
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
            ipv4_unicast: ipv4_unicast.map(Ipv4UnicastConfig::from),
            ipv6_unicast: ipv6_unicast.map(Ipv6UnicastConfig::from),
            deterministic_collision_resolution,
            idle_hold_jitter,
            connect_retry_jitter,
            src_addr,
            src_port,
        }
    }
}

impl From<BgpPeerParameters> for v11::bgp::config::BgpPeerParameters {
    fn from(new: BgpPeerParameters) -> Self {
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
            deterministic_collision_resolution,
            idle_hold_jitter,
            connect_retry_jitter,
            src_addr,
            src_port,
        } = new;
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
            ipv4_unicast: ipv4_unicast
                .map(v11::bgp::config::Ipv4UnicastConfig::from),
            ipv6_unicast: ipv6_unicast
                .map(v11::bgp::config::Ipv6UnicastConfig::from),
            deterministic_collision_resolution,
            idle_hold_jitter,
            connect_retry_jitter,
            src_addr,
            src_port,
        }
    }
}

impl From<v11::bgp::config::BgpPeerConfig> for BgpPeerConfig {
    fn from(old: v11::bgp::config::BgpPeerConfig) -> Self {
        let v11::bgp::config::BgpPeerConfig {
            host,
            name,
            parameters,
        } = old;
        Self {
            host,
            name,
            parameters: parameters.into(),
        }
    }
}

impl From<v11::bgp::config::UnnumberedBgpPeerConfig>
    for UnnumberedBgpPeerConfig
{
    fn from(old: v11::bgp::config::UnnumberedBgpPeerConfig) -> Self {
        let v11::bgp::config::UnnumberedBgpPeerConfig {
            interface,
            name,
            router_lifetime,
            parameters,
        } = old;
        Self {
            interface,
            name,
            router_lifetime,
            parameters: parameters.into(),
        }
    }
}

impl From<v11::bgp::config::Neighbor> for Neighbor {
    fn from(old: v11::bgp::config::Neighbor) -> Self {
        let v11::bgp::config::Neighbor {
            asn,
            name,
            group,
            host,
            parameters,
        } = old;
        Self {
            asn,
            name,
            group,
            host,
            parameters: parameters.into(),
        }
    }
}

impl From<Neighbor> for v11::bgp::config::Neighbor {
    fn from(new: Neighbor) -> Self {
        let Neighbor {
            asn,
            name,
            group,
            host,
            parameters,
        } = new;
        Self {
            asn,
            name,
            group,
            host,
            parameters: parameters.into(),
        }
    }
}

impl From<v11::bgp::config::UnnumberedNeighbor> for UnnumberedNeighbor {
    fn from(old: v11::bgp::config::UnnumberedNeighbor) -> Self {
        let v11::bgp::config::UnnumberedNeighbor {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters,
        } = old;
        Self {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters: parameters.into(),
        }
    }
}

impl From<UnnumberedNeighbor> for v11::bgp::config::UnnumberedNeighbor {
    fn from(new: UnnumberedNeighbor) -> Self {
        let UnnumberedNeighbor {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters,
        } = new;
        Self {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters: parameters.into(),
        }
    }
}

impl From<v11::bgp::config::ApplyRequest> for ApplyRequest {
    fn from(old: v11::bgp::config::ApplyRequest) -> Self {
        let v11::bgp::config::ApplyRequest {
            asn,
            originate,
            checker,
            shaper,
            peers,
            unnumbered_peers,
        } = old;
        Self {
            asn,
            originate,
            checker,
            shaper,
            peers: peers
                .into_iter()
                .map(|(k, v)| {
                    (k, v.into_iter().map(BgpPeerConfig::from).collect())
                })
                .collect(),
            unnumbered_peers: unnumbered_peers
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

impl From<PeerInfo> for v11::bgp::config::PeerInfo {
    fn from(new: PeerInfo) -> Self {
        let PeerInfo {
            name,
            peer_group,
            fsm_state,
            fsm_state_duration,
            asn,
            id,
            local_ip,
            remote_ip,
            local_tcp_port,
            remote_tcp_port,
            received_capabilities,
            timers,
            counters,
            ipv4_unicast,
            ipv6_unicast,
        } = new;
        Self {
            name,
            peer_group,
            fsm_state: fsm_state.into(),
            fsm_state_duration,
            asn,
            id,
            local_ip,
            remote_ip,
            local_tcp_port,
            remote_tcp_port,
            received_capabilities: received_capabilities
                .into_iter()
                .map(Into::into)
                .collect(),
            timers,
            counters,
            ipv4_unicast: ipv4_unicast.into(),
            ipv6_unicast: ipv6_unicast.into(),
        }
    }
}
