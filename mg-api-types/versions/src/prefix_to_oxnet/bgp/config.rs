// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::v1;
use crate::v4;
use crate::v8;
use oxnet::SocketAddrJson;
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::policy::ImportExportPolicy4;
use super::policy::ImportExportPolicy6;

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
    pub ipv4_unicast: Option<Ipv4UnicastConfig>,
    pub ipv6_unicast: Option<Ipv6UnicastConfig>,
    pub deterministic_collision_resolution: bool,
    pub idle_hold_jitter: Option<v4::bgp::config::JitterRange>,
    pub connect_retry_jitter: Option<v4::bgp::config::JitterRange>,
    pub src_addr: Option<IpAddr>,
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

/// Apply changes to an ASN.
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
    pub fsm_state: crate::v2::bgp::session::FsmStateKind,
    pub fsm_state_duration: Duration,
    pub asn: Option<u32>,
    pub id: Option<u32>,
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub local_tcp_port: u16,
    pub remote_tcp_port: u16,
    pub received_capabilities: Vec<v4::bgp::config::BgpCapability>,
    pub timers: v4::bgp::config::PeerTimers,
    pub counters: v4::bgp::config::PeerCounters,
    pub ipv4_unicast: Ipv4UnicastConfig,
    pub ipv6_unicast: Ipv6UnicastConfig,
}

/// IPv4 prefixes to originate from an ASN.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Origin4 {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Ipv4Net>,
}

// ---------------------------------------------------------------------------
// Upgrade conversions: v4 → v10 (for Ipv4/6UnicastConfig used in v8 BgpPeerParameters)
// ---------------------------------------------------------------------------

impl From<v4::bgp::config::Ipv4UnicastConfig> for Ipv4UnicastConfig {
    fn from(old: v4::bgp::config::Ipv4UnicastConfig) -> Self {
        let v4::bgp::config::Ipv4UnicastConfig {
            nexthop,
            import_policy,
            export_policy,
        } = old;
        Self {
            nexthop,
            import_policy: ImportExportPolicy4::from(import_policy),
            export_policy: ImportExportPolicy4::from(export_policy),
        }
    }
}

impl From<v4::bgp::config::Ipv6UnicastConfig> for Ipv6UnicastConfig {
    fn from(old: v4::bgp::config::Ipv6UnicastConfig) -> Self {
        let v4::bgp::config::Ipv6UnicastConfig {
            nexthop,
            import_policy,
            export_policy,
        } = old;
        Self {
            nexthop,
            import_policy: ImportExportPolicy6::from(import_policy),
            export_policy: ImportExportPolicy6::from(export_policy),
        }
    }
}

// ---------------------------------------------------------------------------
// Upgrade conversions: v8 → v10
// ---------------------------------------------------------------------------

impl From<v8::bgp::config::BgpPeerParameters> for BgpPeerParameters {
    fn from(old: v8::bgp::config::BgpPeerParameters) -> Self {
        // v8 is schema-stabilized; compile barrier protects against upstream changes.
        let v8::bgp::config::BgpPeerParameters {
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

impl From<v8::bgp::config::BgpPeerConfig> for BgpPeerConfig {
    fn from(old: v8::bgp::config::BgpPeerConfig) -> Self {
        let v8::bgp::config::BgpPeerConfig {
            host,
            name,
            parameters,
        } = old;
        Self {
            host: host.into(),
            name,
            parameters: BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v8::bgp::config::UnnumberedBgpPeerConfig>
    for UnnumberedBgpPeerConfig
{
    fn from(old: v8::bgp::config::UnnumberedBgpPeerConfig) -> Self {
        let v8::bgp::config::UnnumberedBgpPeerConfig {
            interface,
            name,
            router_lifetime,
            parameters,
        } = old;
        Self {
            interface,
            name,
            router_lifetime,
            parameters: BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v8::bgp::config::Neighbor> for Neighbor {
    fn from(old: v8::bgp::config::Neighbor) -> Self {
        let v8::bgp::config::Neighbor {
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
            host: host.into(),
            parameters: BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v8::bgp::config::UnnumberedNeighbor> for UnnumberedNeighbor {
    fn from(old: v8::bgp::config::UnnumberedNeighbor) -> Self {
        let v8::bgp::config::UnnumberedNeighbor {
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
            parameters: BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v8::bgp::config::ApplyRequest> for ApplyRequest {
    fn from(old: v8::bgp::config::ApplyRequest) -> Self {
        // v8 is schema-stabilized; compile barrier protects against upstream changes.
        let v8::bgp::config::ApplyRequest {
            asn,
            originate,
            checker,
            shaper,
            peers,
            unnumbered_peers,
        } = old;
        Self {
            asn,
            originate: originate
                .into_iter()
                .map(|p| match p {
                    v1::rdb::prefix::Prefix::V4(p4) => {
                        IpNet::V4(Ipv4Net::new_unchecked(p4.value, p4.length))
                    }
                    v1::rdb::prefix::Prefix::V6(p6) => {
                        IpNet::V6(Ipv6Net::new_unchecked(p6.value, p6.length))
                    }
                })
                .collect(),
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

impl From<v1::bgp::config::Origin4> for Origin4 {
    fn from(old: v1::bgp::config::Origin4) -> Self {
        // v1 is frozen; compile barrier protects against upstream field additions.
        let v1::bgp::config::Origin4 { asn, prefixes } = old;
        Self {
            asn,
            prefixes: prefixes
                .into_iter()
                .map(|p| Ipv4Net::new_unchecked(p.value, p.length))
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Downgrade conversions: v10 → v4 (for Ipv4/6UnicastConfig)
// ---------------------------------------------------------------------------

impl From<Ipv4UnicastConfig> for v4::bgp::config::Ipv4UnicastConfig {
    fn from(new: Ipv4UnicastConfig) -> Self {
        let Ipv4UnicastConfig {
            nexthop,
            import_policy,
            export_policy,
        } = new;
        Self {
            nexthop,
            import_policy: v4::bgp::policy::ImportExportPolicy4::from(
                import_policy,
            ),
            export_policy: v4::bgp::policy::ImportExportPolicy4::from(
                export_policy,
            ),
        }
    }
}

impl From<Ipv6UnicastConfig> for v4::bgp::config::Ipv6UnicastConfig {
    fn from(new: Ipv6UnicastConfig) -> Self {
        let Ipv6UnicastConfig {
            nexthop,
            import_policy,
            export_policy,
        } = new;
        Self {
            nexthop,
            import_policy: v4::bgp::policy::ImportExportPolicy6::from(
                import_policy,
            ),
            export_policy: v4::bgp::policy::ImportExportPolicy6::from(
                export_policy,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Downgrade conversions: v10 → v8
// ---------------------------------------------------------------------------

impl From<BgpPeerParameters> for v8::bgp::config::BgpPeerParameters {
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
                .map(v4::bgp::config::Ipv4UnicastConfig::from),
            ipv6_unicast: ipv6_unicast
                .map(v4::bgp::config::Ipv6UnicastConfig::from),
            deterministic_collision_resolution,
            idle_hold_jitter,
            connect_retry_jitter,
            src_addr,
            src_port,
        }
    }
}

impl From<BgpPeerConfig> for v8::bgp::config::BgpPeerConfig {
    fn from(new: BgpPeerConfig) -> Self {
        let BgpPeerConfig {
            host,
            name,
            parameters,
        } = new;
        Self {
            host: *host,
            name,
            parameters: v8::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<UnnumberedBgpPeerConfig>
    for v8::bgp::config::UnnumberedBgpPeerConfig
{
    fn from(new: UnnumberedBgpPeerConfig) -> Self {
        let UnnumberedBgpPeerConfig {
            interface,
            name,
            router_lifetime,
            parameters,
        } = new;
        Self {
            interface,
            name,
            router_lifetime,
            parameters: v8::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<Neighbor> for v8::bgp::config::Neighbor {
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
            host: *host,
            parameters: v8::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<UnnumberedNeighbor> for v8::bgp::config::UnnumberedNeighbor {
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
            parameters: v8::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<PeerInfo> for v4::bgp::config::PeerInfo {
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
            ipv4_unicast: v4::bgp::config::Ipv4UnicastConfig::from(
                ipv4_unicast,
            ),
            ipv6_unicast: v4::bgp::config::Ipv6UnicastConfig::from(
                ipv6_unicast,
            ),
        }
    }
}

impl From<Origin4> for v1::bgp::config::Origin4 {
    fn from(new: Origin4) -> Self {
        // v1 is frozen; compile barrier protects against upstream field additions.
        let Origin4 { asn, prefixes } = new;
        Self {
            asn,
            prefixes: prefixes
                .into_iter()
                .map(|n| v1::rdb::prefix::Prefix4 {
                    value: n.addr(),
                    length: n.width(),
                })
                .collect(),
        }
    }
}
