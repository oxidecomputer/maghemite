// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;

use crate::v1::rdb::prefix::Prefix;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::v1;
use crate::v4;
use crate::v4::bgp::config::Ipv4UnicastConfig;
use crate::v4::bgp::config::Ipv6UnicastConfig;
use crate::v4::bgp::config::JitterRange;
use crate::v4::bgp::policy::ImportExportPolicy4;
use crate::v5;

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

    // new stuff after v6 (VERSION_BGP_SRC_ADDR)
    /// Source IP address to bind when establishing outbound TCP connections.
    /// None means the system selects the source address.
    pub src_addr: Option<IpAddr>,
    /// Source TCP port to bind when establishing outbound TCP connections.
    /// None means the system selects the source port.
    pub src_port: Option<u16>,
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
    pub originate: Vec<Prefix>,
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

// ----- v1 (initial, frozen) -> v8 upgrades -----

impl From<v1::bgp::config::BgpPeerConfig> for BgpPeerConfig {
    fn from(cfg: v1::bgp::config::BgpPeerConfig) -> Self {
        // v1 is frozen; if this destructure stops compiling the v1
        // contract has been violated upstream — fix that, don't teach
        // this conversion to handle a new field.
        let v1::bgp::config::BgpPeerConfig {
            host,
            name,
            parameters,
        } = cfg;
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
        } = parameters;
        Self {
            host,
            name,
            parameters: BgpPeerParameters {
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
                ipv4_unicast: Some(Ipv4UnicastConfig {
                    nexthop: None,
                    import_policy: ImportExportPolicy4::from(allow_import),
                    export_policy: ImportExportPolicy4::from(allow_export),
                }),
                ipv6_unicast: None,
                vlan_id,
                connect_retry_jitter: Some(JitterRange {
                    min: 0.75,
                    max: 1.0,
                }),
                idle_hold_jitter: None,
                deterministic_collision_resolution: false,
                src_addr: None,
                src_port: None,
            },
        }
    }
}

// ----- v4 (mp_bgp, frozen) <-> v8 BgpPeerParameters -----

impl From<BgpPeerParameters> for v4::bgp::config::BgpPeerParameters {
    fn from(p: BgpPeerParameters) -> Self {
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
            // v4 has no source-address binding; the v8 fields are
            // dropped on the way down.
            src_addr: _,
            src_port: _,
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
            ipv4_unicast,
            ipv6_unicast,
            deterministic_collision_resolution,
            idle_hold_jitter,
            connect_retry_jitter,
        }
    }
}

impl From<v4::bgp::config::BgpPeerParameters> for BgpPeerParameters {
    fn from(p: v4::bgp::config::BgpPeerParameters) -> Self {
        // v4 is frozen; if this destructure stops compiling the v4
        // contract has been violated upstream — fix that, don't teach
        // this conversion to handle a new field.
        let v4::bgp::config::BgpPeerParameters {
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
            ipv4_unicast,
            ipv6_unicast,
            deterministic_collision_resolution,
            idle_hold_jitter,
            connect_retry_jitter,
            src_addr: None,
            src_port: None,
        }
    }
}

impl From<BgpPeerConfig> for v4::bgp::config::BgpPeerConfig {
    fn from(cfg: BgpPeerConfig) -> Self {
        let BgpPeerConfig {
            host,
            name,
            parameters,
        } = cfg;
        Self {
            host,
            name,
            parameters: v4::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v4::bgp::config::BgpPeerConfig> for BgpPeerConfig {
    fn from(cfg: v4::bgp::config::BgpPeerConfig) -> Self {
        // v4 is schema-stabilized; new schema fields cannot land here.
        // If this destructure stops compiling, either the addition is
        // a runtime-only field (#[serde(skip)] / #[schemars(skip)] —
        // add it to the destructure with `_:`) or the v4 contract has
        // been violated upstream.
        let v4::bgp::config::BgpPeerConfig {
            host,
            name,
            parameters,
        } = cfg;
        Self {
            host,
            name,
            parameters: BgpPeerParameters::from(parameters),
        }
    }
}

impl From<UnnumberedBgpPeerConfig>
    for v4::bgp::config::UnnumberedBgpPeerConfig
{
    fn from(cfg: UnnumberedBgpPeerConfig) -> Self {
        let UnnumberedBgpPeerConfig {
            interface,
            name,
            router_lifetime,
            parameters,
        } = cfg;
        Self {
            interface,
            name,
            router_lifetime,
            parameters: v4::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v4::bgp::config::UnnumberedBgpPeerConfig>
    for UnnumberedBgpPeerConfig
{
    fn from(cfg: v4::bgp::config::UnnumberedBgpPeerConfig) -> Self {
        // v4 is schema-stabilized; new schema fields cannot land here.
        // If this destructure stops compiling, either the addition is
        // a runtime-only field (#[serde(skip)] / #[schemars(skip)] —
        // add it to the destructure with `_:`) or the v4 contract has
        // been violated upstream.
        let v4::bgp::config::UnnumberedBgpPeerConfig {
            interface,
            name,
            router_lifetime,
            parameters,
        } = cfg;
        Self {
            interface,
            name,
            router_lifetime,
            parameters: BgpPeerParameters::from(parameters),
        }
    }
}

impl From<Neighbor> for v4::bgp::config::Neighbor {
    fn from(n: Neighbor) -> Self {
        let Neighbor {
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
            parameters: v4::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v4::bgp::config::Neighbor> for Neighbor {
    fn from(n: v4::bgp::config::Neighbor) -> Self {
        // v4 is schema-stabilized; new schema fields cannot land here.
        // If this destructure stops compiling, either the addition is
        // a runtime-only field (#[serde(skip)] / #[schemars(skip)] —
        // add it to the destructure with `_:`) or the v4 contract has
        // been violated upstream.
        let v4::bgp::config::Neighbor {
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
            parameters: BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v4::bgp::config::ApplyRequest> for ApplyRequest {
    fn from(req: v4::bgp::config::ApplyRequest) -> Self {
        // v4 is schema-stabilized; new schema fields cannot land here.
        // If this destructure stops compiling, either the addition is
        // a runtime-only field (#[serde(skip)] / #[schemars(skip)] —
        // add it to the destructure with `_:`) or the v4 contract has
        // been violated upstream.
        let v4::bgp::config::ApplyRequest {
            asn,
            originate,
            checker,
            shaper,
            peers,
            unnumbered_peers,
        } = req;
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

// ----- v5 (unnumbered, frozen) <-> v8 UnnumberedNeighbor -----

impl From<UnnumberedNeighbor> for v5::bgp::config::UnnumberedNeighbor {
    fn from(n: UnnumberedNeighbor) -> Self {
        let UnnumberedNeighbor {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters,
        } = n;
        Self {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters: v4::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v5::bgp::config::UnnumberedNeighbor> for UnnumberedNeighbor {
    fn from(n: v5::bgp::config::UnnumberedNeighbor) -> Self {
        // v5 is schema-stabilized; new schema fields cannot land here.
        // If this destructure stops compiling, either the addition is
        // a runtime-only field (#[serde(skip)] / #[schemars(skip)] —
        // add it to the destructure with `_:`) or the v5 contract has
        // been violated upstream.
        let v5::bgp::config::UnnumberedNeighbor {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters,
        } = n;
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

