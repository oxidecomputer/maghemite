// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::num::NonZeroU8;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::v1;
use crate::v1::rdb::prefix::Prefix;
use crate::v4::bgp::config::Ipv4UnicastConfig;
use crate::v4::bgp::config::Ipv6UnicastConfig;
use crate::v4::bgp::config::JitterRange;
use crate::v8;
use crate::v10::common::headers::Dscp;

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
    /// Source IP address to bind when establishing outbound TCP connections.
    /// None means the system selects the source address.
    pub src_addr: Option<IpAddr>,
    /// Source TCP port to bind when establishing outbound TCP connections.
    /// None means the system selects the source port.
    pub src_port: Option<u16>,
    /// IP QoS value for BGP connection (IPv4 DSCP or IPv6 Traffic Class).
    /// `None` defaults to CS6, per RFC 4271 Appendix E.
    pub dscp: Option<Dscp>,
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

// ----- v8 (bgp_src_addr, frozen) <-> v10 BgpPeerParameters -----

impl From<v8::bgp::config::BgpPeerParameters> for BgpPeerParameters {
    fn from(p: v8::bgp::config::BgpPeerParameters) -> Self {
        // v8 is frozen; if this destructure stops compiling the v8
        // contract has been violated upstream — fix that, don't teach
        // this conversion to handle a new field.
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
            min_ttl: min_ttl.and_then(NonZeroU8::new),
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
            dscp: None,
        }
    }
}

impl From<BgpPeerConfig> for v8::bgp::config::BgpPeerConfig {
    fn from(cfg: BgpPeerConfig) -> Self {
        let BgpPeerConfig {
            host,
            name,
            parameters,
        } = cfg;
        Self {
            host,
            name,
            parameters: v8::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v8::bgp::config::BgpPeerConfig> for BgpPeerConfig {
    fn from(cfg: v8::bgp::config::BgpPeerConfig) -> Self {
        // v8 is schema-stabilized; new schema fields cannot land here.
        // If this destructure stops compiling, either the addition is
        // a runtime-only field (#[serde(skip)] / #[schemars(skip)] —
        // add it to the destructure with `_:`) or the v8 contract has
        // been violated upstream.
        let v8::bgp::config::BgpPeerConfig {
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
    for v8::bgp::config::UnnumberedBgpPeerConfig
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
            parameters: v8::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v8::bgp::config::UnnumberedBgpPeerConfig>
    for UnnumberedBgpPeerConfig
{
    fn from(cfg: v8::bgp::config::UnnumberedBgpPeerConfig) -> Self {
        // v8 is schema-stabilized; new schema fields cannot land here.
        // If this destructure stops compiling, either the addition is
        // a runtime-only field (#[serde(skip)] / #[schemars(skip)] —
        // add it to the destructure with `_:`) or the v8 contract has
        // been violated upstream.
        let v8::bgp::config::UnnumberedBgpPeerConfig {
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

impl From<Neighbor> for v8::bgp::config::Neighbor {
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
            parameters: v8::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v8::bgp::config::Neighbor> for Neighbor {
    fn from(n: v8::bgp::config::Neighbor) -> Self {
        // v8 is schema-stabilized; new schema fields cannot land here.
        // If this destructure stops compiling, either the addition is
        // a runtime-only field (#[serde(skip)] / #[schemars(skip)] —
        // add it to the destructure with `_:`) or the v8 contract has
        // been violated upstream.
        let v8::bgp::config::Neighbor {
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

impl From<v8::bgp::config::ApplyRequest> for ApplyRequest {
    fn from(req: v8::bgp::config::ApplyRequest) -> Self {
        // v8 is schema-stabilized; new schema fields cannot land here.
        // If this destructure stops compiling, either the addition is
        // a runtime-only field (#[serde(skip)] / #[schemars(skip)] —
        // add it to the destructure with `_:`) or the v8 contract has
        // been violated upstream.
        let v8::bgp::config::ApplyRequest {
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

// ----- v8 (bgp_src_addr, frozen) <-> v10 UnnumberedNeighbor -----

impl From<UnnumberedNeighbor> for v8::bgp::config::UnnumberedNeighbor {
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
            parameters: v8::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v8::bgp::config::UnnumberedNeighbor> for UnnumberedNeighbor {
    fn from(n: v8::bgp::config::UnnumberedNeighbor) -> Self {
        // v8 is schema-stabilized; new schema fields cannot land here.
        // If this destructure stops compiling, either the addition is
        // a runtime-only field (#[serde(skip)] / #[schemars(skip)] —
        // add it to the destructure with `_:`) or the v8 contract has
        // been violated upstream.
        let v8::bgp::config::UnnumberedNeighbor {
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

impl From<BgpPeerParameters> for v8::bgp::config::BgpPeerParameters {
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
            src_addr,
            src_port,
            dscp: _,
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
            min_ttl: min_ttl.map(NonZeroU8::get),
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
        }
    }
}
