// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use rdb_types_versions::v1::prefix::Prefix;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;
use crate::v4::bgp::{Ipv4UnicastConfig, Ipv6UnicastConfig, JitterRange};

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
    pub checker: Option<v1::bgp::CheckerSource>,
    /// Checker rhai code to apply to egress open and update messages.
    pub shaper: Option<v1::bgp::ShaperSource>,
    /// Lists of peers indexed by peer group.
    pub peers: HashMap<String, Vec<BgpPeerConfig>>,
    /// Lists of unnumbered peers indexed by peer group.
    #[serde(default)]
    pub unnumbered_peers: HashMap<String, Vec<UnnumberedBgpPeerConfig>>,
}
