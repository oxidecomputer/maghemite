// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v4::policy::{ImportExportPolicy4, ImportExportPolicy6};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// BGP neighbor configuration stored in the database and used at API boundary.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct BgpNeighborInfo {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub host: SocketAddr,
    pub parameters: BgpNeighborParameters,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct BgpUnnumberedNeighborInfo {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub interface: String,
    pub router_lifetime: u16,
    pub parameters: BgpNeighborParameters,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct BgpNeighborParameters {
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
    /// Whether IPv4 unicast is enabled for this neighbor.
    /// Defaults to true for backward compatibility with legacy data.
    #[serde(default = "default_ipv4_enabled")]
    pub ipv4_enabled: bool,
    /// Whether IPv6 unicast is enabled for this neighbor.
    /// Defaults to false for backward compatibility with legacy data.
    #[serde(default)]
    pub ipv6_enabled: bool,
    /// Per-address-family import policy for IPv4 routes.
    #[serde(default)]
    pub allow_import4: ImportExportPolicy4,
    /// Per-address-family export policy for IPv4 routes.
    #[serde(default)]
    pub allow_export4: ImportExportPolicy4,
    /// Per-address-family import policy for IPv6 routes.
    #[serde(default)]
    pub allow_import6: ImportExportPolicy6,
    /// Per-address-family export policy for IPv6 routes.
    #[serde(default)]
    pub allow_export6: ImportExportPolicy6,
    /// Optional next-hop address for IPv4 unicast announcements.
    /// If None, derives from TCP connection's local IP.
    #[serde(default)]
    pub nexthop4: Option<IpAddr>,
    /// Optional next-hop address for IPv6 unicast announcements.
    /// If None, derives from TCP connection's local IP.
    #[serde(default)]
    pub nexthop6: Option<IpAddr>,
    pub vlan_id: Option<u16>,
    /// Source IP address to bind when establishing outbound TCP connections.
    #[serde(default)]
    pub src_addr: Option<IpAddr>,
    /// Source TCP port to bind when establishing outbound TCP connections.
    #[serde(default)]
    pub src_port: Option<u16>,
}

/// Default value for ipv4_enabled - true for backward compatibility
fn default_ipv4_enabled() -> bool {
    true
}
