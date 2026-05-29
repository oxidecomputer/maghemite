// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v4;
use crate::v4::bgp::policy::ImportExportPolicy4;
use crate::v4::bgp::policy::ImportExportPolicy6;
use crate::v11::common::headers::Dscp;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::num::NonZeroU8;

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
    pub min_ttl: Option<NonZeroU8>,
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
    /// Resolved IP QoS value (IPv4 DSCP or IPv6 Traffic Class). Defaults to
    /// CS6 (per RFC 4271 Appendix E) for legacy DB rows that predate the
    /// field.
    #[serde(default = "default_dscp")]
    pub dscp: Dscp,
}

/// Default value for ipv4_enabled - true for backward compatibility
fn default_ipv4_enabled() -> bool {
    true
}

/// Default DSCP value for legacy DB rows that lack the field.
fn default_dscp() -> Dscp {
    Dscp::CS6
}

// ----- v4 (mp_bgp, frozen) <-> v11 conversions -----

impl From<v4::rdb::neighbor::BgpNeighborParameters> for BgpNeighborParameters {
    fn from(p: v4::rdb::neighbor::BgpNeighborParameters) -> Self {
        let v4::rdb::neighbor::BgpNeighborParameters {
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
            ipv4_enabled,
            ipv6_enabled,
            allow_import4,
            allow_export4,
            allow_import6,
            allow_export6,
            nexthop4,
            nexthop6,
            vlan_id,
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
            ipv4_enabled,
            ipv6_enabled,
            allow_import4,
            allow_export4,
            allow_import6,
            allow_export6,
            nexthop4,
            nexthop6,
            vlan_id,
            src_addr,
            src_port,
            dscp: default_dscp(),
        }
    }
}

impl From<BgpNeighborParameters> for v4::rdb::neighbor::BgpNeighborParameters {
    fn from(p: BgpNeighborParameters) -> Self {
        let BgpNeighborParameters {
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
            ipv4_enabled,
            ipv6_enabled,
            allow_import4,
            allow_export4,
            allow_import6,
            allow_export6,
            nexthop4,
            nexthop6,
            vlan_id,
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
            ipv4_enabled,
            ipv6_enabled,
            allow_import4,
            allow_export4,
            allow_import6,
            allow_export6,
            nexthop4,
            nexthop6,
            vlan_id,
            src_addr,
            src_port,
        }
    }
}

impl From<v4::rdb::neighbor::BgpNeighborInfo> for BgpNeighborInfo {
    fn from(n: v4::rdb::neighbor::BgpNeighborInfo) -> Self {
        let v4::rdb::neighbor::BgpNeighborInfo {
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

impl From<BgpNeighborInfo> for v4::rdb::neighbor::BgpNeighborInfo {
    fn from(n: BgpNeighborInfo) -> Self {
        let BgpNeighborInfo {
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

impl From<v4::rdb::neighbor::BgpUnnumberedNeighborInfo>
    for BgpUnnumberedNeighborInfo
{
    fn from(n: v4::rdb::neighbor::BgpUnnumberedNeighborInfo) -> Self {
        let v4::rdb::neighbor::BgpUnnumberedNeighborInfo {
            asn,
            name,
            group,
            interface,
            router_lifetime,
            parameters,
        } = n;
        Self {
            asn,
            name,
            group,
            interface,
            router_lifetime,
            parameters: parameters.into(),
        }
    }
}

impl From<BgpUnnumberedNeighborInfo>
    for v4::rdb::neighbor::BgpUnnumberedNeighborInfo
{
    fn from(n: BgpUnnumberedNeighborInfo) -> Self {
        let BgpUnnumberedNeighborInfo {
            asn,
            name,
            group,
            interface,
            router_lifetime,
            parameters,
        } = n;
        Self {
            asn,
            name,
            group,
            interface,
            router_lifetime,
            parameters: parameters.into(),
        }
    }
}
