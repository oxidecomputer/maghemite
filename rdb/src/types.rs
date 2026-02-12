// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::error::Error;
use anyhow::Result;
use chrono::{DateTime, Utc};
use omicron_common::address::{
    IPV4_LINK_LOCAL_MULTICAST_SUBNET, IPV4_MULTICAST_RANGE, IPV4_SSM_SUBNET,
    IPV6_ADMIN_SCOPED_MULTICAST_PREFIX, IPV6_INTERFACE_LOCAL_MULTICAST_SUBNET,
    IPV6_LINK_LOCAL_MULTICAST_SUBNET, IPV6_MULTICAST_RANGE,
    IPV6_RESERVED_SCOPE_MULTICAST_SUBNET, IPV6_SSM_SUBNET,
};
use omicron_common::api::external::Vni;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::Display;
use std::fmt::{self, Formatter};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

// Re-export core types from rdb-types
pub use rdb_types::{
    AddressFamily, PeerId, Prefix, Prefix4, Prefix6, ProtocolFilter,
};

// Marker types for compile-time address family discrimination.
//
// These zero-sized types enable type-level enforcement of IPv4/IPv6
// separation in generic data structures. Used in conjunction with
// PhantomData for compile-time type safety with no runtime overhead.
//
// Example:
// ```
// struct TypedContainer<Af> {
//     data: Vec<u8>,
//     _af: PhantomData<Af>,
// }
//
// // These are different types at compile time
// type Ipv4Container = TypedContainer<Ipv4Marker>;
// type Ipv6Container = TypedContainer<Ipv6Marker>;
// ```

/// IPv4 address family marker (zero-sized type)
#[derive(Clone, Copy, Debug)]
pub struct Ipv4Marker;

/// IPv6 address family marker (zero-sized type)
#[derive(Clone, Copy, Debug)]
pub struct Ipv6Marker;

/// Pre-UNNUMBERED version of Path (uses BgpPathPropertiesV1).
/// Used for API versions before VERSION_UNNUMBERED (5.0.0).
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    JsonSchema,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
)]
#[schemars(rename = "Path")]
pub struct PathV1 {
    pub nexthop: IpAddr,
    pub shutdown: bool,
    pub rib_priority: u8,
    pub bgp: Option<BgpPathPropertiesV1>,
    pub vlan_id: Option<u16>,
}

impl From<Path> for PathV1 {
    fn from(value: Path) -> Self {
        Self {
            nexthop: value.nexthop,
            shutdown: value.shutdown,
            rib_priority: value.rib_priority,
            bgp: value.bgp.map(BgpPathPropertiesV1::from),
            vlan_id: value.vlan_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq)]
pub struct Path {
    pub nexthop: IpAddr,

    /// Interface binding for nexthop resolution.
    ///
    /// This field is only populated for BGP unnumbered sessions where the nexthop
    /// is a link-local IPv6 address. For numbered peers, this is always None.
    ///
    /// Added in API version 5.0.0 (UNNUMBERED).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nexthop_interface: Option<String>,

    pub shutdown: bool,
    pub rib_priority: u8,
    pub bgp: Option<BgpPathProperties>,
    pub vlan_id: Option<u16>,
}

// Define a basic ordering on paths so bestpath selection is deterministic
impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Path {
    fn cmp(&self, other: &Self) -> Ordering {
        // Paths from the same source are considered equal for set membership.
        // This enables BTreeSet::replace() to update paths from the same source.
        //
        // BGP paths: identified by peer IP
        if let (Some(a), Some(b)) = (&self.bgp, &other.bgp)
            && a.peer == b.peer
        {
            return Ordering::Equal;
        }

        // Static paths: identified by (nexthop, nexthop_interface, vlan_id)
        if self.bgp.is_none()
            && other.bgp.is_none()
            && self.nexthop == other.nexthop
            && self.nexthop_interface == other.nexthop_interface
            && self.vlan_id == other.vlan_id
        {
            return Ordering::Equal;
        }

        if self.nexthop != other.nexthop {
            return self.nexthop.cmp(&other.nexthop);
        }
        if self.shutdown != other.shutdown {
            return self.shutdown.cmp(&other.shutdown);
        }
        if self.rib_priority != other.rib_priority {
            return self.rib_priority.cmp(&other.rib_priority);
        }
        self.bgp.cmp(&other.bgp)
    }
}

impl From<StaticRouteKey> for Path {
    fn from(value: StaticRouteKey) -> Self {
        Self {
            nexthop: value.nexthop,
            nexthop_interface: None, // Static routes don't use interface binding
            vlan_id: value.vlan_id,
            rib_priority: value.rib_priority,
            shutdown: false,
            bgp: None,
        }
    }
}

/// Pre-UNNUMBERED version of BgpPathProperties (peer is IpAddr).
/// Used for API versions before VERSION_UNNUMBERED (5.0.0).
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    JsonSchema,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
)]
#[schemars(rename = "BgpPathProperties")]
pub struct BgpPathPropertiesV1 {
    pub origin_as: u32,
    pub id: u32,
    pub peer: IpAddr,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub as_path: Vec<u32>,
    pub stale: Option<DateTime<Utc>>,
}

impl From<BgpPathProperties> for BgpPathPropertiesV1 {
    fn from(value: BgpPathProperties) -> Self {
        Self {
            origin_as: value.origin_as,
            id: value.id,
            // Convert PeerId to IpAddr - only Ip variant is valid for V1 API
            peer: match value.peer {
                PeerId::Ip(ip) => ip,
                PeerId::Interface(iface) => {
                    // This shouldn't happen in pre-UNNUMBERED versions
                    // Log warning and use unspecified address as fallback
                    eprintln!(
                        "Warning: Interface peer '{}' in V1 API context",
                        iface
                    );
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                }
            },
            med: value.med,
            local_pref: value.local_pref,
            as_path: value.as_path,
            stale: value.stale,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq)]
pub struct BgpPathProperties {
    pub origin_as: u32,
    pub id: u32,
    pub peer: PeerId,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub as_path: Vec<u32>,
    pub stale: Option<DateTime<Utc>>,
}

impl BgpPathProperties {
    pub fn as_stale(&self) -> Self {
        let mut s = self.clone();
        s.stale = Some(Utc::now());
        s
    }
}

impl PartialOrd for BgpPathProperties {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for BgpPathProperties {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.origin_as != other.origin_as {
            return self.origin_as.cmp(&other.origin_as);
        }
        if self.id != other.id {
            return self.id.cmp(&other.id);
        }
        // MED should *not* be used as a basis for comparison. Paths with
        // distinct MED values are not distinct paths.
        if self.as_path != other.as_path {
            return self.as_path.cmp(&other.as_path);
        }
        self.stale.cmp(&other.stale)
    }
}

#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    JsonSchema,
    Debug,
)]
pub struct StaticRouteKey {
    pub prefix: Prefix,
    pub nexthop: IpAddr,
    pub vlan_id: Option<u16>,
    pub rib_priority: u8,
}

impl Display for StaticRouteKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[prefix={}, nexthop={}, vlan_id={}, rib_priority={}]",
            self.prefix,
            self.nexthop,
            self.vlan_id.unwrap_or(0),
            self.rib_priority
        )
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Route4Key {
    pub prefix: Prefix4,
    pub nexthop: Ipv4Addr,
}

impl Display for Route4Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.nexthop, self.prefix)
    }
}

impl FromStr for Route4Key {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (nexthop, prefix) =
            s.split_once('/').ok_or("malformed route key".to_string())?;

        Ok(Self {
            prefix: prefix.parse()?,
            nexthop: nexthop
                .parse()
                .map_err(|_| "malformed ip addr".to_string())?,
        })
    }
}

impl Route4Key {
    pub fn db_key(&self) -> Vec<u8> {
        self.to_string().as_bytes().into()
    }
}

pub struct Route4MetricKey {
    pub route: Route4Key,
    pub metric: String,
}

impl Display for Route4MetricKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.route, self.metric,)
    }
}

impl Route4MetricKey {
    pub fn db_key(&self) -> Vec<u8> {
        self.to_string().as_bytes().into()
    }
}

pub struct Policy4Key {
    pub peer: String,
    pub prefix: Prefix4,
    pub tag: String,
}

impl Display for Policy4Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.peer, self.prefix, self.tag,)
    }
}

impl Policy4Key {
    pub fn db_key(&self) -> Vec<u8> {
        self.to_string().as_bytes().into()
    }
}

/// Database key trait for prefix types
pub trait PrefixDbKey: Sized {
    fn db_key(&self) -> Vec<u8>;
    fn from_db_key(v: &[u8]) -> Result<Self, Error>;
}

impl PrefixDbKey for Prefix4 {
    fn db_key(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = self.value.octets().into();
        buf.push(self.length);
        buf
    }

    fn from_db_key(v: &[u8]) -> Result<Self, Error> {
        if v.len() < 5 {
            Err(Error::DbKey(format!(
                "buffer to short for prefix 4 key {} < 5",
                v.len()
            )))
        } else {
            Ok(Prefix4 {
                value: Ipv4Addr::new(v[0], v[1], v[2], v[3]),
                length: v[4],
            })
        }
    }
}

impl PrefixDbKey for Prefix6 {
    fn db_key(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = self.value.octets().into();
        buf.push(self.length);
        buf
    }

    fn from_db_key(v: &[u8]) -> Result<Self, Error> {
        if v.len() < 17 {
            Err(Error::DbKey(format!(
                "buffer too short for prefix 6 key {} < 17",
                v.len()
            )))
        } else {
            let octets: [u8; 16] = v[0..16].try_into().map_err(|_| {
                Error::DbKey("failed to convert to IPv6 octets".to_string())
            })?;
            Ok(Prefix6 {
                value: Ipv6Addr::from(octets),
                length: v[16],
            })
        }
    }
}

/// Extension trait to add `contains` method for checking if a prefix contains
/// an IP address. The base [`Prefix`] type is defined in rdb-types, but this
/// method is specific to RDB's RPF (Reverse Path Forwarding) needs for
/// multicast routing.
pub trait PrefixContains {
    /// Check if this prefix contains the given IP address.
    ///
    /// Performs LPM matching to determine if the address falls
    /// within this prefix. Returns `Some(prefix_length)` if the address is
    /// contained, `None` otherwise.
    fn contains(&self, addr: IpAddr) -> Option<u8>;
}

impl PrefixContains for Prefix {
    fn contains(&self, addr: IpAddr) -> Option<u8> {
        match (self, addr) {
            (Prefix::V4(p), IpAddr::V4(a)) => {
                let prefix_bits = u32::from(p.value);
                let addr_bits = u32::from(a);
                let mask = if p.length == 0 {
                    0
                } else {
                    !0u32 << (32 - p.length)
                };
                if (prefix_bits & mask) == (addr_bits & mask) {
                    Some(p.length)
                } else {
                    None
                }
            }
            (Prefix::V6(p), IpAddr::V6(a)) => {
                let prefix_bits = u128::from(p.value);
                let addr_bits = u128::from(a);
                let mask = if p.length == 0 {
                    0
                } else {
                    !0u128 << (128 - p.length)
                };
                if (prefix_bits & mask) == (addr_bits & mask) {
                    Some(p.length)
                } else {
                    None
                }
            }
            _ => None, // IPv4 prefix with IPv6 address or vice versa
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Asn {
    TwoOctet(u16),
    FourOctet(u32),
}

impl std::fmt::Display for Asn {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        match self {
            Asn::TwoOctet(asn) => write!(f, "{}", asn),
            Asn::FourOctet(asn) => write!(f, "{}", asn),
        }
    }
}

impl From<u32> for Asn {
    fn from(value: u32) -> Asn {
        Asn::FourOctet(value)
    }
}

impl From<u16> for Asn {
    fn from(value: u16) -> Asn {
        Asn::TwoOctet(value)
    }
}

impl Asn {
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::TwoOctet(value) => u32::from(*value),
            Self::FourOctet(value) => *value,
        }
    }
}

pub fn to_buf<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(&value, &mut buf)?;
    Ok(buf)
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone, JsonSchema)]
pub enum PolicyAction {
    Allow,
    Deny,
}

impl FromStr for PolicyAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" | "Allow" => Ok(Self::Allow),
            "deny" | "Deny" => Ok(Self::Allow),
            _ => Err("Unknown policy action, must be allow or deny".into()),
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct Policy {
    pub action: PolicyAction,
    pub priority: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct BgpRouterInfo {
    pub id: u32,
    pub listen: String,
    pub graceful_shutdown: bool,
}

// ============================================================================
// API Compatibility Type (ImportExportPolicy)
// ============================================================================
// This type maintains backward compatibility with the existing v1/v2 API.
// It uses the mixed Prefix type (V4/V6) and is used at the API boundary.
// Internally, code should use ImportExportPolicy4/6 for type safety.

/// Legacy import/export policy type for v1/v2 API compatibility.
///
/// This type uses mixed IPv4/IPv6 prefixes and is used at the API boundary.
/// For internal use, convert to typed variants using
/// `as_ipv4_policy()` and `as_ipv6_policy()`.
#[derive(
    Default, Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq,
)]
#[schemars(rename = "ImportExportPolicy")]
pub enum ImportExportPolicyV1 {
    #[default]
    NoFiltering,
    Allow(BTreeSet<Prefix>),
}

impl ImportExportPolicyV1 {
    /// Extract IPv4 prefixes from this policy as a typed IPv4 policy.
    ///
    /// If this policy is `NoFiltering`, returns `ImportExportPolicy4::NoFiltering`.
    /// If this policy is `Allow(prefixes)`, returns only the IPv4 prefixes.
    /// If the policy has prefixes but none are IPv4, returns `NoFiltering` for IPv4.
    pub fn as_ipv4_policy(&self) -> ImportExportPolicy4 {
        match self {
            ImportExportPolicyV1::NoFiltering => {
                ImportExportPolicy4::NoFiltering
            }
            ImportExportPolicyV1::Allow(prefixes) => {
                let v4_prefixes: BTreeSet<Prefix4> = prefixes
                    .iter()
                    .filter_map(|p| match p {
                        Prefix::V4(p4) => Some(*p4),
                        Prefix::V6(_) => None,
                    })
                    .collect();
                if v4_prefixes.is_empty() {
                    // Policy had prefixes but none were V4 - treat as no filtering for V4
                    ImportExportPolicy4::NoFiltering
                } else {
                    ImportExportPolicy4::Allow(v4_prefixes)
                }
            }
        }
    }

    /// Extract IPv6 prefixes from this policy as a typed IPv6 policy.
    ///
    /// If this policy is `NoFiltering`, returns `ImportExportPolicy6::NoFiltering`.
    /// If this policy is `Allow(prefixes)`, returns only the IPv6 prefixes.
    /// If the policy has prefixes but none are IPv6, returns `NoFiltering` for IPv6.
    pub fn as_ipv6_policy(&self) -> ImportExportPolicy6 {
        match self {
            ImportExportPolicyV1::NoFiltering => {
                ImportExportPolicy6::NoFiltering
            }
            ImportExportPolicyV1::Allow(prefixes) => {
                let v6_prefixes: BTreeSet<Prefix6> = prefixes
                    .iter()
                    .filter_map(|p| match p {
                        Prefix::V4(_) => None,
                        Prefix::V6(p6) => Some(*p6),
                    })
                    .collect();
                if v6_prefixes.is_empty() {
                    // Policy had prefixes but none were V6 - treat as no filtering for V6
                    ImportExportPolicy6::NoFiltering
                } else {
                    ImportExportPolicy6::Allow(v6_prefixes)
                }
            }
        }
    }

    /// Combine IPv4 and IPv6 policies into a legacy mixed-AF policy.
    ///
    /// - If both are `NoFiltering`, returns `NoFiltering`
    /// - Otherwise, combines the allowed prefixes from both into a single set
    pub fn from_per_af_policies(
        v4: &ImportExportPolicy4,
        v6: &ImportExportPolicy6,
    ) -> Self {
        match (v4, v6) {
            (
                ImportExportPolicy4::NoFiltering,
                ImportExportPolicy6::NoFiltering,
            ) => ImportExportPolicyV1::NoFiltering,
            (
                ImportExportPolicy4::Allow(v4_prefixes),
                ImportExportPolicy6::NoFiltering,
            ) => {
                let prefixes: BTreeSet<Prefix> =
                    v4_prefixes.iter().map(|p| Prefix::V4(*p)).collect();
                ImportExportPolicyV1::Allow(prefixes)
            }
            (
                ImportExportPolicy4::NoFiltering,
                ImportExportPolicy6::Allow(v6_prefixes),
            ) => {
                let prefixes: BTreeSet<Prefix> =
                    v6_prefixes.iter().map(|p| Prefix::V6(*p)).collect();
                ImportExportPolicyV1::Allow(prefixes)
            }
            (
                ImportExportPolicy4::Allow(v4_prefixes),
                ImportExportPolicy6::Allow(v6_prefixes),
            ) => {
                let mut prefixes: BTreeSet<Prefix> =
                    v4_prefixes.iter().map(|p| Prefix::V4(*p)).collect();
                prefixes.extend(v6_prefixes.iter().map(|p| Prefix::V6(*p)));
                ImportExportPolicyV1::Allow(prefixes)
            }
        }
    }
}

/// Import/Export policy for IPv4 prefixes only.
#[derive(
    Default, Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq,
)]
pub enum ImportExportPolicy4 {
    #[default]
    NoFiltering,
    Allow(BTreeSet<Prefix4>),
}

/// Import/Export policy for IPv6 prefixes only.
#[derive(
    Default, Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq,
)]
pub enum ImportExportPolicy6 {
    #[default]
    NoFiltering,
    Allow(BTreeSet<Prefix6>),
}

/// Address-family-specific import/export policy wrapper for internal use.
/// This is distinct from the API-facing `ImportExportPolicy` type.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ImportExportPolicy {
    V4(ImportExportPolicy4),
    V6(ImportExportPolicy6),
}

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
}

/// Default value for ipv4_enabled - true for backward compatibility
fn default_ipv4_enabled() -> bool {
    true
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub struct BfdPeerConfig {
    /// Address of the peer to add.
    pub peer: IpAddr,
    /// Address to listen on for control messages from the peer.
    pub listen: IpAddr,
    /// Acceptable time between control messages in microseconds.
    pub required_rx: u64,
    /// Detection threshold for connectivity as a multipler to required_rx
    pub detection_threshold: u8,
    /// Mode is single-hop (RFC 5881) or multi-hop (RFC 5883).
    pub mode: SessionMode,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub enum SessionMode {
    SingleHop,
    MultiHop,
}

#[derive(Clone, Default, Debug)]
pub struct PrefixChangeNotification {
    pub changed: BTreeSet<Prefix>,
}

impl From<Prefix> for PrefixChangeNotification {
    fn from(value: Prefix) -> Self {
        Self {
            changed: BTreeSet::from([value]),
        }
    }
}

impl From<Prefix4> for PrefixChangeNotification {
    fn from(value: Prefix4) -> Self {
        Self {
            changed: BTreeSet::from([value.into()]),
        }
    }
}

impl From<Prefix6> for PrefixChangeNotification {
    fn from(value: Prefix6) -> Self {
        Self {
            changed: BTreeSet::from([value.into()]),
        }
    }
}

impl Display for PrefixChangeNotification {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut pcn = String::new();
        for p in self.changed.iter() {
            pcn.push_str(&format!("{p} "));
        }
        write!(f, "PrefixChangeNotification [ {pcn}]")
    }
}

// ============================================================================
// MRIB (Multicast RIB) Types
// ============================================================================

/// Default VNI for fleet-wide multicast routing.
pub const DEFAULT_MULTICAST_VNI: u32 = Vni::DEFAULT_MULTICAST_VNI.as_u32();

/// A validated IPv4 multicast address.
///
/// This type guarantees that the inner address is a routable multicast address
/// (not link-local).
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(try_from = "Ipv4Addr", into = "Ipv4Addr")]
#[schemars(transparent)]
pub struct MulticastAddrV4(Ipv4Addr);

impl MulticastAddrV4 {
    /// Create a new validated IPv4 multicast address.
    pub fn new(value: Ipv4Addr) -> Result<Self, Error> {
        // Must be in multicast range (224.0.0.0/4)
        if !IPV4_MULTICAST_RANGE.contains(value) {
            return Err(Error::Validation(format!(
                "IPv4 address {value} is not multicast \
                 (must be in {IPV4_MULTICAST_RANGE})"
            )));
        }

        // Reject link-local multicast (224.0.0.0/24)
        if IPV4_LINK_LOCAL_MULTICAST_SUBNET.contains(value) {
            return Err(Error::Validation(format!(
                "IPv4 address {value} is link-local multicast \
                 ({IPV4_LINK_LOCAL_MULTICAST_SUBNET}) which is not routable"
            )));
        }

        Ok(Self(value))
    }

    /// Returns the underlying IPv4 address.
    #[inline]
    pub const fn ip(&self) -> Ipv4Addr {
        self.0
    }
}

impl fmt::Display for MulticastAddrV4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<Ipv4Addr> for MulticastAddrV4 {
    type Error = Error;

    fn try_from(value: Ipv4Addr) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<MulticastAddrV4> for Ipv4Addr {
    fn from(addr: MulticastAddrV4) -> Self {
        addr.0
    }
}

/// A validated IPv6 multicast address.
///
/// This type guarantees that the inner address is a routable multicast address
/// (not interface-local, link-local, or reserved scope).
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(try_from = "Ipv6Addr", into = "Ipv6Addr")]
#[schemars(transparent)]
pub struct MulticastAddrV6(Ipv6Addr);

impl MulticastAddrV6 {
    /// Create a new validated IPv6 multicast address.
    pub fn new(value: Ipv6Addr) -> Result<Self, Error> {
        // Must be in multicast range (ff00::/8)
        if !IPV6_MULTICAST_RANGE.contains(value) {
            return Err(Error::Validation(format!(
                "IPv6 address {value} is not multicast \
                 (must be in {IPV6_MULTICAST_RANGE})"
            )));
        }

        // Reject reserved scope (ff00::/16) (reserved, not usable)
        if IPV6_RESERVED_SCOPE_MULTICAST_SUBNET.contains(value) {
            return Err(Error::Validation(format!(
                "IPv6 address {value} is in reserved scope \
                 ({IPV6_RESERVED_SCOPE_MULTICAST_SUBNET}) which is not routable"
            )));
        }

        // Reject interface-local multicast (ff01::/16)
        if IPV6_INTERFACE_LOCAL_MULTICAST_SUBNET.contains(value) {
            return Err(Error::Validation(format!(
                "IPv6 address {value} is interface-local multicast \
                 ({IPV6_INTERFACE_LOCAL_MULTICAST_SUBNET}) which is not routable"
            )));
        }

        // Reject link-local multicast (ff02::/16)
        if IPV6_LINK_LOCAL_MULTICAST_SUBNET.contains(value) {
            return Err(Error::Validation(format!(
                "IPv6 address {value} is link-local multicast \
                 ({IPV6_LINK_LOCAL_MULTICAST_SUBNET}) which is not routable"
            )));
        }

        Ok(Self(value))
    }

    /// Returns the underlying IPv6 address.
    #[inline]
    pub const fn ip(&self) -> Ipv6Addr {
        self.0
    }
}

impl fmt::Display for MulticastAddrV6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<Ipv6Addr> for MulticastAddrV6 {
    type Error = Error;

    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<MulticastAddrV6> for Ipv6Addr {
    fn from(addr: MulticastAddrV6) -> Self {
        addr.0
    }
}

/// A validated multicast group address (IPv4 or IPv6).
///
/// This type guarantees that the contained address is a routable multicast
/// address. Construction is only possible through validated paths.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub enum MulticastAddr {
    V4(MulticastAddrV4),
    V6(MulticastAddrV6),
}

impl MulticastAddr {
    /// Create an IPv4 multicast address from octets.
    pub fn new_v4(a: u8, b: u8, c: u8, d: u8) -> Result<Self, Error> {
        Ok(Self::V4(MulticastAddrV4::new(Ipv4Addr::new(a, b, c, d))?))
    }

    /// Create an IPv6 multicast address from segments.
    pub fn new_v6(segments: [u16; 8]) -> Result<Self, Error> {
        Ok(Self::V6(MulticastAddrV6::new(Ipv6Addr::new(
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        ))?))
    }

    /// Returns the underlying IP address.
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::V4(v4) => IpAddr::V4(v4.ip()),
            Self::V6(v6) => IpAddr::V6(v6.ip()),
        }
    }
}

impl fmt::Display for MulticastAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            MulticastAddr::V4(addr) => write!(f, "{}", addr),
            MulticastAddr::V6(addr) => write!(f, "{}", addr),
        }
    }
}

impl From<MulticastAddrV4> for MulticastAddr {
    fn from(addr: MulticastAddrV4) -> Self {
        Self::V4(addr)
    }
}

impl From<MulticastAddrV6> for MulticastAddr {
    fn from(addr: MulticastAddrV6) -> Self {
        Self::V6(addr)
    }
}

impl TryFrom<Ipv4Addr> for MulticastAddr {
    type Error = Error;

    fn try_from(value: Ipv4Addr) -> Result<Self, Self::Error> {
        Ok(Self::V4(MulticastAddrV4::new(value)?))
    }
}

impl TryFrom<Ipv6Addr> for MulticastAddr {
    type Error = Error;

    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        Ok(Self::V6(MulticastAddrV6::new(value)?))
    }
}

impl TryFrom<IpAddr> for MulticastAddr {
    type Error = Error;

    fn try_from(value: IpAddr) -> Result<Self, Self::Error> {
        match value {
            IpAddr::V4(v4) => Self::try_from(v4),
            IpAddr::V6(v6) => Self::try_from(v6),
        }
    }
}

/// IPv4 multicast route key with type-enforced address family matching.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub struct MulticastRouteKeyV4 {
    /// Source address (`None` for (*,G) routes).
    pub(crate) source: Option<Ipv4Addr>,
    /// Multicast group address.
    pub(crate) group: MulticastAddrV4,
    /// VNI (Virtual Network Identifier).
    #[serde(default = "default_multicast_vni")]
    pub(crate) vni: u32,
}

/// IPv6 multicast route key with type-enforced address family matching.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub struct MulticastRouteKeyV6 {
    /// Source address (`None` for (*,G) routes).
    pub(crate) source: Option<Ipv6Addr>,
    /// Multicast group address.
    pub(crate) group: MulticastAddrV6,
    /// VNI (Virtual Network Identifier).
    #[serde(default = "default_multicast_vni")]
    pub(crate) vni: u32,
}

/// Multicast route key: (Source, Group) pair for source-specific multicast,
/// or (*, Group) for any-source multicast.
///
/// Uses type-enforced address family matching: IPv4 sources can only be
/// paired with IPv4 groups, and IPv6 sources with IPv6 groups.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub enum MulticastRouteKey {
    V4(MulticastRouteKeyV4),
    V6(MulticastRouteKeyV6),
}

const fn default_multicast_vni() -> u32 {
    DEFAULT_MULTICAST_VNI
}

impl fmt::Display for MulticastRouteKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(key) => match key.source {
                Some(src) => write!(f, "({src},{})", key.group),
                None => write!(f, "(*,{})", key.group),
            },
            Self::V6(key) => match key.source {
                Some(src) => write!(f, "({src},{})", key.group),
                None => write!(f, "(*,{})", key.group),
            },
        }
    }
}

impl MulticastRouteKey {
    /// Create a multicast route key, validating address family matching.
    ///
    /// Use this when the address family is not known at compile time (e.g.,
    /// from API requests). Returns an error if source and group address
    /// families don't match. For compile-time type safety, prefer
    /// [`Self::source_specific_v4`]/[`Self::source_specific_v6`] or
    /// [`Self::any_source`].
    pub fn new(
        source: Option<IpAddr>,
        group: MulticastAddr,
        vni: u32,
    ) -> Result<Self, Error> {
        match group {
            MulticastAddr::V4(g) => {
                let src = match source {
                    None => None,
                    Some(IpAddr::V4(s)) => Some(s),
                    Some(IpAddr::V6(s)) => {
                        return Err(Error::Validation(format!(
                            "source {s} is IPv6 but group {g} is IPv4"
                        )));
                    }
                };
                Ok(Self::V4(MulticastRouteKeyV4 {
                    source: src,
                    group: g,
                    vni,
                }))
            }
            MulticastAddr::V6(g) => {
                let src = match source {
                    None => None,
                    Some(IpAddr::V6(s)) => Some(s),
                    Some(IpAddr::V4(s)) => {
                        return Err(Error::Validation(format!(
                            "source {s} is IPv4 but group {g} is IPv6"
                        )));
                    }
                };
                Ok(Self::V6(MulticastRouteKeyV6 {
                    source: src,
                    group: g,
                    vni,
                }))
            }
        }
    }

    /// Create an any-source multicast route (*,G) with default VNI.
    pub fn any_source(group: MulticastAddr) -> Self {
        match group {
            MulticastAddr::V4(g) => Self::V4(MulticastRouteKeyV4 {
                source: None,
                group: g,
                vni: DEFAULT_MULTICAST_VNI,
            }),
            MulticastAddr::V6(g) => Self::V6(MulticastRouteKeyV6 {
                source: None,
                group: g,
                vni: DEFAULT_MULTICAST_VNI,
            }),
        }
    }

    /// Create a source-specific IPv4 multicast route (S,G) with default VNI.
    pub fn source_specific_v4(
        source: Ipv4Addr,
        group: MulticastAddrV4,
    ) -> Self {
        Self::V4(MulticastRouteKeyV4 {
            source: Some(source),
            group,
            vni: DEFAULT_MULTICAST_VNI,
        })
    }

    /// Create a source-specific IPv6 multicast route (S,G) with default VNI.
    pub fn source_specific_v6(
        source: Ipv6Addr,
        group: MulticastAddrV6,
    ) -> Self {
        Self::V6(MulticastRouteKeyV6 {
            source: Some(source),
            group,
            vni: DEFAULT_MULTICAST_VNI,
        })
    }

    /// Create an any-source multicast route (*,G) with specified VNI.
    pub fn any_source_with_vni(group: MulticastAddr, vni: u32) -> Self {
        match group {
            MulticastAddr::V4(g) => Self::V4(MulticastRouteKeyV4 {
                source: None,
                group: g,
                vni,
            }),
            MulticastAddr::V6(g) => Self::V6(MulticastRouteKeyV6 {
                source: None,
                group: g,
                vni,
            }),
        }
    }

    /// Create a source-specific IPv4 multicast route (S,G) with VNI.
    pub fn source_specific_v4_with_vni(
        source: Ipv4Addr,
        group: MulticastAddrV4,
        vni: u32,
    ) -> Self {
        Self::V4(MulticastRouteKeyV4 {
            source: Some(source),
            group,
            vni,
        })
    }

    /// Create a source-specific IPv6 multicast route (S,G) with VNI.
    pub fn source_specific_v6_with_vni(
        source: Ipv6Addr,
        group: MulticastAddrV6,
        vni: u32,
    ) -> Self {
        Self::V6(MulticastRouteKeyV6 {
            source: Some(source),
            group,
            vni,
        })
    }

    /// Get the source address as IpAddr.
    pub fn source(&self) -> Option<IpAddr> {
        match self {
            Self::V4(k) => k.source.map(IpAddr::V4),
            Self::V6(k) => k.source.map(IpAddr::V6),
        }
    }

    /// Get the group address.
    pub fn group(&self) -> MulticastAddr {
        match self {
            Self::V4(k) => MulticastAddr::V4(k.group),
            Self::V6(k) => MulticastAddr::V6(k.group),
        }
    }

    /// Get the VNI.
    pub fn vni(&self) -> u32 {
        match self {
            Self::V4(k) => k.vni,
            Self::V6(k) => k.vni,
        }
    }

    /// Serialize this key to bytes for use as a sled database key.
    pub fn db_key(&self) -> Result<Vec<u8>, Error> {
        let s = serde_json::to_string(self).map_err(|e| {
            Error::Parsing(format!(
                "failed to serialize multicast route key: {e}"
            ))
        })?;
        Ok(s.as_bytes().into())
    }

    /// Deserialize a key from sled database bytes.
    pub fn from_db_key(v: &[u8]) -> Result<Self, Error> {
        let s = String::from_utf8_lossy(v);
        serde_json::from_str(&s).map_err(|e| {
            Error::DbKey(format!("failed to parse multicast route key: {e}"))
        })
    }

    /// Validate the multicast route key.
    ///
    /// Checks:
    /// - SSM groups require a source address (RFC 4607)
    ///   - IPv4: 232.0.0.0/8
    ///   - IPv6: ff30::/12 (superset covering all ff3x:: scopes for validation)
    /// - Source address (if present) must be unicast
    /// - VNI must be in valid range (0 to 16777215)
    pub fn validate(&self) -> Result<(), Error> {
        // VNI must fit in 24 bits
        const MAX_VNI: u32 = (1 << 24) - 1;
        if self.vni() > MAX_VNI {
            return Err(Error::Validation(format!(
                "VNI {} exceeds maximum value {MAX_VNI}",
                self.vni()
            )));
        }

        // SSM addresses require a source (RFC 4607). Note: ASM addresses
        // can also have sources, allowing (S,G) joins on ASM ranges gives
        // customers source filtering outside the SSM range.
        let is_ssm = match self {
            Self::V4(k) => IPV4_SSM_SUBNET.contains(k.group.ip()),
            Self::V6(k) => IPV6_SSM_SUBNET.contains(k.group.ip()),
        };
        if is_ssm && self.source().is_none() {
            return Err(Error::Validation(format!(
                "SSM group {} requires a source address",
                self.group()
            )));
        }

        // Validate source address if present
        match self {
            Self::V4(k) => {
                if let Some(addr) = k.source {
                    if addr.is_multicast() {
                        return Err(Error::Validation(format!(
                            "source address {addr} must be unicast, not multicast"
                        )));
                    }
                    if addr.is_broadcast() {
                        return Err(Error::Validation(format!(
                            "source address {addr} must be unicast, not broadcast"
                        )));
                    }
                    if addr.is_loopback() {
                        return Err(Error::Validation(format!(
                            "source address {addr} must not be loopback"
                        )));
                    }
                }
            }
            Self::V6(k) => {
                if let Some(addr) = k.source {
                    if addr.is_multicast() {
                        return Err(Error::Validation(format!(
                            "source address {addr} must be unicast, not multicast"
                        )));
                    }
                    if addr.is_loopback() {
                        return Err(Error::Validation(format!(
                            "source address {addr} must not be loopback"
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Multicast route entry containing replication groups and metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MulticastRoute {
    /// The multicast route key (S,G) or (*,G).
    pub key: MulticastRouteKey,
    /// Expected RPF neighbor for the source (for RPF checks).
    pub rpf_neighbor: Option<IpAddr>,
    /// Underlay unicast nexthops for multicast replication.
    ///
    /// Unicast IPv6 addresses where encapsulated overlay multicast traffic
    /// is forwarded. These are sled underlay addresses hosting VMs subscribed
    /// to the multicast group. Forms the outgoing interface list (OIL).
    pub underlay_nexthops: BTreeSet<Ipv6Addr>,
    /// Underlay multicast group address (ff04::X).
    ///
    /// Admin-local scoped IPv6 multicast address corresponding to the overlay
    /// multicast group. 1:1 mapped and always derived from the overlay
    /// multicast group in Omicron.
    pub underlay_group: Ipv6Addr,
    /// Route source (static, IGMP, etc.).
    pub source: MulticastRouteSource,
    /// Creation timestamp.
    pub created: DateTime<Utc>,
    /// Last updated timestamp.
    ///
    /// Only updated when route fields change semantically (rpf_neighbor,
    /// underlay_group, underlay_nexthops, source). An idempotent upsert with
    /// an identical value does not update this timestamp.
    pub updated: DateTime<Utc>,
}

impl MulticastRoute {
    pub fn new(
        key: MulticastRouteKey,
        underlay_group: Ipv6Addr,
        source: MulticastRouteSource,
    ) -> Self {
        let now = Utc::now();
        Self {
            key,
            rpf_neighbor: None,
            underlay_nexthops: BTreeSet::new(),
            underlay_group,
            source,
            created: now,
            updated: now,
        }
    }

    pub fn add_target(&mut self, target: Ipv6Addr) {
        self.underlay_nexthops.insert(target);
        self.updated = Utc::now();
    }

    pub fn remove_target(&mut self, target: &Ipv6Addr) -> bool {
        let removed = self.underlay_nexthops.remove(target);
        if removed {
            self.updated = Utc::now();
        }
        removed
    }

    /// Validate the multicast route.
    ///
    /// Checks:
    /// - Key validation (source unicast, AF match, VNI range)
    /// - Underlay group must be admin-local scoped IPv6 multicast (ff04::/16)
    /// - RPF neighbor (if present) must be unicast
    /// - RPF neighbor address family must match group address family
    /// - Underlay nexthops must be routable unicast IPv6 (not link-local)
    pub fn validate(&self) -> Result<(), Error> {
        self.key.validate()?;

        // Validate underlay_group is admin-local scoped IPv6 multicast
        // (ff04::/16). Overlay groups are mapped 1:1 to admin-local underlay
        // groups.
        if self.underlay_group.segments()[0]
            != IPV6_ADMIN_SCOPED_MULTICAST_PREFIX
        {
            return Err(Error::Validation(format!(
                "underlay_group {} must be admin-local multicast (ff04::X)",
                self.underlay_group
            )));
        }

        // Validate RPF neighbor if present
        if let Some(rpf) = &self.rpf_neighbor {
            match rpf {
                IpAddr::V4(addr) => {
                    if addr.is_multicast() {
                        return Err(Error::Validation(format!(
                            "RPF neighbor {addr} must be unicast, not multicast"
                        )));
                    }
                    if addr.is_broadcast() {
                        return Err(Error::Validation(format!(
                            "RPF neighbor {addr} must be unicast, not broadcast"
                        )));
                    }
                    // Address family must match group
                    if !matches!(self.key.group(), MulticastAddr::V4(_)) {
                        return Err(Error::Validation(format!(
                            "RPF neighbor {addr} is IPv4 but group {} is IPv6",
                            self.key.group()
                        )));
                    }
                }
                IpAddr::V6(addr) => {
                    if addr.is_multicast() {
                        return Err(Error::Validation(format!(
                            "RPF neighbor {addr} must be unicast, not multicast"
                        )));
                    }
                    // AF must match group
                    if !matches!(self.key.group(), MulticastAddr::V6(_)) {
                        return Err(Error::Validation(format!(
                            "RPF neighbor {addr} is IPv6 but group {} is IPv4",
                            self.key.group()
                        )));
                    }
                }
            }
        }

        // Validate underlay nexthops are routable unicast IPv6
        for target in &self.underlay_nexthops {
            if target.is_multicast() {
                return Err(Error::Validation(format!(
                    "underlay nexthop {target} must be unicast, not multicast"
                )));
            }
            if target.is_unspecified() {
                return Err(Error::Validation(format!(
                    "underlay nexthop {target} must not be unspecified (::)"
                )));
            }
            if target.is_loopback() {
                return Err(Error::Validation(format!(
                    "underlay nexthop {target} must not be loopback (::1)"
                )));
            }
            if target.is_unicast_link_local() {
                return Err(Error::Validation(format!(
                    "underlay nexthop {target} must not be link-local (fe80::/10)"
                )));
            }
        }

        Ok(())
    }
}

/// Source of a multicast route entry.
#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq,
)]
pub enum MulticastRouteSource {
    /// Static route configured via API.
    Static,
    /// Learned via IGMP snooping (future).
    Igmp,
    /// Learned via MLD snooping (future).
    Mld,
}

/// Notification for MRIB changes, sent to watchers.
#[derive(Clone, Default, Debug)]
pub struct MribChangeNotification {
    pub changed: BTreeSet<MulticastRouteKey>,
}

impl From<MulticastRouteKey> for MribChangeNotification {
    fn from(value: MulticastRouteKey) -> Self {
        Self {
            changed: BTreeSet::from([value]),
        }
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::Path;
    use std::collections::BTreeSet;

    /// Full structural equality for Path.
    /// Compares ALL fields, unlike Ord which only compares identity.
    ///
    /// This exists because Path's Ord implementation treats paths from the
    /// same source (same peer for BGP, same nexthop+vlan for static) as equal,
    /// enabling BTreeSet::replace() semantics. But for tests, we often want
    /// to verify all fields match exactly.
    pub fn paths_equal(a: &Path, b: &Path) -> bool {
        a.nexthop == b.nexthop
            && a.shutdown == b.shutdown
            && a.rib_priority == b.rib_priority
            && a.vlan_id == b.vlan_id
            && a.bgp == b.bgp
    }

    /// Compare two BTreeSet<Path> using full structural equality.
    pub fn path_sets_equal(a: &BTreeSet<Path>, b: &BTreeSet<Path>) -> bool {
        a.len() == b.len()
            && a.iter().zip(b.iter()).all(|(x, y)| paths_equal(x, y))
    }

    /// Compare two Vec<Path> or slices using full structural equality.
    pub fn path_vecs_equal(a: &[Path], b: &[Path]) -> bool {
        a.len() == b.len()
            && a.iter().zip(b.iter()).all(|(x, y)| paths_equal(x, y))
    }
}
