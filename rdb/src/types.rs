// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::error::Error;
use anyhow::Result;
use chrono::{DateTime, Utc};
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

// Ord defines path *identity* for BTreeSet membership.
//
// A path's identity determines when insert() is a no-op and when
// replace() overwrites an existing entry. Attributes like shutdown,
// rib_priority, med, local_pref, etc. are NOT part of identity —
// they are carried on a path and can be updated via replace().
//
// Identity rules:
// - BGP path:    identified solely by PeerId
// - Static path: identified by (nexthop, nexthop_interface, vlan_id)
// - BGP and static paths are never the same path
//
// Note: this intentionally disagrees with derived Eq (which compares
// all fields). Eq gives structural equality; Ord gives set identity.
impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Path {
    fn cmp(&self, other: &Self) -> Ordering {
        match (&self.bgp, &other.bgp) {
            // BGP path identity is purely PeerId.
            (Some(a), Some(b)) => a.peer.cmp(&b.peer),

            // Static path identity is
            // (nexthop, nexthop_interface, vlan_id).
            (None, None) => self
                .nexthop
                .cmp(&other.nexthop)
                .then_with(|| {
                    self.nexthop_interface.cmp(&other.nexthop_interface)
                })
                .then_with(|| self.vlan_id.cmp(&other.vlan_id)),

            // BGP and static paths are never the same path.
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
        }
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

// BgpPathProperties intentionally does not implement Ord — Path::Ord
// compares only the `peer` field for BGP path identity. All other
// fields are attributes, not identity.
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
            && a.nexthop_interface == b.nexthop_interface
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::DEFAULT_RIB_PRIORITY_BGP;
    use std::{
        cmp::Ordering, collections::BTreeSet, net::IpAddr, str::FromStr,
    };

    fn bgp_path(
        nexthop: IpAddr,
        peer: PeerId,
        id: u32,
        origin_as: u32,
    ) -> Path {
        let nexthop_interface = match &peer {
            PeerId::Interface(iface) => Some(iface.clone()),
            PeerId::Ip(_) => None,
        };
        Path {
            nexthop,
            nexthop_interface,
            shutdown: false,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            bgp: Some(BgpPathProperties {
                origin_as,
                id,
                peer,
                med: None,
                local_pref: Some(100),
                as_path: vec![origin_as],
                stale: None,
            }),
            vlan_id: None,
        }
    }

    fn static_path(nexthop: IpAddr) -> Path {
        Path {
            nexthop,
            nexthop_interface: None,
            shutdown: false,
            rib_priority: 10,
            bgp: None,
            vlan_id: None,
        }
    }

    /// BGP path identity is purely PeerId. Two paths with the
    /// same PeerId are Equal regardless of all other fields.
    /// Different PeerIds are never Equal, even when everything
    /// else matches.
    #[test]
    fn bgp_path_identity() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();
        let ll = IpAddr::from_str("fe80::1").unwrap();

        // Same numbered peer: Equal despite every attribute
        // differing.
        let mut a = bgp_path(ip1, PeerId::Ip(ip1), 1, 100);
        let mut b = a.clone();
        b.bgp.as_mut().unwrap().med = Some(999);
        b.bgp.as_mut().unwrap().local_pref = Some(999);
        b.bgp.as_mut().unwrap().origin_as = 999;
        b.bgp.as_mut().unwrap().id = 999;
        b.bgp.as_mut().unwrap().as_path = vec![1, 2, 3, 4, 5];
        b.nexthop = IpAddr::from_str("99.99.99.99").unwrap();
        b.shutdown = true;
        b.rib_priority = 255;
        b.vlan_id = Some(42);
        assert_eq!(a.cmp(&b), Ordering::Equal);

        // Same unnumbered peer: Equal despite attribute
        // differences.
        a = bgp_path(ll, PeerId::Interface("eth0".into()), 1, 100);
        b = a.clone();
        b.bgp.as_mut().unwrap().med = Some(999);
        b.nexthop = IpAddr::from_str("fe80::99").unwrap();
        assert_eq!(a.cmp(&b), Ordering::Equal);

        // Different numbered peers: not Equal.
        a = bgp_path(ip1, PeerId::Ip(ip1), 1, 100);
        b = bgp_path(ip2, PeerId::Ip(ip2), 1, 100);
        assert_ne!(a.cmp(&b), Ordering::Equal);

        // Different unnumbered peers sharing a link-local: not
        // Equal. (Previously broken: silent path loss.)
        a = bgp_path(ll, PeerId::Interface("eth0".into()), 1, 100);
        b = bgp_path(ll, PeerId::Interface("eth1".into()), 1, 100);
        assert_ne!(a.cmp(&b), Ordering::Equal);

        // Multiple sessions to the same router (same id + AS):
        // not Equal because PeerIds differ.
        a = bgp_path(ip1, PeerId::Ip(ip1), 42, 100);
        b = bgp_path(ip2, PeerId::Ip(ip2), 42, 100);
        assert_ne!(a.cmp(&b), Ordering::Equal);

        // Same nexthop, same id, different peer: not Equal.
        a = bgp_path(ip1, PeerId::Ip(ip1), 1, 100);
        b = bgp_path(ip1, PeerId::Ip(ip2), 1, 100);
        assert_ne!(a.cmp(&b), Ordering::Equal);
    }

    /// Static path identity is (nexthop, nexthop_interface,
    /// vlan_id). Changing shutdown or rib_priority does not
    /// affect identity.
    #[test]
    fn static_path_identity() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();

        // Same source: Equal despite attribute differences.
        let mut a = static_path(ip1);
        let mut b = a.clone();
        b.shutdown = true;
        b.rib_priority = 99;
        assert_eq!(a.cmp(&b), Ordering::Equal);

        // Different nexthop: not Equal.
        a = static_path(ip1);
        b = static_path(ip2);
        assert_ne!(a.cmp(&b), Ordering::Equal);

        // Different nexthop_interface: not Equal.
        a = static_path(ip1);
        a.nexthop_interface = Some("eth0".to_string());
        b = static_path(ip1);
        b.nexthop_interface = Some("eth1".to_string());
        assert_ne!(a.cmp(&b), Ordering::Equal);

        // Different vlan_id: not Equal.
        a = static_path(ip1);
        a.vlan_id = Some(100);
        b = static_path(ip1);
        b.vlan_id = Some(200);
        assert_ne!(a.cmp(&b), Ordering::Equal);
    }

    /// BGP and static paths are never Equal, and BGP sorts after
    /// static (Some > None).
    #[test]
    fn bgp_vs_static_ordering() {
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        let b = bgp_path(ip, PeerId::Ip(ip), 1, 100);
        let s = static_path(ip);
        assert_ne!(b.cmp(&s), Ordering::Equal);
        assert_eq!(b.cmp(&s), Ordering::Greater);
        assert_eq!(s.cmp(&b), Ordering::Less);
    }

    // ---- BTreeSet behavior ----

    /// Paths with distinct identities all coexist in a BTreeSet:
    /// two unnumbered peers (same link-local), one numbered peer,
    /// and one static route.
    #[test]
    fn btreeset_coexistence() {
        let ll = IpAddr::from_str("fe80::1").unwrap();
        let numbered_ip = IpAddr::from_str("10.0.0.1").unwrap();
        let static_nh = IpAddr::from_str("10.0.0.254").unwrap();

        let mut set = BTreeSet::new();
        set.insert(bgp_path(ll, PeerId::Interface("eth0".into()), 1, 100));
        set.insert(bgp_path(ll, PeerId::Interface("eth1".into()), 1, 100));
        set.insert(bgp_path(numbered_ip, PeerId::Ip(numbered_ip), 2, 200));
        set.insert(static_path(static_nh));
        assert_eq!(set.len(), 4);
    }

    /// replace() overwrites the existing entry when identity
    /// matches, for both BGP and static paths.
    #[test]
    fn btreeset_replace() {
        let ip = IpAddr::from_str("10.0.0.1").unwrap();

        // BGP: same peer, different med.
        let a = bgp_path(ip, PeerId::Ip(ip), 1, 100);
        let mut b = a.clone();
        b.bgp.as_mut().unwrap().med = Some(999);

        let mut set = BTreeSet::new();
        set.insert(a);
        set.replace(b);
        assert_eq!(set.len(), 1);
        assert_eq!(
            set.iter().next().unwrap().bgp.as_ref().unwrap().med,
            Some(999),
        );

        // Static: same source, different rib_priority.
        let a = static_path(ip);
        let mut b = a.clone();
        b.rib_priority = 99;

        let mut set = BTreeSet::new();
        set.insert(a);
        set.replace(b);
        assert_eq!(set.len(), 1);
        assert_eq!(set.iter().next().unwrap().rib_priority, 99);
    }

    /// insert() with the same identity is a no-op — the original
    /// value is kept, not overwritten.
    #[test]
    fn btreeset_insert_is_noop() {
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        let a = bgp_path(ip, PeerId::Ip(ip), 1, 100);
        let mut b = a.clone();
        b.bgp.as_mut().unwrap().med = Some(999);

        let mut set = BTreeSet::new();
        set.insert(a);
        let was_new = set.insert(b);
        assert!(!was_new);
        assert_eq!(set.len(), 1);
        assert_eq!(set.iter().next().unwrap().bgp.as_ref().unwrap().med, None,);
    }

    /// remove() targets the correct path by identity, not by
    /// attribute values.
    #[test]
    fn btreeset_remove() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();
        let a = bgp_path(ip1, PeerId::Ip(ip1), 1, 100);
        let b = bgp_path(ip2, PeerId::Ip(ip2), 1, 100);

        let mut set = BTreeSet::new();
        set.insert(a.clone());
        set.insert(b);
        assert_eq!(set.len(), 2);

        // Probe with same peer as `a` but different attributes.
        let mut probe = a.clone();
        probe.bgp.as_mut().unwrap().med = Some(999);
        probe.shutdown = true;
        set.remove(&probe);
        assert_eq!(set.len(), 1);
        assert_eq!(
            set.iter().next().unwrap().bgp.as_ref().unwrap().peer,
            PeerId::Ip(ip2),
        );
    }

    // ---- Ord contract ----

    /// Antisymmetry and transitivity across BGP, static, and
    /// cross-type path comparisons.
    #[test]
    fn ord_contract() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();
        let ip3 = IpAddr::from_str("10.0.0.3").unwrap();

        // BGP paths.
        let a = bgp_path(ip1, PeerId::Ip(ip1), 1, 100);
        let b = bgp_path(ip2, PeerId::Ip(ip2), 1, 100);
        let c = bgp_path(ip3, PeerId::Ip(ip3), 1, 100);
        assert_eq!(a.cmp(&b), b.cmp(&a).reverse());
        assert_eq!(b.cmp(&c), c.cmp(&b).reverse());
        assert_eq!(a.cmp(&c), Ordering::Less); // transitivity

        // Static paths.
        let a = static_path(ip1);
        let b = static_path(ip2);
        let c = static_path(ip3);
        assert_eq!(a.cmp(&b), b.cmp(&a).reverse());
        assert_eq!(b.cmp(&c), c.cmp(&b).reverse());
        assert_eq!(a.cmp(&c), Ordering::Less);

        // Cross-type.
        let bgp = bgp_path(ip1, PeerId::Ip(ip1), 1, 100);
        let st = static_path(ip1);
        assert_eq!(bgp.cmp(&st), st.cmp(&bgp).reverse());
    }
}
