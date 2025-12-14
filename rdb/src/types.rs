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
pub use rdb_types::{AddressFamily, Prefix, Prefix4, Prefix6, ProtocolFilter};

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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq)]
pub struct Path {
    pub nexthop: IpAddr,
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
            vlan_id: value.vlan_id,
            rib_priority: value.rib_priority,
            shutdown: false,
            bgp: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq)]
pub struct BgpPathProperties {
    pub origin_as: u32,
    pub id: u32,
    pub peer: IpAddr,
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
pub enum ImportExportPolicy {
    #[default]
    NoFiltering,
    Allow(BTreeSet<Prefix>),
}

impl ImportExportPolicy {
    /// Extract IPv4 prefixes from this policy as a typed IPv4 policy.
    ///
    /// If this policy is `NoFiltering`, returns `ImportExportPolicy4::NoFiltering`.
    /// If this policy is `Allow(prefixes)`, returns only the IPv4 prefixes.
    /// If the policy has prefixes but none are IPv4, returns `NoFiltering` for IPv4.
    pub fn as_ipv4_policy(&self) -> ImportExportPolicy4 {
        match self {
            ImportExportPolicy::NoFiltering => ImportExportPolicy4::NoFiltering,
            ImportExportPolicy::Allow(prefixes) => {
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
            ImportExportPolicy::NoFiltering => ImportExportPolicy6::NoFiltering,
            ImportExportPolicy::Allow(prefixes) => {
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
            ) => ImportExportPolicy::NoFiltering,
            (
                ImportExportPolicy4::Allow(v4_prefixes),
                ImportExportPolicy6::NoFiltering,
            ) => {
                let prefixes: BTreeSet<Prefix> =
                    v4_prefixes.iter().map(|p| Prefix::V4(*p)).collect();
                ImportExportPolicy::Allow(prefixes)
            }
            (
                ImportExportPolicy4::NoFiltering,
                ImportExportPolicy6::Allow(v6_prefixes),
            ) => {
                let prefixes: BTreeSet<Prefix> =
                    v6_prefixes.iter().map(|p| Prefix::V6(*p)).collect();
                ImportExportPolicy::Allow(prefixes)
            }
            (
                ImportExportPolicy4::Allow(v4_prefixes),
                ImportExportPolicy6::Allow(v6_prefixes),
            ) => {
                let mut prefixes: BTreeSet<Prefix> =
                    v4_prefixes.iter().map(|p| Prefix::V4(*p)).collect();
                prefixes.extend(v6_prefixes.iter().map(|p| Prefix::V6(*p)));
                ImportExportPolicy::Allow(prefixes)
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
pub enum TypedImportExportPolicy {
    V4(ImportExportPolicy4),
    V6(ImportExportPolicy6),
}

/// BGP neighbor configuration stored in the database and used at API boundary.
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct BgpNeighborInfo {
    pub asn: u32,
    pub name: String,
    pub host: SocketAddr,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub group: String,
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
