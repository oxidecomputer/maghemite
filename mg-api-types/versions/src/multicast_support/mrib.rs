// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;
use std::fmt::{self, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use client_common::address::{
    IPV4_LINK_LOCAL_MULTICAST_SUBNET, IPV4_MULTICAST_RANGE, IPV4_SSM_SUBNET,
    IPV6_MULTICAST_RANGE,
};
use client_common::multicast::UnderlayMulticastError;
pub use client_common::multicast::UnderlayMulticastIpv6;
use client_common::vni::VniError;
pub use client_common::vni::{DEFAULT_MULTICAST_VNI, MAX_VNI, Vni};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1::rdb::rib::AddressFamily;

/// Errors raised while validating or serializing multicast route data.
#[derive(thiserror::Error, Debug)]
pub enum MulticastError {
    /// A field failed semantic validation.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Serialization of a value failed.
    #[error("Parsing error {0}")]
    Parsing(String),

    /// A database key could not be decoded.
    #[error("db key error {0}")]
    DbKey(String),
}

// Bridge errors from the shared `client_common` newtypes so call sites using
// `?` with `UnderlayMulticastIpv6::new` or `Vni::new` continue to surface
// validation failures through `MulticastError`.
impl From<UnderlayMulticastError> for MulticastError {
    fn from(value: UnderlayMulticastError) -> Self {
        match value {
            UnderlayMulticastError::NotInSubnet { addr } => {
                MulticastError::Validation(format!(
                    "underlay address {addr} is not within \
                     UNDERLAY_MULTICAST_SUBNET"
                ))
            }
            UnderlayMulticastError::InvalidIpv6(e) => {
                MulticastError::Validation(format!("invalid IPv6 address: {e}"))
            }
        }
    }
}

impl From<VniError> for MulticastError {
    fn from(value: VniError) -> Self {
        MulticastError::Validation(value.to_string())
    }
}

/// Input for adding static multicast routes.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct StaticMulticastRouteInput {
    /// The multicast route key (S,G) or (*,G).
    pub key: MulticastRouteKey,
    /// Underlay multicast group address (ff04::/64).
    pub underlay_group: UnderlayMulticastIpv6,
}

/// Request body for adding static multicast routes to the MRIB.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MribAddStaticRequest {
    /// List of static multicast routes to add.
    pub routes: Vec<StaticMulticastRouteInput>,
}

/// Request body for deleting static multicast routes from the MRIB.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MribDeleteStaticRequest {
    /// List of route keys to delete.
    pub keys: Vec<MulticastRouteKey>,
}

/// Filter for multicast route origin.
#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
pub enum RouteOriginFilter {
    /// Static routes only (operator configured).
    Static,
    /// Dynamic routes only (learned via IGMP, MLD, etc.).
    Dynamic,
}

/// Query parameters for MRIB routes.
///
/// When `group` is provided, looks up a specific route.
/// When `group` is omitted, lists all routes (with optional filters).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MribQuery {
    /// Multicast group address. If provided, returns a specific route.
    /// If omitted, returns all routes matching the filters.
    #[serde(default)]
    pub group: Option<IpAddr>,
    /// Source address (`None` for (*,G) routes). Only used when `group`
    /// is set.
    #[serde(default)]
    pub source: Option<IpAddr>,
    /// VNI (defaults to the fleet-wide multicast VNI). Only used when
    /// `group` is set.
    #[serde(default = "default_multicast_vni")]
    pub vni: Vni,
    /// Filter by address family. Only used when listing all routes.
    #[serde(default)]
    pub address_family: Option<AddressFamily>,
    /// Filter by route origin ("static" or "dynamic").
    /// Only used when listing all routes.
    #[serde(default)]
    pub route_origin: Option<RouteOriginFilter>,
}

const fn default_multicast_vni() -> Vni {
    Vni::DEFAULT_MULTICAST
}

/// A validated IPv4 unicast address suitable for multicast source fields.
///
/// This rejects addresses that cannot appear as a forwarded unicast source:
/// multicast, broadcast, loopback, unspecified, link-local, "this
/// network" (0/8), and Class E reserved (240/4). Private ranges
/// (RFC 1918) are allowed since overlay guests use them.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(try_from = "Ipv4Addr", into = "Ipv4Addr")]
#[schemars(transparent)]
pub struct UnicastAddrV4(Ipv4Addr);

impl UnicastAddrV4 {
    /// Create a new validated IPv4 unicast address.
    pub fn new(value: Ipv4Addr) -> Result<Self, MulticastError> {
        if value.is_multicast() {
            return Err(MulticastError::Validation(format!(
                "{value} is multicast, not unicast"
            )));
        }
        if value.is_broadcast() {
            return Err(MulticastError::Validation(format!(
                "{value} is broadcast, not unicast"
            )));
        }
        if value.is_loopback() {
            return Err(MulticastError::Validation(format!(
                "{value} is loopback, not a valid source"
            )));
        }
        // 0/8 "this network" per RFC 791
        if value.is_unspecified() || value.octets()[0] == 0 {
            return Err(MulticastError::Validation(format!(
                "{value} is in 0/8 (this-network), not a valid source"
            )));
        }
        // 169.254/16 per RFC 3927 Section 7: not forwarded by routers
        if value.is_link_local() {
            return Err(MulticastError::Validation(format!(
                "{value} is link-local, not routable"
            )));
        }
        // Class E reserved (240/4) per RFC 1112 Section 4.
        // Replace with Ipv4Addr::is_reserved() when stabilized.
        if value.octets()[0] >= 240 {
            return Err(MulticastError::Validation(format!(
                "{value} is in the reserved Class E range (240/4)"
            )));
        }
        Ok(Self(value))
    }

    #[inline]
    pub const fn ip(&self) -> Ipv4Addr {
        self.0
    }
}

impl fmt::Display for UnicastAddrV4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<Ipv4Addr> for UnicastAddrV4 {
    type Error = MulticastError;
    fn try_from(value: Ipv4Addr) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<UnicastAddrV4> for Ipv4Addr {
    fn from(addr: UnicastAddrV4) -> Self {
        addr.0
    }
}

/// A validated IPv6 unicast address suitable for multicast source fields.
///
/// Rejects multicast, loopback, unspecified, and link-local (fe80::/10).
/// ULA (fc00::/7) is allowed since overlay guests may use these ranges.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(try_from = "Ipv6Addr", into = "Ipv6Addr")]
#[schemars(transparent)]
pub struct UnicastAddrV6(Ipv6Addr);

impl UnicastAddrV6 {
    /// Create a new validated IPv6 unicast address.
    pub fn new(value: Ipv6Addr) -> Result<Self, MulticastError> {
        if value.is_multicast() {
            return Err(MulticastError::Validation(format!(
                "{value} is multicast, not unicast"
            )));
        }
        if value.is_loopback() {
            return Err(MulticastError::Validation(format!(
                "{value} is loopback, not a valid source"
            )));
        }
        if value.is_unspecified() {
            return Err(MulticastError::Validation(format!(
                "{value} is unspecified, not a valid source"
            )));
        }
        // fe80::/10 per RFC 4291 Section 2.5.6: not forwarded
        if value.is_unicast_link_local() {
            return Err(MulticastError::Validation(format!(
                "{value} is link-local, not routable"
            )));
        }
        Ok(Self(value))
    }

    #[inline]
    pub const fn ip(&self) -> Ipv6Addr {
        self.0
    }
}

impl fmt::Display for UnicastAddrV6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<Ipv6Addr> for UnicastAddrV6 {
    type Error = MulticastError;
    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<UnicastAddrV6> for Ipv6Addr {
    fn from(addr: UnicastAddrV6) -> Self {
        addr.0
    }
}

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
    pub fn new(value: Ipv4Addr) -> Result<Self, MulticastError> {
        // Must be in multicast range (224.0.0.0/4)
        if !IPV4_MULTICAST_RANGE.contains(value) {
            return Err(MulticastError::Validation(format!(
                "IPv4 address {value} is not multicast \
                 (must be in {IPV4_MULTICAST_RANGE})"
            )));
        }

        // Reject link-local multicast (224.0.0.0/24)
        if IPV4_LINK_LOCAL_MULTICAST_SUBNET.contains(value) {
            return Err(MulticastError::Validation(format!(
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
    type Error = MulticastError;

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
    pub fn new(value: Ipv6Addr) -> Result<Self, MulticastError> {
        // Must be in multicast range (ff00::/8)
        if !IPV6_MULTICAST_RANGE.contains(value) {
            return Err(MulticastError::Validation(format!(
                "IPv6 address {value} is not multicast \
                 (must be in {IPV6_MULTICAST_RANGE})"
            )));
        }

        // RFC 4291 section 2.7 splits the second address byte into flags
        // (high nibble) and scope (low nibble). Classify on the scope
        // nibble alone: a /16 prefix comparison encodes flags=0 and would
        // accept, e.g., ff11::1 despite its interface-local scope.
        let scope = value.segments()[0] & 0x000f;
        match scope {
            0x0 => Err(MulticastError::Validation(format!(
                "IPv6 address {value} has reserved multicast scope 0, \
                 which is not routable"
            ))),
            0x1 => Err(MulticastError::Validation(format!(
                "IPv6 address {value} has interface-local multicast scope, \
                 which is not routable"
            ))),
            0x2 => Err(MulticastError::Validation(format!(
                "IPv6 address {value} has link-local multicast scope, \
                 which is not routable"
            ))),
            // RFC 7346 section 2 reserves scope F alongside scope 0.
            0xf => Err(MulticastError::Validation(format!(
                "IPv6 address {value} has reserved multicast scope F, \
                 which is not routable"
            ))),
            _ => Ok(Self(value)),
        }
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
    type Error = MulticastError;

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
    pub fn new_v4(a: u8, b: u8, c: u8, d: u8) -> Result<Self, MulticastError> {
        Ok(Self::V4(MulticastAddrV4::new(Ipv4Addr::new(a, b, c, d))?))
    }

    /// Create an IPv6 multicast address from segments.
    pub fn new_v6(segments: [u16; 8]) -> Result<Self, MulticastError> {
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
    pub const fn ip(&self) -> IpAddr {
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
    type Error = MulticastError;

    fn try_from(value: Ipv4Addr) -> Result<Self, Self::Error> {
        Ok(Self::V4(MulticastAddrV4::new(value)?))
    }
}

impl TryFrom<Ipv6Addr> for MulticastAddr {
    type Error = MulticastError;

    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        Ok(Self::V6(MulticastAddrV6::new(value)?))
    }
}

impl TryFrom<IpAddr> for MulticastAddr {
    type Error = MulticastError;

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
    pub(crate) source: Option<UnicastAddrV4>,
    /// Multicast group address.
    pub(crate) group: MulticastAddrV4,
    /// VNI (Virtual Network Identifier).
    #[serde(default = "default_multicast_vni")]
    pub(crate) vni: Vni,
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
    pub(crate) source: Option<UnicastAddrV6>,
    /// Multicast group address.
    pub(crate) group: MulticastAddrV6,
    /// VNI (Virtual Network Identifier).
    #[serde(default = "default_multicast_vni")]
    pub(crate) vni: Vni,
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
        vni: Vni,
    ) -> Result<Self, MulticastError> {
        match group {
            MulticastAddr::V4(g) => {
                let src = match source {
                    None => None,
                    Some(IpAddr::V4(s)) => Some(UnicastAddrV4::new(s)?),
                    Some(IpAddr::V6(s)) => {
                        return Err(MulticastError::Validation(format!(
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
                    Some(IpAddr::V6(s)) => Some(UnicastAddrV6::new(s)?),
                    Some(IpAddr::V4(s)) => {
                        return Err(MulticastError::Validation(format!(
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
                vni: Vni::DEFAULT_MULTICAST,
            }),
            MulticastAddr::V6(g) => Self::V6(MulticastRouteKeyV6 {
                source: None,
                group: g,
                vni: Vni::DEFAULT_MULTICAST,
            }),
        }
    }

    /// Create a source-specific IPv4 multicast route (S,G) with default VNI.
    pub fn source_specific_v4(
        source: UnicastAddrV4,
        group: MulticastAddrV4,
    ) -> Self {
        Self::V4(MulticastRouteKeyV4 {
            source: Some(source),
            group,
            vni: Vni::DEFAULT_MULTICAST,
        })
    }

    /// Create a source-specific IPv6 multicast route (S,G) with default VNI.
    pub fn source_specific_v6(
        source: UnicastAddrV6,
        group: MulticastAddrV6,
    ) -> Self {
        Self::V6(MulticastRouteKeyV6 {
            source: Some(source),
            group,
            vni: Vni::DEFAULT_MULTICAST,
        })
    }

    /// Create an any-source multicast route (*,G) with specified VNI.
    pub fn any_source_with_vni(group: MulticastAddr, vni: Vni) -> Self {
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
        source: UnicastAddrV4,
        group: MulticastAddrV4,
        vni: Vni,
    ) -> Self {
        Self::V4(MulticastRouteKeyV4 {
            source: Some(source),
            group,
            vni,
        })
    }

    /// Create a source-specific IPv6 multicast route (S,G) with VNI.
    pub fn source_specific_v6_with_vni(
        source: UnicastAddrV6,
        group: MulticastAddrV6,
        vni: Vni,
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
            Self::V4(k) => k.source.map(|s| IpAddr::V4(s.ip())),
            Self::V6(k) => k.source.map(|s| IpAddr::V6(s.ip())),
        }
    }

    /// Get the group address.
    pub const fn group(&self) -> MulticastAddr {
        match self {
            Self::V4(k) => MulticastAddr::V4(k.group),
            Self::V6(k) => MulticastAddr::V6(k.group),
        }
    }

    /// Get the VNI.
    pub const fn vni(&self) -> Vni {
        match self {
            Self::V4(k) => k.vni,
            Self::V6(k) => k.vni,
        }
    }

    /// Serialize this key to bytes for use as a sled database key.
    pub fn db_key(&self) -> Result<Vec<u8>, MulticastError> {
        let s = serde_json::to_string(self).map_err(|e| {
            MulticastError::Parsing(format!(
                "failed to serialize multicast route key: {e}"
            ))
        })?;
        Ok(s.as_bytes().into())
    }

    /// Deserialize a key from sled database bytes.
    pub fn from_db_key(v: &[u8]) -> Result<Self, MulticastError> {
        let s = String::from_utf8_lossy(v);
        serde_json::from_str(&s).map_err(|e| {
            MulticastError::DbKey(format!(
                "failed to parse multicast route key: {e}"
            ))
        })
    }

    /// Validate the multicast route key.
    ///
    /// Checks:
    /// - SSM groups require a source address (RFC 4607)
    ///   - IPv4: 232.0.0.0/8
    ///   - IPv6: FF3x::/32 (flags nibble 3, any scope)
    /// - Source address (if present) must be unicast
    /// - (S,G) joins on ASM ranges are permitted, giving source
    ///   filtering outside the SSM range (IGMPv3/MLDv2 semantics)
    ///
    /// The 24-bit VNI range is enforced by the [`Vni`] newtype at construction
    /// and deserialization, so it is not re-checked here.
    pub fn validate(&self) -> Result<(), MulticastError> {
        // SSM addresses require a source (RFC 4607). This is consistent with
        // DPD's validate_ipv4_multicast / validate_ipv6_multicast.
        //
        // ASM addresses can also have sources, allowing (S,G) joins on
        // ASM ranges for source filtering outside the SSM range.
        //
        // If real-world deployments need (*,G) on SSM addresses, this
        // check and the corresponding DPD validation can be relaxed
        // together and we can update our policy handling.
        let is_ssm = match self {
            Self::V4(k) => IPV4_SSM_SUBNET.contains(k.group.ip()),
            // RFC 4607 section 1 allocates IPv6 SSM as FF3x::/32 (flags
            // nibble 3, any scope, remaining prefix bits zero). A broader
            // ff30::/12 match would also classify RFC 3306 unicast-prefix
            // based addresses with a nonzero network prefix as SSM.
            Self::V6(k) => {
                let segs = k.group.ip().segments();
                segs[0] & 0xfff0 == 0xff30 && segs[1] == 0
            }
        };
        if is_ssm && self.source().is_none() {
            return Err(MulticastError::Validation(format!(
                "SSM group {} requires a source address",
                self.group()
            )));
        }

        Ok(())
    }
}

/// Multicast route entry containing replication groups and metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MulticastRoute {
    /// The multicast route key (S,G) or (*,G).
    pub key: MulticastRouteKey,
    /// Upstream neighbor selected for RPF checks.
    ///
    /// This records one representative neighbor rather than the full ECMP
    /// set. When the unicast route has multiple equal-cost paths, any active
    /// member is valid. `None` means RPF does not apply or no active unicast
    /// path is available.
    ///
    /// Derived from the unicast RIB, never persisted. Listings of static
    /// route configuration always carry `None` here since they reflect
    /// stored configuration only.
    pub rpf_neighbor: Option<IpAddr>,
    /// Underlay multicast group address (ff04::/64).
    ///
    /// Overlay multicast addresses are mapped 1:1 to admin-local scope
    /// underlay addresses. Switches replicate to this address via the
    /// PRE (with tofino_asic).
    ///
    /// OPTE handles the overlay/underlay translation at sled boundaries, while
    /// sled membership is managed by Omicron and programmed to DPD/OPTE
    /// directly.
    pub underlay_group: UnderlayMulticastIpv6,
    /// Route source (static, IGMP, etc.).
    pub source: MulticastSourceProtocol,
    /// Creation timestamp.
    pub created: DateTime<Utc>,
    /// Last updated timestamp.
    ///
    /// Only updated when route fields change semantically (rpf_neighbor,
    /// underlay_group, source). An idempotent upsert with an identical
    /// value does not update this timestamp.
    pub updated: DateTime<Utc>,
}

impl MulticastRoute {
    pub fn new(
        key: MulticastRouteKey,
        underlay_group: UnderlayMulticastIpv6,
        source: MulticastSourceProtocol,
    ) -> Self {
        let now = Utc::now();
        Self {
            key,
            rpf_neighbor: None,
            underlay_group,
            source,
            created: now,
            updated: now,
        }
    }

    /// Validate the multicast route.
    ///
    /// Checks:
    /// - Key validation (source unicast, VNI range)
    /// - RPF neighbor (if present) must be unicast
    ///
    /// A cross-family neighbor is valid: derivation from the unicast RIB
    /// may resolve v4 routes through v6 nexthops ([RFC 8950] style).
    ///
    /// [RFC 8950]: https://www.rfc-editor.org/rfc/rfc8950
    pub fn validate(&self) -> Result<(), MulticastError> {
        self.key.validate()?;

        // underlay_group is validated by UnderlayMulticastIpv6 at
        // construction time (must be within ff04::/64).

        // Validate RPF neighbor if present
        if let Some(rpf) = &self.rpf_neighbor {
            match rpf {
                IpAddr::V4(addr) => {
                    if addr.is_multicast() {
                        return Err(MulticastError::Validation(format!(
                            "RPF neighbor {addr} must be unicast, not multicast"
                        )));
                    }
                    if addr.is_broadcast() {
                        return Err(MulticastError::Validation(format!(
                            "RPF neighbor {addr} must be unicast, not broadcast"
                        )));
                    }
                }
                IpAddr::V6(addr) => {
                    if addr.is_multicast() {
                        return Err(MulticastError::Validation(format!(
                            "RPF neighbor {addr} must be unicast, not multicast"
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Source of a multicast route entry.
#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq,
)]
pub enum MulticastSourceProtocol {
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
mod tests {
    use super::*;

    #[test]
    fn unicast_rejects_non_routable_sources() {
        // 0/8 "this network" (RFC 791).
        assert!(UnicastAddrV4::new(Ipv4Addr::new(0, 1, 2, 3)).is_err());
        // Link-local, 169.254/16 (RFC 3927): not router-forwarded.
        assert!(UnicastAddrV4::new(Ipv4Addr::new(169, 254, 0, 1)).is_err());
        // Link-local, fe80::/10 (RFC 4291): not forwarded.
        assert!(UnicastAddrV6::new("fe80::1".parse().unwrap()).is_err());
    }
}
