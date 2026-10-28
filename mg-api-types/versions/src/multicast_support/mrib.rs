// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! MRIB (Multicast Routing Information Base) types for version
//! `MULTICAST_SUPPORT`.
//!
//! This module defines the validated address types used in multicast routes
//! (unicast sources, IPv4 and IPv6 groups, and the underlay group), the route
//! keys and routes stored in the MRIB, and the errors raised when validation
//! fails. Each address, key, and route type is validated at construction time
//! and at the deserialization boundary. An API request or stored key that
//! doesn't satisfy our validation constraints gets rejected before it reaches
//! the MRIB.
//!
//! Validation of a multicast group address is limited to what the RFCs
//! require, with one Oxide-specific policy exception: `ff04::/64` is our
//! underlay subnet and belongs to the internal underlay mapping. We reject
//! addresses on this subnet, even though the rest of admin-local `ff04::/16`
//! is permitted.
//!
//! Multicast group address rules are described on [`MulticastAddrV4`] and
//! [`MulticastAddrV6`]. Source address rules are described on
//! [`UnicastAddrV4`] and [`UnicastAddrV6`].

use std::fmt::{self, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use dpd_types_versions::v14::mcast::{
    is_ssm_address, validate_external_multicast_ipv4,
    validate_external_multicast_ipv6,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use dpd_types_versions::v1::network::VniError;
pub use dpd_types_versions::v8::mcast::{
    UnderlayMulticastError, UnderlayMulticastIpv6,
};
pub use dpd_types_versions::v14::mcast::{
    EmbeddedIpv4, ExternalMulticastIpError as MulticastGroupError,
    InvalidEmbeddedRp, InvalidMulticastSource, MulticastSourceError,
    UnicastAddrV4, UnicastAddrV6,
};
pub use dpd_types_versions::v14::network::Vni;

/// Errors raised while validating multicast addresses and route keys.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MulticastRouteError {
    /// The group address failed multicast address validation, returning a
    /// [`MulticastGroupError`].
    #[error(transparent)]
    Group(#[from] MulticastGroupError),

    /// A source address uses a different IP address family than the group
    /// address.
    #[error(
        "Source IP {source_ip} does not match multicast group address family \
         ({group})"
    )]
    SourceFamilyMismatch {
        /// The rejected source address.
        source_ip: IpAddr,
        /// The group address whose IP address family it must match.
        group: IpAddr,
    },

    /// The source address failed unicast source validation, returning a
    /// [`MulticastSourceError`].
    #[error(transparent)]
    Source(#[from] MulticastSourceError),

    /// An SSM group requires a source address ([RFC 4607] §2).
    ///
    /// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
    #[error(
        "Group IP {group} is a Source-Specific Multicast address and requires \
         a source to be defined"
    )]
    SsmRequiresSource {
        /// The SSM group address.
        group: IpAddr,
    },
}

/// A validated IPv4 multicast address.
///
/// IPv4 admits the whole multicast range apart from the base address of
/// `224.0.0.0`, which [RFC 1112] §4 guarantees is never assigned to a group,
/// and the SSM null address of `232.0.0.0` ([RFC 4607] §4.3).
///
/// [RFC 1112]: https://www.rfc-editor.org/rfc/rfc1112.html
/// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
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
pub struct MulticastAddrV4(Ipv4Addr);

impl MulticastAddrV4 {
    /// Create a validated IPv4 multicast address.
    ///
    /// # Errors
    ///
    /// Returns the first [`MulticastGroupError`] the address fails.
    pub fn new(value: Ipv4Addr) -> Result<Self, MulticastGroupError> {
        validate_external_multicast_ipv4(value)?;
        Ok(Self(value))
    }

    /// Return the inner IPv4 address.
    #[inline]
    pub const fn ip(&self) -> Ipv4Addr {
        self.0
    }

    /// Return whether this is a source-specific multicast (SSM) group.
    pub fn is_ssm(&self) -> bool {
        is_ssm_address(IpAddr::V4(self.0))
    }
}

impl fmt::Display for MulticastAddrV4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<Ipv4Addr> for MulticastAddrV4 {
    type Error = MulticastGroupError;

    fn try_from(value: Ipv4Addr) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<MulticastAddrV4> for Ipv4Addr {
    fn from(addr: MulticastAddrV4) -> Self {
        addr.0
    }
}

impl From<MulticastAddrV4> for IpAddr {
    fn from(addr: MulticastAddrV4) -> Self {
        IpAddr::V4(addr.0)
    }
}

/// A validated IPv6 multicast address.
///
/// All IPv6 scopes are admitted except for the reserved scope of `0x0` and
/// the interface-local `0x1` and link-local `0x2` ones, which a router must
/// not forward past ([RFC 4291] §2.7). Scope `0xf` is retained because
/// [RFC 4291] §2.7 treats it as global when it is sent or received.
/// Addresses on the `ff04::/64` underlay subnet are rejected.
///
/// The four flag bits above the scope nibble are `|X|R|P|T|` ([RFC 7371]
/// §4.2.1): T marks a transient address, P a prefix-based one, R an embedded
/// rendezvous point, and X may be either zero or one. [RFC 7371] §4.1.1
/// names the same field `|X|Y|P|T|`, where Y is the bit that [RFC 3956]
/// defines as the R flag.
///
/// Prefix-based addresses require only that the P flag implies the T flag
/// ([RFC 7371] §4.1.1, which replaces that passage of [RFC 3306] §4). The
/// replacement drops the "reserved field MUST be zero" rule. The `ff2` and
/// `rsvd` nibbles are sent as zero and ignored on receipt instead, per
/// [RFC 7371] §4.1.1 and [RFC 3956] §3. Neither is validated here. The
/// prefix length is otherwise unbounded. The `plen` ceiling of 64 comes from
/// [RFC 3956] §4 and applies to embedded rendezvous point (RP) addresses
/// only. [RFC 3306] §4 notes the same 64-bit ceiling on the
/// network prefix without requiring it.
///
/// Embedded RP addresses require the R, P, and T flags ([RFC 7371] §4.2.2
/// and §4.2.3), a prefix length from 1 through 64, a nonzero RP interface ID
/// ([RFC 3956] §6.3), and a derived RP address outside `::/16`, link-local
/// space, and the multicast range. [RFC 3956] §4 states those exclusions
/// as requirements, and §10 repeats them as a security consideration.
///
/// SSM classification is described on [`is_ssm_address`]. The only SSM
/// address rejected is the reserved null address of `ff3x::4000:0` from
/// [RFC 4607] §4.3. The network prefix is unchecked otherwise: [RFC 3306] §6
/// applies to the node that's forming the address, and [RFC 4607] §1 has a
/// system treat all of the `ff3x::/32` block as SSM.
///
/// Group IDs below `4000:0` are assigned with flags P=T=0 ([RFC 3307] §4.1),
/// making them invalid SSM addresses that routers may drop ([RFC 4607] §1).
/// The band just above it, `4000:0001` through `7fff:ffff`, is reserved for
/// IANA allocation ([RFC 4607] §4.3, [RFC 3307] §4.2) rather than forbidden
/// as a destination. From `8000:0` up is the dynamic range of [RFC 3307]
/// §4.3, which [RFC 10028] §3 partitions. Host SSM allocation sits at
/// `f000:0` through `fcff:ffff`. None of these ranges is rejected.
///
/// Permanently assigned addresses (T=0) with the P and R flags cleared are
/// permitted. They face the same `ff04::/64` underlay reservation as any
/// other address, and the all-zero group ID `ff0x::` is refused outright.
/// [RFC 4291] §2.7.1 reserves it and never assigns it. A registered meaning
/// is independent of scope ([RFC 4291] §2.7). `ff0e::101` and `ff05::fb`
/// keep their registered meanings in the overlay.
///
/// [RFC 3306]: https://www.rfc-editor.org/rfc/rfc3306.html
/// [RFC 3307]: https://www.rfc-editor.org/rfc/rfc3307.html
/// [RFC 3956]: https://www.rfc-editor.org/rfc/rfc3956.html
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
/// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
/// [RFC 7371]: https://www.rfc-editor.org/rfc/rfc7371.html
/// [RFC 10028]: https://www.rfc-editor.org/rfc/rfc10028.html
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
pub struct MulticastAddrV6(Ipv6Addr);

impl MulticastAddrV6 {
    /// Create a validated IPv6 multicast address.
    ///
    /// # Errors
    ///
    /// Returns the first [`MulticastGroupError`] the address fails.
    pub fn new(value: Ipv6Addr) -> Result<Self, MulticastGroupError> {
        validate_external_multicast_ipv6(value)?;
        Ok(Self(value))
    }

    /// Return the inner IPv6 address.
    #[inline]
    pub const fn ip(&self) -> Ipv6Addr {
        self.0
    }

    /// Return whether this is a source-specific multicast (SSM) group.
    pub fn is_ssm(&self) -> bool {
        is_ssm_address(IpAddr::V6(self.0))
    }
}

impl fmt::Display for MulticastAddrV6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<Ipv6Addr> for MulticastAddrV6 {
    type Error = MulticastGroupError;

    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<MulticastAddrV6> for Ipv6Addr {
    fn from(addr: MulticastAddrV6) -> Self {
        addr.0
    }
}

impl From<MulticastAddrV6> for IpAddr {
    fn from(addr: MulticastAddrV6) -> Self {
        IpAddr::V6(addr.0)
    }
}

/// A validated multicast group address (IPv4 or IPv6), one of
/// [`MulticastAddrV4`] or [`MulticastAddrV6`].
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
)]
#[serde(try_from = "IpAddr", into = "IpAddr")]
pub enum MulticastAddr {
    /// An IPv4 multicast group address.
    V4(MulticastAddrV4),
    /// An IPv6 multicast group address.
    V6(MulticastAddrV6),
}

impl MulticastAddr {
    /// Create an IPv4 multicast address from octets.
    ///
    /// # Errors
    ///
    /// Returns the error from [`MulticastAddrV4::new`].
    pub fn new_v4(
        a: u8,
        b: u8,
        c: u8,
        d: u8,
    ) -> Result<Self, MulticastGroupError> {
        Ok(Self::V4(MulticastAddrV4::new(Ipv4Addr::new(a, b, c, d))?))
    }

    /// Create an IPv6 multicast address from segments.
    ///
    /// # Errors
    ///
    /// Returns the error from [`MulticastAddrV6::new`].
    pub fn new_v6(segments: [u16; 8]) -> Result<Self, MulticastGroupError> {
        Ok(Self::V6(MulticastAddrV6::new(Ipv6Addr::from(segments))?))
    }

    /// Return the inner IP address.
    pub const fn ip(&self) -> IpAddr {
        match self {
            Self::V4(v4) => IpAddr::V4(v4.ip()),
            Self::V6(v6) => IpAddr::V6(v6.ip()),
        }
    }

    /// Return whether this is a source-specific multicast (SSM) group.
    pub fn is_ssm(&self) -> bool {
        match self {
            Self::V4(v4) => v4.is_ssm(),
            Self::V6(v6) => v6.is_ssm(),
        }
    }
}

impl fmt::Display for MulticastAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            MulticastAddr::V4(addr) => addr.fmt(f),
            MulticastAddr::V6(addr) => addr.fmt(f),
        }
    }
}

impl From<MulticastAddr> for IpAddr {
    fn from(addr: MulticastAddr) -> Self {
        addr.ip()
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
    type Error = MulticastGroupError;

    fn try_from(value: Ipv4Addr) -> Result<Self, Self::Error> {
        Ok(Self::V4(MulticastAddrV4::new(value)?))
    }
}

impl TryFrom<Ipv6Addr> for MulticastAddr {
    type Error = MulticastGroupError;

    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        Ok(Self::V6(MulticastAddrV6::new(value)?))
    }
}

impl TryFrom<IpAddr> for MulticastAddr {
    type Error = MulticastGroupError;

    fn try_from(value: IpAddr) -> Result<Self, Self::Error> {
        match value {
            IpAddr::V4(v4) => Self::try_from(v4),
            IpAddr::V6(v6) => Self::try_from(v6),
        }
    }
}

impl JsonSchema for MulticastAddr {
    fn schema_name() -> String {
        "MulticastAddr".to_string()
    }

    fn json_schema(
        generator: &mut schemars::r#gen::SchemaGenerator,
    ) -> schemars::schema::Schema {
        let mut schema = IpAddr::json_schema(generator).into_object();
        schema.metadata().description = Some(
            "A validated multicast group address (IPv4 or IPv6), one of \
             [`MulticastAddrV4`] or [`MulticastAddrV6`]."
                .to_string(),
        );
        schema.into()
    }
}

/// Reject a `(*,G)` wildcard key on an SSM group.
///
/// ASM groups can carry a source, which allows for `(S,G)` source filtering
/// outside the SSM range.
fn require_ssm_source(
    group: MulticastAddr,
    has_source: bool,
) -> Result<(), MulticastRouteError> {
    if !has_source && group.is_ssm() {
        return Err(MulticastRouteError::SsmRequiresSource {
            group: group.ip(),
        });
    }
    Ok(())
}

/// IPv4 multicast route key with type-enforced IP address family matching.
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
)]
#[serde(
    try_from = "MulticastRouteKeyV4Shadow",
    into = "MulticastRouteKeyV4Shadow"
)]
pub struct MulticastRouteKeyV4 {
    /// Multicast group address.
    pub(crate) group: MulticastAddrV4,
    /// Source address (`None` for `(*,G)` routes).
    pub(crate) source: Option<UnicastAddrV4>,
    /// VNI (Virtual Network Identifier).
    pub(crate) vni: Vni,
}

impl MulticastRouteKeyV4 {
    /// Return the source address, or `None` for a `(*,G)` wildcard route.
    #[inline]
    pub const fn source(&self) -> Option<UnicastAddrV4> {
        self.source
    }

    /// Return the group address.
    #[inline]
    pub const fn group(&self) -> MulticastAddrV4 {
        self.group
    }

    /// Return the VNI.
    #[inline]
    pub const fn vni(&self) -> Vni {
        self.vni
    }
}

/// IPv4 multicast route key with type-enforced IP address family matching.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "MulticastRouteKeyV4")]
pub(crate) struct MulticastRouteKeyV4Shadow {
    /// Source address (`None` for `(*,G)` routes).
    pub(crate) source: Option<UnicastAddrV4>,
    /// Multicast group address.
    pub(crate) group: MulticastAddrV4,
    /// VNI (Virtual Network Identifier).
    pub(crate) vni: Vni,
}

impl TryFrom<MulticastRouteKeyV4Shadow> for MulticastRouteKeyV4 {
    type Error = MulticastRouteError;

    fn try_from(key: MulticastRouteKeyV4Shadow) -> Result<Self, Self::Error> {
        require_ssm_source(MulticastAddr::V4(key.group), key.source.is_some())?;
        Ok(Self {
            source: key.source,
            group: key.group,
            vni: key.vni,
        })
    }
}

impl From<MulticastRouteKeyV4> for MulticastRouteKeyV4Shadow {
    fn from(key: MulticastRouteKeyV4) -> Self {
        Self {
            source: key.source,
            group: key.group,
            vni: key.vni,
        }
    }
}

impl JsonSchema for MulticastRouteKeyV4 {
    fn schema_name() -> String {
        MulticastRouteKeyV4Shadow::schema_name()
    }

    fn json_schema(
        generator: &mut schemars::r#gen::SchemaGenerator,
    ) -> schemars::schema::Schema {
        MulticastRouteKeyV4Shadow::json_schema(generator)
    }
}

/// IPv6 multicast route key with type-enforced IP address family matching.
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
)]
#[serde(
    try_from = "MulticastRouteKeyV6Shadow",
    into = "MulticastRouteKeyV6Shadow"
)]
pub struct MulticastRouteKeyV6 {
    /// Multicast group address.
    pub(crate) group: MulticastAddrV6,
    /// Source address (`None` for `(*,G)` routes).
    pub(crate) source: Option<UnicastAddrV6>,
    /// VNI (Virtual Network Identifier).
    pub(crate) vni: Vni,
}

impl MulticastRouteKeyV6 {
    /// Return the source address, or `None` for a `(*,G)` wildcard route.
    #[inline]
    pub const fn source(&self) -> Option<UnicastAddrV6> {
        self.source
    }

    /// Return the group address.
    #[inline]
    pub const fn group(&self) -> MulticastAddrV6 {
        self.group
    }

    /// Return the VNI.
    #[inline]
    pub const fn vni(&self) -> Vni {
        self.vni
    }
}

/// IPv6 multicast route key with type-enforced IP address family matching.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "MulticastRouteKeyV6")]
pub(crate) struct MulticastRouteKeyV6Shadow {
    /// Source address (`None` for `(*,G)` routes).
    pub(crate) source: Option<UnicastAddrV6>,
    /// Multicast group address.
    pub(crate) group: MulticastAddrV6,
    /// VNI (Virtual Network Identifier).
    pub(crate) vni: Vni,
}

impl TryFrom<MulticastRouteKeyV6Shadow> for MulticastRouteKeyV6 {
    type Error = MulticastRouteError;

    fn try_from(key: MulticastRouteKeyV6Shadow) -> Result<Self, Self::Error> {
        require_ssm_source(MulticastAddr::V6(key.group), key.source.is_some())?;
        Ok(Self {
            source: key.source,
            group: key.group,
            vni: key.vni,
        })
    }
}

impl From<MulticastRouteKeyV6> for MulticastRouteKeyV6Shadow {
    fn from(key: MulticastRouteKeyV6) -> Self {
        Self {
            source: key.source,
            group: key.group,
            vni: key.vni,
        }
    }
}

impl JsonSchema for MulticastRouteKeyV6 {
    fn schema_name() -> String {
        MulticastRouteKeyV6Shadow::schema_name()
    }

    fn json_schema(
        generator: &mut schemars::r#gen::SchemaGenerator,
    ) -> schemars::schema::Schema {
        MulticastRouteKeyV6Shadow::json_schema(generator)
    }
}

/// Multicast route key: (Source, Group) when a source is set, or (*, Group)
/// without one (i.e., any-source multicast).
///
/// Uses type-enforced IP address family matching: IPv4 sources can only be
/// paired with IPv4 groups, and IPv6 sources with IPv6 groups.
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
pub enum MulticastRouteKey {
    /// An IPv4 route key.
    V4(MulticastRouteKeyV4),
    /// An IPv6 route key.
    V6(MulticastRouteKeyV6),
}

impl From<MulticastRouteKeyV4> for MulticastRouteKey {
    fn from(key: MulticastRouteKeyV4) -> Self {
        Self::V4(key)
    }
}

impl From<MulticastRouteKeyV6> for MulticastRouteKey {
    fn from(key: MulticastRouteKeyV6) -> Self {
        Self::V6(key)
    }
}

impl fmt::Display for MulticastRouteKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(key) => match key.source {
                Some(src) => write!(f, "({src},{})@{}", key.group, key.vni),
                None => write!(f, "(*,{})@{}", key.group, key.vni),
            },
            Self::V6(key) => match key.source {
                Some(src) => write!(f, "({src},{})@{}", key.group, key.vni),
                None => write!(f, "(*,{})@{}", key.group, key.vni),
            },
        }
    }
}

impl MulticastRouteKey {
    /// Create a multicast route key, validating IP address family matching.
    ///
    /// Use this when the IP address family is not known at compile time
    /// (e.g., from API requests). For compile-time type safety, prefer
    /// [`Self::source_specific_v4`]/[`Self::source_specific_v6`] or
    /// [`Self::any_source`].
    ///
    /// # Errors
    ///
    /// Returns [`MulticastRouteError::SsmRequiresSource`] if `group` is an
    /// SSM address and `source` is `None` ([RFC 4607] §2).
    ///
    /// Returns [`MulticastRouteError::SourceFamilyMismatch`] if `source` and
    /// `group` use different IP address families.
    ///
    /// Returns [`MulticastRouteError::Source`] if `source` fails validation
    /// as a [`UnicastAddrV4`] or [`UnicastAddrV6`].
    ///
    /// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
    pub fn new(
        source: Option<IpAddr>,
        group: MulticastAddr,
        vni: Vni,
    ) -> Result<Self, MulticastRouteError> {
        match group {
            MulticastAddr::V4(g) => {
                let src = match source {
                    None => None,
                    Some(IpAddr::V4(s)) => Some(UnicastAddrV4::new(s)?),
                    Some(IpAddr::V6(s)) => {
                        UnicastAddrV6::new(s)?;
                        return Err(
                            MulticastRouteError::SourceFamilyMismatch {
                                source_ip: IpAddr::V6(s),
                                group: IpAddr::V4(g.ip()),
                            },
                        );
                    }
                };
                Ok(Self::V4(MulticastRouteKeyV4::try_from(
                    MulticastRouteKeyV4Shadow {
                        source: src,
                        group: g,
                        vni,
                    },
                )?))
            }
            MulticastAddr::V6(g) => {
                let src = match source {
                    None => None,
                    Some(IpAddr::V6(s)) => Some(UnicastAddrV6::new(s)?),
                    Some(IpAddr::V4(s)) => {
                        UnicastAddrV4::new(s)?;
                        return Err(
                            MulticastRouteError::SourceFamilyMismatch {
                                source_ip: IpAddr::V4(s),
                                group: IpAddr::V6(g.ip()),
                            },
                        );
                    }
                };
                Ok(Self::V6(MulticastRouteKeyV6::try_from(
                    MulticastRouteKeyV6Shadow {
                        source: src,
                        group: g,
                        vni,
                    },
                )?))
            }
        }
    }

    /// Create an any-source multicast route key `(*,G)`.
    ///
    /// # Errors
    ///
    /// Returns [`MulticastRouteError::SsmRequiresSource`] if `group` is an
    /// SSM address ([RFC 4607] §2).
    ///
    /// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
    pub fn any_source(
        group: MulticastAddr,
        vni: Vni,
    ) -> Result<Self, MulticastRouteError> {
        Self::new(None, group, vni)
    }

    /// Create a source-specific IPv4 multicast route key `(S,G)`.
    pub fn source_specific_v4(
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

    /// Create a source-specific IPv6 multicast route key `(S,G)`.
    pub fn source_specific_v6(
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

    /// Return the source address as `IpAddr`.
    pub fn source(&self) -> Option<IpAddr> {
        match self {
            Self::V4(k) => k.source.map(|s| IpAddr::V4(s.ip())),
            Self::V6(k) => k.source.map(|s| IpAddr::V6(s.ip())),
        }
    }

    /// Return the group address.
    pub const fn group(&self) -> MulticastAddr {
        match self {
            Self::V4(k) => MulticastAddr::V4(k.group),
            Self::V6(k) => MulticastAddr::V6(k.group),
        }
    }

    /// Return the VNI.
    pub const fn vni(&self) -> Vni {
        match self {
            Self::V4(k) => k.vni,
            Self::V6(k) => k.vni,
        }
    }
}

/// Multicast route entry -> key, underlay group, and metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MulticastRoute {
    /// The multicast route key `(S,G)` or `(*,G)`.
    pub key: MulticastRouteKey,
    /// Underlay multicast group address within the `ff04::/64` subnet allocated
    /// by Omicron for rack-internal multicast traffic.
    ///
    /// Overlay multicast addresses are mapped 1:1 to these admin-local scope
    /// underlay addresses. OPTE's M2P (multicast-to-underlay) mapping
    /// translates an overlay group to this address for guest-originated
    /// traffic and uses it as the packet's outer IPv6 destination. The switch
    /// performs the same mapping for external ingress and replicates via its
    /// PRE (Packet Replication Engine) or similar.
    ///
    /// Omicron owns group creation, deletion, and NAT configuration, while ddmd
    /// programs underlay members on the switch from imported DDM subscriptions.
    pub underlay_group: UnderlayMulticastIpv6,
    /// Protocol that originated the route.
    pub source: MulticastSourceProtocol,
    /// Creation timestamp.
    pub created: DateTime<Utc>,
    /// Last updated timestamp.
    pub updated: DateTime<Utc>,
}

impl MulticastRoute {
    /// Create a route, setting both timestamps to the current time.
    pub fn new(
        key: MulticastRouteKey,
        underlay_group: UnderlayMulticastIpv6,
        source: MulticastSourceProtocol,
    ) -> Self {
        let now = Utc::now();
        Self {
            key,
            underlay_group,
            source,
            created: now,
            updated: now,
        }
    }
}

/// Protocol that originated a multicast route entry.
#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq,
)]
pub enum MulticastSourceProtocol {
    /// Static route configured via API.
    Static,
}

#[cfg(any(test, feature = "testing"))]
mod arbitrary_impls {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use dpd_types_versions::testing::{
        ipv4_asm_group_strategy, ipv4_ssm_group_strategy,
        ipv6_asm_group_strategy, ipv6_ssm_group_strategy,
    };
    use proptest::prelude::*;

    use super::{
        MulticastAddr, MulticastAddrV4, MulticastAddrV6, MulticastRouteKey,
        UnicastAddrV4, UnicastAddrV6, Vni,
    };

    fn group_v4(addr: Ipv4Addr) -> MulticastAddr {
        MulticastAddrV4::new(addr)
            .expect("generated IPv4 group is valid")
            .into()
    }

    fn group_v6(addr: Ipv6Addr) -> MulticastAddr {
        MulticastAddrV6::new(addr)
            .expect("generated IPv6 group is valid")
            .into()
    }

    /// Generate valid IPv4 multicast groups (ASM or SSM).
    impl Arbitrary for MulticastAddrV4 {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            prop_oneof![ipv4_asm_group_strategy(), ipv4_ssm_group_strategy()]
                .prop_map(|addr| {
                    MulticastAddrV4::new(addr)
                        .expect("generated IPv4 group is valid")
                })
                .boxed()
        }
    }

    /// Generate valid IPv6 multicast groups (ASM or SSM).
    impl Arbitrary for MulticastAddrV6 {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            prop_oneof![ipv6_asm_group_strategy(), ipv6_ssm_group_strategy()]
                .prop_map(|addr| {
                    MulticastAddrV6::new(addr)
                        .expect("generated IPv6 group is valid")
                })
                .boxed()
        }
    }

    /// Generate valid route keys of each IP address family: ASM `(*,G)`, ASM
    /// `(S,G)` (with a source), and SSM `(S,G)`.
    impl Arbitrary for MulticastRouteKey {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            let parts = prop_oneof![
                2 => (
                    proptest::option::of(any::<UnicastAddrV4>()),
                    ipv4_asm_group_strategy(),
                )
                    .prop_map(|(src, grp)| {
                        (src.map(IpAddr::from), group_v4(grp))
                    }),
                1 => (any::<UnicastAddrV4>(), ipv4_ssm_group_strategy())
                    .prop_map(|(src, grp)| {
                        (Some(IpAddr::from(src)), group_v4(grp))
                    }),
                2 => (
                    proptest::option::of(any::<UnicastAddrV6>()),
                    ipv6_asm_group_strategy(),
                )
                    .prop_map(|(src, grp)| {
                        (src.map(IpAddr::from), group_v6(grp))
                    }),
                1 => (any::<UnicastAddrV6>(), ipv6_ssm_group_strategy())
                    .prop_map(|(src, grp)| {
                        (Some(IpAddr::from(src)), group_v6(grp))
                    }),
            ];
            (parts, any::<Vni>())
                .prop_map(|((source, group), vni)| {
                    MulticastRouteKey::new(source, group, vni)
                        .expect("generated route key parts are valid")
                })
                .boxed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vni() -> Vni {
        Vni::new(77).unwrap()
    }

    #[test]
    fn multicast_addr_serializes_as_ip_string() {
        let v4 = MulticastAddrV4::new("239.1.1.1".parse().unwrap()).unwrap();
        let json = serde_json::to_string(&v4).unwrap();
        assert_eq!(json, "\"239.1.1.1\"");
        assert_eq!(serde_json::from_str::<MulticastAddrV4>(&json).unwrap(), v4);

        let v6 = MulticastAddrV6::new("ff0e::1".parse().unwrap()).unwrap();
        let json = serde_json::to_string(&v6).unwrap();
        assert_eq!(json, "\"ff0e::1\"");
        assert_eq!(serde_json::from_str::<MulticastAddrV6>(&json).unwrap(), v6);

        assert!(
            serde_json::from_str::<MulticastAddrV4>("\"10.0.0.1\"").is_err()
        );
        assert!(
            serde_json::from_str::<MulticastAddrV6>("\"ff04::1\"").is_err()
        );

        for (addr, json) in [
            (MulticastAddr::from(v4), "\"239.1.1.1\""),
            (MulticastAddr::from(v6), "\"ff0e::1\""),
        ] {
            assert_eq!(serde_json::to_string(&addr).unwrap(), json);
            assert_eq!(
                serde_json::from_str::<MulticastAddr>(json).unwrap(),
                addr
            );
        }
        assert!(serde_json::from_str::<MulticastAddr>("\"10.0.0.1\"").is_err());
        assert!(serde_json::from_str::<MulticastAddr>("\"ff04::1\"").is_err());
        assert!(
            serde_json::from_str::<MulticastAddr>(r#"{"V4":"239.1.1.1"}"#)
                .is_err()
        );
    }

    fn v6(addr: &str) -> Result<MulticastAddrV6, MulticastGroupError> {
        MulticastAddrV6::new(addr.parse().unwrap())
    }

    fn group_err(
        res: Result<MulticastAddrV6, MulticastGroupError>,
    ) -> MulticastGroupError {
        match res {
            Err(e) => e,
            other => panic!("expected a group error, got {other:?}"),
        }
    }

    fn group(addr: &str) -> Result<MulticastAddr, MulticastGroupError> {
        MulticastAddr::try_from(addr.parse::<IpAddr>().unwrap())
    }

    #[test]
    fn accepts_ipv4_asm() {
        for addr in [
            "224.1.2.3",
            "239.255.255.250",
            "225.0.0.1",
            "231.255.255.255",
        ] {
            let parsed = MulticastAddrV4::new(addr.parse().unwrap())
                .unwrap_or_else(|e| panic!("{addr} should be accepted: {e}"));
            assert_eq!(parsed.ip(), addr.parse::<Ipv4Addr>().unwrap());
            assert!(!parsed.is_ssm());
        }
    }

    #[test]
    fn accepts_ipv4_ssm() {
        for addr in ["232.0.0.1", "232.1.2.3", "232.255.255.255"] {
            let parsed = MulticastAddrV4::new(addr.parse().unwrap())
                .unwrap_or_else(|e| panic!("{addr} should be accepted: {e}"));
            assert!(parsed.is_ssm());
        }
    }

    #[test]
    fn accepts_ipv4_local_network_control_block() {
        for addr in [
            "224.0.0.1",
            "224.0.0.22",
            "224.0.0.251",
            "224.0.0.255",
            "224.0.1.0",
        ] {
            let parsed = MulticastAddrV4::new(addr.parse().unwrap())
                .unwrap_or_else(|e| panic!("{addr} should be accepted: {e}"));
            assert_eq!(parsed.ip(), addr.parse::<Ipv4Addr>().unwrap());
        }
    }

    #[test]
    fn group_rejects_non_multicast() {
        for addr in ["10.0.0.1", "192.168.1.1", "2001:db8::1", "::1"] {
            assert!(
                matches!(
                    group(addr),
                    Err(MulticastGroupError::NotMulticast(_))
                ),
                "{addr} should be rejected as non-multicast"
            );
        }
    }

    #[test]
    fn ipv4_rejects_only_reserved_base_and_ssm_null() {
        for addr in ["232.0.0.255", "232.0.1.0"] {
            assert!(
                MulticastAddrV4::new(addr.parse().unwrap()).is_ok(),
                "{addr} should be accepted"
            );
        }
        assert!(matches!(
            MulticastAddrV4::new(Ipv4Addr::new(224, 0, 0, 0)),
            Err(MulticastGroupError::ReservedBaseAddress(_))
        ));
        assert!(matches!(
            MulticastAddrV4::new(Ipv4Addr::new(232, 0, 0, 0)),
            Err(MulticastGroupError::ReservedSsmNull(_))
        ));
    }

    #[test]
    fn ipv6_scope_rules() {
        for addr in [
            "ff03::1",
            "ff05::1",
            "ff06::1",
            "ff07::1",
            "ff08::1",
            "ff09::1",
            "ff0d::1",
            "ff0e::1",
            "ff0f::1",
            "ff3e::4000:1",
        ] {
            assert!(v6(addr).is_ok(), "{addr} should be accepted");
        }

        assert!(matches!(
            group_err(v6("ff00::1")),
            MulticastGroupError::ReservedIpv6Scope(_)
        ));
        for addr in ["ff01::1", "ff02::1", "ff11::1", "ff32::4000:1"] {
            assert!(
                matches!(
                    group_err(v6(addr)),
                    MulticastGroupError::LocalIpv6Scope(_)
                ),
                "{addr} should be rejected as local scope"
            );
        }
    }

    #[test]
    fn ipv6_rejects_underlay_subnet_only() {
        for addr in ["ff04::1", "ff04::ffff:ffff:ffff:ffff"] {
            assert!(
                matches!(
                    group_err(v6(addr)),
                    MulticastGroupError::ReservedUnderlaySubnet(_)
                ),
                "{addr} should be rejected as underlay"
            );
        }

        for addr in ["ff04:0:0:1::1", "ff04:1::1", "ff04::1:0:0:0:1", "ff14::1"]
        {
            assert!(v6(addr).is_ok(), "{addr} should be accepted");
        }
    }

    #[test]
    fn ipv6_rejects_reserved_base_address() {
        for addr in ["ff03::", "ff05::", "ff0e::", "ff0f::"] {
            assert!(
                matches!(
                    group_err(v6(addr)),
                    MulticastGroupError::ReservedBaseAddress(_)
                ),
                "{addr} should be rejected as a reserved base address"
            );
        }
        for addr in ["ff05::1", "ff0e::1", "ff1e::"] {
            assert!(v6(addr).is_ok(), "{addr} should be accepted");
        }
    }

    #[test]
    fn ipv6_ssm_rejects_only_null_address() {
        for addr in ["ff3e::4000:0", "ff3e:f000::4000:0"] {
            assert!(
                matches!(
                    group_err(v6(addr)),
                    MulticastGroupError::ReservedSsmNull(_)
                ),
                "{addr} should be rejected as invalid SSM"
            );
        }
        for addr in [
            "ff3e::1",
            "ff3e:0:0:1::8000:1",
            "ff3e::1234",
            "ff3e::3fff:ffff",
            "ff3e::4000:1",
            "ff3e::7fff:ffff",
            "ff3e::8000:0",
            "ff3e::ffff:ffff",
            "ff35::4000:1",
            "ff3e:0:1234::f000:1",
            "ff3e:f000:1234::1",
            "ff3e:0:1234::4000:0",
        ] {
            assert!(v6(addr).is_ok(), "{addr} should be accepted");
        }
    }

    #[test]
    fn accepts_rfc3306_unicast_prefix_ipv6_as_asm() {
        let parsed = v6("ff3e:20:1234::1").unwrap();
        assert!(!parsed.is_ssm());
    }

    fn assert_asm(addr: &str) {
        let parsed = v6(addr)
            .unwrap_or_else(|e| panic!("{addr} should be accepted: {e}"));
        assert!(!parsed.is_ssm(), "{addr} should not be SSM");
        assert!(
            MulticastRouteKey::any_source(MulticastAddr::V6(parsed), vni())
                .is_ok(),
            "(*,{addr}) should be accepted as ASM"
        );
    }

    #[test]
    fn accepts_prefix_based_ipv6_as_asm() {
        for addr in [
            "ff3e:40::1",
            "ff3e:80::1",
            "ff3e:f020::1",
            "ff3e:ff20::1",
            "ff3e:140:2001:db8::1",
            "ff3e:40:2001:db8::1",
            "ff7e:140:2001:db8:beef:feed:0:1234",
            "ff7e:f140:2001:db8:beef:feed:0:1234",
            "fffe:f40:2001:db8:beef:feed:0:1234",
        ] {
            assert_asm(addr);
        }
    }

    #[test]
    fn accepts_transient_flagged_ipv6_as_asm() {
        assert_asm("ff1e::1");
    }

    #[test]
    fn ssm_requires_sources() {
        for addr in ["232.1.2.3", "ff3e::4000:1", "ff35::4000:1", "ffbe::1"] {
            let group = group(addr).unwrap();

            for res in [
                MulticastRouteKey::new(None, group, vni()),
                MulticastRouteKey::any_source(group, vni()),
            ] {
                assert!(
                    matches!(
                        res,
                        Err(MulticastRouteError::SsmRequiresSource { group: g })
                            if g == group.ip()
                    ),
                    "(*,{addr}) should require a source"
                );
            }
        }
    }

    #[test]
    fn ssm_key_without_source_fails_decode() {
        for (json, group) in [
            (
                r#"{"V4":{"source":null,"group":"232.1.2.3","vni":77}}"#,
                "232.1.2.3",
            ),
            (r#"{"V4":{"group":"232.1.2.3","vni":77}}"#, "232.1.2.3"),
            (
                r#"{"V6":{"source":null,"group":"ff3e::4000:1","vni":77}}"#,
                "ff3e::4000:1",
            ),
            (r#"{"V6":{"group":"ffbe::1","vni":77}}"#, "ffbe::1"),
        ] {
            let err = serde_json::from_str::<MulticastRouteKey>(json)
                .expect_err(json)
                .to_string();
            assert!(
                err.contains(&format!("Group IP {group} is a Source-Specific")),
                "{json}: {err}"
            );
        }

        for json in [
            r#"{"V4":{"source":null,"group":"239.1.2.3","vni":77}}"#,
            r#"{"V4":{"source":"192.0.2.1","group":"232.1.2.3","vni":77}}"#,
            r#"{"V6":{"group":"ff0e::1","vni":77}}"#,
            r#"{"V6":{"source":"2001:db8::1","group":"ff3e::4000:1","vni":77}}"#,
        ] {
            let key = serde_json::from_str::<MulticastRouteKey>(json)
                .unwrap_or_else(|e| panic!("{json} should decode: {e}"));
            assert_eq!(key.vni(), vni(), "{json}");
        }
    }

    #[test]
    fn route_key_requires_vni() {
        for json in [
            r#"{"V4":{"source":null,"group":"239.1.2.3"}}"#,
            r#"{"V6":{"group":"ff0e::1"}}"#,
        ] {
            let err = serde_json::from_str::<MulticastRouteKey>(json)
                .expect_err(json)
                .to_string();
            assert!(err.contains("missing field `vni`"), "{json}: {err}");
        }

        for schema in [
            serde_json::to_value(schemars::schema_for!(MulticastRouteKeyV4))
                .unwrap(),
            serde_json::to_value(schemars::schema_for!(MulticastRouteKeyV6))
                .unwrap(),
        ] {
            let required = schema["required"].as_array().unwrap();
            assert!(required.contains(&"vni".into()), "{schema}");
            assert!(schema["properties"]["vni"].get("default").is_none());
        }
    }

    #[test]
    fn route_key_display_includes_vni() {
        let sg = MulticastRouteKey::new(
            Some("192.0.2.1".parse().unwrap()),
            group("232.1.2.3").unwrap(),
            vni(),
        )
        .unwrap();
        assert_eq!(sg.to_string(), "(192.0.2.1,232.1.2.3)@77");

        let any =
            MulticastRouteKey::any_source(group("ff0e::1").unwrap(), vni())
                .unwrap();
        assert_eq!(any.to_string(), "(*,ff0e::1)@77");
    }

    #[test]
    fn source_validation_precedes_family_mismatch() {
        assert!(matches!(
            MulticastRouteKey::new(
                Some("::1".parse().unwrap()),
                group("232.1.2.3").unwrap(),
                vni(),
            ),
            Err(MulticastRouteError::Source(
                MulticastSourceError::InvalidIpv6 {
                    reason: InvalidMulticastSource::Loopback,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn route_key_rejects_source_family_mismatch() {
        let group = MulticastAddr::new_v4(239, 1, 1, 1).unwrap();
        assert!(matches!(
            MulticastRouteKey::new(
                Some("2001:db8::1".parse().unwrap()),
                group,
                vni(),
            ),
            Err(MulticastRouteError::SourceFamilyMismatch { .. })
        ));
    }

    #[test]
    fn ipv6_rejects_prefix_based_without_transient() {
        for addr in ["ff2e::1", "ff2e:20:2001:db8::1"] {
            assert!(
                matches!(
                    group_err(v6(addr)),
                    MulticastGroupError::MalformedPrefixBased { .. }
                ),
                "{addr} should be rejected as malformed prefix-based"
            );
        }
    }

    #[test]
    fn accepts_embedded_rendezvous_point_as_asm() {
        for addr in [
            "ff7e:140:2001:db8::1",
            "ff7e:120:2001:db8::1",
            "ff7e:f140:2001:db8:beef:feed:0:1234",
            "ff7e:140:2001:db8:beef:feed:0:1234",
        ] {
            let parsed = v6(addr)
                .unwrap_or_else(|e| panic!("{addr} should be accepted: {e}"));
            assert!(!parsed.is_ssm(), "{addr} should not be SSM");
        }
    }
}
