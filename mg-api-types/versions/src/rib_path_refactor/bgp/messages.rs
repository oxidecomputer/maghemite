// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{v1, v4, v11};

use itertools::Either;
use oxnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::ops::RangeInclusive;

/// BGP Autonomous System.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct Asn(NonZeroU32);

impl Asn {
    /// 2-octet ASN value defined as a placeholder for 4-octet ASNs.
    /// To quote RFC 4893:
    /// ```text
    /// To represent 4-octet AS numbers (which are not mapped from 2-octets)
    /// as 2-octet AS numbers in the AS path information encoded with 2-octet
    /// AS numbers, this document reserves a 2-octet AS number.
    /// ```
    pub const AS_TRANS: u16 = 23456;
    const AS2_PRIVATE: RangeInclusive<u32> = 64512..=65534;
    const AS4_PRIVATE: RangeInclusive<u32> = 4_200_000_000..=4_294_967_294;

    pub fn new(val: u32) -> Option<Self> {
        NonZeroU32::new(val).map(|v| Asn(v))
    }

    pub fn val(&self) -> u32 {
        self.0.get()
    }

    /// Returns a bool indicating if this ASN falls within the IANA private-use
    /// ranges defined in RFC 6996:
    /// - 2-octet: 64512–65534
    /// - 4-octet: 4200000000–4294967294
    pub fn is_private(&self) -> bool {
        Self::AS2_PRIVATE.contains(&self.val())
            || Self::AS4_PRIVATE.contains(&self.val())
    }
}

impl std::fmt::Display for Asn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.val())
    }
}

/// Component of an AS_PATH. The wire format of each segment begins with a
/// 1-octet length field, indicating the number of ASNs in the segment. So
/// each segment can contain at most 255 (u8::MAX) ASNs.
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize,
)]
pub enum AsPathSegment {
    Set(AsSet),
    Sequence(AsSequence),
}

impl AsPathSegment {
    /// An AsPathSegment is encoded with a 1-octet length field indicating the
    /// number of ASNs within it. Therefore the max value is 255.
    pub const MAX_LEN: usize = 255;

    /// Returns the number of ASNs in the segment.
    pub fn len(&self) -> usize {
        match self {
            AsPathSegment::Set(as_set) => as_set.len(),
            AsPathSegment::Sequence(as_seq) => as_seq.len(),
        }
    }

    /// Returns the AS_PATH length value used in BGP bestpath.
    /// AS_SETs always contribute 1 regardless of how many ASNs are in the set,
    /// whereas AS_SEQUENCES contribute the number of ASNs they contain.
    pub fn path_len(&self) -> usize {
        match self {
            AsPathSegment::Set(as_set) => as_set.path_len(),
            AsPathSegment::Sequence(as_seq) => as_seq.path_len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            AsPathSegment::Set(as_set) => as_set.is_empty(),
            AsPathSegment::Sequence(as_seq) => as_seq.is_empty(),
        }
    }

    pub fn is_full(&self) -> bool {
        match self {
            AsPathSegment::Set(as_set) => as_set.is_full(),
            AsPathSegment::Sequence(as_seq) => as_seq.is_full(),
        }
    }

    pub fn remove_private_as(&mut self, peer: Asn) {
        match self {
            AsPathSegment::Set(as_set) => as_set.remove_private_as(peer),
            AsPathSegment::Sequence(as_seq) => as_seq.remove_private_as(peer),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = Asn> + '_ {
        match self {
            Self::Sequence(s) => Either::Left(s.iter()),
            Self::Set(s) => Either::Right(s.iter()),
        }
    }

    /// Returns the type code of the AS_PATH segment. Per RFC 4271 Section 4.3:
    /// ```text
    /// The path segment type is a 1-octet length field with the
    /// following values defined:
    ///
    ///    Value      Segment Type
    ///
    ///    1         AS_SET: unordered set of ASes a route in the
    ///                 UPDATE message has traversed
    ///
    ///    2         AS_SEQUENCE: ordered set of ASes a route in
    ///                 the UPDATE message has traversed
    /// ```
    pub fn type_code(&self) -> u8 {
        match self {
            AsPathSegment::Set(as_set) => as_set.type_code(),
            AsPathSegment::Sequence(as_seq) => as_seq.type_code(),
        }
    }
}

impl From<AsSet> for AsPathSegment {
    fn from(value: AsSet) -> Self {
        Self::Set(value)
    }
}

impl From<AsSequence> for AsPathSegment {
    fn from(value: AsSequence) -> Self {
        Self::Sequence(value)
    }
}

/// AS_SET: unordered set of ASes a route in the UPDATE message has traversed
#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct AsSet(BTreeSet<Asn>);

impl AsSet {
    /// AS_PATH segment type code
    pub const TYPE_CODE: u8 = 1;
    /// Per RFC 4271 Section 9.1.2.2:
    /// An AS_SET counts as 1, no matter how may ASes are in the set.
    const BESTPATH_CONTRIBUTION: usize = 1;

    pub fn new(asns: impl IntoIterator<Item = Asn>) -> Option<Self> {
        let set: BTreeSet<Asn> = asns.into_iter().collect();
        if set.is_empty() || set.len() > AsPathSegment::MAX_LEN {
            return None;
        }
        Some(AsSet(set))
    }

    /// Returns the number of ASNs within the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the AS_PATH length value used in BGP bestpath.
    pub fn path_len(&self) -> usize {
        Self::BESTPATH_CONTRIBUTION
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.0.len() >= AsPathSegment::MAX_LEN
    }

    pub fn iter(&self) -> impl Iterator<Item = Asn> + '_ {
        self.0.iter().copied()
    }

    pub fn type_code(&self) -> u8 {
        Self::TYPE_CODE
    }

    /// Strip out all ASNs which fall within the private range.
    pub fn remove_private_as(&mut self, peer: Asn) {
        self.0.retain(|asn| !asn.is_private() || *asn == peer)
    }
}

/// Ordered set of ASes a route in the UPDATE message has traversed
#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    PartialEq,
    Serialize,
)]
pub struct AsSequence(Vec<Asn>);

impl AsSequence {
    /// AS_PATH segment type code
    pub const TYPE_CODE: u8 = 2;

    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Returns the number of ASNs within the sequence.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the AS_PATH length value used in BGP bestpath.
    pub fn path_len(&self) -> usize {
        let len = self.0.len();
        debug_assert!(len <= AsPathSegment::MAX_LEN);
        len
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.0.len() >= AsPathSegment::MAX_LEN
    }

    pub fn iter(&self) -> impl Iterator<Item = Asn> + '_ {
        self.0.iter().copied()
    }

    pub fn type_code(&self) -> u8 {
        Self::TYPE_CODE
    }

    /// Strips out all ASNs which fall within the private range.
    pub fn remove_private_as(&mut self, peer: Asn) {
        self.0.retain(|asn| !asn.is_private() || *asn == peer)
    }

    /// Returns the leftover prefix that didn't fit.
    fn prepend_what_fits<'a>(&mut self, asns: &'a [Asn]) -> &'a [Asn] {
        let (overflow, fits) =
            asns.split_at(asns.len().saturating_sub(self.headroom()));
        self.0.splice(0..0, fits.iter().copied());
        overflow
    }

    /// Converts an `Asn` slice into an iterator of `AsSequence` elements that
    /// each hold up to `AsSequence::MAX_LEN` elements.
    /// Only the leftmost segment will have empty space.
    fn chunked(asns: &[Asn]) -> impl Iterator<Item = AsSequence> + '_ {
        asns.rchunks(AsPathSegment::MAX_LEN)
            .rev()
            .map(|chunk| AsSequence(chunk.to_vec()))
    }

    /// Returns the amount of space left in this segment.
    fn headroom(&self) -> usize {
        AsPathSegment::MAX_LEN.saturating_sub(self.0.len())
    }
}

impl<'a> IntoIterator for &'a AsSequence {
    type Item = Asn;
    type IntoIter = std::iter::Copied<std::slice::Iter<'a, Asn>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().copied()
    }
}

/// The set of ASes a route in the UPDATE message has traversed. Composed of
/// AsPathSegments which are either AsSequence (ordered) or AsSet (unordered).
#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    PartialEq,
    Serialize,
)]
pub struct AsPath(Vec<AsPathSegment>);

impl AsPath {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Prepend an array of ASNs to the front of the AS_PATH
    pub fn prepend(&mut self, new: &[Asn]) {
        // Leading AS_SEQUENCE absorbs what fits.
        // AS_SETs and full AS_SEQUENCEs absorb nothing.
        let overflow = match self.0.first_mut() {
            Some(AsPathSegment::Sequence(seq)) => seq.prepend_what_fits(new),
            _ => new,
        };

        // chunked() yields prefix-first with the partial segment in front,
        // so splicing at 0..0 preserves order and leaves headroom up front.
        self.0
            .splice(0..0, AsSequence::chunked(overflow).map(Into::into));
    }

    /// Strips all private ASNs from the AsPath, except for the peer's ASN.
    /// The peer's ASN is retained even if it is private in order to preserve
    /// loop prevention.
    pub fn remove_private_as(&mut self, peer: Asn) {
        self.0
            .iter_mut()
            .for_each(|seg| seg.remove_private_as(peer));
        self.compact();
    }

    /// AS_PATH length for BGP best-path selection.
    /// An AS_SEQUENCE contributes its ASN count, while an AS_SET counts as 1.
    /// Max possible value is 32,639 due to encoding limit.
    pub fn path_len(&self) -> usize {
        let len = self.0.iter().map(|seg| seg.path_len()).sum();
        debug_assert!(len <= 32639);
        len
    }

    /// Compacts all AsPathSegments owned by self. This ensures that each
    /// chunk of contiguous AS_SEQUENCE segments are packed as tightly as
    /// they can be, i.e. the rightmost segments are filled to max capacity
    /// (AsPathSegment::MAX_LEN) and the leftmost segment may be partially
    /// or completely full. AS_SETs by definition cannot be compacted, and
    /// they act as barriers between chunks of contiguous AS_SEQUENCEs.
    /// e.g.
    /// Let's say we begin with the following AsPath:
    /// [
    ///     Seq(10, 20, 30),
    ///     Seq(40 * 255),
    ///     Seq(50 * 253),
    ///     Set{555, 777},
    ///     Seq(60, 70),
    ///     Seq(80 * 254),
    ///     Seq(90 * 252)
    /// ]
    ///
    /// The compacted result would be:
    /// [
    ///     Seq(10),
    ///     Seq(20, 30, 40 * 253)
    ///     Seq(40 * 2, 50 * 253),
    ///     Set{555, 777},
    ///     Seq(50, 60, 70 * 251),
    ///     Seq(70 * 3, 80 * 252)
    /// ]
    fn compact(&mut self) {
        let mut out = Vec::with_capacity(self.0.len());
        let mut run: Vec<Asn> = Vec::new();

        for seg in self.0.drain(..) {
            match seg {
                AsPathSegment::Sequence(seq) => run.extend(seq.iter()),
                set @ AsPathSegment::Set(_) => {
                    out.extend(AsSequence::chunked(&run).map(Into::into));
                    run.clear();
                    out.push(set);
                }
            }
        }
        out.extend(AsSequence::chunked(&run).map(Into::into));

        self.0 = out;
    }

    /// Returns an Iterator of all Asns from all AsPathSegments.
    pub fn asns(&self) -> impl Iterator<Item = Asn> + '_ {
        self.0.iter().flat_map(AsPathSegment::iter)
    }
}

#[derive(Debug)]
pub enum CommunityParseError {
    BadFormat,
    BadValue,
}

impl std::fmt::Display for CommunityParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommunityParseError::BadFormat => write!(f, "Bad Format"),
            CommunityParseError::BadValue => write!(f, "Bad Value"),
        }
    }
}

impl std::error::Error for CommunityParseError {}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Community(u32);

impl Community {
    // RFC 8326
    pub const GRACEFUL_SHUTDOWN: Self = Self(0xFFFF_0000);

    // RFC 7611
    pub const ACCEPT_OWN: Self = Self(0xFFFF_0001);

    // draft-l3vpn-legacy-rtc-00
    pub const ROUTE_FILTER_TRANSLATED_V4: Self = Self(0xFFFF_0002);
    pub const ROUTE_FILTER_V4: Self = Self(0xFFFF_0003);
    pub const ROUTE_FILTER_TRANSLATED_V6: Self = Self(0xFFFF_0004);
    pub const ROUTE_FILTER_V6: Self = Self(0xFFFF_0005);

    // RFC 9494
    pub const LLGR_STALE: Self = Self(0xFFFF_0006);
    pub const NO_LLGR: Self = Self(0xFFFF_0007);

    // draft-agrewal-idr-accept-own-nexthop-00
    pub const ACCEPT_OWN_NEXTHOP: Self = Self(0xFFFF_0008);

    // RFC 9026
    pub const STANDBY_PE: Self = Self(0xFFFF_0009);

    // RFC 7999
    pub const BLACKHOLE: Self = Self(0xFFFF_029A);

    // RFC 1997
    pub const NO_EXPORT: Self = Self(0xFFFF_FF01);
    pub const NO_ADVERTISE: Self = Self(0xFFFF_FF02);
    pub const NO_EXPORT_SUBCONFED: Self = Self(0xFFFF_FF03);
    // LOCAL_AS seems to be a common display alias originally coined by Cisco,
    // rather than a standardized name. We'll support it for input convenience,
    // but for output we will display NO_EXPORT_SUBCONFED.
    pub const LOCAL_AS: Self = Self::NO_EXPORT_SUBCONFED;

    // RFC 3765
    pub const NO_PEER: Self = Self(0xFFFF_FF04);
}

impl From<u32> for Community {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<Community> for u32 {
    fn from(c: Community) -> u32 {
        c.0
    }
}

impl std::fmt::Display for Community {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::GRACEFUL_SHUTDOWN => write!(f, "Graceful-Shutdown"),
            Self::ACCEPT_OWN => write!(f, "Accept-Own"),
            Self::ROUTE_FILTER_TRANSLATED_V4 => {
                write!(f, "Route-Filter-Translated-V4")
            }
            Self::ROUTE_FILTER_V4 => write!(f, "Route-Filter-V4"),
            Self::ROUTE_FILTER_TRANSLATED_V6 => {
                write!(f, "Route-Filter-Translated-V6")
            }
            Self::ROUTE_FILTER_V6 => write!(f, "Route-Filter-V6"),
            Self::LLGR_STALE => write!(f, "LLGR-Stale"),
            Self::NO_LLGR => write!(f, "No-LLGR"),
            Self::ACCEPT_OWN_NEXTHOP => write!(f, "Accept-Own-Nexthop"),
            Self::STANDBY_PE => write!(f, "Standby-PE"),
            Self::BLACKHOLE => write!(f, "Blackhole"),
            Self::NO_EXPORT => write!(f, "No-Export"),
            Self::NO_ADVERTISE => write!(f, "No-Advertise"),
            // Display NO_EXPORT_SUBCONFED over LOCAL_AS
            Self::NO_EXPORT_SUBCONFED => write!(f, "No-Export-SubConfed"),
            Self::NO_PEER => write!(f, "No-Peer"),
            Self(v) => write!(f, "{}:{}", v >> 16, v & 0xFFFF),
        }
    }
}

impl std::str::FromStr for Community {
    type Err = CommunityParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "graceful-shutdown" => Ok(Self::GRACEFUL_SHUTDOWN),
            "accept-own" => Ok(Self::ACCEPT_OWN),
            "route-filter-translated-v4" => {
                Ok(Self::ROUTE_FILTER_TRANSLATED_V4)
            }
            "route-filter-v4" => Ok(Self::ROUTE_FILTER_V4),
            "route-filter-translated-v6" => {
                Ok(Self::ROUTE_FILTER_TRANSLATED_V6)
            }
            "route-filter-v6" => Ok(Self::ROUTE_FILTER_V6),
            "llgr-stale" => Ok(Self::LLGR_STALE),
            "no-llgr" => Ok(Self::NO_LLGR),
            "accept-own-nexthop" => Ok(Self::ACCEPT_OWN_NEXTHOP),
            "standby-pe" => Ok(Self::STANDBY_PE),
            "blackhole" => Ok(Self::BLACKHOLE),
            "no-export" => Ok(Self::NO_EXPORT),
            "no-advertise" => Ok(Self::NO_ADVERTISE),
            "no-export-subconfed" => Ok(Self::NO_EXPORT_SUBCONFED),
            "no-peer" => Ok(Self::NO_PEER),
            s => {
                // parse "AA:NN" format
                let (hi, lo) =
                    s.split_once(':').ok_or(CommunityParseError::BadFormat)?;
                let hi: u16 =
                    hi.parse().map_err(|_| CommunityParseError::BadValue)?;
                let lo: u16 =
                    lo.parse().map_err(|_| CommunityParseError::BadValue)?;
                Ok(Self((u32::from(hi)) << 16 | u32::from(lo)))
            }
        }
    }
}

/// The value encoding of a path attribute.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathAttributeValue {
    /// The type of origin associated with a path
    Origin(v1::bgp::messages::PathOrigin),
    /// The AS set associated with a path
    AsPath(AsPath),
    /// The nexthop associated with a path (IPv4 only for traditional BGP)
    NextHop(Ipv4Addr),
    /// A metric used for external (inter-AS) links to discriminate among
    /// multiple entry or exit points.
    MultiExitDisc(u32),
    /// Local pref is included in update messages sent to internal peers and
    /// indicates a degree of preference.
    LocalPref(u32),
    /// AGGREGATOR: AS number and IP address of the last aggregating BGP
    /// speaker (2-octet ASN)
    Aggregator(v4::bgp::messages::Aggregator),
    /// Indicates communities associated with a path.
    Communities(Vec<v1::bgp::messages::Community>),
    /// Indicates this route was formed via aggregation (RFC 4271 §5.1.7)
    AtomicAggregate,
    /// The 4-byte encoded AS set associated with a path
    As4Path(Vec<v1::bgp::messages::As4PathSegment>),
    /// AS4_AGGREGATOR: AS number and IP address of the last aggregating BGP
    /// speaker (4-octet ASN)
    As4Aggregator(v4::bgp::messages::As4Aggregator),
    /// Carries reachable MP-BGP NLRI and Next-hop (advertisement).
    MpReachNlri(v11::bgp::messages::MpReachNlri),
    /// Carries unreachable MP-BGP NLRI (withdrawal).
    MpUnreachNlri(v11::bgp::messages::MpUnreachNlri),
}

/// A self-describing BGP path attribute
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PathAttribute {
    /// Type encoding for the attribute
    pub typ: v4::bgp::messages::PathAttributeType,
    /// Value of the attribute
    pub value: PathAttributeValue,
}

/// An update message is used to advertise feasible routes that share common
/// path attributes to a peer, or to withdraw multiple unfeasible routes from
/// service.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Witdrawn Length        |       Withdrawn Routes        :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                                                               :
/// :                Withdrawn Routes (cont, variable)              :
/// :                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Path Attribute Length      |       Path Attributes         :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                                                               :
/// :                Path Attributes (cont, variable)               :
/// :                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                                                               :
/// :       Network Layer Reachability Information (variable)       :
/// :                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Ref: RFC 4271 §4.3
#[derive(
    Debug, PartialEq, Eq, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct UpdateMessage {
    pub withdrawn: Vec<Ipv4Net>,
    pub path_attributes: Vec<PathAttribute>,
    pub nlri: Vec<Ipv4Net>,

    /// All attribute parse errors encountered during from_wire().
    /// Includes both TreatAsWithdraw and Discard errors.
    /// SessionReset errors cause early return and are not collected here.
    /// Not serialized - only used for internal signaling.
    /// Use the treat_as_withdraw() method to check if any TreatAsWithdraw errors occurred.
    //
    // This field intentionally references `crate::impls::…` rather than a
    // versioned identifier — the only documented deviation from RFD 619's
    // "version modules only refer to versioned identifiers" rule. The
    // carried types are `#[serde(skip)]`/`#[schemars(skip)]` and therefore
    // not part of any OpenAPI surface; they exist solely for in-process
    // RFC 7606 (treat-as-withdraw / discard) signaling between the BGP
    // decoder in the `bgp` crate and its consumers. Keeping them adjacent
    // to the latest-shape impls (rather than duplicating into every
    // version) is the pragmatic trade-off; see `impls/bgp/parse.rs` for
    // the full rationale.
    #[serde(skip, default)]
    #[schemars(skip)]
    pub errors: Vec<(
        crate::impls::bgp::parse::UpdateParseErrorReason,
        crate::impls::bgp::parse::AttributeAction,
    )>,
}

/// Holds a BGP message. May be an Open, Update, Notification or Keep Alive
/// message.
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Message {
    Open(v1::bgp::messages::OpenMessage),
    Update(UpdateMessage),
    Notification(v1::bgp::messages::NotificationMessage),
    KeepAlive,
    RouteRefresh(v1::bgp::messages::RouteRefreshMessage),
}
