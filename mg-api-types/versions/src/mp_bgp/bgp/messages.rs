// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! BGP wire-message types added in the MP_BGP API version.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::v1::rdb::prefix::{Prefix4, Prefix6};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1::bgp::messages::As4PathSegment;
use crate::v1::bgp::messages::Community;
use crate::v1::bgp::messages::PathOrigin;

/// Address families supported by Maghemite BGP.
#[derive(
    Debug,
    Copy,
    Clone,
    Deserialize,
    Eq,
    IntoPrimitive,
    JsonSchema,
    PartialEq,
    Serialize,
    TryFromPrimitive,
)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[repr(u16)]
pub enum Afi {
    /// Internet protocol version 4
    Ipv4 = 1,
    /// Internet protocol version 6
    Ipv6 = 2,
}

/// IPv6 double nexthop: global unicast address + link-local address.
/// Per RFC 2545, when advertising IPv6 routes, both addresses may be present.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
pub struct Ipv6DoubleNexthop {
    /// Global unicast address
    pub global: Ipv6Addr,
    /// Link-local address
    pub link_local: Ipv6Addr,
}

/// BGP next-hops can come in multiple forms, defined in several different RFCs.
/// This enum represents the forms supported by this implementation.
///
/// In the case of IPv6, RFC 2545 defined the use of either:
/// 1) A single non-link-local next-hop (length=16)
/// 2) A non-link-local plus a link-local next-hop (length=32)
///
/// This does not account for only a link-local address as the sole next-hop.
/// As such, many different implementations decided they would encode this in a
/// variety of ways (since there was no canonical source of truth):
/// a) Single-address encoding just the link-local (length=16)
/// b) Double-address encoding the link-local in both positions (length=32)
/// c) Double-address encoding the link-local in its normal position, but 0's in
///    the non-link-local position (length=32)
/// etc.
/// This led to `draft-ietf-idr-linklocal-capability` which specifies more
/// detailed encoding and error handling standards, signaled via a new
/// Link-Local Next Hop Capability.
///
/// In addition to this, RFC 8950 (formerly RFC 5549) specified the
/// advertisement of IPv4 NLRI via an IPv6 next-hop, enabled via the Extended
/// Next Hop capability.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[schemars(
    description = "A BGP next-hop address in one of three formats: IPv4, IPv6 single, or IPv6 double."
)]
pub enum BgpNexthop {
    Ipv4(Ipv4Addr),
    Ipv6Single(Ipv6Addr),
    Ipv6Double(Ipv6DoubleNexthop),
}

/// Path attribute flag bits (RFC 4271 §4.3).
pub mod path_attribute_flags {
    /// Treat a path attribute as optional
    pub const OPTIONAL: u8 = 0b10000000;
    /// Path attribute must be redistributed
    pub const TRANSITIVE: u8 = 0b01000000;
    /// Treat path attribute as partial
    pub const PARTIAL: u8 = 0b00100000;
    /// If set the path attribute length is encoded in two octets instead of
    /// one
    pub const EXTENDED_LENGTH: u8 = 0b00010000;
}

/// An enumeration describing available path attribute type codes.
//
// This enum is the MP-BGP form (RFC 4760) which adds the MpReachNlri and
// MpUnreachNlri variants to the original v1 form. The schema-published doc
// comment is intentionally limited to the first line for stability across
// API versions.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    IntoPrimitive,
    JsonSchema,
    PartialEq,
    Serialize,
    TryFromPrimitive,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum PathAttributeTypeCode {
    /// RFC 4271
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    MultiExitDisc = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
    Communities = 8,

    /// RFC 4760
    MpReachNlri = 14,
    MpUnreachNlri = 15,

    /// RFC 6793
    As4Path = 17,
    As4Aggregator = 18,
}

/// AGGREGATOR path attribute (RFC 4271 §5.1.8)
///
/// The AGGREGATOR attribute is an optional transitive attribute that contains
/// the AS number and IP address of the last BGP speaker that formed the
/// aggregate route.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema,
)]
pub struct Aggregator {
    /// Autonomous System Number that formed the aggregate (2-octet)
    pub asn: u16,
    /// IP address of the BGP speaker that formed the aggregate
    pub address: Ipv4Addr,
}

/// AS4_AGGREGATOR path attribute (RFC 6793)
///
/// The AS4_AGGREGATOR attribute is an optional transitive attribute with the
/// same semantics as AGGREGATOR, but carries a 4-octet AS number instead of
/// 2-octet.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema,
)]
pub struct As4Aggregator {
    /// Autonomous System Number that formed the aggregate (4-octet)
    pub asn: u32,
    /// IP address of the BGP speaker that formed the aggregate
    pub address: Ipv4Addr,
}

/// IPv4 Unicast MP_REACH_NLRI contents.
///
/// Contains the next-hop and NLRI for IPv4 unicast route announcements
/// carried via MP-BGP (RFC 4760).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MpReachIpv4Unicast {
    /// Next-hop for IPv4 routes.
    ///
    /// Currently must be `BgpNexthop::Ipv4`, but will support IPv6 nexthops
    /// when extended next-hop capability (RFC 8950) is implemented.
    pub nexthop: BgpNexthop,
    /// Reserved byte from RFC 4760 §3 (historically "Number of SNPAs" in RFC 2858).
    /// MUST be 0 per RFC 4760, but MUST be ignored by receiver.
    /// Stored for validation logging in session layer.
    /// This field is positioned before NLRI to match the wire format encoding.
    pub reserved: u8,
    /// IPv4 prefixes being announced
    pub nlri: Vec<Prefix4>,
}

/// IPv6 Unicast MP_REACH_NLRI contents.
///
/// Contains the next-hop and NLRI for IPv6 unicast route announcements
/// carried via MP-BGP (RFC 4760).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MpReachIpv6Unicast {
    /// Next-hop for IPv6 routes.
    ///
    /// Can be `BgpNexthop::Ipv6Single` (16 bytes) or `BgpNexthop::Ipv6Double`
    /// (32 bytes with link-local address).
    pub nexthop: BgpNexthop,
    /// Reserved byte from RFC 4760 §3 (historically "Number of SNPAs" in RFC 2858).
    /// MUST be 0 per RFC 4760, but MUST be ignored by receiver.
    /// Stored for validation logging in session layer.
    /// This field is positioned before NLRI to match the wire format encoding.
    pub reserved: u8,
    /// IPv6 prefixes being announced
    pub nlri: Vec<Prefix6>,
}

/// MP_REACH_NLRI path attribute
///
/// Each variant represents a specific AFI+SAFI combination, providing
/// compile-time guarantees about the address family of routes being announced.
///
/// ```text
/// 3.  Multiprotocol Reachable NLRI - MP_REACH_NLRI (Type Code 14):
///
///    This is an optional non-transitive attribute that can be used for the
///    following purposes:
///
///    (a) to advertise a feasible route to a peer
///
///    (b) to permit a router to advertise the Network Layer address of the
///        router that should be used as the next hop to the destinations
///        listed in the Network Layer Reachability Information field of the
///        MP_NLRI attribute.
///
///    The attribute is encoded as shown below:
///
///    +---------------------------------------------------------+
///    | Address Family Identifier (2 octets)                    |
///    +---------------------------------------------------------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "afi_safi", rename_all = "snake_case")]
pub enum MpReachNlri {
    /// IPv4 Unicast routes (AFI=1, SAFI=1)
    Ipv4Unicast(MpReachIpv4Unicast),
    /// IPv6 Unicast routes (AFI=2, SAFI=1)
    Ipv6Unicast(MpReachIpv6Unicast),
}

/// IPv4 Unicast MP_UNREACH_NLRI contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MpUnreachIpv4Unicast {
    pub withdrawn: Vec<Prefix4>,
}

/// IPv6 Unicast MP_UNREACH_NLRI contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MpUnreachIpv6Unicast {
    pub withdrawn: Vec<Prefix6>,
}

/// MP_UNREACH_NLRI path attribute
///
/// Each variant represents a specific AFI+SAFI combination, providing
/// compile-time guarantees about the address family of routes being withdrawn.
///
/// ```text
/// 4.  Multiprotocol Unreachable NLRI - MP_UNREACH_NLRI (Type Code 15):
///
///    This is an optional non-transitive attribute that can be used for the
///    purpose of withdrawing multiple unfeasible routes from service.
///
///    The attribute is encoded as shown below:
///
///         +---------------------------------------------------------+
///         | Address Family Identifier (2 octets)                    |
///         +---------------------------------------------------------+
///         | Subsequent Address Family Identifier (1 octet)          |
///         +---------------------------------------------------------+
///         | Withdrawn Routes (variable)                             |
///         +---------------------------------------------------------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "afi_safi", rename_all = "snake_case")]
pub enum MpUnreachNlri {
    /// IPv4 Unicast routes being withdrawn (AFI=1, SAFI=1)
    Ipv4Unicast(MpUnreachIpv4Unicast),
    /// IPv6 Unicast routes being withdrawn (AFI=2, SAFI=1)
    Ipv6Unicast(MpUnreachIpv6Unicast),
}

/// The value encoding of a path attribute.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathAttributeValue {
    /// The type of origin associated with a path
    Origin(PathOrigin),
    /// The AS set associated with a path
    AsPath(Vec<As4PathSegment>),
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
    Aggregator(Aggregator),
    /// Indicates communities associated with a path.
    Communities(Vec<Community>),
    /// Indicates this route was formed via aggregation (RFC 4271 §5.1.7)
    AtomicAggregate,
    /// The 4-byte encoded AS set associated with a path
    As4Path(Vec<As4PathSegment>),
    /// AS4_AGGREGATOR: AS number and IP address of the last aggregating BGP
    /// speaker (4-octet ASN)
    As4Aggregator(As4Aggregator),
    /// Carries reachable MP-BGP NLRI and Next-hop (advertisement).
    MpReachNlri(MpReachNlri),
    /// Carries unreachable MP-BGP NLRI (withdrawal).
    MpUnreachNlri(MpUnreachNlri),
}

/// Type encoding for a path attribute.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PathAttributeType {
    /// Flags may include, Optional, Transitive, Partial and Extended Length.
    pub flags: u8,
    /// Type code for the path attribute.
    pub type_code: PathAttributeTypeCode,
}

/// A self-describing BGP path attribute
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PathAttribute {
    /// Type encoding for the attribute
    pub typ: PathAttributeType,
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
    pub withdrawn: Vec<Prefix4>,
    pub path_attributes: Vec<PathAttribute>, // XXX: use map for O(1) lookups?
    pub nlri: Vec<Prefix4>,

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
    Open(crate::v1::bgp::messages::OpenMessage),
    Update(UpdateMessage),
    Notification(crate::v1::bgp::messages::NotificationMessage),
    KeepAlive,
    RouteRefresh(crate::v1::bgp::messages::RouteRefreshMessage),
}

// ----------------------------------------------------------------------------
// Cross-version downgrade: v4 `Message`/`UpdateMessage` → v2 history-module
// wire shapes. The v2 shapes carry the V4/V6 rdb `Prefix` enum, so
// `withdrawn`/`nlri` are routed through `Prefix::V4(...)`; v4 path
// attributes that have no v1 representation (MP_REACH/UNREACH,
// AtomicAggregate) are dropped via `Option::<v1::PathAttribute>::from`.
// ----------------------------------------------------------------------------

impl From<UpdateMessage> for crate::v2::bgp::history::UpdateMessage {
    fn from(msg: UpdateMessage) -> Self {
        // The latest UpdateMessage carries IPv4-only NLRI in its body; IPv6
        // NLRI lives in MP_REACH/UNREACH path attributes, which v2 does not
        // surface. Converting v4 prefixes back into the V4/V6 enum gives the
        // pre-MP-BGP wire shape.
        Self {
            withdrawn: msg
                .withdrawn
                .into_iter()
                .map(crate::v1::rdb::prefix::Prefix::V4)
                .collect(),
            path_attributes: msg
                .path_attributes
                .into_iter()
                .filter_map(
                    Option::<crate::v1::bgp::messages::PathAttribute>::from,
                )
                .collect(),
            nlri: msg
                .nlri
                .into_iter()
                .map(crate::v1::rdb::prefix::Prefix::V4)
                .collect(),
        }
    }
}

impl From<Message> for crate::v2::bgp::history::Message {
    fn from(msg: Message) -> Self {
        match msg {
            Message::Open(open) => Self::Open(open),
            Message::Update(update) => Self::Update(update.into()),
            Message::Notification(notif) => Self::Notification(notif),
            Message::KeepAlive => Self::KeepAlive,
            Message::RouteRefresh(rr) => Self::RouteRefresh(rr),
        }
    }
}

// ----------------------------------------------------------------------------
// Cross-version downgrade: v4 PathAttribute family → v1 representations.
// MP-BGP type codes / attribute values have no v1 equivalent and either
// fall through to AS4 codes (type-code level) or are dropped (value
// level, surfaced through the `Option`-returning value conversion).
//
// These v4 → v1 conversions skip the v2 hop that RFD 619 §4.5 prefers.
// The skip is intentional: v2 introduces a `bgp::history` module whose
// `Message`/`UpdateMessage` differ from v1's `bgp::messages::Message`
// (v2 wraps v1's Open/Notification/RouteRefresh types but carries a
// v2-local UpdateMessage on top of v1 PathAttributes). There is no
// useful v2-`messages` shape to hop through, so v4 → v1 PathAttribute
// translation lives here, next to the matching v4 → v2 history block.
// ----------------------------------------------------------------------------

impl From<PathAttributeTypeCode>
    for crate::v1::bgp::messages::PathAttributeTypeCode
{
    fn from(code: PathAttributeTypeCode) -> Self {
        use crate::v1::bgp::messages::PathAttributeTypeCode as V1Code;
        match code {
            PathAttributeTypeCode::Origin => V1Code::Origin,
            PathAttributeTypeCode::AsPath => V1Code::AsPath,
            PathAttributeTypeCode::NextHop => V1Code::NextHop,
            PathAttributeTypeCode::MultiExitDisc => V1Code::MultiExitDisc,
            PathAttributeTypeCode::LocalPref => V1Code::LocalPref,
            PathAttributeTypeCode::AtomicAggregate => V1Code::AtomicAggregate,
            PathAttributeTypeCode::Aggregator => V1Code::Aggregator,
            PathAttributeTypeCode::Communities => V1Code::Communities,
            // MP-BGP type codes have no v1 equivalent; map to As4Path as a
            // fallback (they are filtered out before this conversion runs
            // in the value-level mapping).
            PathAttributeTypeCode::MpReachNlri
            | PathAttributeTypeCode::MpUnreachNlri => V1Code::As4Path,
            PathAttributeTypeCode::As4Path => V1Code::As4Path,
            PathAttributeTypeCode::As4Aggregator => V1Code::As4Aggregator,
        }
    }
}

impl From<PathAttributeType> for crate::v1::bgp::messages::PathAttributeType {
    fn from(t: PathAttributeType) -> Self {
        let PathAttributeType { flags, type_code } = t;
        Self {
            flags,
            type_code: crate::v1::bgp::messages::PathAttributeTypeCode::from(
                type_code,
            ),
        }
    }
}

impl From<PathAttributeValue>
    for Option<crate::v1::bgp::messages::PathAttributeValue>
{
    fn from(val: PathAttributeValue) -> Self {
        use crate::v1::bgp::messages::PathAttributeValue as V1Val;
        use std::net::IpAddr;
        match val {
            PathAttributeValue::Origin(o) => Some(V1Val::Origin(o)),
            PathAttributeValue::AsPath(p) => Some(V1Val::AsPath(p)),
            PathAttributeValue::NextHop(nh) => {
                Some(V1Val::NextHop(IpAddr::V4(nh)))
            }
            PathAttributeValue::MultiExitDisc(m) => {
                Some(V1Val::MultiExitDisc(m))
            }
            PathAttributeValue::LocalPref(l) => Some(V1Val::LocalPref(l)),
            PathAttributeValue::Aggregator(a) => {
                Some(V1Val::Aggregator(a.to_bytes()))
            }
            PathAttributeValue::Communities(c) => Some(V1Val::Communities(c)),
            // AtomicAggregate / MP-BGP attributes have no v1 representation.
            PathAttributeValue::AtomicAggregate
            | PathAttributeValue::MpReachNlri(_)
            | PathAttributeValue::MpUnreachNlri(_) => None,
            PathAttributeValue::As4Path(p) => Some(V1Val::As4Path(p)),
            PathAttributeValue::As4Aggregator(a) => {
                Some(V1Val::As4Aggregator(a.to_bytes()))
            }
        }
    }
}

impl From<PathAttribute> for Option<crate::v1::bgp::messages::PathAttribute> {
    fn from(attr: PathAttribute) -> Self {
        let PathAttribute { typ, value } = attr;
        let value_opt: Option<crate::v1::bgp::messages::PathAttributeValue> =
            value.into();
        value_opt.map(|value| crate::v1::bgp::messages::PathAttribute {
            typ: crate::v1::bgp::messages::PathAttributeType::from(typ),
            value,
        })
    }
}

// ----------------------------------------------------------------------------
// Cross-version downgrade: v4 `Message`/`UpdateMessage` → v1 wire shapes.
// As with the PathAttribute block above, this skips v2 deliberately —
// v2's `bgp::history::Message` is a sibling shape, not a v1 → v4
// intermediate, so the v4 → v1 conversion cannot factor through it.
// ----------------------------------------------------------------------------

impl From<UpdateMessage> for crate::v1::bgp::messages::UpdateMessage {
    fn from(msg: UpdateMessage) -> Self {
        // Compile barrier: a latest UpdateMessage field addition will
        // fail to bind here, forcing a deliberate decision about how
        // (or whether) to surface it on the v1 form.
        let UpdateMessage {
            withdrawn,
            path_attributes,
            nlri,
            // `errors` is the runtime parse-error trace (#[serde(skip)],
            // #[schemars(skip)]); it never appears on the wire and has
            // no v1 representation.
            errors: _,
        } = msg;
        Self {
            withdrawn: withdrawn
                .into_iter()
                .map(|p| {
                    crate::v1::bgp::messages::Prefix::from(
                        crate::v1::rdb::prefix::Prefix::V4(p),
                    )
                })
                .collect(),
            // Filter out attributes that don't have v1 equivalents (MP-BGP,
            // AtomicAggregate).
            path_attributes: path_attributes
                .into_iter()
                .filter_map(
                    Option::<crate::v1::bgp::messages::PathAttribute>::from,
                )
                .collect(),
            nlri: nlri
                .into_iter()
                .map(|p| {
                    crate::v1::bgp::messages::Prefix::from(
                        crate::v1::rdb::prefix::Prefix::V4(p),
                    )
                })
                .collect(),
        }
    }
}

impl From<Message> for crate::v1::bgp::messages::Message {
    fn from(msg: Message) -> Self {
        // The match exhausts all latest Message variants; adding a
        // variant fails to compile here, forcing an explicit v1 mapping.
        match msg {
            Message::Open(open) => Self::Open(open),
            Message::Update(update) => Self::Update(update.into()),
            Message::Notification(notif) => Self::Notification(notif),
            Message::KeepAlive => Self::KeepAlive,
            Message::RouteRefresh(rr) => Self::RouteRefresh(rr),
        }
    }
}
