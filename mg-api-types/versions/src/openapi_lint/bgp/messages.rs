// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::{Ipv4Addr, Ipv6Addr};

use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};
use oxnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v4::bgp::messages::Ipv6DoubleNexthop;
use crate::{v1, v4, v11};

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
#[serde(rename_all = "snake_case")]
pub enum Afi {
    /// Internet protocol version 4
    Ipv4 = 1,
    /// Internet protocol version 6
    Ipv6 = 2,
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
#[serde(rename_all = "snake_case")]
pub enum BgpNexthop {
    Ipv4(Ipv4Addr),
    Ipv6Single(Ipv6Addr),
    Ipv6Double(Ipv6DoubleNexthop),
}

/// BGP community value
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    FromPrimitive,
    IntoPrimitive,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[repr(u32)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Community {
    /// All routes received carrying a communities attribute
    /// containing this value MUST NOT be advertised outside a BGP
    /// confederation boundary (a stand-alone autonomous system that
    /// is not part of a confederation should be considered a
    /// confederation itself)
    NoExport = 0xFFFFFF01,

    /// All routes received carrying a communities attribute
    /// containing this value MUST NOT be advertised to other BGP
    /// peers.
    NoAdvertise = 0xFFFFFF02,

    /// All routes received carrying a communities attribute
    /// containing this value MUST NOT be advertised to external BGP
    /// peers (this includes peers in other members autonomous
    /// systems inside a BGP confederation).
    NoExportSubConfed = 0xFFFFFF03,

    /// All routes received carrying a communities attribute
    /// containing this value must set the local preference for
    /// the received routes to a low value, preferably zero.
    GracefulShutdown = 0xFFFF0000,

    /// A user defined community
    #[num_enum(catch_all)]
    UserDefined(u32),
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
    pub nlri: Vec<Ipv4Net>,
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
    pub nlri: Vec<Ipv6Net>,
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

/// The value encoding of a path attribute.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PathAttributeValue {
    /// The type of origin associated with a path
    Origin(v1::bgp::messages::PathOrigin),
    /// The AS set associated with a path
    AsPath(Vec<v1::bgp::messages::As4PathSegment>),
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
    Communities(Vec<Community>),
    /// Indicates this route was formed via aggregation (RFC 4271 §5.1.7)
    AtomicAggregate,
    /// The 4-byte encoded AS set associated with a path
    As4Path(Vec<v1::bgp::messages::As4PathSegment>),
    /// AS4_AGGREGATOR: AS number and IP address of the last aggregating BGP
    /// speaker (4-octet ASN)
    As4Aggregator(v4::bgp::messages::As4Aggregator),
    /// Carries reachable MP-BGP NLRI and Next-hop (advertisement).
    MpReachNlri(MpReachNlri),
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

impl From<Afi> for v4::bgp::messages::Afi {
    fn from(new: Afi) -> Self {
        match new {
            Afi::Ipv4 => Self::Ipv4,
            Afi::Ipv6 => Self::Ipv6,
        }
    }
}

impl From<v4::bgp::messages::Afi> for Afi {
    fn from(old: v4::bgp::messages::Afi) -> Self {
        match old {
            v4::bgp::messages::Afi::Ipv4 => Self::Ipv4,
            v4::bgp::messages::Afi::Ipv6 => Self::Ipv6,
        }
    }
}

impl From<BgpNexthop> for v4::bgp::messages::BgpNexthop {
    fn from(new: BgpNexthop) -> Self {
        match new {
            BgpNexthop::Ipv4(addr) => Self::Ipv4(addr),
            BgpNexthop::Ipv6Single(addr) => Self::Ipv6Single(addr),
            BgpNexthop::Ipv6Double(addrs) => Self::Ipv6Double(addrs),
        }
    }
}

impl From<Community> for v1::bgp::messages::Community {
    fn from(new: Community) -> Self {
        match new {
            Community::NoExport => Self::NoExport,
            Community::NoAdvertise => Self::NoAdvertise,
            Community::NoExportSubConfed => Self::NoExportSubConfed,
            Community::GracefulShutdown => Self::GracefulShutdown,
            Community::UserDefined(value) => Self::UserDefined(value),
        }
    }
}

impl From<MpReachIpv4Unicast> for v11::bgp::messages::MpReachIpv4Unicast {
    fn from(new: MpReachIpv4Unicast) -> Self {
        let MpReachIpv4Unicast {
            nexthop,
            reserved,
            nlri,
        } = new;
        Self {
            nexthop: nexthop.into(),
            reserved,
            nlri,
        }
    }
}

impl From<MpReachIpv6Unicast> for v11::bgp::messages::MpReachIpv6Unicast {
    fn from(new: MpReachIpv6Unicast) -> Self {
        let MpReachIpv6Unicast {
            nexthop,
            reserved,
            nlri,
        } = new;
        Self {
            nexthop: nexthop.into(),
            reserved,
            nlri,
        }
    }
}

impl From<MpReachNlri> for v11::bgp::messages::MpReachNlri {
    fn from(new: MpReachNlri) -> Self {
        match new {
            MpReachNlri::Ipv4Unicast(reach) => Self::Ipv4Unicast(reach.into()),
            MpReachNlri::Ipv6Unicast(reach) => Self::Ipv6Unicast(reach.into()),
        }
    }
}

impl From<PathAttributeValue> for v11::bgp::messages::PathAttributeValue {
    fn from(new: PathAttributeValue) -> Self {
        match new {
            PathAttributeValue::Origin(x) => Self::Origin(x),
            PathAttributeValue::AsPath(x) => Self::AsPath(x),
            PathAttributeValue::NextHop(x) => Self::NextHop(x),
            PathAttributeValue::MultiExitDisc(x) => Self::MultiExitDisc(x),
            PathAttributeValue::LocalPref(x) => Self::LocalPref(x),
            PathAttributeValue::Aggregator(x) => Self::Aggregator(x),
            PathAttributeValue::Communities(x) => {
                Self::Communities(x.into_iter().map(Into::into).collect())
            }
            PathAttributeValue::AtomicAggregate => Self::AtomicAggregate,
            PathAttributeValue::As4Path(x) => Self::As4Path(x),
            PathAttributeValue::As4Aggregator(x) => Self::As4Aggregator(x),
            PathAttributeValue::MpReachNlri(x) => Self::MpReachNlri(x.into()),
            PathAttributeValue::MpUnreachNlri(x) => Self::MpUnreachNlri(x),
        }
    }
}

impl From<PathAttribute> for v11::bgp::messages::PathAttribute {
    fn from(new: PathAttribute) -> Self {
        let PathAttribute { typ, value } = new;
        Self {
            typ,
            value: value.into(),
        }
    }
}

impl From<UpdateMessage> for v11::bgp::messages::UpdateMessage {
    fn from(new: UpdateMessage) -> Self {
        let UpdateMessage {
            withdrawn,
            path_attributes,
            nlri,
            errors,
        } = new;
        Self {
            withdrawn,
            path_attributes: path_attributes
                .into_iter()
                .map(v11::bgp::messages::PathAttribute::from)
                .collect(),
            nlri,
            errors,
        }
    }
}

impl From<Message> for v11::bgp::messages::Message {
    fn from(new: Message) -> Self {
        match new {
            Message::Open(x) => Self::Open(x),
            Message::Update(x) => Self::Update(x.into()),
            Message::Notification(x) => Self::Notification(x),
            Message::KeepAlive => Self::KeepAlive,
            Message::RouteRefresh(x) => Self::RouteRefresh(x),
        }
    }
}
