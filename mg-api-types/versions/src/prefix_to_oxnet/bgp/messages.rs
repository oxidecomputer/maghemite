// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use oxnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::{v1, v4};

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
    pub nexthop: v4::bgp::messages::BgpNexthop,
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
    pub nexthop: v4::bgp::messages::BgpNexthop,
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

/// IPv4 Unicast MP_UNREACH_NLRI contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MpUnreachIpv4Unicast {
    pub withdrawn: Vec<Ipv4Net>,
}

/// IPv6 Unicast MP_UNREACH_NLRI contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MpUnreachIpv6Unicast {
    pub withdrawn: Vec<Ipv6Net>,
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
    Communities(Vec<v1::bgp::messages::Community>),
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
    MpUnreachNlri(MpUnreachNlri),
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

impl From<MpReachIpv4Unicast> for v4::bgp::messages::MpReachIpv4Unicast {
    fn from(v: MpReachIpv4Unicast) -> Self {
        Self {
            nexthop: v.nexthop,
            reserved: v.reserved,
            nlri: v.nlri.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<MpReachIpv6Unicast> for v4::bgp::messages::MpReachIpv6Unicast {
    fn from(v: MpReachIpv6Unicast) -> Self {
        Self {
            nexthop: v.nexthop,
            reserved: v.reserved,
            nlri: v.nlri.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<MpReachNlri> for v4::bgp::messages::MpReachNlri {
    fn from(v: MpReachNlri) -> Self {
        match v {
            MpReachNlri::Ipv4Unicast(i) => Self::Ipv4Unicast(i.into()),
            MpReachNlri::Ipv6Unicast(i) => Self::Ipv6Unicast(i.into()),
        }
    }
}

impl From<MpUnreachIpv4Unicast> for v4::bgp::messages::MpUnreachIpv4Unicast {
    fn from(v: MpUnreachIpv4Unicast) -> Self {
        Self {
            withdrawn: v.withdrawn.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<MpUnreachIpv6Unicast> for v4::bgp::messages::MpUnreachIpv6Unicast {
    fn from(v: MpUnreachIpv6Unicast) -> Self {
        Self {
            withdrawn: v.withdrawn.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<MpUnreachNlri> for v4::bgp::messages::MpUnreachNlri {
    fn from(v: MpUnreachNlri) -> Self {
        match v {
            MpUnreachNlri::Ipv4Unicast(i) => Self::Ipv4Unicast(i.into()),
            MpUnreachNlri::Ipv6Unicast(i) => Self::Ipv6Unicast(i.into()),
        }
    }
}

impl From<PathAttributeValue> for v4::bgp::messages::PathAttributeValue {
    fn from(v: PathAttributeValue) -> Self {
        match v {
            PathAttributeValue::Origin(x) => Self::Origin(x),
            PathAttributeValue::AsPath(x) => Self::AsPath(x),
            PathAttributeValue::NextHop(x) => Self::NextHop(x),
            PathAttributeValue::MultiExitDisc(x) => Self::MultiExitDisc(x),
            PathAttributeValue::LocalPref(x) => Self::LocalPref(x),
            PathAttributeValue::Aggregator(x) => Self::Aggregator(x),
            PathAttributeValue::Communities(x) => Self::Communities(x),
            PathAttributeValue::AtomicAggregate => Self::AtomicAggregate,
            PathAttributeValue::As4Path(x) => Self::As4Path(x),
            PathAttributeValue::As4Aggregator(x) => Self::As4Aggregator(x),
            PathAttributeValue::MpReachNlri(x) => Self::MpReachNlri(x.into()),
            PathAttributeValue::MpUnreachNlri(x) => {
                Self::MpUnreachNlri(x.into())
            }
        }
    }
}

impl From<PathAttribute> for v4::bgp::messages::PathAttribute {
    fn from(v: PathAttribute) -> Self {
        Self {
            typ: v.typ,
            value: v.value.into(),
        }
    }
}

impl From<UpdateMessage> for v4::bgp::messages::UpdateMessage {
    fn from(v: UpdateMessage) -> Self {
        Self {
            withdrawn: v.withdrawn.into_iter().map(Into::into).collect(),
            path_attributes: v
                .path_attributes
                .into_iter()
                .map(v4::bgp::messages::PathAttribute::from)
                .collect(),
            nlri: v.nlri.into_iter().map(Into::into).collect(),
            errors: v.errors,
        }
    }
}

impl From<Message> for v4::bgp::messages::Message {
    fn from(v: Message) -> Self {
        match v {
            Message::Open(x) => Self::Open(x),
            Message::Update(x) => Self::Update(x.into()),
            Message::Notification(x) => Self::Notification(x),
            Message::KeepAlive => Self::KeepAlive,
            Message::RouteRefresh(x) => Self::RouteRefresh(x),
        }
    }
}
