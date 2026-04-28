// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! BGP wire-message enumerations published since the initial admin API
//! version. These types encode IANA-assigned numeric codes used in BGP
//! protocol messages.

use std::collections::BTreeSet;
use std::net::IpAddr;

use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v4::messages::ExtendedNexthopElement;

/// Maximum BGP message size in octets per RFC 4271 §4.
pub const MAX_MESSAGE_SIZE: usize = 4096;

/// BGP Message types.
///
/// Ref: RFC 4271 §4.1
#[derive(
    Clone, Copy, Debug, Eq, IntoPrimitive, PartialEq, TryFromPrimitive,
)]
#[repr(u8)]
pub enum MessageType {
    /// The first message sent by each side once a TCP connection is
    /// established.
    ///
    /// RFC 4271 §4.2
    Open = 1,

    /// Used to transfer routing information between BGP peers.
    ///
    /// RFC 4271 §4.3
    Update = 2,

    /// Sent when an error condition is detected.
    ///
    /// RFC 4271 §4.5
    Notification = 3,

    /// Exchanged between peers often enough not to cause the hold timer to
    /// expire.
    ///
    /// RFC 4271 §4.4
    KeepAlive = 4,

    /// When this message is received from a peer, we send that peer all
    /// current outbound routes.
    ///
    /// RFC 2918
    RouteRefresh = 5,
}

/// Tag identifying which BGP message variant is held by `Message`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MessageKind {
    Open,
    Update,
    Notification,
    KeepAlive,
    RouteRefresh,
}

#[derive(Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum OptionalParameterCode {
    Reserved = 0,
    Authentication = 1,
    Capabilities = 2,
    ExtendedLength = 255,
}

/// The set of capability codes supported by this BGP implementation
#[derive(
    Clone, Copy, Debug, Eq, IntoPrimitive, PartialEq, TryFromPrimitive,
)]
#[repr(u8)]
pub enum CapabilityCode {
    /// RFC 5492
    Reserved = 0,

    /// RFC 2858
    MultiprotocolExtensions = 1,

    /// RFC 2918
    RouteRefresh = 2,

    /// RFC 5291
    OutboundRouteFiltering = 3,

    /// RFC 8277 (deprecated)
    MultipleRoutesToDestination = 4,

    /// RFC 8950
    ExtendedNextHopEncoding = 5,

    /// RFC 8654
    BGPExtendedMessage = 6,

    /// RFC 8205
    BgpSec = 7,

    /// RFC 8277
    MultipleLabels = 8,

    /// RFC 9234
    BgpRole = 9,

    /// RFC 4724
    GracefulRestart = 64,

    /// RFC 6793
    FourOctetAs = 65,

    /// draft-ietf-idr-dynamic-cap
    DynamicCapability = 67,

    /// draft-ietf-idr-bgp-multisession
    MultisessionBgp = 68,

    /// RFC 7911
    AddPath = 69,

    /// RFC 7313
    EnhancedRouteRefresh = 70,

    /// draft-uttaro-idr-bgp-persistence
    LongLivedGracefulRestart = 71,

    /// draft-ietf-idr-rpd-04
    RoutingPolicyDistribution = 72,

    /// draft-walton-bgp-hostname-capability
    Fqdn = 73,

    /// RFC 8810 (deprecated)
    PrestandardRouteRefresh = 128,

    /// RFC 8810 (deprecated)
    PrestandardOrfAndPd = 129,

    /// RFC 8810 (deprecated)
    PrestandardOutboundRouteFiltering = 130,

    /// RFC 8810 (deprecated)
    PrestandardMultisession = 131,

    /// RFC 8810 (deprecated)
    PrestandardFqdn = 184,

    /// RFC 8810 (deprecated)
    PrestandardOperationalMessage = 185,

    /// RFC 8810
    Experimental0 = 186,
    Experimental1,
    Experimental2,
    Experimental3,
    Experimental4,
    Experimental5,
    Experimental6,
    Experimental7,
    Experimental8,
    Experimental9,
    Experimental10,
    Experimental11,
    Experimental12,
    Experimental13,
    Experimental14,
    Experimental15,
    Experimental16,
    Experimental17,
    Experimental18,
    Experimental19,
    Experimental20,
    Experimental21,
    Experimental22,
    Experimental23,
    Experimental24,
    Experimental25,
    Experimental26,
    Experimental27,
    Experimental28,
    Experimental29,
    Experimental30,
    Experimental31,
    Experimental32,
    Experimental33,
    Experimental34,
    Experimental35,
    Experimental36,
    Experimental37,
    Experimental38,
    Experimental39,
    Experimental40,
    Experimental41,
    Experimental42,
    Experimental43,
    Experimental44,
    Experimental45,
    Experimental46,
    Experimental47,
    Experimental48,
    Experimental49,
    Experimental50,
    Experimental51,
}

/// Subsequent address families supported by Maghemite BGP.
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
#[repr(u8)]
pub enum Safi {
    /// Network Layer Reachability Information used for unicast forwarding
    Unicast = 1,
}

/// An enumeration describing available path attribute type codes (initial
/// API version, prior to MP-BGP).
///
/// The schema-published name is `PathAttributeTypeCode` (preserved via
/// `#[schemars(rename = ...)]`); the in-source name disambiguates from the
/// 12-variant MP-BGP form at [`crate::v4::messages::PathAttributeTypeCode`].
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
#[schemars(rename = "PathAttributeTypeCode")]
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

    /// RFC 6793
    As4Path = 17,
    As4Aggregator = 18,
}

/// Enumeration describes possible AS path types
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
pub enum AsPathType {
    /// The path is to be interpreted as a set
    AsSet = 1,
    /// The path is to be interpreted as a sequence
    AsSequence = 2,
}

/// This enumeration contains possible notification error codes.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    IntoPrimitive,
    TryFromPrimitive,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Header = 1,
    Open,
    Update,
    HoldTimerExpired,
    Fsm,
    Cease,
}

/// Header error subcode types
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    IntoPrimitive,
    TryFromPrimitive,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum HeaderErrorSubcode {
    Unspecific = 0,
    ConnectionNotSynchronized,
    BadMessageLength,
    BadMessageType,
}

/// Open message error subcode types
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    IntoPrimitive,
    TryFromPrimitive,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum OpenErrorSubcode {
    Unspecific = 0,
    UnsupportedVersionNumber,
    BadPeerAS,
    BadBgpIdentifier,
    UnsupportedOptionalParameter,
    Deprecated,
    UnacceptableHoldTime,
    UnsupportedCapability,
}

/// Update message error subcode types
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    IntoPrimitive,
    TryFromPrimitive,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum UpdateErrorSubcode {
    Unspecific = 0,
    MalformedAttributeList,
    UnrecognizedWellKnownAttribute,
    MissingWellKnownAttribute,
    AttributeFlags,
    AttributeLength,
    InvalidOriginAttribute,
    Deprecated,
    InvalidNexthopAttribute,
    OptionalAttribute,
    InvalidNetworkField,
    MalformedAsPath,
}

/// Cease error subcode types from RFC 4486
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    IntoPrimitive,
    TryFromPrimitive,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum CeaseErrorSubcode {
    Unspecific = 0,
    MaximumNumberofPrefixesReached,
    AdministrativeShutdown,
    PeerDeconfigured,
    AdministrativeReset,
    ConnectionRejected,
    OtherConfigurationChange,
    ConnectionCollisionResolution,
    OutOfResources,
}

/// An enumeration indicating the origin type of a path.
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
pub enum PathOrigin {
    /// Interior gateway protocol
    Igp = 0,
    /// Exterior gateway protocol
    Egp = 1,
    /// Incomplete path origin
    Incomplete = 2,
}

/// A BGP message header.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                                                               +
/// |                           Marker                              |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Length               |      Type     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// This object contains the length and type fields. The marker is automatically
/// generated when [`to_wire`] is called, and consumed when [`from_wire`] is
/// called.
///
/// Ref: RFC 4271 §4.1
#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    /// Total length of the message, including the header. May be no larger than
    /// 4096.
    pub length: u16,

    /// Indicates the type of message.
    pub typ: MessageType,
}

impl Header {
    pub const WIRE_SIZE: usize = 19;
}

/// A type-length-value object. The length is implicit in the length of the
/// value tracked by Vec.
pub struct Tlv {
    pub typ: u8,
    pub value: Vec<u8>,
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
#[serde(rename_all = "snake_case")]
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

/// The add path element comes as a BGP capability extension as described in
/// RFC 7911.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    JsonSchema,
    PartialOrd,
    Ord,
)]
pub struct AddPathElement {
    /// Address family identifier.
    /// <https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml>
    pub afi: u16,
    /// Subsequent address family identifier. There are a large pile of these
    /// <https://www.iana.org/assignments/safi-namespace/safi-namespace.xhtml>
    pub safi: u8,
    /// This field indicates whether the sender is (a) able to receive multiple
    /// paths from its peer (value 1), (b) able to send multiple paths to its
    /// peer (value 2), or (c) both (value 3) for the <AFI, SAFI>.
    pub send_receive: u8,
}

// ============================================================================
// v1 wire-shape Prefix and PathAttribute compatibility types.
//
// These match the initial API schema. They have the same source name as the
// MP-BGP-aware versions in [`crate::v4::messages`], disambiguated by the
// `v1::messages` module path. The schemars name matches the in-source name
// (`Prefix`, `PathAttribute`, `PathAttributeType`, `PathAttributeValue`),
// since the schema name is "PathAttribute" in v1 and "PathAttribute" in v4
// — but each version generates its own schema document.
// ============================================================================

/// V1 Prefix wire-shape (length + raw octets), used by the v1 admin API.
#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, JsonSchema,
)]
pub struct Prefix {
    pub length: u8,
    pub value: Vec<u8>,
}

/// The value encoding of a path attribute (v1, pre-MP-BGP).
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathAttributeValue {
    /// The type of origin associated with a path
    Origin(PathOrigin),
    /// The AS set associated with a path
    AsPath(Vec<crate::v4::messages::As4PathSegment>),
    /// The nexthop associated with a path
    NextHop(IpAddr),
    /// A metric used for external (inter-AS) links to discriminate among
    /// multiple entry or exit points.
    MultiExitDisc(u32),
    /// Local pref is included in update messages sent to internal peers and
    /// indicates a degree of preference.
    LocalPref(u32),
    /// This attribute is included in routes that are formed by aggregation.
    Aggregator([u8; 6]),
    /// Indicates communities associated with a path.
    Communities(Vec<Community>),
    /// The 4-byte encoded AS set associated with a path
    As4Path(Vec<crate::v4::messages::As4PathSegment>),
    /// This attribute is included in routes that are formed by aggregation.
    As4Aggregator([u8; 8]),
}

/// Type encoding for a path attribute (v1).
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema,
)]
pub struct PathAttributeType {
    /// Flags may include, Optional, Transitive, Partial and Extended Length.
    pub flags: u8,
    /// Type code for the path attribute.
    pub type_code: PathAttributeTypeCode,
}

/// A self-describing BGP path attribute (v1, pre-MP-BGP).
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PathAttribute {
    /// Type encoding for the attribute
    pub typ: PathAttributeType,
    /// Value of the attribute
    pub value: PathAttributeValue,
}

/// This enumeration contains possible notification error subcodes.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSubcode {
    Header(HeaderErrorSubcode),
    Open(OpenErrorSubcode),
    Update(UpdateErrorSubcode),
    HoldTime(u8),
    Fsm(u8),
    Cease(CeaseErrorSubcode),
}

/// The IANA/IETF currently defines the following optional parameter types.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum OptionalParameter {
    /// Code 0
    Reserved,

    /// Code 1: RFC 4217, RFC 5492 (deprecated)
    Authentication, //TODO

    /// Code 2: RFC 5492
    Capabilities(BTreeSet<Capability>),

    /// Unassigned
    Unassigned,

    /// Code 255: RFC 9072
    ExtendedLength, //TODO
}

// An issue tracking the TODOs below is here
// <https://github.com/oxidecomputer/maghemite/issues/80>

/// Optional capabilities supported by a BGP implementation.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    JsonSchema,
    PartialOrd,
    Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Multiprotocol extensions as defined in RFC 2858
    MultiprotocolExtensions {
        afi: u16,
        safi: u8,
    },

    /// Route refresh capability as defined in RFC 2918.
    RouteRefresh {},

    //TODO
    /// Outbound filtering capability as defined in RFC 5291. Note this
    /// capability is not yet implemented.
    OutboundRouteFiltering {},

    //TODO
    /// Multiple routes to destination capability as defined in RFC 8277
    /// (deprecated). Note this capability is not yet implemented.
    MultipleRoutesToDestination {},

    /// Multiple nexthop encoding capability as defined in RFC 8950.
    ExtendedNextHopEncoding {
        //XXX trying to avoid a version bump on 86 billion data structures
        // right now.
        #[schemars(skip)]
        elements: Vec<ExtendedNexthopElement>,
    },

    //TODO
    /// Extended message capability as defined in RFC 8654. Note this
    /// capability is not yet implemented.
    BGPExtendedMessage {},

    //TODO
    /// BGPSec as defined in RFC 8205. Note this capability is not yet
    /// implemented.
    BgpSec {},

    //TODO
    /// Multiple label support as defined in RFC 8277. Note this capability
    /// is not yet implemented.
    MultipleLabels {},

    //TODO
    /// BGP role capability as defined in RFC 9234. Note this capability is not
    /// yet implemented.
    BgpRole {},

    //TODO
    /// Graceful restart as defined in RFC 4724. Note this capability is not
    /// yet implemented.
    GracefulRestart {},

    /// Four octet AS numbers as defined in RFC 6793.
    FourOctetAs {
        asn: u32,
    },

    //TODO
    /// Dynamic capabilities as defined in draft-ietf-idr-dynamic-cap. Note
    /// this capability is not yet implemented.
    DynamicCapability {},

    //TODO
    /// Multi session support as defined in draft-ietf-idr-bgp-multisession.
    /// Note this capability is not yet supported.
    MultisessionBgp {},

    /// Add path capability as defined in RFC 7911.
    AddPath {
        elements: BTreeSet<AddPathElement>,
    },

    //TODO
    /// Enhanced route refresh as defined in RFC 7313. Note this capability is
    /// not yet supported.
    EnhancedRouteRefresh {},

    //TODO
    /// Long-lived graceful restart as defined in
    /// draft-uttaro-idr-bgp-persistence. Note this capability is not yet
    /// supported.
    LongLivedGracefulRestart {},

    //TODO
    /// Routing policy distribution as defined indraft-ietf-idr-rpd-04. Note
    /// this capability is not yet supported.
    RoutingPolicyDistribution {},

    //TODO
    /// Fully qualified domain names as defined
    /// intdraft-walton-bgp-hostname-capability. Note this capability is not
    /// yet supported.
    Fqdn {},

    //TODO
    /// Pre-standard route refresh as defined in RFC 8810 (deprecated). Note
    /// this capability is not yet supported.
    PrestandardRouteRefresh {},

    //TODO
    /// Pre-standard prefix-based outbound route filtering as defined in
    /// RFC 8810 (deprecated). Note this is not yet implemented.
    PrestandardOrfAndPd {},

    //TODO
    /// Pre-standard outbound route filtering as defined in RFC 8810
    /// (deprecated). Note this is not yet implemented.
    PrestandardOutboundRouteFiltering {},

    //TODO
    /// Pre-standard multisession as defined in RFC 8810 (deprecated). Note
    /// this is not yet implemented.
    PrestandardMultisession {},

    //TODO
    /// Pre-standard fully qualified domain names as defined in RFC 8810
    /// (deprecated). Note this is not yet implemented.
    PrestandardFqdn {},

    //TODO
    /// Pre-standard operational messages as defined in RFC 8810 (deprecated).
    /// Note this is not yet implemented.
    PrestandardOperationalMessage {},

    /// Experimental capability as defined in RFC 8810.
    Experimental {
        code: u8,
    },

    Unassigned {
        code: u8,
    },

    Reserved {
        code: u8,
    },
}

/// The autonomous system number used in OPEN messages when 4-byte ASNs are in
/// use.
///
/// Ref: RFC 4893 §7
pub const AS_TRANS: u16 = 23456;

/// The version number for BGP-4
pub const BGP4: u8 = 4;

/// The first message sent by each side once a TCP connection is established.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Version    |     My Autonomous System      |   Hold Time   :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :               |                BGP Identifier                 :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :               | Opt Parm Len  |     Optional Parameters       :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                                                               :
/// :             Optional Parameters (cont, variable)              :
/// :                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Ref: RFC 4271 §4.2
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OpenMessage {
    /// BGP protocol version.
    pub version: u8,

    /// Autonomous system number of the sender. When 4-byte ASNs are in use this
    /// value is set to AS_TRANS which has a value of 23456.
    ///
    /// Ref: RFC 4893 §7
    pub asn: u16,

    /// Number of seconds the sender proposes for the hold timer.
    pub hold_time: u16,

    /// BGP identifier of the sender
    pub id: u32,

    /// A list of optional parameters.
    pub parameters: Vec<OptionalParameter>,
}

/// Notification messages are exchanged between BGP peers when an exceptional
/// event has occurred.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NotificationMessage {
    /// Error code associated with the notification
    pub error_code: ErrorCode,

    /// Error subcode associated with the notification
    pub error_subcode: ErrorSubcode,

    /*
     * Implementation notes for later on the data field ...
     *
     * What follows is verbatim from RFC 4271
     * <https://datatracker.ietf.org/doc/html/rfc4271>
     *
     * §6.1 Message Header Error Handling
     * ==================================
     *
     *   If at least one of the following is true:
     *
     *    - if the Length field of the message header is less than 19 or
     *      greater than 4096, or
     *
     *    - if the Length field of an OPEN message is less than the minimum
     *      length of the OPEN message, or
     *
     *    - if the Length field of an UPDATE message is less than the
     *      minimum length of the UPDATE message, or
     *
     *    - if the Length field of a KEEPALIVE message is not equal to 19,
     *      or
     *
     *    - if the Length field of a NOTIFICATION message is less than the
     *      minimum length of the NOTIFICATION message,
     *
     *     then the Error Subcode MUST be set to Bad Message Length.  The Data
     *     field MUST contain the erroneous Length field.
     *
     *     If the Type field of the message header is not recognized, then the
     *     Error Subcode MUST be set to Bad Message Type.  The Data field MUST
     *     contain the erroneous Type field.
     *
     * §6.2 Open Message Error Handling
     * ================================
     *
     *     If the version number in the Version field of the received OPEN
     *     message is not supported, then the Error Subcode MUST be set to
     *     Unsupported Version Number.  The Data field is a 2-octet unsigned
     *     integer, which indicates the largest, locally-supported version
     *     number less than the version the remote BGP peer bid
     *
     * §6.3 Update Message Error Handling
     * ==================================
     *
     *     If any recognized attribute has Attribute Flags that conflict with
     *     the Attribute Type Code, then the Error Subcode MUST be set to
     *     Attribute Flags Error.  The Data field MUST contain the erroneous
     *     attribute (type, length, and value).
     *
     *     If any recognized attribute has an Attribute Length that conflicts
     *     with the expected length (based on the attribute type code), then the
     *     Error Subcode MUST be set to Attribute Length Error.  The Data field
     *     MUST contain the erroneous attribute (type, length, and value).
     *
     *     If any of the well-known mandatory attributes are not present, then
     *     the Error Subcode MUST be set to Missing Well-known Attribute.  The
     *     Data field MUST contain the Attribute Type Code of the missing,
     *     well-known attribute.
     *
     *     If any of the well-known mandatory attributes are not recognized,
     *     then the Error Subcode MUST be set to Unrecognized Well-known
     *     Attribute.  The Data field MUST contain the unrecognized attribute
     *     (type, length, and value).
     *
     *     If the ORIGIN attribute has an undefined value, then the Error Sub-
     *     code MUST be set to Invalid Origin Attribute.  The Data field MUST
     *     contain the unrecognized attribute (type, length, and value).
     *
     *     If the NEXT_HOP attribute field is syntactically incorrect, then the
     *     Error Subcode MUST be set to Invalid NEXT_HOP Attribute.  The Data
     *     field MUST contain the incorrect attribute (type, length, and value).
     *     Syntactic correctness means that the NEXT_HOP attribute represents a
     *     valid IP host address.
     *
     *     If an optional attribute is recognized, then the value of this
     *     attribute MUST be checked.  If an error is detected, the attribute
     *     MUST be discarded, and the Error Subcode MUST be set to Optional
     *     Attribute Error.  The Data field MUST contain the attribute (type,
     *     length, and value).
     *
     */
    pub data: Vec<u8>,
}

// A message sent between peers to ask for re-advertisement of all outbound
// routes. Defined in RFC 2918.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RouteRefreshMessage {
    /// Address family identifier.
    pub afi: u16,
    /// Subsequent address family identifier.
    pub safi: u8,
}
