// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! BGP wire-message enumerations published since the initial admin API
//! version. These types encode IANA-assigned numeric codes used in BGP
//! protocol messages.

use num_enum::{IntoPrimitive, TryFromPrimitive};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

/// An enumeration describing available path attribute type codes.
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
