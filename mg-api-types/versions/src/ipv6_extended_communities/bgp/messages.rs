// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv4Addr;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use oxnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{v1, v4, v11};

/// Custom BGP Path Attribute containing information about an Oxide VTEP.
/// This attr is added exclusively to host routes (IPv4 /32 or IPv6 /128) which
/// correspond to VTEP IPs participating in multi-rack tunneling for DDM.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct OxideVtep {
    /// Router ID of the VTEP originating this attribute (and its route)
    #[serde(deserialize_with = "OxideVtep::deserialize_router_id")]
    router_id: String,
}

impl OxideVtep {
    /// Construct an attribute with a router ID of 1..=1023 UTF-8 bytes.
    pub fn new(router_id: String) -> Result<Self, OxideVtepParseError> {
        if !(1..=1023).contains(&router_id.len()) {
            return Err(OxideVtepParseError::BadLength(router_id.len() + 1));
        }
        Ok(Self { router_id })
    }

    pub fn router_id(&self) -> &str {
        &self.router_id
    }

    fn deserialize_router_id<'de, D>(
        deserializer: D,
    ) -> Result<String, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?)
            .map(|vtep| vtep.router_id)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OxideVtepParseError {
    #[error(
        "Oxide VTEP length must be between 2 and 1024 bytes (including the version byte), got {0}"
    )]
    BadLength(usize),
    #[error("unsupported Oxide VTEP version: {0}")]
    UnsupportedVersion(u8),
    #[error("Oxide VTEP payload is not valid UTF-8: {0}")]
    InvalidPayload(#[from] std::string::FromUtf8Error),
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

    /// Oxide Multi-rack VTEP discovery
    OxideVtep = 254,
}

/// Type encoding for a path attribute.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PathAttributeType {
    /// Flags may include, Optional, Transitive, Partial and Extended Length.
    pub flags: u8,
    /// Type code for the path attribute.
    pub type_code: PathAttributeTypeCode,
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
    MpReachNlri(v11::bgp::messages::MpReachNlri),
    /// Carries unreachable MP-BGP NLRI (withdrawal).
    MpUnreachNlri(v11::bgp::messages::MpUnreachNlri),
    /// Carries an Oxide VTEP attribute
    OxideVtep(OxideVtep),
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
    pub withdrawn: Vec<Ipv4Net>,
    pub path_attributes: Vec<PathAttribute>,
    pub nlri: Vec<Ipv4Net>,

    /// All attribute parse errors encountered during from_wire().
    /// Includes both TreatAsWithdraw and Discard errors.
    /// SessionReset errors cause early return and are not collected here.
    /// Not serialized - only used for internal signaling.
    /// Use the treat_as_withdraw() method to check if any TreatAsWithdraw errors occurred.
    // Internal parse signaling is shared across versions, not an API shape.
    // See `impls/bgp/parse.rs` for the exception to version-only references.
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

// Downgrade to the most recent historical shape of each type.
/// A path attribute that cannot be represented by the pre-v13 admin API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "BGP path attribute {type_code:?} cannot be represented in mg-admin API versions before 13"
)]
pub struct PathAttributeDowngradeError {
    pub type_code: PathAttributeTypeCode,
}

impl TryFrom<PathAttributeTypeCode>
    for v4::bgp::messages::PathAttributeTypeCode
{
    type Error = PathAttributeDowngradeError;

    fn try_from(v: PathAttributeTypeCode) -> Result<Self, Self::Error> {
        Ok(match v {
            PathAttributeTypeCode::Origin => Self::Origin,
            PathAttributeTypeCode::AsPath => Self::AsPath,
            PathAttributeTypeCode::NextHop => Self::NextHop,
            PathAttributeTypeCode::MultiExitDisc => Self::MultiExitDisc,
            PathAttributeTypeCode::LocalPref => Self::LocalPref,
            PathAttributeTypeCode::AtomicAggregate => Self::AtomicAggregate,
            PathAttributeTypeCode::Aggregator => Self::Aggregator,
            PathAttributeTypeCode::Communities => Self::Communities,
            PathAttributeTypeCode::MpReachNlri => Self::MpReachNlri,
            PathAttributeTypeCode::MpUnreachNlri => Self::MpUnreachNlri,
            PathAttributeTypeCode::As4Path => Self::As4Path,
            PathAttributeTypeCode::As4Aggregator => Self::As4Aggregator,
            PathAttributeTypeCode::OxideVtep => {
                return Err(PathAttributeDowngradeError { type_code: v });
            }
        })
    }
}

impl TryFrom<PathAttributeType> for v4::bgp::messages::PathAttributeType {
    type Error = PathAttributeDowngradeError;

    fn try_from(v: PathAttributeType) -> Result<Self, Self::Error> {
        Ok(Self {
            flags: v.flags,
            type_code: v.type_code.try_into()?,
        })
    }
}

impl TryFrom<PathAttributeValue> for v11::bgp::messages::PathAttributeValue {
    type Error = PathAttributeDowngradeError;

    fn try_from(v: PathAttributeValue) -> Result<Self, Self::Error> {
        Ok(match v {
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
            PathAttributeValue::MpReachNlri(x) => Self::MpReachNlri(x),
            PathAttributeValue::MpUnreachNlri(x) => Self::MpUnreachNlri(x),
            PathAttributeValue::OxideVtep(_) => {
                return Err(PathAttributeDowngradeError {
                    type_code: PathAttributeTypeCode::OxideVtep,
                });
            }
        })
    }
}

impl TryFrom<PathAttribute> for v11::bgp::messages::PathAttribute {
    type Error = PathAttributeDowngradeError;

    fn try_from(v: PathAttribute) -> Result<Self, Self::Error> {
        Ok(Self {
            typ: v.typ.try_into()?,
            value: v.value.try_into()?,
        })
    }
}

impl TryFrom<UpdateMessage> for v11::bgp::messages::UpdateMessage {
    type Error = PathAttributeDowngradeError;

    fn try_from(v: UpdateMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            withdrawn: v.withdrawn,
            path_attributes: v
                .path_attributes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            nlri: v.nlri,
            errors: v.errors,
        })
    }
}

impl TryFrom<Message> for v11::bgp::messages::Message {
    type Error = PathAttributeDowngradeError;

    fn try_from(v: Message) -> Result<Self, Self::Error> {
        Ok(match v {
            Message::Open(x) => Self::Open(x),
            Message::Update(x) => Self::Update(x.try_into()?),
            Message::Notification(x) => Self::Notification(x),
            Message::KeepAlive => Self::KeepAlive,
            Message::RouteRefresh(x) => Self::RouteRefresh(x),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oxide_vtep_construction_validates_router_id_length() {
        for router_id in [String::new(), "α".repeat(512)] {
            assert!(matches!(
                OxideVtep::new(router_id.clone()),
                Err(OxideVtepParseError::BadLength(len))
                    if len == router_id.len() + 1
            ));
            let json = serde_json::json!({ "router_id": router_id });
            assert!(serde_json::from_value::<OxideVtep>(json).is_err());
        }
        for router_id in ["a".into(), format!("{}a", "α".repeat(511))] {
            let expected = OxideVtep::new(router_id.clone()).unwrap();
            let json = serde_json::json!({ "router_id": router_id });
            let vtep: OxideVtep = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(vtep, expected);
            assert_eq!(serde_json::to_value(&vtep).unwrap(), json);
            assert_eq!(OxideVtep::from_wire(&vtep.to_wire()).unwrap(), vtep);
        }
    }
}
