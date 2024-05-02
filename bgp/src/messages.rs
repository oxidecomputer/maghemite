// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::error::Error;
use nom::{
    bytes::complete::{tag, take},
    number::complete::{be_u16, be_u32, be_u8, u8 as parse_u8},
};
use num_enum::FromPrimitive;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const MAX_MESSAGE_SIZE: usize = 4096;

/// BGP Message types.
///
/// Ref: RFC 4271 §4.1
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Copy, Clone)]
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

impl From<&Message> for MessageType {
    fn from(m: &Message) -> Self {
        match m {
            Message::Open(_) => Self::Open,
            Message::Update(_) => Self::Update,
            Message::Notification(_) => Self::Notification,
            Message::KeepAlive => Self::KeepAlive,
            Message::RouteRefresh(_) => Self::RouteRefresh,
        }
    }
}

/// Holds a BGP message. May be an Open, Update, Notification or Keep Alive
/// message.
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Message {
    Open(OpenMessage),
    Update(UpdateMessage),
    Notification(NotificationMessage),
    KeepAlive,
    RouteRefresh(RouteRefreshMessage),
}

impl Message {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Open(m) => m.to_wire(),
            Self::Update(m) => m.to_wire(),
            Self::Notification(m) => m.to_wire(),
            Self::KeepAlive => Ok(Vec::new()),
            Self::RouteRefresh(m) => m.to_wire(),
        }
    }
}

impl From<OpenMessage> for Message {
    fn from(m: OpenMessage) -> Message {
        Message::Open(m)
    }
}

impl From<UpdateMessage> for Message {
    fn from(m: UpdateMessage) -> Message {
        Message::Update(m)
    }
}

impl From<NotificationMessage> for Message {
    fn from(m: NotificationMessage) -> Message {
        Message::Notification(m)
    }
}

impl From<RouteRefreshMessage> for Message {
    fn from(m: RouteRefreshMessage) -> Message {
        Message::RouteRefresh(m)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MessageConvertError {
    #[error("not an update")]
    NotAnUpdate,

    #[error("not a notification")]
    NotANotification,

    #[error("not an open")]
    NotAnOpen,

    #[error("not a keepalive")]
    NotAKeepalive,

    #[error("not a route refresh")]
    NotARouteRefresh,
}

impl TryFrom<Message> for OpenMessage {
    type Error = MessageConvertError;
    fn try_from(value: Message) -> Result<Self, Self::Error> {
        if let Message::Open(msg) = value {
            Ok(msg)
        } else {
            Err(MessageConvertError::NotAnOpen)
        }
    }
}

impl TryFrom<Message> for UpdateMessage {
    type Error = MessageConvertError;
    fn try_from(value: Message) -> Result<Self, Self::Error> {
        if let Message::Update(msg) = value {
            Ok(msg)
        } else {
            Err(MessageConvertError::NotAnUpdate)
        }
    }
}

impl TryFrom<Message> for NotificationMessage {
    type Error = MessageConvertError;
    fn try_from(value: Message) -> Result<Self, Self::Error> {
        if let Message::Notification(msg) = value {
            Ok(msg)
        } else {
            Err(MessageConvertError::NotANotification)
        }
    }
}

impl TryFrom<Message> for RouteRefreshMessage {
    type Error = MessageConvertError;
    fn try_from(value: Message) -> Result<Self, Self::Error> {
        if let Message::RouteRefresh(msg) = value {
            Ok(msg)
        } else {
            Err(MessageConvertError::NotARouteRefresh)
        }
    }
}

/// Each BGP message has a fixed sized header.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   +                                                               +
///   |                                                               |
///   +                                                               +
///   |                           Marker                              |
///   +                                                               +
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |          Length               |      Type     |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// This object contains the length and type fields. The marker is automatically
/// generated when [`to_wire`] is called, and consumed with [`from_wire`] is
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

/// According to RFC 4271 §4.1 the header marker is all ones.
const MARKER: [u8; 16] = [0xFFu8; 16];

impl Header {
    pub const WIRE_SIZE: usize = 19;

    /// Create a new BGP message header. Length must be between 19 and 4096 per
    /// RFC 4271 §4.1.
    pub fn new(length: u16, typ: MessageType) -> Result<Header, Error> {
        if usize::from(length) < Header::WIRE_SIZE {
            return Err(Error::TooSmall("message header length".into()));
        }
        if usize::from(length) > MAX_MESSAGE_SIZE {
            return Err(Error::TooLarge("message header length".into()));
        }
        Ok(Header { length, typ })
    }

    /// Serialize the header to wire format.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = MARKER.to_vec();
        buf.extend_from_slice(&self.length.to_be_bytes());
        buf.push(self.typ as u8);
        buf
    }

    /// Deserialize a header from wire format.
    pub fn from_wire(input: &[u8]) -> Result<Header, Error> {
        let (input, _) = tag(MARKER)(input)?;
        let (input, length) = be_u16(input)?;
        let (_, typ) = parse_u8(input)?;
        let typ = MessageType::try_from(typ)?;
        Ok(Header { length, typ })
    }
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

impl OpenMessage {
    /// Create a new open message for a sender with a 2-byte ASN
    pub fn new2(asn: u16, hold_time: u16, id: u32) -> OpenMessage {
        OpenMessage {
            version: BGP4,
            asn,
            hold_time,
            id,
            parameters: Vec::new(),
        }
    }

    /// Create a new open message for a sender with a 4-byte ASN
    pub fn new4(asn: u32, hold_time: u16, id: u32) -> OpenMessage {
        OpenMessage {
            version: BGP4,
            asn: AS_TRANS,
            hold_time,
            id,
            parameters: vec![OptionalParameter::Capabilities(BTreeSet::from(
                [Capability::FourOctetAs { asn }],
            ))],
        }
    }

    pub fn add_capabilities(&mut self, capabilities: &BTreeSet<Capability>) {
        if capabilities.is_empty() {
            return;
        }
        for p in &mut self.parameters {
            if let OptionalParameter::Capabilities(cs) = p {
                cs.extend(capabilities.iter().cloned());
                return;
            }
        }
        self.parameters
            .push(OptionalParameter::Capabilities(capabilities.clone()));
    }

    pub fn get_capabilities(&self) -> BTreeSet<Capability> {
        for p in self.parameters.iter() {
            if let OptionalParameter::Capabilities(caps) = p {
                return caps.clone();
            }
        }
        BTreeSet::new()
    }

    pub fn has_capability(&self, code: CapabilityCode) -> bool {
        self.get_capabilities()
            .into_iter()
            .any(|x| CapabilityCode::from(x) == code)
    }

    /// Serialize an open message to wire format.
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();

        // version
        buf.push(self.version);

        // as
        buf.extend_from_slice(&self.asn.to_be_bytes());

        // hold time
        buf.extend_from_slice(&self.hold_time.to_be_bytes());

        // id
        buf.extend_from_slice(&self.id.to_be_bytes());

        // opt param len
        let opt_buf = self.parameters_to_wire()?;
        if opt_buf.len() > u8::MAX as usize {
            return Err(Error::TooLarge(
                "open message optional parameters".into(),
            ));
        }
        buf.push(opt_buf.len() as u8);
        buf.extend_from_slice(&opt_buf);

        Ok(buf)
    }

    fn parameters_to_wire(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        for p in &self.parameters {
            buf.extend_from_slice(&p.to_wire()?);
        }
        Ok(buf)
    }

    /// Deserialize an open message from wire format.
    pub fn from_wire(input: &[u8]) -> Result<OpenMessage, Error> {
        let (input, version) = parse_u8(input)?;
        let (input, asn) = be_u16(input)?;
        let (input, hold_time) = be_u16(input)?;
        let (input, id) = be_u32(input)?;
        let (input, param_len) = parse_u8(input)?;
        let param_len = param_len as usize;

        if input.len() < param_len {
            return Err(Error::TooSmall(
                "open message optional parameters".into(),
            ));
        }

        let parameters = Self::parameters_from_wire(&input[..param_len])?;

        Ok(OpenMessage {
            version,
            asn,
            hold_time,
            id,
            parameters,
        })
    }

    pub fn parameters_from_wire(
        mut buf: &[u8],
    ) -> Result<Vec<OptionalParameter>, Error> {
        let mut result = Vec::new();

        while !buf.is_empty() {
            let (out, param) = OptionalParameter::from_wire(buf)?;
            result.push(param);
            buf = out;
        }

        Ok(result)
    }
}

/// A type-length-value object. The length is implicit in the length of the
/// value tracked by Vec.
pub struct Tlv {
    pub typ: u8,
    pub value: Vec<u8>,
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
    pub withdrawn: Vec<Prefix>,
    pub path_attributes: Vec<PathAttribute>,
    pub nlri: Vec<Prefix>,
}

impl UpdateMessage {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();

        // withdrawn
        let withdrawn = self.withdrawn_to_wire()?;
        if withdrawn.len() > u16::MAX as usize {
            return Err(Error::TooLarge(
                "update: too many withdrawn prefixes".into(),
            ));
        }
        let len = withdrawn.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&withdrawn);

        // path attributes
        let attrs = self.path_attrs_to_wire()?;
        if attrs.len() > u16::MAX as usize {
            return Err(Error::TooLarge(
                "update: too many path attributes".into(),
            ));
        }
        let len = attrs.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&attrs);

        // nlri
        buf.extend_from_slice(&self.nlri_to_wire()?);

        if buf.len() > MAX_MESSAGE_SIZE {
            return Err(Error::TooLarge(
                "update exceeds max message size".into(),
            ));
        }

        Ok(buf)
    }

    fn withdrawn_to_wire(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        for w in &self.withdrawn {
            buf.extend_from_slice(&w.to_wire()?);
        }
        Ok(buf)
    }

    fn path_attrs_to_wire(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        for p in &self.path_attributes {
            buf.extend_from_slice(&p.to_wire(
                p.typ.flags & path_attribute_flags::EXTENDED_LENGTH != 0,
            )?);
        }
        Ok(buf)
    }

    fn nlri_to_wire(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        for n in &self.nlri {
            // TODO hacked in ADD_PATH
            //buf.extend_from_slice(&0u32.to_be_bytes());
            buf.extend_from_slice(&n.to_wire()?);
        }
        Ok(buf)
    }

    pub fn from_wire(input: &[u8]) -> Result<UpdateMessage, Error> {
        let (input, len) = be_u16(input)?;
        let (input, withdrawn_input) = take(len)(input)?;
        let withdrawn = Self::prefixes_from_wire(withdrawn_input)?;

        let (input, len) = be_u16(input)?;
        let (input, attrs_input) = take(len)(input)?;
        let path_attributes = Self::path_attrs_from_wire(attrs_input)?;

        let nlri = Self::prefixes_from_wire(input)?;

        Ok(UpdateMessage {
            withdrawn,
            path_attributes,
            nlri,
        })
    }

    fn prefixes_from_wire(mut buf: &[u8]) -> Result<Vec<Prefix>, Error> {
        let mut result = Vec::new();
        while !buf.is_empty() {
            let (out, pfx) = Prefix::from_wire(buf)?;
            result.push(pfx);
            buf = out;
        }
        Ok(result)
    }

    fn path_attrs_from_wire(
        mut buf: &[u8],
    ) -> Result<Vec<PathAttribute>, Error> {
        let mut result = Vec::new();
        loop {
            if buf.is_empty() {
                break;
            }
            let (out, pa) = PathAttribute::from_wire(buf)?;
            result.push(pa);
            buf = out;
        }
        Ok(result)
    }

    pub fn nexthop4(&self) -> Option<Ipv4Addr> {
        for a in &self.path_attributes {
            if let PathAttributeValue::NextHop(IpAddr::V4(addr)) = a.value {
                return Some(addr);
            }
        }
        None
    }

    pub fn graceful_shutdown(&self) -> bool {
        self.has_community(Community::GracefulShutdown)
    }

    pub fn multi_exit_discriminator(&self) -> Option<u32> {
        for a in &self.path_attributes {
            if let PathAttributeValue::MultiExitDisc(med) = &a.value {
                return Some(*med);
            }
        }
        None
    }

    pub fn local_pref(&self) -> Option<u32> {
        for a in &self.path_attributes {
            if let PathAttributeValue::LocalPref(value) = &a.value {
                return Some(*value);
            }
        }
        None
    }

    pub fn set_local_pref(&mut self, value: u32) {
        for a in &mut self.path_attributes {
            if let PathAttributeValue::LocalPref(current) = &mut a.value {
                *current = value;
                return;
            }
        }
        self.path_attributes
            .push(PathAttributeValue::LocalPref(value).into());
    }

    pub fn clear_local_pref(&mut self) {
        self.path_attributes
            .retain(|a| a.typ.type_code != PathAttributeTypeCode::LocalPref);
    }

    pub fn as_path(&self) -> Option<Vec<As4PathSegment>> {
        for a in &self.path_attributes {
            if let PathAttributeValue::AsPath(path) = &a.value {
                return Some(path.clone());
            }
            if let PathAttributeValue::As4Path(path) = &a.value {
                return Some(path.clone());
            }
        }
        None
    }

    pub fn path_len(&self) -> Option<usize> {
        self.as_path()
            .map(|p| p.iter().fold(0, |a, b| a + b.value.len()))
    }

    pub fn has_community(&self, community: Community) -> bool {
        for a in &self.path_attributes {
            if let PathAttributeValue::Communities(communities) = &a.value {
                for c in communities {
                    if *c == community {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn add_community(&mut self, community: Community) {
        for a in &mut self.path_attributes {
            if let PathAttributeValue::Communities(ref mut communities) =
                &mut a.value
            {
                communities.push(community);
                return;
            }
        }
        self.path_attributes
            .push(PathAttributeValue::Communities(vec![community]).into());
    }
}

/// This data structure captures a network prefix as it's laid out in a BGP
/// message. There is a prefix length followed by a variable number of bytes.
/// Just enough bytes to express the prefix.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    JsonSchema,
    Ord,
    PartialOrd,
)]
pub struct Prefix {
    pub length: u8,
    pub value: Vec<u8>,
}

impl Prefix {
    fn to_wire(&self) -> Result<Vec<u8>, Error> {
        if self.value.len() > u8::MAX as usize {
            return Err(Error::TooLarge("prefix too long".into()));
        }
        let mut buf = vec![self.length];
        let n = (self.length as usize).div_ceil(8);
        buf.extend_from_slice(&self.value[..n]);
        Ok(buf)
    }

    fn from_wire(input: &[u8]) -> Result<(&[u8], Prefix), Error> {
        let (input, len) = parse_u8(input)?;
        let (input, value) = take(len.div_ceil(8))(input)?;
        Ok((
            input,
            Prefix {
                value: value.to_owned(),
                length: len,
            },
        ))
    }

    pub fn as_prefix4(&self) -> rdb::Prefix4 {
        let v = &self.value;
        match self.length {
            0 => rdb::Prefix4 {
                value: Ipv4Addr::UNSPECIFIED,
                length: 0,
            },
            x if x <= 8 => rdb::Prefix4 {
                value: Ipv4Addr::from([v[0], 0, 0, 0]),
                length: x,
            },
            x if x <= 16 => rdb::Prefix4 {
                value: Ipv4Addr::from([v[0], v[1], 0, 0]),
                length: x,
            },
            x if x <= 24 => rdb::Prefix4 {
                value: Ipv4Addr::from([v[0], v[1], v[2], 0]),
                length: x,
            },
            x => rdb::Prefix4 {
                value: Ipv4Addr::from([v[0], v[1], v[2], v[3]]),
                length: x,
            },
        }
    }

    pub fn as_prefix6(&self) -> rdb::Prefix6 {
        let v = &self.value;
        match self.length {
            0 => rdb::Prefix6 {
                value: Ipv6Addr::UNSPECIFIED,
                length: 0,
            },
            x if x <= 8 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
                length: x,
            },
            x if x <= 16 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
                length: x,
            },
            x if x <= 24 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
                length: x,
            },
            x if x <= 32 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
                length: x,
            },
            x if x <= 40 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], v[4], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0,
                ]),
                length: x,
            },
            x if x <= 48 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], v[4], v[5], 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0,
                ]),
                length: x,
            },
            x if x <= 56 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], 0, 0, 0, 0, 0, 0,
                    0, 0, 0,
                ]),
                length: x,
            },
            x if x <= 64 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], 0, 0, 0, 0,
                    0, 0, 0, 0,
                ]),
                length: x,
            },
            x if x <= 72 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], 0, 0,
                    0, 0, 0, 0, 0,
                ]),
                length: x,
            },
            x if x <= 80 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9],
                    0, 0, 0, 0, 0, 0,
                ]),
                length: x,
            },
            x if x <= 88 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9],
                    v[10], 0, 0, 0, 0, 0,
                ]),
                length: x,
            },
            x if x <= 96 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9],
                    v[10], v[11], 0, 0, 0, 0,
                ]),
                length: x,
            },
            x if x <= 104 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9],
                    v[10], v[11], v[12], 0, 0, 0,
                ]),
                length: x,
            },
            x if x <= 112 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9],
                    v[10], v[11], v[12], v[13], 0, 0,
                ]),
                length: x,
            },
            x if x <= 120 => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9],
                    v[10], v[11], v[12], v[13], v[14], 0,
                ]),
                length: x,
            },
            x => rdb::Prefix6 {
                value: Ipv6Addr::from([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9],
                    v[10], v[11], v[12], v[13], v[14], v[15],
                ]),
                length: x,
            },
        }
    }

    pub fn within(&self, x: &Prefix) -> bool {
        if self.length > 128 || x.length > 128 {
            return false;
        }
        if self.length < x.length {
            return false;
        }
        if self.value.len() > 16 || x.value.len() > 16 {
            return false;
        }

        let mut a = self.value.clone();
        a.resize(16, 0);
        let mut a = u128::from_le_bytes(a.try_into().unwrap());

        let mut b = x.value.clone();
        b.resize(16, 0);
        let mut b = u128::from_le_bytes(b.try_into().unwrap());

        let mask = (1u128 << x.length) - 1;
        a &= mask;
        b &= mask;

        a == b
    }
}

impl std::str::FromStr for Prefix {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = match s.split_once('/') {
            Some(split) => split,
            None => return Err("invalid prefix".to_owned()),
        };
        let addr: IpAddr = match addr.parse() {
            Ok(addr) => addr,
            Err(_) => return Err("invalid addr".to_owned()),
        };
        let length: u8 = match len.parse() {
            Ok(len) => len,
            Err(_) => return Err("invalid length".to_owned()),
        };
        let value = match addr {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        Ok(Self { value, length })
    }
}

impl From<rdb::Prefix4> for Prefix {
    fn from(p: rdb::Prefix4) -> Self {
        Self {
            value: p.value.octets().into(),
            length: p.length,
        }
    }
}

/// A self-describing BGP path attribute
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PathAttribute {
    /// Type encoding for the attribute
    pub typ: PathAttributeType,

    /// Value of the attribute
    pub value: PathAttributeValue,
}

impl From<PathAttributeValue> for PathAttribute {
    fn from(v: PathAttributeValue) -> Self {
        let flags = match v {
            PathAttributeValue::Origin(_) => path_attribute_flags::TRANSITIVE,
            PathAttributeValue::AsPath(_) => path_attribute_flags::TRANSITIVE,
            PathAttributeValue::As4Path(_) => path_attribute_flags::TRANSITIVE,
            PathAttributeValue::NextHop(_) => path_attribute_flags::TRANSITIVE,
            PathAttributeValue::LocalPref(_) => {
                path_attribute_flags::TRANSITIVE
            }
            PathAttributeValue::Communities(_) => {
                path_attribute_flags::OPTIONAL
                    | path_attribute_flags::TRANSITIVE
            }
            _ => path_attribute_flags::OPTIONAL,
        };
        Self {
            typ: PathAttributeType {
                flags,
                type_code: v.clone().into(),
            },
            value: v,
        }
    }
}

impl PathAttribute {
    pub fn to_wire(&self, extended_length: bool) -> Result<Vec<u8>, Error> {
        let mut buf = self.typ.to_wire();
        let val = &self.value.to_wire()?;
        if extended_length {
            if val.len() > u16::MAX as usize {
                return Err(Error::TooLarge("extended path attribute".into()));
            }
            let len = val.len() as u16;
            buf.extend_from_slice(&len.to_be_bytes())
        } else {
            if val.len() > u8::MAX as usize {
                return Err(Error::TooLarge("pathattribute".into()));
            }
            buf.push(val.len() as u8);
        }
        buf.extend_from_slice(val);
        Ok(buf)
    }

    fn from_wire(input: &[u8]) -> Result<(&[u8], PathAttribute), Error> {
        let (input, type_input) = take(2usize)(input)?;
        let typ = PathAttributeType::from_wire(type_input)?;

        let (input, len) =
            if typ.flags & path_attribute_flags::EXTENDED_LENGTH != 0 {
                let (input, len) = be_u16(input)?;
                (input, len as usize)
            } else {
                let (input, len) = parse_u8(input)?;
                (input, len as usize)
            };
        let (input, pa_input) = take(len)(input)?;
        let value = PathAttributeValue::from_wire(pa_input, typ.type_code)?;
        Ok((input, PathAttribute { typ, value }))
    }
}

/// Type encoding for a path attribute.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PathAttributeType {
    /// Flags may include, Optional, Transitive, Partial and Extended Length.
    pub flags: u8,

    /// Type code for the path attribute.
    pub type_code: PathAttributeTypeCode,
}

impl PathAttributeType {
    pub fn to_wire(&self) -> Vec<u8> {
        vec![self.flags, self.type_code as u8]
    }

    pub fn from_wire(input: &[u8]) -> Result<PathAttributeType, Error> {
        let (input, flags) = parse_u8(input)?;
        let (_, type_code) = parse_u8(input)?;
        let type_code = PathAttributeTypeCode::try_from(type_code)?;
        Ok(PathAttributeType { flags, type_code })
    }
}

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
#[derive(
    Debug,
    PartialEq,
    Eq,
    Copy,
    Clone,
    TryFromPrimitive,
    Serialize,
    Deserialize,
    JsonSchema,
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

    /// RFC 6793
    As4Path = 17,
    As4Aggregator = 18,
}

impl From<PathAttributeValue> for PathAttributeTypeCode {
    fn from(v: PathAttributeValue) -> Self {
        match v {
            PathAttributeValue::Origin(_) => PathAttributeTypeCode::Origin,
            PathAttributeValue::AsPath(_) => PathAttributeTypeCode::AsPath,
            PathAttributeValue::NextHop(_) => PathAttributeTypeCode::NextHop,
            PathAttributeValue::MultiExitDisc(_) => {
                PathAttributeTypeCode::MultiExitDisc
            }
            PathAttributeValue::LocalPref(_) => {
                PathAttributeTypeCode::LocalPref
            }
            PathAttributeValue::Aggregator(_) => {
                PathAttributeTypeCode::Aggregator
            }
            PathAttributeValue::Communities(_) => {
                PathAttributeTypeCode::Communities
            }
            /* TODO according to RFC 4893 we do not have this as an explicit
             * attribute type when 4-byte ASNs have been negotiated - but are
             * there some circumstances when we'll need transitional mode?
             */
            //PathAttributeValue::As4Path(_) => PathAttributeTypeCode::As4Path,
            PathAttributeValue::As4Path(_) => PathAttributeTypeCode::AsPath,
            PathAttributeValue::As4Aggregator(_) => {
                PathAttributeTypeCode::As4Aggregator
            }
        }
    }
}

/// The value encoding of a path attribute.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathAttributeValue {
    /// The type of origin associated with a path
    Origin(PathOrigin),
    /* TODO according to RFC 4893 we do not have this as an explicit attribute
     * type when 4-byte ASNs have been negotiated - but are there some
     * circumstances when we'll need transitional mode?
     */
    /// The AS set associated with a path
    AsPath(Vec<As4PathSegment>),
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
    As4Path(Vec<As4PathSegment>),
    /// This attribute is included in routes that are formed by aggregation.
    As4Aggregator([u8; 8]),
    //MpReachNlri(MpReachNlri), //TODO for IPv6
}

impl PathAttributeValue {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Origin(x) => Ok(vec![*x as u8]),
            Self::AsPath(segments) => {
                let mut buf = Vec::new();
                for s in segments {
                    buf.push(s.typ as u8);
                    buf.push(s.value.len() as u8);
                    for v in &s.value {
                        buf.extend_from_slice(&v.to_be_bytes());
                    }
                }
                Ok(buf)
            }
            Self::NextHop(addr) => match addr {
                IpAddr::V4(a) => Ok(a.octets().into()),
                IpAddr::V6(a) => Ok(a.octets().into()),
            },
            Self::As4Path(segments) => {
                let mut buf = Vec::new();
                for s in segments {
                    buf.extend_from_slice(&s.to_wire()?);
                }
                Ok(buf)
            }
            Self::Communities(communities) => {
                let mut buf = Vec::new();
                for community in communities {
                    buf.extend_from_slice(&u32::from(*community).to_be_bytes());
                }
                Ok(buf)
            }
            Self::LocalPref(value) => Ok(value.to_be_bytes().into()),
            Self::MultiExitDisc(value) => Ok(value.to_be_bytes().into()),
            x => Err(Error::UnsupportedPathAttributeValue(x.clone())),
        }
    }

    pub fn from_wire(
        mut input: &[u8],
        type_code: PathAttributeTypeCode,
    ) -> Result<PathAttributeValue, Error> {
        match type_code {
            PathAttributeTypeCode::Origin => {
                let (_input, origin) = be_u8(input)?;
                Ok(PathAttributeValue::Origin(PathOrigin::try_from(origin)?))
            }
            PathAttributeTypeCode::AsPath => {
                let mut segments = Vec::new();
                loop {
                    if input.is_empty() {
                        break;
                    }
                    let (out, seg) = As4PathSegment::from_wire(input)?;
                    segments.push(seg);
                    input = out;
                }
                Ok(PathAttributeValue::As4Path(segments))
            }
            PathAttributeTypeCode::NextHop => {
                let (_input, b) = take(4usize)(input)?;
                Ok(PathAttributeValue::NextHop(
                    Ipv4Addr::new(b[0], b[1], b[2], b[3]).into(),
                ))
            }
            PathAttributeTypeCode::MultiExitDisc => {
                let (_input, v) = be_u32(input)?;
                Ok(PathAttributeValue::MultiExitDisc(v))
            }
            PathAttributeTypeCode::As4Path => {
                let mut segments = Vec::new();
                loop {
                    if input.is_empty() {
                        break;
                    }
                    let (out, seg) = As4PathSegment::from_wire(input)?;
                    segments.push(seg);
                    input = out;
                }
                Ok(PathAttributeValue::As4Path(segments))
            }
            PathAttributeTypeCode::Communities => {
                let mut communities = Vec::new();
                loop {
                    if input.is_empty() {
                        break;
                    }
                    let (out, v) = be_u32(input)?;
                    communities.push(Community::from(v));
                    input = out;
                }
                Ok(PathAttributeValue::Communities(communities))
            }
            PathAttributeTypeCode::LocalPref => {
                let (_input, v) = be_u32(input)?;
                Ok(PathAttributeValue::LocalPref(v))
            }
            x => Err(Error::UnsupportedPathAttributeTypeCode(x)),
        }
    }
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

/// An enumeration indicating the origin type of a path.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    TryFromPrimitive,
    Serialize,
    Deserialize,
    JsonSchema,
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

// A self describing segment found in path sets and sequences.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AsPathSegment {
    // Indicates if this segment is a part of a set or sequence.
    pub typ: AsPathType,
    // AS numbers in the segment.
    pub value: Vec<u16>,
}

// A self describing segment found in path sets and sequences of 4-byte ASNs.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct As4PathSegment {
    // Indicates if this segment is a part of a set or sequence.
    pub typ: AsPathType,
    // 4 byte AS numbers in the segment.
    pub value: Vec<u32>,
}

impl As4PathSegment {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        if self.value.len() > u8::MAX as usize {
            return Err(Error::TooLarge("AS4 path segment".into()));
        }
        let mut buf = vec![self.typ as u8, self.value.len() as u8];
        for v in &self.value {
            buf.extend_from_slice(&v.to_be_bytes());
        }
        Ok(buf)
    }

    pub fn from_wire(input: &[u8]) -> Result<(&[u8], As4PathSegment), Error> {
        let (input, typ) = parse_u8(input)?;
        let typ = AsPathType::try_from(typ)?;

        let (input, len) = parse_u8(input)?;
        let len = (len as usize) * 4;
        let mut segment = As4PathSegment {
            typ,
            value: Vec::new(),
        };
        if len == 0 {
            return Ok((input, segment));
        }

        let (input, mut value_input) = take(len)(input)?;
        loop {
            if value_input.is_empty() {
                break;
            }
            let (out, value) = be_u32(value_input)?;
            segment.value.push(value);
            value_input = out;
        }
        Ok((input, segment))
    }
}

/// Enumeration describes possible AS path types
#[derive(
    Debug,
    PartialEq,
    Eq,
    Copy,
    Clone,
    TryFromPrimitive,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum AsPathType {
    /// The path is to be interpreted as a set
    AsSet = 1,
    /// The path is to be interpreted as a sequence
    AsSequence = 2,
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

impl NotificationMessage {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        let buf = vec![self.error_code as u8, self.error_subcode.as_u8()];
        //TODO data, see comment above on data field
        Ok(buf)
    }

    pub fn from_wire(input: &[u8]) -> Result<NotificationMessage, Error> {
        let (input, error_code) = parse_u8(input)?;
        let error_code = ErrorCode::try_from(error_code)?;

        let (input, error_subcode) = parse_u8(input)?;
        let error_subcode = match error_code {
            ErrorCode::Header => {
                HeaderErrorSubcode::try_from(error_subcode)?.into()
            }
            ErrorCode::Open => {
                OpenErrorSubcode::try_from(error_subcode)?.into()
            }
            ErrorCode::Update => {
                UpdateErrorSubcode::try_from(error_subcode)?.into()
            }
            ErrorCode::HoldTimerExpired => {
                ErrorSubcode::HoldTime(error_subcode)
            }
            ErrorCode::Fsm => ErrorSubcode::Fsm(error_subcode),
            ErrorCode::Cease => {
                CeaseErrorSubcode::try_from(error_subcode)?.into()
            }
        };
        Ok(NotificationMessage {
            error_code,
            error_subcode,
            data: input.to_owned(),
        })
    }
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

impl RouteRefreshMessage {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.afi.to_be_bytes());
        buf.push(0); // reserved
        buf.push(self.safi);
        Ok(buf)
    }
    pub fn from_wire(input: &[u8]) -> Result<RouteRefreshMessage, Error> {
        let (input, afi) = be_u16(input)?;
        let (input, _reserved) = parse_u8(input)?;
        let (_, safi) = parse_u8(input)?;
        Ok(RouteRefreshMessage { afi, safi })
    }
}

/// This enumeration contains possible notification error codes.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
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

/// This enumeration contains possible notification error subcodes.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSubcode {
    Header(HeaderErrorSubcode),
    Open(OpenErrorSubcode),
    Update(UpdateErrorSubcode),
    HoldTime(u8),
    Fsm(u8),
    Cease(CeaseErrorSubcode),
}

impl From<HeaderErrorSubcode> for ErrorSubcode {
    fn from(x: HeaderErrorSubcode) -> ErrorSubcode {
        ErrorSubcode::Header(x)
    }
}

impl From<OpenErrorSubcode> for ErrorSubcode {
    fn from(x: OpenErrorSubcode) -> ErrorSubcode {
        ErrorSubcode::Open(x)
    }
}

impl From<UpdateErrorSubcode> for ErrorSubcode {
    fn from(x: UpdateErrorSubcode) -> ErrorSubcode {
        ErrorSubcode::Update(x)
    }
}

impl From<CeaseErrorSubcode> for ErrorSubcode {
    fn from(x: CeaseErrorSubcode) -> ErrorSubcode {
        ErrorSubcode::Cease(x)
    }
}

impl ErrorSubcode {
    fn as_u8(&self) -> u8 {
        match self {
            Self::Header(h) => *h as u8,
            Self::Open(o) => *o as u8,
            Self::Update(u) => *u as u8,
            Self::HoldTime(x) => *x,
            Self::Fsm(x) => *x,
            Self::Cease(x) => *x as u8,
        }
    }
}

/// Header error subcode types
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
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

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum OptionalParameterCode {
    Reserved = 0,
    Authentication = 1,
    Capabilities = 2,
    ExtendedLength = 255,
}

impl OptionalParameter {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Reserved => Err(Error::ReservedOptionalParameter),
            Self::Unassigned => Err(Error::Unassigned(0)),
            Self::Capabilities(cs) => {
                let mut buf = vec![OptionalParameterCode::Capabilities as u8];
                let mut csbuf = Vec::new();
                for c in cs {
                    let cbuf = c.to_wire()?;
                    csbuf.extend_from_slice(&cbuf);
                }
                buf.push(csbuf.len() as u8);
                buf.extend_from_slice(&csbuf);
                Ok(buf)
            }
            x => Err(Error::UnsupportedOptionalParameter(x.clone())),
        }
    }

    pub fn from_wire(
        input: &[u8],
    ) -> Result<(&[u8], OptionalParameter), Error> {
        let (input, code) = parse_u8(input)?;
        let code = OptionalParameterCode::try_from(code)?;
        let (input, len) = parse_u8(input)?;
        let (input, mut cap_input) = take(len)(input)?;

        match code {
            OptionalParameterCode::Reserved => {
                Err(Error::ReservedOptionalParameter)
            }
            OptionalParameterCode::Capabilities => {
                let mut result = BTreeSet::new();
                while !cap_input.is_empty() {
                    let (out, cap) = Capability::from_wire(cap_input)?;
                    result.insert(cap);
                    cap_input = out;
                }
                Ok((input, OptionalParameter::Capabilities(result)))
            }
            x => Err(Error::UnsupportedOptionalParameterCode(x)),
        }
    }
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

    //TODO
    /// Multiple nexthop encoding capability as defined in RFC 8950. Note this
    /// capability is not yet implemented.
    ExtendedNextHopEncoding {},

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

impl Capability {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::MultiprotocolExtensions { afi, safi } => {
                let mut buf =
                    vec![CapabilityCode::MultiprotocolExtensions as u8, 4];
                buf.extend_from_slice(&afi.to_be_bytes());
                buf.push(0);
                buf.push(*safi);
                Ok(buf)
            }
            Self::RouteRefresh {} => {
                let buf = vec![CapabilityCode::RouteRefresh as u8, 0];
                Ok(buf)
            }
            Self::GracefulRestart {} => {
                //TODO audit
                let buf = vec![CapabilityCode::GracefulRestart as u8, 0];
                Ok(buf)
            }
            Self::FourOctetAs { asn } => {
                let mut buf = vec![CapabilityCode::FourOctetAs as u8, 4];
                buf.extend_from_slice(&asn.to_be_bytes());
                Ok(buf)
            }
            Self::AddPath { elements } => {
                let mut buf = vec![
                    CapabilityCode::AddPath as u8,
                    (elements.len() * 4) as u8,
                ];
                for e in elements {
                    buf.extend_from_slice(&e.afi.to_be_bytes());
                    buf.push(e.safi);
                    buf.push(e.send_receive);
                }
                Ok(buf)
            }
            Self::EnhancedRouteRefresh {} => {
                //TODO audit
                let buf = vec![CapabilityCode::EnhancedRouteRefresh as u8, 0];
                Ok(buf)
            }
            Self::Experimental { code: _ } => Err(Error::Experimental),
            Self::Unassigned { code } => Err(Error::Unassigned(*code)),
            Self::Reserved { code: _ } => Err(Error::ReservedCapability),
            x => Err(Error::UnsupportedCapability(x.clone())),
        }
    }

    pub fn from_wire(input: &[u8]) -> Result<(&[u8], Capability), Error> {
        let (input, code) = parse_u8(input)?;
        let code = CapabilityCode::try_from(code)?;
        let (input, len) = parse_u8(input)?;
        let len = len as usize;
        if input.len() < len {
            return Err(Error::Eom);
        }
        let mut input = input;

        match code {
            CapabilityCode::MultiprotocolExtensions => {
                let (input, afi) = be_u16(input)?;
                let (input, _) = be_u8(input)?;
                let (input, safi) = be_u8(input)?;
                Ok((input, Capability::MultiprotocolExtensions { afi, safi }))
            }
            CapabilityCode::RouteRefresh => {
                Ok((&input[len..], Capability::RouteRefresh {}))
            }

            CapabilityCode::GracefulRestart => {
                //TODO handle for real
                Ok((&input[len..], Capability::GracefulRestart {}))
            }
            CapabilityCode::FourOctetAs => {
                let (input, asn) = be_u32(input)?;
                Ok((input, Capability::FourOctetAs { asn }))
            }
            CapabilityCode::AddPath => {
                let mut elements = BTreeSet::new();
                while !input.is_empty() {
                    let (remaining, afi) = be_u16(input)?;
                    let (remaining, safi) = be_u8(remaining)?;
                    let (remaining, send_receive) = be_u8(remaining)?;
                    elements.insert(AddPathElement {
                        afi,
                        safi,
                        send_receive,
                    });
                    input = remaining;
                }
                Ok((input, Capability::AddPath { elements }))
            }
            CapabilityCode::EnhancedRouteRefresh => {
                //TODO handle for real
                Ok((&input[len..], Capability::EnhancedRouteRefresh {}))
            }

            CapabilityCode::Fqdn => {
                //TODO handle for real
                Ok((&input[len..], Capability::Fqdn {}))
            }

            CapabilityCode::PrestandardRouteRefresh => {
                //TODO handle for real
                Ok((&input[len..], Capability::PrestandardRouteRefresh {}))
            }

            CapabilityCode::BGPExtendedMessage => {
                //TODO handle for real
                Ok((&input[len..], Capability::BGPExtendedMessage {}))
            }

            CapabilityCode::LongLivedGracefulRestart => {
                //TODO handle for real
                Ok((&input[len..], Capability::LongLivedGracefulRestart {}))
            }

            CapabilityCode::MultipleRoutesToDestination => {
                //TODO handle for real
                Ok((&input[len..], Capability::MultipleRoutesToDestination {}))
            }

            CapabilityCode::ExtendedNextHopEncoding => {
                //TODO handle for real
                Ok((&input[len..], Capability::ExtendedNextHopEncoding {}))
            }

            CapabilityCode::OutboundRouteFiltering => {
                //TODO handle for real
                Ok((&input[len..], Capability::OutboundRouteFiltering {}))
            }

            CapabilityCode::BgpSec => {
                //TODO handle for real
                Ok((&input[len..], Capability::BgpSec {}))
            }

            CapabilityCode::MultipleLabels => {
                //TODO handle for real
                Ok((&input[len..], Capability::MultipleLabels {}))
            }

            CapabilityCode::BgpRole => {
                //TODO handle for real
                Ok((&input[len..], Capability::BgpRole {}))
            }

            CapabilityCode::DynamicCapability => {
                //TODO handle for real
                Ok((&input[len..], Capability::DynamicCapability {}))
            }

            CapabilityCode::MultisessionBgp => {
                //TODO handle for real
                Ok((&input[len..], Capability::MultisessionBgp {}))
            }

            CapabilityCode::RoutingPolicyDistribution => {
                //TODO handle for real
                Ok((&input[len..], Capability::RoutingPolicyDistribution {}))
            }

            CapabilityCode::PrestandardOrfAndPd => {
                //TODO handle for real
                Ok((&input[len..], Capability::PrestandardOrfAndPd {}))
            }

            CapabilityCode::PrestandardOutboundRouteFiltering => {
                //TODO handle for real
                Ok((
                    &input[len..],
                    Capability::PrestandardOutboundRouteFiltering {},
                ))
            }

            CapabilityCode::PrestandardMultisession => {
                //TODO handle for real
                Ok((&input[len..], Capability::PrestandardMultisession {}))
            }

            CapabilityCode::PrestandardFqdn => {
                //TODO handle for real
                Ok((&input[len..], Capability::PrestandardFqdn {}))
            }

            CapabilityCode::PrestandardOperationalMessage => {
                //TODO handle for real
                Ok((
                    &input[len..],
                    Capability::PrestandardOperationalMessage {},
                ))
            }

            CapabilityCode::Experimental0 => {
                Ok((&input[len..], Capability::Experimental { code: 0 }))
            }
            CapabilityCode::Experimental1 => {
                Ok((&input[len..], Capability::Experimental { code: 1 }))
            }
            CapabilityCode::Experimental2 => {
                Ok((&input[len..], Capability::Experimental { code: 2 }))
            }
            CapabilityCode::Experimental3 => {
                Ok((&input[len..], Capability::Experimental { code: 3 }))
            }
            CapabilityCode::Experimental4 => {
                Ok((&input[len..], Capability::Experimental { code: 4 }))
            }
            CapabilityCode::Experimental5 => {
                Ok((&input[len..], Capability::Experimental { code: 5 }))
            }
            CapabilityCode::Experimental6 => {
                Ok((&input[len..], Capability::Experimental { code: 6 }))
            }
            CapabilityCode::Experimental7 => {
                Ok((&input[len..], Capability::Experimental { code: 7 }))
            }
            CapabilityCode::Experimental8 => {
                Ok((&input[len..], Capability::Experimental { code: 8 }))
            }
            CapabilityCode::Experimental9 => {
                Ok((&input[len..], Capability::Experimental { code: 9 }))
            }
            CapabilityCode::Experimental10 => {
                Ok((&input[len..], Capability::Experimental { code: 10 }))
            }
            CapabilityCode::Experimental11 => {
                Ok((&input[len..], Capability::Experimental { code: 11 }))
            }
            CapabilityCode::Experimental12 => {
                Ok((&input[len..], Capability::Experimental { code: 12 }))
            }
            CapabilityCode::Experimental13 => {
                Ok((&input[len..], Capability::Experimental { code: 13 }))
            }
            CapabilityCode::Experimental14 => {
                Ok((&input[len..], Capability::Experimental { code: 14 }))
            }
            CapabilityCode::Experimental15 => {
                Ok((&input[len..], Capability::Experimental { code: 15 }))
            }
            CapabilityCode::Experimental16 => {
                Ok((&input[len..], Capability::Experimental { code: 16 }))
            }
            CapabilityCode::Experimental17 => {
                Ok((&input[len..], Capability::Experimental { code: 17 }))
            }
            CapabilityCode::Experimental18 => {
                Ok((&input[len..], Capability::Experimental { code: 18 }))
            }
            CapabilityCode::Experimental19 => {
                Ok((&input[len..], Capability::Experimental { code: 19 }))
            }
            CapabilityCode::Experimental20 => {
                Ok((&input[len..], Capability::Experimental { code: 20 }))
            }
            CapabilityCode::Experimental21 => {
                Ok((&input[len..], Capability::Experimental { code: 21 }))
            }
            CapabilityCode::Experimental22 => {
                Ok((&input[len..], Capability::Experimental { code: 22 }))
            }
            CapabilityCode::Experimental23 => {
                Ok((&input[len..], Capability::Experimental { code: 23 }))
            }
            CapabilityCode::Experimental24 => {
                Ok((&input[len..], Capability::Experimental { code: 24 }))
            }
            CapabilityCode::Experimental25 => {
                Ok((&input[len..], Capability::Experimental { code: 25 }))
            }
            CapabilityCode::Experimental26 => {
                Ok((&input[len..], Capability::Experimental { code: 26 }))
            }
            CapabilityCode::Experimental27 => {
                Ok((&input[len..], Capability::Experimental { code: 27 }))
            }
            CapabilityCode::Experimental28 => {
                Ok((&input[len..], Capability::Experimental { code: 28 }))
            }
            CapabilityCode::Experimental29 => {
                Ok((&input[len..], Capability::Experimental { code: 29 }))
            }
            CapabilityCode::Experimental30 => {
                Ok((&input[len..], Capability::Experimental { code: 30 }))
            }
            CapabilityCode::Experimental31 => {
                Ok((&input[len..], Capability::Experimental { code: 31 }))
            }
            CapabilityCode::Experimental32 => {
                Ok((&input[len..], Capability::Experimental { code: 32 }))
            }
            CapabilityCode::Experimental33 => {
                Ok((&input[len..], Capability::Experimental { code: 33 }))
            }
            CapabilityCode::Experimental34 => {
                Ok((&input[len..], Capability::Experimental { code: 34 }))
            }
            CapabilityCode::Experimental35 => {
                Ok((&input[len..], Capability::Experimental { code: 35 }))
            }
            CapabilityCode::Experimental36 => {
                Ok((&input[len..], Capability::Experimental { code: 36 }))
            }
            CapabilityCode::Experimental37 => {
                Ok((&input[len..], Capability::Experimental { code: 37 }))
            }
            CapabilityCode::Experimental38 => {
                Ok((&input[len..], Capability::Experimental { code: 38 }))
            }
            CapabilityCode::Experimental39 => {
                Ok((&input[len..], Capability::Experimental { code: 39 }))
            }
            CapabilityCode::Experimental40 => {
                Ok((&input[len..], Capability::Experimental { code: 40 }))
            }
            CapabilityCode::Experimental41 => {
                Ok((&input[len..], Capability::Experimental { code: 41 }))
            }
            CapabilityCode::Experimental42 => {
                Ok((&input[len..], Capability::Experimental { code: 42 }))
            }
            CapabilityCode::Experimental43 => {
                Ok((&input[len..], Capability::Experimental { code: 43 }))
            }
            CapabilityCode::Experimental44 => {
                Ok((&input[len..], Capability::Experimental { code: 44 }))
            }
            CapabilityCode::Experimental45 => {
                Ok((&input[len..], Capability::Experimental { code: 45 }))
            }
            CapabilityCode::Experimental46 => {
                Ok((&input[len..], Capability::Experimental { code: 46 }))
            }
            CapabilityCode::Experimental47 => {
                Ok((&input[len..], Capability::Experimental { code: 47 }))
            }
            CapabilityCode::Experimental48 => {
                Ok((&input[len..], Capability::Experimental { code: 48 }))
            }
            CapabilityCode::Experimental49 => {
                Ok((&input[len..], Capability::Experimental { code: 49 }))
            }
            CapabilityCode::Experimental50 => {
                Ok((&input[len..], Capability::Experimental { code: 50 }))
            }
            CapabilityCode::Experimental51 => {
                Ok((&input[len..], Capability::Experimental { code: 51 }))
            }
            CapabilityCode::Reserved => {
                Ok((&input[len..], Capability::Reserved { code: 0 }))
            }
        }
    }
}

/// The set of capability codes supported by this BGP implementation
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Copy, Clone)]
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

impl From<Capability> for CapabilityCode {
    fn from(value: Capability) -> Self {
        match value {
            Capability::MultiprotocolExtensions { afi: _, safi: _ } => {
                CapabilityCode::MultiprotocolExtensions
            }
            Capability::RouteRefresh {} => CapabilityCode::RouteRefresh,
            Capability::OutboundRouteFiltering {} => {
                CapabilityCode::OutboundRouteFiltering
            }
            Capability::MultipleRoutesToDestination {} => {
                CapabilityCode::MultipleRoutesToDestination
            }
            Capability::ExtendedNextHopEncoding {} => {
                CapabilityCode::ExtendedNextHopEncoding
            }
            Capability::BGPExtendedMessage {} => {
                CapabilityCode::BGPExtendedMessage
            }
            Capability::BgpSec {} => CapabilityCode::BgpSec,
            Capability::MultipleLabels {} => CapabilityCode::MultipleLabels,
            Capability::BgpRole {} => CapabilityCode::BgpRole,
            Capability::GracefulRestart {} => CapabilityCode::GracefulRestart,
            Capability::FourOctetAs { asn: _ } => CapabilityCode::FourOctetAs,
            Capability::DynamicCapability {} => {
                CapabilityCode::DynamicCapability
            }
            Capability::MultisessionBgp {} => CapabilityCode::MultisessionBgp,
            Capability::AddPath { elements: _ } => CapabilityCode::AddPath,
            Capability::EnhancedRouteRefresh {} => {
                CapabilityCode::EnhancedRouteRefresh
            }
            Capability::LongLivedGracefulRestart {} => {
                CapabilityCode::LongLivedGracefulRestart
            }
            Capability::RoutingPolicyDistribution {} => {
                CapabilityCode::RoutingPolicyDistribution
            }
            Capability::Fqdn {} => CapabilityCode::Fqdn,
            Capability::PrestandardRouteRefresh {} => {
                CapabilityCode::PrestandardRouteRefresh
            }
            Capability::PrestandardOrfAndPd {} => {
                CapabilityCode::PrestandardOrfAndPd
            }
            Capability::PrestandardOutboundRouteFiltering {} => {
                CapabilityCode::PrestandardOutboundRouteFiltering
            }
            Capability::PrestandardMultisession {} => {
                CapabilityCode::PrestandardMultisession
            }
            Capability::PrestandardFqdn {} => CapabilityCode::PrestandardFqdn,
            Capability::PrestandardOperationalMessage {} => {
                CapabilityCode::PrestandardOperationalMessage
            }
            Capability::Experimental { code } => match code {
                0 => CapabilityCode::Experimental0,
                1 => CapabilityCode::Experimental1,
                2 => CapabilityCode::Experimental2,
                3 => CapabilityCode::Experimental3,
                4 => CapabilityCode::Experimental4,
                5 => CapabilityCode::Experimental5,
                6 => CapabilityCode::Experimental6,
                7 => CapabilityCode::Experimental7,
                8 => CapabilityCode::Experimental8,
                9 => CapabilityCode::Experimental9,
                10 => CapabilityCode::Experimental10,
                11 => CapabilityCode::Experimental11,
                12 => CapabilityCode::Experimental12,
                13 => CapabilityCode::Experimental13,
                14 => CapabilityCode::Experimental14,
                15 => CapabilityCode::Experimental15,
                16 => CapabilityCode::Experimental16,
                17 => CapabilityCode::Experimental17,
                18 => CapabilityCode::Experimental18,
                19 => CapabilityCode::Experimental19,
                20 => CapabilityCode::Experimental20,
                21 => CapabilityCode::Experimental21,
                22 => CapabilityCode::Experimental22,
                23 => CapabilityCode::Experimental23,
                24 => CapabilityCode::Experimental24,
                25 => CapabilityCode::Experimental25,
                26 => CapabilityCode::Experimental26,
                27 => CapabilityCode::Experimental27,
                28 => CapabilityCode::Experimental28,
                29 => CapabilityCode::Experimental29,
                30 => CapabilityCode::Experimental30,
                31 => CapabilityCode::Experimental31,
                32 => CapabilityCode::Experimental32,
                33 => CapabilityCode::Experimental33,
                34 => CapabilityCode::Experimental34,
                35 => CapabilityCode::Experimental35,
                36 => CapabilityCode::Experimental36,
                37 => CapabilityCode::Experimental37,
                38 => CapabilityCode::Experimental38,
                39 => CapabilityCode::Experimental39,
                40 => CapabilityCode::Experimental40,
                41 => CapabilityCode::Experimental41,
                42 => CapabilityCode::Experimental42,
                43 => CapabilityCode::Experimental43,
                44 => CapabilityCode::Experimental44,
                45 => CapabilityCode::Experimental45,
                46 => CapabilityCode::Experimental46,
                47 => CapabilityCode::Experimental47,
                48 => CapabilityCode::Experimental48,
                49 => CapabilityCode::Experimental49,
                50 => CapabilityCode::Experimental50,
                51 => CapabilityCode::Experimental51,
                _ => CapabilityCode::Experimental0,
            },
            Capability::Unassigned { code: _ } => CapabilityCode::Reserved,
            Capability::Reserved { code: _ } => CapabilityCode::Reserved,
        }
    }
}

/// Address families supported by Maghemite BGP.
#[repr(u16)]
pub enum Afi {
    /// Internet protocol version 4
    Ipv4 = 1,
    /// Internet protocol version 6
    Ipv6 = 2,
}

/// Subsequent address families supported by Maghemite BGP.
#[repr(u8)]
pub enum Safi {
    /// Network Layer Reachability Information used for unicast forwarding
    NlriUnicast = 1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use pretty_hex::*;

    #[test]
    fn header_round_trip() {
        let h0 = Header {
            length: 0x1701,
            typ: MessageType::Notification,
        };

        let buf = h0.to_wire();
        println!("buf: {}", buf.hex_dump());

        assert_eq!(
            buf,
            vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // marker
                0x17, 0x01, // length
                3,    // type
            ]
        );

        let h1 = Header::from_wire(&buf).expect("header from wire");
        assert_eq!(h0, h1);
    }

    #[test]
    fn open_round_trip() {
        let om0 = OpenMessage::new4(395849, 0x1234, 0xaabbccdd);

        let buf = om0.to_wire().expect("open message to wire");
        println!("buf: {}", buf.hex_dump());

        let om1 = OpenMessage::from_wire(&buf).expect("open message from wire");
        assert_eq!(om0, om1);
    }

    #[test]
    fn update_round_trip() {
        let um0 = UpdateMessage {
            withdrawn: vec![Prefix {
                value: vec![0x00, 0x17, 0x01, 0xc],
                length: 32,
            }],
            path_attributes: vec![PathAttribute {
                typ: PathAttributeType {
                    flags: path_attribute_flags::OPTIONAL
                        | path_attribute_flags::PARTIAL,
                    type_code: PathAttributeTypeCode::As4Path,
                },
                value: PathAttributeValue::As4Path(vec![As4PathSegment {
                    typ: AsPathType::AsSequence,
                    value: vec![395849, 123456, 987654, 111111],
                }]),
            }],
            nlri: vec![
                Prefix {
                    value: vec![0x00, 0x17, 0x01, 0xd],
                    length: 32,
                },
                Prefix {
                    value: vec![0x00, 0x17, 0x01, 0xe],
                    length: 32,
                },
            ],
        };

        let buf = um0.to_wire().expect("update message to wire");
        println!("buf: {}", buf.hex_dump());

        let um1 =
            UpdateMessage::from_wire(&buf).expect("update message from wire");
        assert_eq!(um0, um1);
    }

    #[test]
    fn prefix_within() {
        let prefixes: &[Prefix] = &[
            "10.10.10.10/32".parse().unwrap(),
            "10.10.10.0/24".parse().unwrap(),
            "10.10.0.0/16".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];

        for i in 0..prefixes.len() {
            for j in i..prefixes.len() {
                // shorter prefixes contain longer or equal
                assert!(prefixes[i].within(&prefixes[j]));
                if i != j {
                    // longer prefixes should not contain shorter
                    assert!(!prefixes[j].within(&prefixes[i]))
                }
            }
        }

        let a: Prefix = "10.10.0.0/16".parse().unwrap();
        let b: Prefix = "10.20.0.0/16".parse().unwrap();
        assert!(!a.within(&b));
        let a: Prefix = "10.10.0.0/24".parse().unwrap();
        assert!(!a.within(&b));

        let b: Prefix = "0.0.0.0/0".parse().unwrap();
        assert!(a.within(&b));
    }
}
