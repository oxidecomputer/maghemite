// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::error::Error;
use nom::{
    bytes::complete::{tag, take},
    number::complete::{be_u8, be_u16, be_u32, u8 as parse_u8},
};
use num_enum::FromPrimitive;
use num_enum::{IntoPrimitive, TryFromPrimitive};
pub use rdb::types::Prefix;
use rdb::types::{AddressFamily, Prefix4, Prefix6};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashSet},
    fmt::{Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const MAX_MESSAGE_SIZE: usize = 4096;

/// Trait for encoding/decoding values to/from BGP wire format.
///
/// This trait separates serialization/deserialization concerns from semantic
/// validation. Implementations should perform only structural validation
/// (buffer bounds, required fields, etc.). Semantic validation (protocol
/// rules, consistency constraints) should be performed separately via dedicated
/// validation methods.
pub trait BgpWireFormat<T>: Sized {
    type Error;

    /// Encode value to wire format bytes.
    /// This is infallible as it simply formats existing validated data.
    fn to_wire(&self) -> Vec<u8>;

    /// Decode value from wire format, returning (remaining_bytes, value).
    /// This can fail due to malformed input (bounds checking, invalid values).
    fn from_wire(input: &[u8]) -> Result<(&[u8], T), Self::Error>;
}

/// Errors from parsing NLRI prefixes.
///
/// These preserve the specific failure reason so callers can convert
/// to `UpdateParseErrorReason` with the appropriate section context.
#[derive(Debug, Clone)]
pub enum PrefixParseError {
    /// No data available for prefix length byte
    MissingLength,
    /// Prefix length exceeds maximum for address family
    InvalidMask { length: u8, max: u8 },
    /// Not enough bytes for declared prefix length
    Truncated { needed: usize, available: usize },
}

impl PrefixParseError {
    /// Convert to UpdateParseErrorReason with section context.
    pub fn into_reason(self, section: &'static str) -> UpdateParseErrorReason {
        match self {
            Self::MissingLength => {
                UpdateParseErrorReason::NlriMissingLength { section }
            }
            Self::InvalidMask { length, max } => {
                UpdateParseErrorReason::InvalidNlriMask {
                    section,
                    length,
                    max,
                }
            }
            Self::Truncated { needed, available } => {
                UpdateParseErrorReason::TruncatedNlri {
                    section,
                    needed,
                    available,
                }
            }
        }
    }
}

impl BgpWireFormat<Prefix4> for Prefix4 {
    type Error = PrefixParseError;

    fn to_wire(&self) -> Vec<u8> {
        let mut buf = vec![self.length];
        let n = (self.length as usize).div_ceil(8);
        buf.extend_from_slice(&self.value.octets()[..n]);
        buf
    }

    fn from_wire(input: &[u8]) -> Result<(&[u8], Self), Self::Error> {
        if input.is_empty() {
            return Err(PrefixParseError::MissingLength);
        }

        let len = input[0];

        // Validate length bound for IPv4 (structural validation)
        if len > Prefix4::HOST_MASK {
            return Err(PrefixParseError::InvalidMask {
                length: len,
                max: Prefix4::HOST_MASK,
            });
        }

        let byte_count = (len as usize).div_ceil(8);
        if input.len() < 1 + byte_count {
            return Err(PrefixParseError::Truncated {
                needed: 1 + byte_count,
                available: input.len(),
            });
        }

        let mut bytes = [0u8; 4];
        bytes[..byte_count].copy_from_slice(&input[1..1 + byte_count]);

        // Note: BGP wire format encodes the bitlength of a prefix in the first
        // byte, followed by the minimum number of bytes required to hold the
        // prefix's bitlength:
        //
        // ```
        //  The Prefix field contains an IP address prefix, followed by
        //  enough trailing bits to make the end of the field fall on an
        //  octet boundary.  Note that the value of the trailing bits is
        //  irrelevant.
        // ```
        //
        // Example: 192.168.1.0/25 is encoded as follows:
        //   [25, 192, 168, 1, 128]
        //     ^
        //     +--- prefix length in bits
        //
        // The last encoded byte carries the 25th bit of the prefix plus 7
        // padding bits (128 = 0b10000000).
        //
        // We make the trailing bits irrelevant by zeroing them during Prefix
        // type instantiation.
        Ok((
            &input[1 + byte_count..],
            Prefix4::new(Ipv4Addr::from(bytes), len),
        ))
    }
}

impl BgpWireFormat<Prefix6> for Prefix6 {
    type Error = PrefixParseError;

    fn to_wire(&self) -> Vec<u8> {
        let mut buf = vec![self.length];
        let n = (self.length as usize).div_ceil(8);
        buf.extend_from_slice(&self.value.octets()[..n]);
        buf
    }

    fn from_wire(input: &[u8]) -> Result<(&[u8], Self), PrefixParseError> {
        if input.is_empty() {
            return Err(PrefixParseError::MissingLength);
        }

        let len = input[0];

        // Validate length bound for IPv6 (structural validation)
        if len > Prefix6::HOST_MASK {
            return Err(PrefixParseError::InvalidMask {
                length: len,
                max: Prefix6::HOST_MASK,
            });
        }

        let byte_count = (len as usize).div_ceil(8);
        if input.len() < 1 + byte_count {
            return Err(PrefixParseError::Truncated {
                needed: 1 + byte_count,
                available: input.len(),
            });
        }

        let mut bytes = [0u8; 16];
        bytes[..byte_count].copy_from_slice(&input[1..1 + byte_count]);

        // Note: BGP wire format encodes the bitlength of a prefix in the first
        // byte, followed by the minimum number of bytes required to hold the
        // prefix's bitlength:
        //
        // ```
        //  The Prefix field contains an IP address prefix, followed by
        //  enough trailing bits to make the end of the field fall on an
        //  octet boundary.  Note that the value of the trailing bits is
        //  irrelevant.
        // ```
        //
        // Example: A /25 prefix (2001:d8::/25) transmits 4 bytes:
        //   [25, 0x20, 0x01, 0x0d, 0x80]
        //     ^
        //     +--- prefix length in bits
        //
        // The last encoded byte carries the 25th bit of the prefix plus 7
        // padding bits (0x80 = 0b10000000).
        //
        // We make the trailing bits irrelevant by zeroing them during Prefix
        // type instantiation.
        Ok((
            &input[1 + byte_count..],
            Prefix6::new(Ipv6Addr::from(bytes), len),
        ))
    }
}

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

    pub fn title(&self) -> &'static str {
        match self {
            Message::Open(_) => "open message",
            Message::Update(_) => "update message",
            Message::Notification(_) => "notification message",
            Message::KeepAlive => "keepalive message",
            Message::RouteRefresh(_) => "route refresh message",
        }
    }

    pub fn kind(&self) -> MessageKind {
        match self {
            Message::Open(_) => MessageKind::Open,
            Message::Update(_) => MessageKind::Update,
            Message::Notification(_) => MessageKind::Notification,
            Message::KeepAlive => MessageKind::KeepAlive,
            Message::RouteRefresh(_) => MessageKind::RouteRefresh,
        }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Message::Open(o) => write!(f, "{o}"),
            Message::Update(u) => write!(f, "{u}"),
            Message::Notification(n) => write!(f, "{n}"),
            Message::KeepAlive => write!(f, "Keepalive"),
            Message::RouteRefresh(r) => write!(f, "{r}"),
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MessageKind {
    Open,
    Update,
    Notification,
    KeepAlive,
    RouteRefresh,
}

impl Display for MessageKind {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            MessageKind::Open => write!(f, "open"),
            MessageKind::Update => write!(f, "update"),
            MessageKind::Notification => write!(f, "notification"),
            MessageKind::KeepAlive => write!(f, "keepalive"),
            MessageKind::RouteRefresh => write!(f, "route_refresh"),
        }
    }
}

impl slog::Value for MessageKind {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str(key, &self.to_string())
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
            asn: u16::try_from(asn).unwrap_or(AS_TRANS),
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

    pub fn asn(&self) -> u32 {
        let mut remote_asn = self.asn as u32;
        for p in &self.parameters {
            if let OptionalParameter::Capabilities(caps) = p {
                for c in caps {
                    if let Capability::FourOctetAs { asn } = c {
                        remote_asn = *asn;
                    }
                }
            }
        }
        remote_asn
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

impl Display for OpenMessage {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let param_string = self
            .parameters
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            f,
            "Open [ version: {}, asn: {}, hold_time: {}, id: {}, parameters: [ {param_string}] ]",
            self.version, self.asn, self.hold_time, self.id
        )
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
    pub withdrawn: Vec<Prefix4>,
    pub path_attributes: Vec<PathAttribute>, // XXX: use map for O(1) lookups?
    pub nlri: Vec<Prefix4>,

    /// True if a TreatAsWithdraw error occurred during from_wire().
    /// When true, session should process all NLRI (v4 + v6) as withdrawals.
    /// Not serialized - only used for internal signaling.
    #[serde(skip)]
    pub treat_as_withdraw: bool,

    /// All attribute parse errors encountered during from_wire().
    /// Includes both TreatAsWithdraw and Discard errors.
    /// SessionReset errors cause early return and are not collected here.
    /// Not serialized - only used for internal signaling.
    #[serde(skip)]
    pub errors: Vec<(UpdateParseErrorReason, AttributeAction)>,
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
            buf.extend_from_slice(&w.to_wire());
        }
        Ok(buf)
    }

    /// RFC 7606 Section 5.1:
    /// ```text
    /// 5.  Parsing of Network Layer Reachability Information (NLRI) Fields
    ///
    /// 5.1.  Encoding NLRI
    ///
    ///    To facilitate the determination of the NLRI field in an UPDATE
    ///    message with a malformed attribute:
    ///
    ///    o  The MP_REACH_NLRI or MP_UNREACH_NLRI attribute (if present) SHALL
    ///       be encoded as the very first path attribute in an UPDATE message.
    ///
    ///    o  An UPDATE message MUST NOT contain more than one of the following:
    ///       non-empty Withdrawn Routes field, non-empty Network Layer
    ///       Reachability Information field, MP_REACH_NLRI attribute, and
    ///       MP_UNREACH_NLRI attribute.
    ///
    ///    Since older BGP speakers may not implement these restrictions, an
    ///    implementation MUST still be prepared to receive these fields in any
    ///    position or combination.
    /// ```
    ///
    /// Note: While we MUST encode MP-BGP attributes first per the spec, during
    /// decoding we accept them in any position for interoperability with older
    /// BGP speakers (see the last paragraph above).
    fn path_attrs_to_wire(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();

        // Encode MP-BGP attributes first (RFC 7606 Section 5.1 requirement)
        for p in &self.path_attributes {
            if matches!(
                p.value,
                PathAttributeValue::MpReachNlri(_)
                    | PathAttributeValue::MpUnreachNlri(_)
            ) {
                buf.extend_from_slice(&p.to_wire(
                    p.typ.flags & path_attribute_flags::EXTENDED_LENGTH != 0,
                )?);
            }
        }

        // Then encode all other attributes
        for p in &self.path_attributes {
            if !matches!(
                p.value,
                PathAttributeValue::MpReachNlri(_)
                    | PathAttributeValue::MpUnreachNlri(_)
            ) {
                buf.extend_from_slice(&p.to_wire(
                    p.typ.flags & path_attribute_flags::EXTENDED_LENGTH != 0,
                )?);
            }
        }

        Ok(buf)
    }

    fn nlri_to_wire(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        for n in &self.nlri {
            // TODO hacked in ADD_PATH
            //buf.extend_from_slice(&0u32.to_be_bytes());
            buf.extend_from_slice(&n.to_wire());
        }
        Ok(buf)
    }

    /// Parse UPDATE message with RFC 7606 error tracking.
    ///
    /// Parses sequentially: withdrawn → attributes → nlri.
    /// If an attribute error occurs, continues to parse NLRI so it can be
    /// withdrawn per RFC 7606 "treat-as-withdraw" semantics.
    ///
    /// Returns `Ok(UpdateMessage)` on success (possibly with `treat_as_withdraw`
    /// field set), or `Err(UpdateParseError)` for fatal errors requiring session
    /// reset.
    pub fn from_wire(input: &[u8]) -> Result<UpdateMessage, UpdateParseError> {
        // 1. Parse withdrawn routes length and extract bytes
        let (input, len) = be_u16::<_, nom::error::Error<&[u8]>>(input)
            .map_err(|e| UpdateParseError {
                error_code: ErrorCode::Update,
                error_subcode: ErrorSubcode::Update(
                    UpdateErrorSubcode::MalformedAttributeList,
                ),
                reason: UpdateParseErrorReason::Other {
                    detail: format!("failed to parse withdrawn length: {e}"),
                },
            })?;
        let (input, withdrawn_input) = take(len)(input).map_err(
            |_e: nom::Err<nom::error::Error<&[u8]>>| UpdateParseError {
                error_code: ErrorCode::Update,
                error_subcode: ErrorSubcode::Update(
                    UpdateErrorSubcode::MalformedAttributeList,
                ),
                reason: UpdateParseErrorReason::InvalidWithdrawnLength {
                    declared: len,
                    available: input.len(),
                },
            },
        )?;

        // 2. Parse withdrawn prefixes (SessionReset on failure)
        let withdrawn = match Self::prefixes4_from_wire(withdrawn_input) {
            Ok(w) => w,
            Err(e) => {
                return Err(UpdateParseError {
                    error_code: ErrorCode::Update,
                    error_subcode: ErrorSubcode::Update(
                        UpdateErrorSubcode::InvalidNetworkField,
                    ),
                    reason: e.into_reason("withdrawn"),
                });
            }
        };

        // 3. Parse path attributes length and extract bytes
        let (input, len) = be_u16::<_, nom::error::Error<&[u8]>>(input)
            .map_err(|e| UpdateParseError {
                error_code: ErrorCode::Update,
                error_subcode: ErrorSubcode::Update(
                    UpdateErrorSubcode::MalformedAttributeList,
                ),
                reason: UpdateParseErrorReason::Other {
                    detail: format!(
                        "failed to parse path attributes length: {e}"
                    ),
                },
            })?;
        let (input, attrs_input) = take(len)(input).map_err(
            |_e: nom::Err<nom::error::Error<&[u8]>>| UpdateParseError {
                error_code: ErrorCode::Update,
                error_subcode: ErrorSubcode::Update(
                    UpdateErrorSubcode::MalformedAttributeList,
                ),
                reason: UpdateParseErrorReason::InvalidAttributeLength {
                    declared: len,
                    available: input.len(),
                },
            },
        )?;

        // 4. Parse path attributes, collecting all errors
        let ParsedPathAttrs {
            attrs: path_attributes,
            errors: attr_errors,
            treat_as_withdraw,
        } = Self::path_attrs_from_wire(attrs_input)?;

        // 6. Parse NLRI (remaining bytes)
        //    Even if attrs had errors, we need NLRI for TreatAsWithdraw
        let nlri = match Self::prefixes4_from_wire(input) {
            Ok(n) => n,
            Err(e) => {
                // NLRI parse failure = SessionReset (strongest action)
                return Err(UpdateParseError {
                    error_code: ErrorCode::Update,
                    error_subcode: ErrorSubcode::Update(
                        UpdateErrorSubcode::InvalidNetworkField,
                    ),
                    reason: e.into_reason("nlri"),
                });
            }
        };

        // 7. Validate mandatory attributes (RFC 4271 Section 5.1.2)
        //    Only required when UPDATE carries reachability information (NLRI).
        //    Missing mandatory attrs = TreatAsWithdraw per RFC 7606.
        let mut errors = attr_errors;
        let mut treat_as_withdraw = treat_as_withdraw;

        // Check if we have any NLRI (traditional or MP-BGP)
        let has_traditional_nlri = !nlri.is_empty();
        let has_mp_reach = path_attributes
            .iter()
            .any(|a| matches!(a.value, PathAttributeValue::MpReachNlri(_)));

        if has_traditional_nlri || has_mp_reach {
            // ORIGIN is always required when there's NLRI
            let has_origin = path_attributes
                .iter()
                .any(|a| matches!(a.value, PathAttributeValue::Origin(_)));
            if !has_origin {
                treat_as_withdraw = true;
                errors.push((
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::Origin,
                    },
                    AttributeAction::TreatAsWithdraw,
                ));
            }

            // AS_PATH is always required when there's NLRI
            // Note: AS_PATH parses to As4Path variant internally (always uses 4-byte ASNs)
            let has_as_path = path_attributes.iter().any(|a| {
                matches!(
                    a.value,
                    PathAttributeValue::AsPath(_)
                        | PathAttributeValue::As4Path(_)
                )
            });
            if !has_as_path {
                treat_as_withdraw = true;
                errors.push((
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::AsPath,
                    },
                    AttributeAction::TreatAsWithdraw,
                ));
            }

            // NEXT_HOP is required for traditional NLRI (IPv4 in NLRI field).
            // When MP_REACH_NLRI is present without traditional NLRI, the nexthop
            // is carried inside the MP attribute, so NEXT_HOP is not required.
            if has_traditional_nlri {
                let has_next_hop = path_attributes
                    .iter()
                    .any(|a| matches!(a.value, PathAttributeValue::NextHop(_)));
                if !has_next_hop {
                    treat_as_withdraw = true;
                    errors.push((
                        UpdateParseErrorReason::MissingAttribute {
                            type_code: PathAttributeTypeCode::NextHop,
                        },
                        AttributeAction::TreatAsWithdraw,
                    ));
                }
            }
        }

        Ok(UpdateMessage {
            withdrawn,
            path_attributes,
            nlri,
            treat_as_withdraw,
            errors,
        })
    }

    /// Parse prefixes from wire format.
    /// Dispatches to the appropriate version-specific parser.
    pub fn prefixes_from_wire(
        buf: &[u8],
        afi: AddressFamily,
    ) -> Result<Vec<Prefix>, PrefixParseError> {
        match afi {
            AddressFamily::Ipv4 => Self::prefixes4_from_wire(buf)
                .map(|v| v.into_iter().map(Prefix::V4).collect()),
            AddressFamily::Ipv6 => Self::prefixes6_from_wire(buf)
                .map(|v| v.into_iter().map(Prefix::V6).collect()),
        }
    }

    /// Parse IPv4 prefixes from wire format.
    pub fn prefixes4_from_wire(
        mut buf: &[u8],
    ) -> Result<Vec<Prefix4>, PrefixParseError> {
        let mut result = Vec::new();
        while !buf.is_empty() {
            let (out, prefix4) = Prefix4::from_wire(buf)?;
            result.push(prefix4);
            buf = out;
        }
        Ok(result)
    }

    /// Parse IPv6 prefixes from wire format.
    pub fn prefixes6_from_wire(
        mut buf: &[u8],
    ) -> Result<Vec<Prefix6>, PrefixParseError> {
        let mut result = Vec::new();
        while !buf.is_empty() {
            let (out, prefix6) = Prefix6::from_wire(buf)?;
            result.push(prefix6);
            buf = out;
        }
        Ok(result)
    }

    /// Parse path attributes from wire format with RFC 7606 error handling.
    ///
    /// This function handles the framing (type header + length parsing) for each
    /// attribute internally, which allows it to continue parsing after non-fatal
    /// errors because it always knows where the next attribute starts.
    ///
    /// For any given path attribute, only the first instance is respected.
    /// Subsequent instances are discarded. The exceptions to this are MP-BGP
    /// attributes, which are not allowed to show up multiple times in an
    /// Update.
    ///
    /// All of this is mandated by RFC 7606 Section 3(g):
    /// ```text
    /// g.  If the MP_REACH_NLRI attribute or the MP_UNREACH_NLRI [RFC4760]
    ///     attribute appears more than once in the UPDATE message, then a
    ///     NOTIFICATION message MUST be sent with the Error Subcode
    ///     "Malformed Attribute List".  If any other attribute (whether
    ///     recognized or unrecognized) appears more than once in an UPDATE
    ///     message, then all the occurrences of the attribute other than the
    ///     first one SHALL be discarded and the UPDATE message will continue
    ///     to be processed.
    /// ```
    ///
    /// # Returns
    /// - `Ok(ParsedPathAttrs)`: Successfully parsed (may contain non-fatal errors)
    /// - `Err(UpdateParseError)`: Fatal error (SessionReset) - parsing cannot continue
    fn path_attrs_from_wire(
        mut buf: &[u8],
    ) -> Result<ParsedPathAttrs, UpdateParseError> {
        let mut result = Vec::new();
        let mut errors = Vec::new();
        let mut treat_as_withdraw = false;
        let mut seen_types: HashSet<u8> = HashSet::new();
        let mut has_mp_reach = false;
        let mut has_mp_unreach = false;

        loop {
            if buf.is_empty() {
                break;
            }

            // ===== FRAMING: Parse attribute header (type + length) =====

            // 1. Parse 2-byte type header (flags + type_code)
            let (remaining, type_bytes) =
                match take::<_, _, nom::error::Error<&[u8]>>(2usize)(buf) {
                    Ok((r, t)) => (r, t),
                    Err(e) => {
                        // Can't even read type header - fatal framing error
                        return Err(UpdateParseError {
                            error_code: ErrorCode::Update,
                            error_subcode: ErrorSubcode::Update(
                                UpdateErrorSubcode::MalformedAttributeList,
                            ),
                            reason:
                                UpdateParseErrorReason::AttributeParseError {
                                    type_code: None,
                                    detail: format!(
                                        "failed to read attribute type: {e}"
                                    ),
                                },
                        });
                    }
                };

            // 2. Parse PathAttributeType from the 2 bytes
            let typ = match PathAttributeType::from_wire(type_bytes) {
                Ok(t) => t,
                Err(e) => {
                    // Unknown/invalid type code - fatal framing error
                    // (we don't know the length encoding without valid flags)
                    return Err(UpdateParseError {
                        error_code: ErrorCode::Update,
                        error_subcode: ErrorSubcode::Update(
                            UpdateErrorSubcode::MalformedAttributeList,
                        ),
                        reason: UpdateParseErrorReason::AttributeParseError {
                            type_code: None,
                            detail: format!("invalid attribute type: {e}"),
                        },
                    });
                }
            };

            let type_code_u8 = typ.type_code as u8;

            // 3. Validate attribute flags (RFC 7606 Section 3c)
            //    Even if flag validation fails, we need to parse the length to skip
            //    the attribute. Track the error but continue to length parsing.
            let flag_error = validate_attribute_flags(&typ).err();

            // 4. Parse length (1 or 2 bytes depending on EXTENDED_LENGTH flag)
            let (remaining, len) =
                if typ.flags & path_attribute_flags::EXTENDED_LENGTH != 0 {
                    match be_u16::<_, nom::error::Error<&[u8]>>(remaining) {
                        Ok((r, l)) => (r, l as usize),
                        Err(e) => {
                            // Can't read extended length - fatal framing error
                            return Err(UpdateParseError {
                            error_code: ErrorCode::Update,
                            error_subcode: ErrorSubcode::Update(
                                UpdateErrorSubcode::MalformedAttributeList,
                            ),
                            reason:
                                UpdateParseErrorReason::AttributeParseError {
                                    type_code: Some(type_code_u8),
                                    detail: format!(
                                        "failed to read extended length: {e}"
                                    ),
                                },
                        });
                        }
                    }
                } else {
                    match parse_u8::<_, nom::error::Error<&[u8]>>(remaining) {
                        Ok((r, l)) => (r, l as usize),
                        Err(e) => {
                            // Can't read length - fatal framing error
                            return Err(UpdateParseError {
                            error_code: ErrorCode::Update,
                            error_subcode: ErrorSubcode::Update(
                                UpdateErrorSubcode::MalformedAttributeList,
                            ),
                            reason:
                                UpdateParseErrorReason::AttributeParseError {
                                    type_code: Some(type_code_u8),
                                    detail: format!(
                                        "failed to read length: {e}"
                                    ),
                                },
                        });
                        }
                    }
                };

            // 5. Extract `len` bytes for the attribute value
            let (remaining, value_bytes) = match take::<
                _,
                _,
                nom::error::Error<&[u8]>,
            >(len)(remaining)
            {
                Ok((r, v)) => (r, v),
                Err(e) => {
                    // Declared length exceeds available bytes - fatal framing error
                    return Err(UpdateParseError {
                        error_code: ErrorCode::Update,
                        error_subcode: ErrorSubcode::Update(
                            UpdateErrorSubcode::MalformedAttributeList,
                        ),
                        reason: UpdateParseErrorReason::AttributeParseError {
                            type_code: Some(type_code_u8),
                            detail: format!(
                                "attribute truncated: declared {} bytes, {e}",
                                len
                            ),
                        },
                    });
                }
            };

            // ===== We now know where the next attribute starts! =====
            // Update buf to point past this attribute for the next iteration
            buf = remaining;

            // ===== Handle flag validation error =====
            // Now that we've advanced buf, we can handle the flag error
            if let Some((reason, action)) = flag_error {
                match action {
                    AttributeAction::SessionReset => {
                        return Err(UpdateParseError {
                            error_code: ErrorCode::Update,
                            error_subcode: ErrorSubcode::Update(
                                UpdateErrorSubcode::MalformedAttributeList,
                            ),
                            reason,
                        });
                    }
                    AttributeAction::TreatAsWithdraw => {
                        treat_as_withdraw = true;
                        errors.push((reason, action));
                        continue; // Skip value parsing, move to next attribute
                    }
                    AttributeAction::Discard => {
                        errors.push((reason, action));
                        continue; // Skip value parsing, move to next attribute
                    }
                }
            }

            // ===== VALUE PARSING: Parse the attribute value =====
            match PathAttribute::from_bytes(typ.clone(), value_bytes) {
                Ok(pa) => {
                    // ===== DUPLICATE DETECTION =====
                    let is_mp_reach =
                        pa.typ.type_code == PathAttributeTypeCode::MpReachNlri;
                    let is_mp_unreach = pa.typ.type_code
                        == PathAttributeTypeCode::MpUnreachNlri;

                    // Track MP-BGP duplicates for Session Reset (RFC 7606 §3g)
                    if is_mp_reach {
                        if has_mp_reach {
                            // Duplicate MP_REACH_NLRI - Session Reset
                            return Err(UpdateParseError {
                                error_code: ErrorCode::Update,
                                error_subcode: ErrorSubcode::Update(
                                    UpdateErrorSubcode::MalformedAttributeList,
                                ),
                                reason:
                                    UpdateParseErrorReason::DuplicateMpReachNlri,
                            });
                        }
                        has_mp_reach = true;
                    }
                    if is_mp_unreach {
                        if has_mp_unreach {
                            // Duplicate MP_UNREACH_NLRI - Session Reset
                            return Err(UpdateParseError {
                                error_code: ErrorCode::Update,
                                error_subcode: ErrorSubcode::Update(
                                    UpdateErrorSubcode::MalformedAttributeList,
                                ),
                                reason: UpdateParseErrorReason::DuplicateMpUnreachNlri,
                            });
                        }
                        has_mp_unreach = true;
                    }

                    let is_mp_bgp = is_mp_reach || is_mp_unreach;

                    if is_mp_bgp || !seen_types.contains(&type_code_u8) {
                        // Keep MP-BGP attributes and first occurrence of
                        // non-MP-BGP attributes.
                        seen_types.insert(type_code_u8);
                        result.push(pa);
                    }
                    // else: discard duplicate non-MP-BGP attribute per RFC 7606 3(g)
                }
                Err(reason) => {
                    // Value parsing failed - determine action based on attribute type
                    let action = typ.error_action();

                    match action {
                        AttributeAction::SessionReset => {
                            // Fatal error - return immediately
                            return Err(UpdateParseError {
                                error_code: ErrorCode::Update,
                                error_subcode: ErrorSubcode::Update(
                                    UpdateErrorSubcode::MalformedAttributeList,
                                ),
                                reason,
                            });
                        }
                        AttributeAction::TreatAsWithdraw => {
                            // Record error, skip this attribute, continue parsing
                            treat_as_withdraw = true;
                            errors.push((reason, action));
                        }
                        AttributeAction::Discard => {
                            // Record error, skip this attribute, continue parsing
                            errors.push((reason, action));
                        }
                    }
                }
            }
        }

        Ok(ParsedPathAttrs {
            attrs: result,
            errors,
            treat_as_withdraw,
        })
    }

    /// This method parses an UpdateMessage and returns a BgpNexthop which
    /// represents the most correct next-hop for the situation. Since there
    /// are so many different ways to encode a BGP nexthop (often only being
    /// valid with certain combinations of MP-BGP address-families and next-hop
    /// capabilities), this method centralizes the logic for parsing and
    /// selection of received nexthops.
    pub fn nexthop(&self) -> Result<BgpNexthop, Error> {
        // Find MP_REACH_NLRI if present
        match self.path_attributes.iter().find_map(|a| match &a.value {
            PathAttributeValue::MpReachNlri(mp) => Some(mp),
            _ => None,
        }) {
            // This Update is MP-BGP, nexthop is already parsed
            Some(mp) => Ok(*mp.nexthop()),
            // This Update is not MP-BGP, use the NEXT_HOP attribute
            None => self
                .nexthop4()
                .map(|n4| n4.into())
                .ok_or(Error::MissingNexthop),
        }
    }

    pub fn nexthop4(&self) -> Option<Ipv4Addr> {
        self.path_attributes.iter().find_map(|a| match a.value {
            PathAttributeValue::NextHop(addr) => Some(addr),
            _ => None,
        })
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
            if let PathAttributeValue::Communities(communities) = &mut a.value {
                communities.push(community);
                return;
            }
        }
        self.path_attributes
            .push(PathAttributeValue::Communities(vec![community]).into());
    }
}

impl Display for UpdateMessage {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let w_str = self
            .withdrawn
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");

        let n_str = self
            .nlri
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");

        let p_str = self
            .path_attributes
            .iter()
            .map(|pa| pa.value.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        write!(
            f,
            "Update[ treat-as-withdraw: ({}) path_attributes: ({p_str}) withdrawn({}) nlri({}) ]",
            self.treat_as_withdraw,
            if !w_str.is_empty() { &w_str } else { "empty" },
            if !n_str.is_empty() { &n_str } else { "empty" }
        )
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

    /// Parse a path attribute from bounded value bytes.
    ///
    /// The caller has already:
    /// 1. Parsed the 2-byte type header (flags + type code)
    /// 2. Validated the attribute flags via `validate_attribute_flags()`
    /// 3. Parsed the length and extracted exactly `len` bytes
    ///
    /// This function parses only the attribute value from the bounded slice.
    fn from_bytes(
        typ: PathAttributeType,
        value_bytes: &[u8],
    ) -> Result<PathAttribute, UpdateParseErrorReason> {
        let value = PathAttributeValue::from_wire(value_bytes, typ.type_code)?;
        Ok(PathAttribute { typ, value })
    }
}

/// RFC 7606 Section 3(c): Validate attribute flags match expected values.
///
/// Each attribute type has specific requirements for the Optional and Transitive
/// flags. If the received flags don't match, the attribute is malformed.
///
/// Returns `Ok(())` if flags are valid, or `Err` with the appropriate error and action.
fn validate_attribute_flags(
    typ: &PathAttributeType,
) -> Result<(), (UpdateParseErrorReason, AttributeAction)> {
    use path_attribute_flags::*;

    let optional = typ.flags & OPTIONAL != 0;
    let transitive = typ.flags & TRANSITIVE != 0;

    // Define expected flags for each known attribute type
    // Format: (expected_optional, expected_transitive)
    let expected = match typ.type_code {
        // Well-known mandatory/discretionary: Optional=0, Transitive=1
        PathAttributeTypeCode::Origin
        | PathAttributeTypeCode::AsPath
        | PathAttributeTypeCode::NextHop
        | PathAttributeTypeCode::LocalPref
        | PathAttributeTypeCode::AtomicAggregate => (false, true),

        // Optional non-transitive: Optional=1, Transitive=0
        PathAttributeTypeCode::MultiExitDisc
        | PathAttributeTypeCode::MpReachNlri
        | PathAttributeTypeCode::MpUnreachNlri => (true, false),

        // Optional transitive: Optional=1, Transitive=1
        PathAttributeTypeCode::Aggregator
        | PathAttributeTypeCode::Communities
        | PathAttributeTypeCode::As4Path
        | PathAttributeTypeCode::As4Aggregator => (true, true),
    };

    let (expected_optional, expected_transitive) = expected;

    if optional != expected_optional || transitive != expected_transitive {
        let reason = UpdateParseErrorReason::InvalidAttributeFlags {
            type_code: typ.type_code as u8,
            flags: typ.flags,
        };
        let action = typ.error_action();
        return Err((reason, action));
    }

    Ok(())
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

    /// Determine RFC 7606 action for errors on this attribute type.
    ///
    /// RFC 7606 specifies different error handling actions for different attribute types:
    /// - Session Reset: Critical errors that prevent reliable parsing
    /// - Treat-as-withdraw: Errors in route-affecting attributes
    /// - Attribute Discard: Errors in informational-only attributes
    pub fn error_action(&self) -> AttributeAction {
        match self.type_code {
            // Well-known mandatory attributes (RFC 7606 Section 7.1-7.3)
            PathAttributeTypeCode::Origin
            | PathAttributeTypeCode::AsPath
            | PathAttributeTypeCode::NextHop => {
                AttributeAction::TreatAsWithdraw
            }

            // MP-BGP attributes: SessionReset on any error because we never
            // negotiate AFI/SAFIs we don't support, so receiving one we can't
            // parse is a protocol violation
            PathAttributeTypeCode::MpReachNlri
            | PathAttributeTypeCode::MpUnreachNlri => {
                AttributeAction::SessionReset
            }

            // MULTI_EXIT_DISC (RFC 7606 Section 7.4): affects route selection
            PathAttributeTypeCode::MultiExitDisc => {
                AttributeAction::TreatAsWithdraw
            }

            // LOCAL_PREF (RFC 7606 Section 7.5): affects route selection
            // Note: From eBGP peers this should be discarded, but that requires
            // session context. For now, treat as withdraw for safety.
            PathAttributeTypeCode::LocalPref => {
                AttributeAction::TreatAsWithdraw
            }

            // Communities (RFC 7606 Section 7.8): affects policy/route selection
            PathAttributeTypeCode::Communities => {
                AttributeAction::TreatAsWithdraw
            }

            // AS4_PATH: Same as AS_PATH, affects loop detection and route selection
            PathAttributeTypeCode::As4Path => AttributeAction::TreatAsWithdraw,

            // ATOMIC_AGGREGATE (RFC 7606 Section 7.6): informational only
            // AGGREGATOR (RFC 7606 Section 7.7): informational only
            // AS4_AGGREGATOR: Same as AGGREGATOR
            // These don't affect route selection, so discard is safe
            PathAttributeTypeCode::AtomicAggregate
            | PathAttributeTypeCode::Aggregator
            | PathAttributeTypeCode::As4Aggregator => AttributeAction::Discard,
        }
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

    /// RFC 4760
    MpReachNlri = 14,
    MpUnreachNlri = 15,

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
            PathAttributeValue::MpReachNlri(_) => {
                PathAttributeTypeCode::MpReachNlri
            }
            PathAttributeValue::MpUnreachNlri(_) => {
                PathAttributeTypeCode::MpUnreachNlri
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
    /// The nexthop associated with a path (IPv4 only for traditional BGP)
    NextHop(Ipv4Addr),
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
    /// Carries reachable MP-BGP NLRI and Next-hop (advertisement).
    MpReachNlri(MpReachNlri),
    /// Carries unreachable MP-BGP NLRI (withdrawal).
    MpUnreachNlri(MpUnreachNlri),
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
            Self::NextHop(addr) => Ok(addr.octets().into()),
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
            Self::MpReachNlri(mp) => mp.to_wire(),
            Self::MpUnreachNlri(mp) => mp.to_wire(),
            x => Err(Error::UnsupportedPathAttributeValue(x.clone())),
        }
    }

    pub fn from_wire(
        mut input: &[u8],
        type_code: PathAttributeTypeCode,
    ) -> Result<PathAttributeValue, UpdateParseErrorReason> {
        // Helper for nom type annotation
        type NomErr<'a> = nom::error::Error<&'a [u8]>;

        match type_code {
            PathAttributeTypeCode::Origin => {
                let (_input, origin) =
                    be_u8::<_, NomErr<'_>>(input).map_err(|e| {
                        UpdateParseErrorReason::AttributeParseError {
                            type_code: Some(type_code as u8),
                            detail: format!("{e}"),
                        }
                    })?;
                PathOrigin::try_from(origin)
                    .map(PathAttributeValue::Origin)
                    .map_err(|_| UpdateParseErrorReason::InvalidOriginValue {
                        value: origin,
                    })
            }
            PathAttributeTypeCode::AsPath => {
                let mut segments = Vec::new();
                loop {
                    if input.is_empty() {
                        break;
                    }
                    let (out, seg) =
                        As4PathSegment::from_wire(input).map_err(|e| {
                            UpdateParseErrorReason::MalformedAsPath {
                                detail: format!("{e}"),
                            }
                        })?;
                    segments.push(seg);
                    input = out;
                }
                Ok(PathAttributeValue::As4Path(segments))
            }
            PathAttributeTypeCode::NextHop => {
                // For IPv4 unicast, the length of this attribute MUST be 4 octets.
                if input.len() != 4 {
                    return Err(UpdateParseErrorReason::MalformedNextHop {
                        expected: 4,
                        got: input.len(),
                    });
                }
                let (_input, b) = take::<_, _, NomErr<'_>>(4usize)(input)
                    .map_err(|e| {
                        UpdateParseErrorReason::AttributeParseError {
                            type_code: Some(type_code as u8),
                            detail: format!("{e}"),
                        }
                    })?;
                Ok(PathAttributeValue::NextHop(Ipv4Addr::new(
                    b[0], b[1], b[2], b[3],
                )))
            }
            PathAttributeTypeCode::MultiExitDisc => {
                let (_input, v) =
                    be_u32::<_, NomErr<'_>>(input).map_err(|e| {
                        UpdateParseErrorReason::AttributeParseError {
                            type_code: Some(type_code as u8),
                            detail: format!("{e}"),
                        }
                    })?;
                Ok(PathAttributeValue::MultiExitDisc(v))
            }
            PathAttributeTypeCode::As4Path => {
                let mut segments = Vec::new();
                loop {
                    if input.is_empty() {
                        break;
                    }
                    let (out, seg) =
                        As4PathSegment::from_wire(input).map_err(|e| {
                            UpdateParseErrorReason::MalformedAsPath {
                                detail: format!("{e}"),
                            }
                        })?;
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
                    let (out, v) =
                        be_u32::<_, NomErr<'_>>(input).map_err(|e| {
                            UpdateParseErrorReason::AttributeParseError {
                                type_code: Some(type_code as u8),
                                detail: format!("{e}"),
                            }
                        })?;
                    communities.push(Community::from(v));
                    input = out;
                }
                Ok(PathAttributeValue::Communities(communities))
            }
            PathAttributeTypeCode::LocalPref => {
                let (_input, v) =
                    be_u32::<_, NomErr<'_>>(input).map_err(|e| {
                        UpdateParseErrorReason::AttributeParseError {
                            type_code: Some(type_code as u8),
                            detail: format!("{e}"),
                        }
                    })?;
                Ok(PathAttributeValue::LocalPref(v))
            }
            PathAttributeTypeCode::MpReachNlri => {
                let (_remaining, mp_reach) = MpReachNlri::from_wire(input)?;
                Ok(PathAttributeValue::MpReachNlri(mp_reach))
            }
            PathAttributeTypeCode::MpUnreachNlri => {
                let (_remaining, mp_unreach) = MpUnreachNlri::from_wire(input)?;
                Ok(PathAttributeValue::MpUnreachNlri(mp_unreach))
            }
            x => Err(UpdateParseErrorReason::UnrecognizedMandatoryAttribute {
                type_code: x as u8,
            }),
        }
    }
}

impl Display for PathAttributeValue {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PathAttributeValue::Origin(po) => write!(f, "origin: {po}"),
            PathAttributeValue::AsPath(path_segs) => {
                let path = path_segs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                write!(f, "as-path: [{path}]")
            }
            PathAttributeValue::NextHop(nh) => write!(f, "next-hop: {nh}"),
            PathAttributeValue::MultiExitDisc(med) => write!(f, "med: {med}"),
            PathAttributeValue::LocalPref(pref) => {
                write!(f, "local-pref: {pref}")
            }
            /*
             *    RFC 4271
             *
             *    g) AGGREGATOR (Type Code 7)
             *
             *       AGGREGATOR is an optional transitive attribute of length 6.
             *       The attribute contains the last AS number that formed the
             *       aggregate route (encoded as 2 octets), followed by the IP
             *       address of the BGP speaker that formed the aggregate route
             *       (encoded as 4 octets).  This SHOULD be the same address as
             *       the one used for the BGP Identifier of the speaker.
             */
            PathAttributeValue::Aggregator(agg) => {
                let [a0, a1, a2, a3, a4, a5] = *agg;
                let asn = u16::from_be_bytes([a0, a1]);
                let ip = Ipv4Addr::from([a2, a3, a4, a5]);
                write!(f, "aggregator: [ asn: {asn}, ip: {ip} ]",)
            }
            PathAttributeValue::Communities(comms) => {
                let comms = comms
                    .iter()
                    .map(|c| u32::from(*c).to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                write!(f, "communities: [{comms}]")
            }
            PathAttributeValue::MpReachNlri(reach) => {
                write!(f, "mp-reach-nlri: {}", reach)
            }
            PathAttributeValue::MpUnreachNlri(unreach) => {
                write!(f, "mp-unreach-nlri: {}", unreach)
            }
            PathAttributeValue::As4Path(path_segs) => {
                let path = path_segs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                write!(f, "as4-path: [{path}]")
            }
            /*
             *   RFC 6793
             *
             *   Similarly, this document defines a new BGP path attribute called
             *   AS4_AGGREGATOR, which is optional transitive.  The AS4_AGGREGATOR
             *   attribute has the same semantics and the same encoding as the
             *   AGGREGATOR attribute, except that it carries a four-octet AS number.
             */
            PathAttributeValue::As4Aggregator(agg) => {
                let [a0, a1, a2, a3, a4, a5, a6, a7] = *agg;
                let asn = u32::from_be_bytes([a0, a1, a2, a3]);
                let ip = Ipv4Addr::from([a4, a5, a6, a7]);
                write!(f, "as4-aggregator: [ asn: {asn}, ip: {ip} ]")
            }
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

impl Display for PathOrigin {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PathOrigin::Igp => write!(f, "igp"),
            PathOrigin::Egp => write!(f, "egp"),
            PathOrigin::Incomplete => write!(f, "incomplete"),
        }
    }
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

impl Display for As4PathSegment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.typ {
            // Wrap an AS-SET in curly braces
            AsPathType::AsSet => {
                let set = self
                    .value
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                write!(f, "{{ {set} }}")
            }
            // Wrap an AS-SEQUENCE in nothing
            AsPathType::AsSequence => {
                let seq = self
                    .value
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                write!(f, "{seq}")
            }
        }
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
/// Next Hop capability. This excerpt contains the encoding logic from RFC 8950:
/// ```text
///    Specifically, this document allows advertising the MP_REACH_NLRI
///    attribute [RFC4760] with this content:
///
///    *  AFI = 1
///
///    *  SAFI = 1, 2, or 4
///
///    *  Length of Next Hop Address = 16 or 32
///
///    *  Next Hop Address = IPv6 address of a next hop (potentially
///       followed by the link-local IPv6 address of the next hop).  This
///       field is to be constructed as per Section 3 of [RFC2545].
///
///    *  NLRI = NLRI as per the AFI/SAFI definition
///
///    [..]
///
///    This is in addition to the existing mode of operation allowing
///    advertisement of NLRI for <AFI/SAFI> of <1/1>, <1/2>, and <1/4> with
///    a next-hop address of an IPv4 type and advertisement of NLRI for an
///    <AFI/SAFI> of <1/128> and <1/129> with a next-hop address of a VPN-
///    IPv4 type.
///
///    The BGP speaker receiving the advertisement MUST use the Length of
///    Next Hop Address field to determine which network-layer protocol the
///    next-hop address belongs to.
///
///    *  When the AFI/SAFI is <1/1>, <1/2>, or <1/4> and when the Length of
///       Next Hop Address field is equal to 16 or 32, the next-hop address
///       is of type IPv6.
///
///    *  When the AFI/SAFI is <1/128> or <1/129> and when the Length of
///       Next Hop Address field is equal to 24 or 48, the next-hop address
///       is of type VPN-IPv6.
/// ```
///
/// RFC 8950 also goes on to state that Extended Next Hop is not specified for
/// any AFI/SAFI other than IPv4 {Unicast, Multicast, Labeled Unicast,
/// Unicast VPN, Multicast VPN}, because IPv4 next-hops can already be signaled
/// within IPv6 or VPN-IPv6 encoding (via IPv4-mapped IPv6 addresses).
///
/// So for our purposes, IPv4 Unicast NLRI may have Next-hops in the form of:
/// a) IPv4 nexthop
/// b) IPv6 single GUA (w/ Extended Next-Hop)
/// c) IPv6 single LL (w/ Extended Next-Hop + Link-Local Next Hop)
/// d) IPv6 double (w/ Extended Next-Hop)
///
/// and IPv6 Unicast NLRI may have Next-hops in the form of:
/// a) IPv6 single (IPv4-mapped)
/// b) IPv6 single GUA
/// c) IPv6 single LL (w/ Link-Local Next Hop)
/// d) IPv6 double
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
pub enum BgpNexthop {
    Ipv4(Ipv4Addr),
    Ipv6Single(Ipv6Addr),
    Ipv6Double((Ipv6Addr, Ipv6Addr)),
}

impl BgpNexthop {
    /// Parse next-hop from raw bytes based on AFI and length.
    ///
    /// Per RFC 4760 and RFC 2545:
    /// - IPv4: 4 bytes (single IPv4 address)
    /// - IPv6: 16 bytes (single global unicast) or 32 bytes (global + link-local)
    ///
    /// # Arguments
    /// * `nh_bytes` - Raw next-hop bytes
    /// * `nh_len` - Next-hop length field
    /// * `afi` - Validated AFI (determines expected format)
    ///
    /// # Returns
    /// Parsed BgpNexthop or error if length is invalid for the AFI
    pub fn from_bytes(
        nh_bytes: &[u8],
        nh_len: u8,
        afi: Afi,
    ) -> Result<Self, Error> {
        if nh_bytes.len() != nh_len as usize {
            return Err(Error::InvalidAddress(format!(
                "next-hop bytes length {} doesn't match nh_len {}",
                nh_bytes.len(),
                nh_len
            )));
        }

        // SAFETY: The length check above guarantees nh_bytes.len() == nh_len.
        // Each match arm below only matches when nh_len equals the exact size
        // needed for copy_from_slice, so all slice operations are bounds-safe.
        // XXX: extended nexthop support
        match (afi, nh_len) {
            (Afi::Ipv4, 4) => {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(nh_bytes);
                Ok(BgpNexthop::Ipv4(Ipv4Addr::from(bytes)))
            }
            (Afi::Ipv6, 16) => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(nh_bytes);
                Ok(BgpNexthop::Ipv6Single(Ipv6Addr::from(bytes)))
            }
            (Afi::Ipv6, 32) => {
                let mut bytes1 = [0u8; 16];
                let mut bytes2 = [0u8; 16];
                bytes1.copy_from_slice(&nh_bytes[..16]);
                bytes2.copy_from_slice(&nh_bytes[16..32]);
                Ok(BgpNexthop::Ipv6Double((
                    Ipv6Addr::from(bytes1),
                    Ipv6Addr::from(bytes2),
                )))
            }
            _ => Err(Error::InvalidAddress(format!(
                "invalid next-hop length {} for AFI {:?}",
                nh_len, afi
            ))),
        }
    }

    /// Get byte length of this next-hop
    pub fn byte_len(&self) -> u8 {
        match self {
            // 4 bytes
            BgpNexthop::Ipv4(_) => (Ipv4Addr::BITS / 8) as u8,
            // 16 bytes
            BgpNexthop::Ipv6Single(_) => (Ipv6Addr::BITS / 8) as u8,
            // 32 bytes
            BgpNexthop::Ipv6Double(_) => ((Ipv6Addr::BITS * 2) / 8) as u8,
        }
    }

    /// Serialize next-hop to wire format bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            BgpNexthop::Ipv4(addr) => addr.octets().to_vec(),
            BgpNexthop::Ipv6Single(addr) => addr.octets().to_vec(),
            BgpNexthop::Ipv6Double((addr1, addr2)) => {
                let mut buf = Vec::new();
                buf.extend_from_slice(&addr1.octets());
                buf.extend_from_slice(&addr2.octets());
                buf
            }
        }
    }
}

impl Display for BgpNexthop {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BgpNexthop::Ipv4(a4) => write!(f, "{a4}"),
            BgpNexthop::Ipv6Single(a6) => write!(f, "{a6}"),
            BgpNexthop::Ipv6Double((a, b)) => write!(f, "({a}, {b})"),
        }
    }
}

impl From<Ipv4Addr> for BgpNexthop {
    fn from(value: Ipv4Addr) -> Self {
        BgpNexthop::Ipv4(value)
    }
}

impl From<Ipv6Addr> for BgpNexthop {
    fn from(value: Ipv6Addr) -> Self {
        BgpNexthop::Ipv6Single(value)
    }
}

impl From<(Ipv6Addr, Ipv6Addr)> for BgpNexthop {
    fn from(value: (Ipv6Addr, Ipv6Addr)) -> Self {
        BgpNexthop::Ipv6Double(value)
    }
}

impl From<IpAddr> for BgpNexthop {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ip4) => BgpNexthop::Ipv4(ip4),
            IpAddr::V6(ip6) => BgpNexthop::Ipv6Single(ip6),
        }
    }
}

/// Parse IPv4 prefixes from wire format
fn prefixes4_from_wire(
    mut buf: &[u8],
) -> Result<Vec<Prefix4>, PrefixParseError> {
    let mut result = Vec::new();
    while !buf.is_empty() {
        let (out, prefix4) = Prefix4::from_wire(buf)?;
        result.push(prefix4);
        buf = out;
    }
    Ok(result)
}

/// Parse IPv6 prefixes from wire format
fn prefixes6_from_wire(
    mut buf: &[u8],
) -> Result<Vec<Prefix6>, PrefixParseError> {
    let mut result = Vec::new();
    while !buf.is_empty() {
        let (out, prefix6) = Prefix6::from_wire(buf)?;
        result.push(prefix6);
        buf = out;
    }
    Ok(result)
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
    /// IPv6 prefixes being announced
    pub nlri: Vec<Prefix6>,
}

impl MpReachNlri {
    /// Returns the AFI for this MP_REACH_NLRI.
    pub fn afi(&self) -> Afi {
        match self {
            Self::Ipv4Unicast(_) => Afi::Ipv4,
            Self::Ipv6Unicast(_) => Afi::Ipv6,
        }
    }

    /// Returns the SAFI for this MP_REACH_NLRI (always Unicast).
    pub fn safi(&self) -> Safi {
        Safi::Unicast
    }

    /// Returns the next-hop for this MP_REACH_NLRI.
    pub fn nexthop(&self) -> &BgpNexthop {
        match self {
            Self::Ipv4Unicast(inner) => &inner.nexthop,
            Self::Ipv6Unicast(inner) => &inner.nexthop,
        }
    }

    /// Returns true if there are no prefixes in this MP_REACH_NLRI.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Ipv4Unicast(inner) => inner.nlri.is_empty(),
            Self::Ipv6Unicast(inner) => inner.nlri.is_empty(),
        }
    }

    /// Returns the number of prefixes in this MP_REACH_NLRI.
    pub fn len(&self) -> usize {
        match self {
            Self::Ipv4Unicast(inner) => inner.nlri.len(),
            Self::Ipv6Unicast(inner) => inner.nlri.len(),
        }
    }

    /// Create an IPv4 Unicast MP_REACH_NLRI.
    pub fn ipv4_unicast(nexthop: BgpNexthop, nlri: Vec<Prefix4>) -> Self {
        Self::Ipv4Unicast(MpReachIpv4Unicast { nexthop, nlri })
    }

    /// Create an IPv6 Unicast MP_REACH_NLRI.
    pub fn ipv6_unicast(nexthop: BgpNexthop, nlri: Vec<Prefix6>) -> Self {
        Self::Ipv6Unicast(MpReachIpv6Unicast { nexthop, nlri })
    }

    /// Serialize to wire format.
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();

        // AFI (2 bytes)
        buf.extend_from_slice(&(self.afi() as u16).to_be_bytes());

        // SAFI (1 byte)
        buf.push(self.safi() as u8);

        // Next-hop
        let nh_bytes = self.nexthop().to_bytes();
        buf.push(nh_bytes.len() as u8); // Next-hop length
        buf.extend_from_slice(&nh_bytes);

        // Reserved (1 byte, must be 0)
        buf.push(0);

        // NLRI
        match self {
            Self::Ipv4Unicast(inner) => {
                for prefix in &inner.nlri {
                    buf.extend_from_slice(&prefix.to_wire());
                }
            }
            Self::Ipv6Unicast(inner) => {
                for prefix in &inner.nlri {
                    buf.extend_from_slice(&prefix.to_wire());
                }
            }
        }

        Ok(buf)
    }

    /// Parse from wire format.
    ///
    /// This validates the AFI/SAFI and parses the next-hop and NLRI into
    /// their proper typed representations.
    ///
    /// Returns an error if:
    /// - The AFI/SAFI combination is unsupported
    /// - The next-hop length is invalid for the AFI
    /// - The NLRI is malformed
    pub fn from_wire(
        input: &[u8],
    ) -> Result<(&[u8], Self), UpdateParseErrorReason> {
        // Parse AFI (2 bytes)
        let (input, afi_raw) = be_u16::<_, nom::error::Error<&[u8]>>(input)
            .map_err(|e| UpdateParseErrorReason::AttributeParseError {
                type_code: Some(PathAttributeTypeCode::MpReachNlri as u8),
                detail: format!("failed to parse AFI: {e}"),
            })?;
        let afi = Afi::try_from(afi_raw).map_err(|_| {
            UpdateParseErrorReason::UnsupportedAfiSafi {
                afi: afi_raw,
                safi: 0,
            }
        })?;

        // Parse SAFI (1 byte)
        let (input, safi_raw) = be_u8::<_, nom::error::Error<&[u8]>>(input)
            .map_err(|e| UpdateParseErrorReason::AttributeParseError {
                type_code: Some(PathAttributeTypeCode::MpReachNlri as u8),
                detail: format!("failed to parse SAFI: {e}"),
            })?;
        let _safi = Safi::try_from(safi_raw).map_err(|_| {
            UpdateParseErrorReason::UnsupportedAfiSafi {
                afi: afi_raw,
                safi: safi_raw,
            }
        })?;

        // Parse Next-hop Length (1 byte)
        let (input, nh_len) = be_u8::<_, nom::error::Error<&[u8]>>(input)
            .map_err(|e| UpdateParseErrorReason::AttributeParseError {
                type_code: Some(PathAttributeTypeCode::MpReachNlri as u8),
                detail: format!("failed to parse next-hop length: {e}"),
            })?;

        // Extract next-hop bytes
        if input.len() < nh_len as usize {
            let expected = match afi {
                Afi::Ipv4 => "4",
                Afi::Ipv6 => "16 or 32",
            };
            return Err(UpdateParseErrorReason::InvalidMpNextHopLength {
                afi: afi_raw,
                expected,
                got: input.len(),
            });
        }
        let nh_bytes = &input[..nh_len as usize];
        let input = &input[nh_len as usize..];

        // Parse next-hop
        let nexthop =
            BgpNexthop::from_bytes(nh_bytes, nh_len, afi).map_err(|_| {
                let expected = match afi {
                    Afi::Ipv4 => "4",
                    Afi::Ipv6 => "16 or 32",
                };
                UpdateParseErrorReason::InvalidMpNextHopLength {
                    afi: afi_raw,
                    expected,
                    got: nh_len as usize,
                }
            })?;

        // Parse Reserved byte (1 byte)
        let (input, _reserved) = be_u8::<_, nom::error::Error<&[u8]>>(input)
            .map_err(|e| UpdateParseErrorReason::AttributeParseError {
                type_code: Some(PathAttributeTypeCode::MpReachNlri as u8),
                detail: format!("failed to parse reserved byte: {e}"),
            })?;

        // Parse NLRI based on AFI
        match afi {
            Afi::Ipv4 => {
                let nlri = prefixes4_from_wire(input)
                    .map_err(|e| e.into_reason("mp_reach"))?;
                Ok((
                    &[],
                    Self::Ipv4Unicast(MpReachIpv4Unicast { nexthop, nlri }),
                ))
            }
            Afi::Ipv6 => {
                let nlri = prefixes6_from_wire(input)
                    .map_err(|e| e.into_reason("mp_reach"))?;
                Ok((
                    &[],
                    Self::Ipv6Unicast(MpReachIpv6Unicast { nexthop, nlri }),
                ))
            }
        }
    }
}

impl Display for MpReachNlri {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4Unicast(inner) => write!(
                f,
                "MpReachNlri::Ipv4Unicast[nh={}, nlri={}]",
                inner.nexthop,
                inner.nlri.len()
            ),
            Self::Ipv6Unicast(inner) => write!(
                f,
                "MpReachNlri::Ipv6Unicast[nh={}, nlri={}]",
                inner.nexthop,
                inner.nlri.len()
            ),
        }
    }
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

impl MpUnreachNlri {
    pub fn afi(&self) -> Afi {
        match self {
            Self::Ipv4Unicast(_) => Afi::Ipv4,
            Self::Ipv6Unicast(_) => Afi::Ipv6,
        }
    }

    pub fn safi(&self) -> Safi {
        Safi::Unicast
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Ipv4Unicast(inner) => inner.withdrawn.is_empty(),
            Self::Ipv6Unicast(inner) => inner.withdrawn.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Ipv4Unicast(inner) => inner.withdrawn.len(),
            Self::Ipv6Unicast(inner) => inner.withdrawn.len(),
        }
    }

    /// Create an IPv4 Unicast MP_UNREACH_NLRI.
    pub fn ipv4_unicast(withdrawn: Vec<Prefix4>) -> Self {
        Self::Ipv4Unicast(MpUnreachIpv4Unicast { withdrawn })
    }

    /// Create an IPv6 Unicast MP_UNREACH_NLRI.
    pub fn ipv6_unicast(withdrawn: Vec<Prefix6>) -> Self {
        Self::Ipv6Unicast(MpUnreachIpv6Unicast { withdrawn })
    }

    /// Serialize to wire format.
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();

        // AFI (2 bytes)
        buf.extend_from_slice(&(self.afi() as u16).to_be_bytes());

        // SAFI (1 byte)
        buf.push(self.safi() as u8);

        // Withdrawn routes
        match self {
            Self::Ipv4Unicast(inner) => {
                for prefix in &inner.withdrawn {
                    buf.extend_from_slice(&prefix.to_wire());
                }
            }
            Self::Ipv6Unicast(inner) => {
                for prefix in &inner.withdrawn {
                    buf.extend_from_slice(&prefix.to_wire());
                }
            }
        }

        Ok(buf)
    }

    /// Parse from wire format.
    ///
    /// This validates the AFI/SAFI and parses the withdrawn routes into
    /// their proper typed representations.
    ///
    /// Returns an error if:
    /// - The AFI/SAFI combination is unsupported
    /// - The withdrawn routes are malformed
    pub fn from_wire(
        input: &[u8],
    ) -> Result<(&[u8], Self), UpdateParseErrorReason> {
        // Parse AFI (2 bytes)
        let (input, afi_raw) = be_u16::<_, nom::error::Error<&[u8]>>(input)
            .map_err(|e| UpdateParseErrorReason::AttributeParseError {
                type_code: Some(PathAttributeTypeCode::MpUnreachNlri as u8),
                detail: format!("failed to parse AFI: {e}"),
            })?;
        let afi = Afi::try_from(afi_raw).map_err(|_| {
            UpdateParseErrorReason::UnsupportedAfiSafi {
                afi: afi_raw,
                safi: 0,
            }
        })?;

        // Parse SAFI (1 byte)
        let (input, safi_raw) = be_u8::<_, nom::error::Error<&[u8]>>(input)
            .map_err(|e| UpdateParseErrorReason::AttributeParseError {
                type_code: Some(PathAttributeTypeCode::MpUnreachNlri as u8),
                detail: format!("failed to parse SAFI: {e}"),
            })?;
        let _safi = Safi::try_from(safi_raw).map_err(|_| {
            UpdateParseErrorReason::UnsupportedAfiSafi {
                afi: afi_raw,
                safi: safi_raw,
            }
        })?;

        // Parse withdrawn routes based on AFI
        match afi {
            Afi::Ipv4 => {
                let withdrawn = prefixes4_from_wire(input)
                    .map_err(|e| e.into_reason("mp_unreach"))?;
                Ok((&[], Self::Ipv4Unicast(MpUnreachIpv4Unicast { withdrawn })))
            }
            Afi::Ipv6 => {
                let withdrawn = prefixes6_from_wire(input)
                    .map_err(|e| e.into_reason("mp_unreach"))?;
                Ok((&[], Self::Ipv6Unicast(MpUnreachIpv6Unicast { withdrawn })))
            }
        }
    }
}

impl Display for MpUnreachNlri {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4Unicast(inner) => write!(
                f,
                "MpUnreachNlri::Ipv4Unicast[withdrawn={}]",
                inner.withdrawn.len()
            ),
            Self::Ipv6Unicast(inner) => write!(
                f,
                "MpUnreachNlri::Ipv6Unicast[withdrawn={}]",
                inner.withdrawn.len()
            ),
        }
    }
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

impl Display for NotificationMessage {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "Notification [ error_code: {}, error_subcode: {}, data: {:?} ]",
            self.error_code, self.error_subcode, self.data
        )
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

impl Display for RouteRefreshMessage {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "Route Refresh [ afi: {}, safi: {} ]",
            self.afi, self.safi
        )
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

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let val = *self as u8;
        match self {
            ErrorCode::Header => write!(f, "{val} (Header)"),
            ErrorCode::Open => write!(f, "{val} (Open)"),
            ErrorCode::Update => write!(f, "{val} (Update)"),
            ErrorCode::HoldTimerExpired => {
                write!(f, "{val} (HoldTimerExpired)")
            }
            ErrorCode::Fsm => write!(f, "{val} (FSM)"),
            ErrorCode::Cease => write!(f, "{val} (Cease)"),
        }
    }
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

impl Display for ErrorSubcode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ErrorSubcode::Header(header_error_subcode) => {
                write!(f, "{header_error_subcode}")
            }
            ErrorSubcode::Open(open_error_subcode) => {
                write!(f, "{open_error_subcode}")
            }
            ErrorSubcode::Update(update_error_subcode) => {
                write!(f, "{update_error_subcode}")
            }
            ErrorSubcode::HoldTime(i) => write!(f, "{i}"),
            ErrorSubcode::Fsm(i) => write!(f, "{i}"),
            ErrorSubcode::Cease(cease_error_subcode) => {
                write!(f, "{cease_error_subcode}")
            }
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

impl Display for HeaderErrorSubcode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let val = *self as u8;
        match self {
            HeaderErrorSubcode::Unspecific => write!(f, "{val}(Unspecific)"),
            HeaderErrorSubcode::ConnectionNotSynchronized => {
                write!(f, "{val}(Connection Not Synchronized)")
            }
            HeaderErrorSubcode::BadMessageLength => {
                write!(f, "{val}(Bad Message Length)")
            }
            HeaderErrorSubcode::BadMessageType => {
                write!(f, "{val}(Bad Message Type)")
            }
        }
    }
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

impl Display for OpenErrorSubcode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let val = *self as u8;
        match self {
            OpenErrorSubcode::Unspecific => write!(f, "{val} (Unspecific)"),
            OpenErrorSubcode::UnsupportedVersionNumber => {
                write!(f, "{val} (UnsupportedVersionNumber)")
            }
            OpenErrorSubcode::BadPeerAS => write!(f, "{val} (Bad Peer AS)"),
            OpenErrorSubcode::BadBgpIdentifier => {
                write!(f, "{val} (Bad BGP Identifier)")
            }
            OpenErrorSubcode::UnsupportedOptionalParameter => {
                write!(f, "{val} (Unsupported Optional Parameter)")
            }
            OpenErrorSubcode::Deprecated => write!(f, "{val} (Deprecated)"),
            OpenErrorSubcode::UnacceptableHoldTime => {
                write!(f, "{val} (Unacceptable Hold Time)")
            }
            OpenErrorSubcode::UnsupportedCapability => {
                write!(f, "{val} (Unsupported Capability)")
            }
        }
    }
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

impl Display for UpdateErrorSubcode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let val = *self as u8;
        match self {
            UpdateErrorSubcode::Unspecific => write!(f, "{val} (Unspecific)"),
            UpdateErrorSubcode::MalformedAttributeList => {
                write!(f, "{val} (Malformed Attribute List)")
            }
            UpdateErrorSubcode::UnrecognizedWellKnownAttribute => {
                write!(f, "{val} (Unrecognized Well-Known Attribute)")
            }
            UpdateErrorSubcode::MissingWellKnownAttribute => {
                write!(f, "{val} (Missing Well-Known Attribute)")
            }
            UpdateErrorSubcode::AttributeFlags => {
                write!(f, "{val} (Attribute Flags)")
            }
            UpdateErrorSubcode::AttributeLength => {
                write!(f, "{val} (Attribute Length)")
            }
            UpdateErrorSubcode::InvalidOriginAttribute => {
                write!(f, "{val} (Invalid Origin Attribute)")
            }
            UpdateErrorSubcode::Deprecated => write!(f, "{val} (Deprecated)"),
            UpdateErrorSubcode::InvalidNexthopAttribute => {
                write!(f, "{val} (Invalid Nexthop Attribute)")
            }
            UpdateErrorSubcode::OptionalAttribute => {
                write!(f, "{val} (Optional Attribute)")
            }
            UpdateErrorSubcode::InvalidNetworkField => {
                write!(f, "{val} (Invalid Network Field)")
            }
            UpdateErrorSubcode::MalformedAsPath => {
                write!(f, "{val} (Malformed AS Path)")
            }
        }
    }
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

impl Display for CeaseErrorSubcode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let val = *self as u8;
        match self {
            CeaseErrorSubcode::Unspecific => write!(f, "{val} (Unspecific)"),
            CeaseErrorSubcode::MaximumNumberofPrefixesReached => {
                write!(f, "{val} (Maximum Number of Prefixes Reached)")
            }
            CeaseErrorSubcode::AdministrativeShutdown => {
                write!(f, "{val} (Administrative Shutdown)")
            }
            CeaseErrorSubcode::PeerDeconfigured => {
                write!(f, "{val} (Peer Deconfigured)")
            }
            CeaseErrorSubcode::AdministrativeReset => {
                write!(f, "{val} (Administratively Reset)")
            }
            CeaseErrorSubcode::ConnectionRejected => {
                write!(f, "{val} (Connection Rejected)")
            }
            CeaseErrorSubcode::OtherConfigurationChange => {
                write!(f, "{val} (Other Configuration Rejected)")
            }
            CeaseErrorSubcode::ConnectionCollisionResolution => {
                write!(f, "{val} (Connection Collision Resolution)")
            }
            CeaseErrorSubcode::OutOfResources => {
                write!(f, "{val} (Out of Resources)")
            }
        }
    }
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

impl Display for OptionalParameter {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            OptionalParameter::Reserved => write!(f, "Reserved (0)"),
            OptionalParameter::Authentication => {
                write!(f, "Authentication (1)")
            }
            OptionalParameter::Capabilities(caps) => {
                let mut cap_string = String::new();
                for cap in caps {
                    cap_string.push_str(&format!("{cap}, "));
                }
                write!(f, "Capabilities [ {cap_string}]")
            }
            OptionalParameter::Unassigned => write!(f, "Unassigned"),
            OptionalParameter::ExtendedLength => {
                write!(f, "Extended Length (255)")
            }
        }
    }
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

impl Display for AddPathElement {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "AddPathElement {{ afi: {}, safi: {}, send_receive: {} }}",
            self.afi, self.safi, self.send_receive
        )
    }
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

impl Display for Capability {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Capability::MultiprotocolExtensions { afi, safi } => {
                write!(f, "MP-Extensions {afi}/{safi}")
            }
            Capability::RouteRefresh {} => {
                write!(f, "Route Refresh")
            }
            Capability::OutboundRouteFiltering {} => {
                write!(f, "ORF")
            }
            Capability::MultipleRoutesToDestination {} => {
                write!(f, "Multiple Routes to Destination")
            }
            Capability::ExtendedNextHopEncoding {} => {
                write!(f, "Extended Next Hop Encoding")
            }
            Capability::BGPExtendedMessage {} => {
                write!(f, "BGP Extended Message")
            }
            Capability::BgpSec {} => {
                write!(f, "BGP Sec")
            }
            Capability::MultipleLabels {} => {
                write!(f, "Multiple Labels")
            }
            Capability::BgpRole {} => {
                write!(f, "BGP Role")
            }
            Capability::GracefulRestart {} => {
                write!(f, "Graceful Restart")
            }
            Capability::FourOctetAs { asn } => {
                write!(f, "Four Octet ASN {asn}")
            }
            Capability::DynamicCapability {} => {
                write!(f, "Dynamic Capability")
            }
            Capability::MultisessionBgp {} => {
                write!(f, "Multi-session BGP")
            }
            Capability::AddPath { elements } => {
                let mut elements_string = String::new();
                for e in elements {
                    elements_string.push_str(&format!("{e}, "));
                }
                write!(f, "AddPath [ {elements_string}]")
            }
            Capability::EnhancedRouteRefresh {} => {
                write!(f, "Enhanced Route Refresh")
            }
            Capability::LongLivedGracefulRestart {} => {
                write!(f, "Long-Lived Graceful Restart")
            }
            Capability::RoutingPolicyDistribution {} => {
                write!(f, "Routing Policy Distribution")
            }
            Capability::Fqdn {} => {
                write!(f, "FQDN")
            }
            Capability::PrestandardRouteRefresh {} => {
                write!(f, "Route Refresh (Prestandard)")
            }
            Capability::PrestandardOrfAndPd {} => {
                write!(f, "ORF / Policy Distribution (Prestandard)")
            }
            Capability::PrestandardOutboundRouteFiltering {} => {
                write!(f, "ORF (Prestandard)")
            }
            Capability::PrestandardMultisession {} => {
                write!(f, "Multi-session BGP (Prestandard)")
            }
            Capability::PrestandardFqdn {} => {
                write!(f, "FQDN (Prestandard)")
            }
            Capability::PrestandardOperationalMessage {} => {
                write!(f, "Operational Message (Prestandard)")
            }
            Capability::Experimental { code } => {
                write!(f, "Experimental ({code})")
            }
            Capability::Unassigned { code } => {
                write!(f, "Unassigned ({code})")
            }
            Capability::Reserved { code } => {
                write!(f, "Reserved ({code})")
            }
        }
    }
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
        let (input, len) = parse_u8(input)?;
        let len = len as usize;
        if input.len() < len {
            return Err(Error::Eom);
        }
        let code = match CapabilityCode::try_from(code) {
            Ok(code) => code,
            Err(_) => {
                return Ok((&input[len..], Capability::Unassigned { code }));
            }
        };
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

    /// Helper function to generate an IPv4 Unicast MP-BGP capability.
    pub fn ipv4_unicast() -> Self {
        Self::MultiprotocolExtensions {
            afi: Afi::Ipv4 as u16,
            safi: Safi::Unicast as u8,
        }
    }

    /// Helper function to generate an IPv6 Unicast MP-BGP capability.
    pub fn ipv6_unicast() -> Self {
        Self::MultiprotocolExtensions {
            afi: Afi::Ipv6 as u16,
            safi: Safi::Unicast as u8,
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
#[derive(
    Debug,
    Copy,
    Clone,
    Deserialize,
    Eq,
    PartialEq,
    Serialize,
    TryFromPrimitive,
    JsonSchema,
)]
#[repr(u16)]
pub enum Afi {
    /// Internet protocol version 4
    Ipv4 = 1,
    /// Internet protocol version 6
    Ipv6 = 2,
}

impl From<Afi> for AddressFamily {
    fn from(value: Afi) -> Self {
        match value {
            Afi::Ipv4 => AddressFamily::Ipv4,
            Afi::Ipv6 => AddressFamily::Ipv6,
        }
    }
}

impl From<AddressFamily> for Afi {
    fn from(value: AddressFamily) -> Self {
        match value {
            AddressFamily::Ipv4 => Afi::Ipv4,
            AddressFamily::Ipv6 => Afi::Ipv6,
        }
    }
}

impl Display for Afi {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Afi::Ipv4 => write!(f, "IPv4"),
            Afi::Ipv6 => write!(f, "IPv6"),
        }
    }
}

impl slog::Value for Afi {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str(key, &self.to_string())
    }
}

/// Subsequent address families supported by Maghemite BGP.
#[derive(
    Debug,
    Copy,
    Clone,
    Deserialize,
    Eq,
    PartialEq,
    Serialize,
    TryFromPrimitive,
    JsonSchema,
)]
#[repr(u8)]
pub enum Safi {
    /// Network Layer Reachability Information used for unicast forwarding
    Unicast = 1,
}

impl Display for Safi {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Safi::Unicast => write!(f, "Unicast"),
        }
    }
}

impl slog::Value for Safi {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str(key, &self.to_string())
    }
}

// ============================================================================
// BGP Message Parse Error Types
// ============================================================================
// These types support revised UPDATE message error handling per RFC 7606,
// which relaxes the "session reset" approach in RFC 4271 §6.3 for UPDATE
// errors. Instead, most attribute errors trigger "treat-as-withdraw" behavior
// allowing sessions to remain established while individual routes are
// withdrawn.
//
// Design:
// - UpdateParseErrorReason: Enum encoding all possible parse error reasons
//   with Display impl for human-readable messages.
// - UpdateParseError: Fatal UPDATE errors requiring session reset.
// - MessageParseError: Wrapper for all message types' parse errors.
// - UpdateMessage.treat_as_withdraw: Bool set when treat-as-withdraw occurs
//   during parsing. false = normal, true = process all NLRI as withdrawals.
// - UpdateMessage.errors: Vec collecting all non-fatal parse errors encountered.

/// All possible reasons for UPDATE parse errors.
///
/// This enum codifies error reasons instead of using strings, providing
/// type safety and consistent error messages via the Display impl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateParseErrorReason {
    // Frame structure errors (fatal)
    /// Withdrawn routes length exceeds available bytes
    InvalidWithdrawnLength { declared: u16, available: usize },
    /// Path attributes length exceeds available bytes
    InvalidAttributeLength { declared: u16, available: usize },

    // Attribute parsing errors
    /// Next-hop attribute has wrong length
    MalformedNextHop { expected: usize, got: usize },
    /// Origin attribute has invalid value
    InvalidOriginValue { value: u8 },
    /// AS_PATH attribute is malformed
    MalformedAsPath { detail: String },
    /// Attribute flags are invalid for this type
    InvalidAttributeFlags { type_code: u8, flags: u8 },

    // MP-BGP errors
    /// Duplicate MP_REACH_NLRI attribute in UPDATE
    DuplicateMpReachNlri,
    /// Duplicate MP_UNREACH_NLRI attribute in UPDATE
    DuplicateMpUnreachNlri,
    /// AFI/SAFI combination not recognized (raw bytes)
    UnsupportedAfiSafi { afi: u16, safi: u8 },
    /// MP next-hop has invalid length for AFI
    InvalidMpNextHopLength {
        afi: u16,
        expected: &'static str,
        got: usize,
    },

    // Attribute-specific errors
    /// Missing mandatory well-known attribute
    MissingAttribute { type_code: PathAttributeTypeCode },
    /// Attribute has invalid length for its type
    AttributeLengthError {
        type_code: PathAttributeTypeCode,
        expected: usize,
        got: usize,
    },
    /// Unrecognized mandatory attribute (not optional/transitive)
    UnrecognizedMandatoryAttribute { type_code: u8 },
    /// Attribute parsing failed (generic fallback for nom errors)
    AttributeParseError {
        type_code: Option<u8>,
        detail: String,
    },

    // NLRI/prefix parsing errors
    /// NLRI section is empty when prefix length byte expected
    NlriMissingLength {
        /// Which section: "nlri", "withdrawn", "mp_reach", "mp_unreach"
        section: &'static str,
    },
    /// Prefix length exceeds maximum for address family (32 for IPv4, 128 for IPv6)
    InvalidNlriMask {
        section: &'static str,
        length: u8,
        max: u8,
    },
    /// Not enough bytes for declared prefix length
    TruncatedNlri {
        section: &'static str,
        needed: usize,
        available: usize,
    },

    // Generic fallback
    /// Other parse error (avoid if possible; prefer specific variant)
    Other { detail: String },
}

impl Display for UpdateParseErrorReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWithdrawnLength {
                declared,
                available,
            } => {
                write!(
                    f,
                    "withdrawn length {} exceeds available {}",
                    declared, available
                )
            }
            Self::InvalidAttributeLength {
                declared,
                available,
            } => {
                write!(
                    f,
                    "attribute length {} exceeds available {}",
                    declared, available
                )
            }
            Self::MalformedNextHop { expected, got } => {
                write!(
                    f,
                    "next-hop length mismatch: expected {}, got {}",
                    expected, got
                )
            }
            Self::InvalidOriginValue { value } => {
                write!(f, "invalid ORIGIN value: {}", value)
            }
            Self::MalformedAsPath { detail } => {
                write!(f, "malformed AS_PATH: {}", detail)
            }
            Self::InvalidAttributeFlags { type_code, flags } => {
                write!(
                    f,
                    "invalid flags 0x{:02x} for attribute type {}",
                    flags, type_code
                )
            }
            Self::DuplicateMpReachNlri => {
                write!(f, "duplicate MP_REACH_NLRI attribute")
            }
            Self::DuplicateMpUnreachNlri => {
                write!(f, "duplicate MP_UNREACH_NLRI attribute")
            }
            Self::UnsupportedAfiSafi { afi, safi } => {
                write!(f, "unsupported AFI/SAFI: {}/{}", afi, safi)
            }
            Self::InvalidMpNextHopLength { afi, expected, got } => {
                write!(
                    f,
                    "invalid MP next-hop length for AFI {}: expected {}, got {}",
                    afi, expected, got
                )
            }
            Self::MissingAttribute { type_code } => {
                write!(f, "missing mandatory attribute: {:?}", type_code)
            }
            Self::AttributeLengthError {
                type_code,
                expected,
                got,
            } => {
                write!(
                    f,
                    "attribute {:?} length error: expected {}, got {}",
                    type_code, expected, got
                )
            }
            Self::UnrecognizedMandatoryAttribute { type_code } => {
                write!(f, "unrecognized mandatory attribute: {}", type_code)
            }
            Self::AttributeParseError { type_code, detail } => {
                match type_code {
                    Some(tc) => {
                        write!(f, "attribute {} parse error: {}", tc, detail)
                    }
                    None => write!(f, "attribute parse error: {}", detail),
                }
            }
            Self::NlriMissingLength { section } => {
                write!(f, "{} NLRI missing prefix length byte", section)
            }
            Self::InvalidNlriMask {
                section,
                length,
                max,
            } => {
                write!(
                    f,
                    "{} NLRI prefix length {} exceeds maximum {}",
                    section, length, max
                )
            }
            Self::TruncatedNlri {
                section,
                needed,
                available,
            } => {
                write!(
                    f,
                    "truncated {} NLRI: need {} bytes, have {}",
                    section, needed, available
                )
            }
            Self::Other { detail } => {
                write!(f, "{}", detail)
            }
        }
    }
}

/// Parsed path attributes from wire format.
///
/// Note: Existence of this struct means no fatal (SessionReset) errors occurred.
/// The parse may still have collected non-fatal errors that require
/// TreatAsWithdraw or Discard handling.
pub struct ParsedPathAttrs {
    /// Successfully parsed attributes
    pub attrs: Vec<PathAttribute>,
    /// All non-fatal errors collected during parsing
    pub errors: Vec<(UpdateParseErrorReason, AttributeAction)>,
    /// True if any TreatAsWithdraw error occurred
    pub treat_as_withdraw: bool,
}

/// Fatal UPDATE parse error requiring session reset.
///
/// Returned by `UpdateMessage::from_wire()` when the error cannot be handled
/// via treat-as-withdraw (e.g., NLRI parse failure, frame structure errors).
#[derive(Debug, Clone)]
pub struct UpdateParseError {
    pub error_code: ErrorCode,
    pub error_subcode: ErrorSubcode,
    pub reason: UpdateParseErrorReason,
}

impl Display for UpdateParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}/{:?}: {}",
            self.error_code, self.error_subcode, self.reason
        )
    }
}

/// All possible reasons for OPEN parse errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenParseErrorReason {
    /// Version number not supported
    InvalidVersion { version: u8 },
    /// Hold time is invalid
    InvalidHoldTime { hold_time: u16 },
    /// Capability not supported
    UnsupportedCapability { code: u8 },
    /// Message too small for required field
    TooSmall { field: &'static str },
    /// Other parse error
    Other { detail: String },
}

impl Display for OpenParseErrorReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVersion { version } => {
                write!(f, "unsupported version: {}", version)
            }
            Self::InvalidHoldTime { hold_time } => {
                write!(f, "invalid hold time: {}", hold_time)
            }
            Self::UnsupportedCapability { code } => {
                write!(f, "unsupported capability: {}", code)
            }
            Self::TooSmall { field } => {
                write!(f, "message too small for {}", field)
            }
            Self::Other { detail } => write!(f, "{}", detail),
        }
    }
}

/// Fatal OPEN parse error requiring session reset.
#[derive(Debug, Clone)]
pub struct OpenParseError {
    pub error_code: ErrorCode,
    pub error_subcode: ErrorSubcode,
    pub reason: OpenParseErrorReason,
}

impl Display for OpenParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}/{:?}: {}",
            self.error_code, self.error_subcode, self.reason
        )
    }
}

/// All possible reasons for NOTIFICATION parse errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationParseErrorReason {
    /// Message too small for required field
    TooSmall { field: &'static str },
    /// Invalid error code
    InvalidErrorCode { code: u8 },
    /// Other parse error
    Other { detail: String },
}

impl Display for NotificationParseErrorReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall { field } => {
                write!(f, "message too small for {}", field)
            }
            Self::InvalidErrorCode { code } => {
                write!(f, "invalid error code: {}", code)
            }
            Self::Other { detail } => write!(f, "{}", detail),
        }
    }
}

/// Fatal NOTIFICATION parse error.
#[derive(Debug, Clone)]
pub struct NotificationParseError {
    pub error_code: ErrorCode,
    pub error_subcode: ErrorSubcode,
    pub reason: NotificationParseErrorReason,
}

impl Display for NotificationParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}/{:?}: {}",
            self.error_code, self.error_subcode, self.reason
        )
    }
}

/// All possible reasons for ROUTE_REFRESH parse errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteRefreshParseErrorReason {
    /// Message too small for required field
    TooSmall { field: &'static str },
    /// Invalid AFI value
    InvalidAfi { afi: u16 },
    /// Other parse error
    Other { detail: String },
}

impl Display for RouteRefreshParseErrorReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall { field } => {
                write!(f, "message too small for {}", field)
            }
            Self::InvalidAfi { afi } => write!(f, "invalid AFI: {}", afi),
            Self::Other { detail } => write!(f, "{}", detail),
        }
    }
}

/// Fatal ROUTE_REFRESH parse error.
#[derive(Debug, Clone)]
pub struct RouteRefreshParseError {
    pub error_code: ErrorCode,
    pub error_subcode: ErrorSubcode,
    pub reason: RouteRefreshParseErrorReason,
}

impl Display for RouteRefreshParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}/{:?}: {}",
            self.error_code, self.error_subcode, self.reason
        )
    }
}

/// Wrapper enum identifying which message type caused a fatal parse error.
///
/// Used by the connection layer to send `ConnectionEvent::ParseError` to the
/// session FSM. All variants represent fatal errors requiring session reset.
#[derive(Debug, Clone)]
pub enum MessageParseError {
    Update(UpdateParseError),
    Open(OpenParseError),
    Notification(NotificationParseError),
    RouteRefresh(RouteRefreshParseError),
}

impl MessageParseError {
    /// Returns a human-readable description of the error for logging/history.
    pub fn description(&self) -> String {
        match self {
            Self::Update(e) => format!("UPDATE: {}", e),
            Self::Open(e) => format!("OPEN: {}", e),
            Self::Notification(e) => format!("NOTIFICATION: {}", e),
            Self::RouteRefresh(e) => format!("ROUTE_REFRESH: {}", e),
        }
    }

    /// Returns the error codes for sending a NOTIFICATION message.
    pub fn error_codes(&self) -> (ErrorCode, ErrorSubcode) {
        match self {
            Self::Update(e) => (e.error_code, e.error_subcode),
            Self::Open(e) => (e.error_code, e.error_subcode),
            Self::Notification(e) => (e.error_code, e.error_subcode),
            Self::RouteRefresh(e) => (e.error_code, e.error_subcode),
        }
    }

    /// Returns the message type that caused the error.
    pub fn message_type(&self) -> &'static str {
        match self {
            Self::Update(_) => "UPDATE",
            Self::Open(_) => "OPEN",
            Self::Notification(_) => "NOTIFICATION",
            Self::RouteRefresh(_) => "ROUTE_REFRESH",
        }
    }
}

impl Display for MessageParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// RFC 7606 action classification for path attribute errors.
///
/// This enum carries no data - the error reason is stored separately
/// in `UpdateParseErrorReason`. Ordered from strongest to weakest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeAction {
    /// Terminate session with NOTIFICATION.
    SessionReset,
    /// Treat all NLRI in message as withdrawn.
    TreatAsWithdraw,
    /// Silently discard the attribute.
    Discard,
}

// ============================================================================
// API Compatibility Types (VERSION_INITIAL / v1.0.0)
// ============================================================================
// These types maintain backward compatibility with the INITIAL API version.
// They support IPv4-only prefixes as the INITIAL release predates IPv6 support.
// Used exclusively for API responses via /bgp/message-history endpoint (v1).
// Never used internally - always convert from current types at API boundary.
//
// Delete these types when VERSION_INITIAL is retired (MGD_API_VERSION_INITIAL
// is no longer supported by dropping support for v1.0.0 API clients).

/// V1 Prefix type for API compatibility (/bgp/message-history)
/// Maintains the old serialization format: {"length": u8, "value": Vec<u8>}
#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, JsonSchema,
)]
pub struct PrefixV1 {
    pub length: u8,
    pub value: Vec<u8>,
}

impl From<Prefix> for PrefixV1 {
    fn from(prefix: Prefix) -> Self {
        // Convert new Prefix enum to old struct format using wire format:
        // length byte followed by prefix octets.
        let wire_bytes = match &prefix {
            Prefix::V4(p) => p.to_wire(),
            Prefix::V6(p) => p.to_wire(),
        };

        // First byte is length, remaining bytes are the address octets
        let length = wire_bytes[0];
        let value = wire_bytes[1..].to_vec();
        Self { length, value }
    }
}

/// V1 UpdateMessage type for API compatibility
/// Uses PrefixV1 for NLRI and withdrawn prefixes
#[derive(
    Debug, PartialEq, Eq, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct UpdateMessageV1 {
    pub withdrawn: Vec<PrefixV1>,
    pub path_attributes: Vec<PathAttribute>,
    pub nlri: Vec<PrefixV1>,
}

impl From<UpdateMessage> for UpdateMessageV1 {
    fn from(msg: UpdateMessage) -> Self {
        Self {
            withdrawn: msg
                .withdrawn
                .into_iter()
                .map(|p| PrefixV1::from(Prefix::V4(p)))
                .collect(),
            path_attributes: msg.path_attributes,
            nlri: msg
                .nlri
                .into_iter()
                .map(|p| PrefixV1::from(Prefix::V4(p)))
                .collect(),
        }
    }
}

/// V1 Message enum for API compatibility
/// Uses V1 types for Message variants
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum MessageV1 {
    Open(OpenMessage),
    Update(UpdateMessageV1),
    Notification(NotificationMessage),
    KeepAlive,
    RouteRefresh(RouteRefreshMessage),
}

impl From<Message> for MessageV1 {
    fn from(msg: Message) -> Self {
        match msg {
            Message::Open(open) => Self::Open(open),
            Message::Update(update) => {
                Self::Update(UpdateMessageV1::from(update))
            }
            Message::Notification(notif) => Self::Notification(notif),
            Message::KeepAlive => Self::KeepAlive,
            Message::RouteRefresh(rr) => Self::RouteRefresh(rr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_common::{cidr, ip, parse};
    use pretty_assertions::assert_eq;
    use pretty_hex::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[derive(Debug)]
    struct PrefixConversionTestCase {
        description: &'static str,
        address_family: AddressFamily,
        prefix_length: u8,
        input_bytes: Vec<u8>,
        expected_address: &'static str,
    }

    impl PrefixConversionTestCase {
        fn new_ipv4(
            description: &'static str,
            prefix_length: u8,
            input_addr: Ipv4Addr,
            expected_address: &'static str,
        ) -> Self {
            Self {
                description,
                address_family: AddressFamily::Ipv4,
                prefix_length,
                input_bytes: input_addr.octets().to_vec(),
                expected_address,
            }
        }

        fn new_ipv6(
            description: &'static str,
            prefix_length: u8,
            input_addr: Ipv6Addr,
            expected_address: &'static str,
        ) -> Self {
            Self {
                description,
                address_family: AddressFamily::Ipv6,
                prefix_length,
                input_bytes: input_addr.octets().to_vec(),
                expected_address,
            }
        }
    }

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
            withdrawn: vec![rdb::Prefix4::new(
                std::net::Ipv4Addr::new(0, 23, 1, 12),
                32,
            )],
            path_attributes: vec![
                PathAttribute {
                    typ: PathAttributeType {
                        flags: path_attribute_flags::TRANSITIVE,
                        type_code: PathAttributeTypeCode::Origin,
                    },
                    value: PathAttributeValue::Origin(PathOrigin::Igp),
                },
                PathAttribute {
                    typ: PathAttributeType {
                        flags: path_attribute_flags::TRANSITIVE,
                        type_code: PathAttributeTypeCode::AsPath,
                    },
                    value: PathAttributeValue::As4Path(vec![As4PathSegment {
                        typ: AsPathType::AsSequence,
                        value: vec![395849, 123456, 987654, 111111],
                    }]),
                },
                PathAttribute {
                    typ: PathAttributeType {
                        flags: path_attribute_flags::TRANSITIVE,
                        type_code: PathAttributeTypeCode::NextHop,
                    },
                    value: PathAttributeValue::NextHop(
                        std::net::Ipv4Addr::new(192, 0, 2, 1),
                    ),
                },
            ],
            nlri: vec![
                rdb::Prefix4::new(std::net::Ipv4Addr::new(0, 23, 1, 13), 32),
                rdb::Prefix4::new(std::net::Ipv4Addr::new(0, 23, 1, 14), 32),
            ],
            treat_as_withdraw: false,
            errors: vec![],
        };

        let buf = um0.to_wire().expect("update message to wire");
        println!("buf: {}", buf.hex_dump());

        let um1 =
            UpdateMessage::from_wire(&buf).expect("update message from wire");
        assert_eq!(um0, um1);
    }

    #[test]
    fn prefix_within() {
        // Test IPv4 prefix containment
        let ipv4_prefixes: &[Prefix] = &[
            cidr!("10.10.10.10/32"),
            cidr!("10.10.10.0/24"),
            cidr!("10.10.0.0/16"),
            cidr!("10.0.0.0/8"),
            cidr!("0.0.0.0/0"),
        ];

        for i in 0..ipv4_prefixes.len() {
            for j in i..ipv4_prefixes.len() {
                // shorter prefixes contain longer or equal
                assert!(ipv4_prefixes[i].within(&ipv4_prefixes[j]));
                if i != j {
                    // longer prefixes should not contain shorter
                    assert!(!ipv4_prefixes[j].within(&ipv4_prefixes[i]))
                }
            }
        }

        // Test IPv6 prefix containment
        let ipv6_prefixes: &[Prefix] = &[
            cidr!("2001:db8:1:1::1/128"),
            cidr!("2001:db8:1:1::/64"),
            cidr!("2001:db8:1::/48"),
            cidr!("2001:db8::/32"),
            cidr!("::/0"),
        ];

        for i in 0..ipv6_prefixes.len() {
            for j in i..ipv6_prefixes.len() {
                // shorter prefixes contain longer or equal
                assert!(ipv6_prefixes[i].within(&ipv6_prefixes[j]));
                if i != j {
                    // longer prefixes should not contain shorter
                    assert!(!ipv6_prefixes[j].within(&ipv6_prefixes[i]))
                }
            }
        }

        // Test non-overlapping prefixes
        let a: Prefix = cidr!("10.10.0.0/16");
        let b: Prefix = cidr!("10.20.0.0/16");
        assert!(!a.within(&b));
        let a: Prefix = cidr!("10.10.0.0/24");
        assert!(!a.within(&b));

        let a: Prefix = cidr!("2001:db8:1::/48");
        let b: Prefix = cidr!("2001:db8:2::/48");
        assert!(!a.within(&b));

        // Test default routes contain same-family prefixes
        let ipv4_default: Prefix = cidr!("0.0.0.0/0");
        let ipv6_default: Prefix = cidr!("::/0");

        let any_ipv4: Prefix = cidr!("192.168.1.0/24");
        let any_ipv6: Prefix = cidr!("2001:db8::/48");

        assert!(any_ipv4.within(&ipv4_default));
        assert!(any_ipv6.within(&ipv6_default));

        // Test cross-family default route edge cases
        // IPv4 prefixes should NOT be within IPv6 default route
        assert!(!any_ipv4.within(&ipv6_default));
        assert!(!ipv4_default.within(&ipv6_default));

        // IPv6 prefixes should NOT be within IPv4 default route
        assert!(!any_ipv6.within(&ipv4_default));
        assert!(!ipv6_default.within(&ipv4_default));
    }

    #[test]
    fn prefix_conversion() {
        // Test both IPv4 and IPv6 prefix conversions including edge cases and host bit zeroing
        let test_cases = vec![
            // IPv4 test cases
            // Input: 0.0.0.0 (default route)
            PrefixConversionTestCase::new_ipv4(
                "IPv4 default route",
                0,
                ip!("0.0.0.0"),
                "0.0.0.0",
            ),
            // Input: 10.255.255.255/8 -> 10.0.0.0/8 (host bits zeroed)
            PrefixConversionTestCase::new_ipv4(
                "IPv4 Class A with host bits",
                8,
                ip!("10.255.255.255"),
                "10.0.0.0",
            ),
            // Input: 172.31.255.255/12 -> 172.16.0.0/12 (host bits zeroed)
            PrefixConversionTestCase::new_ipv4(
                "IPv4 large private network with host bits",
                12,
                ip!("172.31.255.255"),
                "172.16.0.0",
            ),
            // Input: 172.16.255.255/16 -> 172.16.0.0/16 (host bits zeroed)
            PrefixConversionTestCase::new_ipv4(
                "IPv4 common allocation with host bits",
                16,
                ip!("172.16.255.255"),
                "172.16.0.0",
            ),
            // Input: 203.0.113.255/20 -> 203.0.112.0/20 (host bits zeroed)
            PrefixConversionTestCase::new_ipv4(
                "IPv4 prefix with host bits in last 12 bits",
                20,
                ip!("203.0.113.255"),
                "203.0.112.0",
            ),
            // Input: 192.168.1.123/24 -> 192.168.1.0/24 (host bits zeroed)
            PrefixConversionTestCase::new_ipv4(
                "IPv4 common subnet with host bits",
                24,
                ip!("192.168.1.123"),
                "192.168.1.0",
            ),
            // Input: 198.51.100.7/30 -> 198.51.100.4/30 (host bits zeroed)
            PrefixConversionTestCase::new_ipv4(
                "IPv4 point-to-point link with host bits",
                30,
                ip!("198.51.100.7"),
                "198.51.100.4",
            ),
            // Input: 10.0.0.1/32 -> 10.0.0.1/32 (no host bits to zero)
            PrefixConversionTestCase::new_ipv4(
                "IPv4 host route - no host bits to zero",
                32,
                ip!("10.0.0.1"),
                "10.0.0.1",
            ),
            // IPv6 test cases
            // Input: :: (all zeros, default route)
            PrefixConversionTestCase::new_ipv6(
                "IPv6 default route",
                0,
                ip!("::"),
                "::",
            ),
            // Input: fd00:ffff:ffff:ffff:ffff:ffff:ffff:ffff/8 -> fd00::/8 (host bits zeroed)
            PrefixConversionTestCase::new_ipv6(
                "IPv6 unique local address prefix with host bits",
                8,
                ip!("fd00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                "fd00::",
            ),
            // Input: 2001:db8:1234:5678:9abc:def0:1122:3344/32 -> 2001:db8::/32 (host bits zeroed)
            PrefixConversionTestCase::new_ipv6(
                "IPv6 common allocation size with host bits",
                32,
                ip!("2001:db8:1234:5678:9abc:def0:1122:3344"),
                "2001:db8::",
            ),
            // Input: 2001:db8:1234:ffff:ffff:ffff:ffff:ffff/48 -> 2001:db8:1234::/48 (host bits zeroed)
            PrefixConversionTestCase::new_ipv6(
                "IPv6 site prefix with host bits in last 80 bits",
                48,
                ip!("2001:db8:1234:ffff:ffff:ffff:ffff:ffff"),
                "2001:db8:1234::",
            ),
            // Input: 2001:db8::1234:5678:9abc:def0/64 -> 2001:db8::/64 (host bits zeroed)
            PrefixConversionTestCase::new_ipv6(
                "IPv6 common prefix length with host bits",
                64,
                ip!("2001:db8::1234:5678:9abc:def0"),
                "2001:db8::",
            ),
            // Input: 2001:db8::ff/120 -> 2001:db8::/120 (host bits zeroed)
            PrefixConversionTestCase::new_ipv6(
                "IPv6 leaves only 8 host bits",
                120,
                ip!("2001:db8::ff"),
                "2001:db8::",
            ),
            // Input: 2001:db8::1/128 -> 2001:db8::1/128 (no host bits to zero)
            PrefixConversionTestCase::new_ipv6(
                "IPv6 host route - no host bits to zero",
                128,
                ip!("2001:db8::1"),
                "2001:db8::1",
            ),
        ];

        for test_case in test_cases {
            let prefix = match test_case.address_family {
                AddressFamily::Ipv4 => {
                    let mut octets = [0u8; 4];
                    octets.copy_from_slice(&test_case.input_bytes);
                    rdb::Prefix::V4(rdb::Prefix4::new(
                        Ipv4Addr::from(octets),
                        test_case.prefix_length,
                    ))
                }
                AddressFamily::Ipv6 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&test_case.input_bytes);
                    rdb::Prefix::V6(rdb::Prefix6::new(
                        Ipv6Addr::from(octets),
                        test_case.prefix_length,
                    ))
                }
            };

            match test_case.address_family {
                AddressFamily::Ipv4 => {
                    if let rdb::Prefix::V4(rdb_prefix4) = prefix {
                        assert_eq!(
                            rdb_prefix4.length, test_case.prefix_length,
                            "IPv4 length mismatch for {}",
                            test_case.description
                        );
                        assert_eq!(
                            rdb_prefix4.value,
                            Ipv4Addr::from_str(test_case.expected_address)
                                .unwrap(),
                            "IPv4 address mismatch for {}: expected {}, got {}",
                            test_case.description,
                            test_case.expected_address,
                            rdb_prefix4.value
                        );
                        assert!(
                            rdb_prefix4.host_bits_are_unset(),
                            "IPv4 host bits not properly zeroed for {}",
                            test_case.description
                        );
                    } else {
                        panic!("Expected IPv4 prefix");
                    }
                }
                AddressFamily::Ipv6 => {
                    if let rdb::Prefix::V6(rdb_prefix6) = prefix {
                        assert_eq!(
                            rdb_prefix6.length, test_case.prefix_length,
                            "IPv6 length mismatch for {}",
                            test_case.description
                        );
                        assert_eq!(
                            rdb_prefix6.value,
                            Ipv6Addr::from_str(test_case.expected_address)
                                .unwrap(),
                            "IPv6 address mismatch for {}: expected {}, got {}",
                            test_case.description,
                            test_case.expected_address,
                            rdb_prefix6.value
                        );
                        assert!(
                            rdb_prefix6.host_bits_are_unset(),
                            "IPv6 host bits not properly zeroed for {}",
                            test_case.description
                        );
                    } else {
                        panic!("Expected IPv6 prefix");
                    }
                }
            }
        }
    }

    #[test]
    fn test_nexthop_length_validation() {
        // Test that NEXT_HOP path attribute with incorrect length is rejected

        // Build a minimal valid UPDATE message manually, then corrupt the NEXT_HOP length
        let mut buf = Vec::new();

        // Withdrawn routes length (0)
        buf.extend_from_slice(&0u16.to_be_bytes());

        // Path attributes length (will be filled in later)
        let path_attrs_len_offset = buf.len();
        buf.extend_from_slice(&0u16.to_be_bytes());

        let path_attrs_start = buf.len();

        // ORIGIN attribute (well-known, transitive, complete)
        buf.push(0x40); // flags
        buf.push(1); // type code (ORIGIN)
        buf.push(1); // length
        buf.push(0); // IGP

        // AS_PATH attribute (well-known, transitive, complete)
        buf.push(0x40); // flags
        buf.push(2); // type code (AS_PATH)
        buf.push(6); // length
        buf.push(2); // AS_SEQUENCE
        buf.push(1); // path segment length
        buf.extend_from_slice(&(65000u32).to_be_bytes());

        // NEXT_HOP attribute with WRONG LENGTH (16 bytes instead of 4)
        buf.push(0x40); // flags
        buf.push(3); // type code (NEXT_HOP)
        buf.push(16); // length - THIS IS WRONG, should be 4 for IPv4!
        buf.extend_from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1,
        ]); // :: (IPv6)

        // Fill in path attributes length
        let path_attrs_len = (buf.len() - path_attrs_start) as u16;
        buf[path_attrs_len_offset..path_attrs_len_offset + 2]
            .copy_from_slice(&path_attrs_len.to_be_bytes());

        // NLRI: 198.51.100.0/24
        buf.push(24); // prefix length
        buf.extend_from_slice(&[198, 51, 100]); // prefix bytes

        // With RFC 7606 error handling, path attribute errors result in
        // TreatAsWithdraw. The parsing succeeds but returns UpdateMessage
        // with treat_as_withdraw = true and error in errors vec.
        let result = UpdateMessage::from_wire(&buf);
        assert!(result.is_ok(), "Expected Ok with treat_as_withdraw set");

        let msg = result.unwrap();
        assert!(
            msg.treat_as_withdraw,
            "Expected treat_as_withdraw to be true for bad NEXT_HOP length"
        );

        // Verify errors: MalformedNextHop parse error + MissingAttribute
        // (malformed NEXT_HOP doesn't count as present for mandatory attr check)
        assert_eq!(msg.errors.len(), 2, "Expected two errors");

        // First error: MalformedNextHop from parsing
        let (reason, action) = &msg.errors[0];
        assert!(
            matches!(action, AttributeAction::TreatAsWithdraw),
            "Expected TreatAsWithdraw action"
        );
        match reason {
            UpdateParseErrorReason::MalformedNextHop { expected, got } => {
                assert_eq!(*expected, 4, "Expected length should be 4");
                assert_eq!(*got, 16, "Got length should be 16");
            }
            other => panic!(
                "Expected MalformedNextHop {{ expected: 4, got: 16 }}, got {:?}",
                other
            ),
        }

        // Second error: MissingAttribute for NEXT_HOP (malformed doesn't count)
        let (reason2, action2) = &msg.errors[1];
        assert!(
            matches!(action2, AttributeAction::TreatAsWithdraw),
            "Expected TreatAsWithdraw action for missing attr"
        );
        assert!(
            matches!(
                reason2,
                UpdateParseErrorReason::MissingAttribute {
                    type_code: PathAttributeTypeCode::NextHop
                }
            ),
            "Second error should be MissingAttribute for NextHop, got {:?}",
            reason2
        );

        // The NLRI should still be parsed (for processing as withdrawals)
        assert!(!msg.nlri.is_empty(), "Expected NLRI to be present");
    }

    // =========================================================================
    // BgpNexthop tests
    // =========================================================================

    #[test]
    fn bgp_nexthop_ipv4_from_bytes() {
        let bytes = [192, 0, 2, 1];
        let nh = BgpNexthop::from_bytes(&bytes, 4, Afi::Ipv4)
            .expect("valid IPv4 nexthop");
        assert_eq!(nh, BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn bgp_nexthop_ipv6_single_from_bytes() {
        let addr = Ipv6Addr::from_str("2001:db8::1").unwrap();
        let bytes = addr.octets();
        let nh = BgpNexthop::from_bytes(&bytes, 16, Afi::Ipv6)
            .expect("valid IPv6 single nexthop");
        assert_eq!(nh, BgpNexthop::Ipv6Single(addr));
    }

    #[test]
    fn bgp_nexthop_ipv6_double_from_bytes() {
        let global = Ipv6Addr::from_str("2001:db8::1").unwrap();
        let link_local = Ipv6Addr::from_str("fe80::1").unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&global.octets());
        bytes.extend_from_slice(&link_local.octets());

        let nh = BgpNexthop::from_bytes(&bytes, 32, Afi::Ipv6)
            .expect("valid IPv6 double nexthop");
        assert_eq!(nh, BgpNexthop::Ipv6Double((global, link_local)));
    }

    #[test]
    fn bgp_nexthop_invalid_length() {
        // IPv4 AFI with wrong length
        let bytes = [192, 0, 2, 1, 0, 0]; // 6 bytes instead of 4
        let result = BgpNexthop::from_bytes(&bytes, 6, Afi::Ipv4);
        assert!(result.is_err());

        // IPv6 AFI with wrong length (neither 16 nor 32)
        let bytes = [0u8; 20];
        let result = BgpNexthop::from_bytes(&bytes, 20, Afi::Ipv6);
        assert!(result.is_err());
    }

    #[test]
    fn bgp_nexthop_length_mismatch() {
        // nh_bytes.len() != nh_len
        let bytes = [192, 0, 2, 1];
        let result = BgpNexthop::from_bytes(&bytes, 8, Afi::Ipv4);
        assert!(result.is_err());
    }

    #[test]
    fn bgp_nexthop_byte_len() {
        let ipv4 = BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(ipv4.byte_len(), 4);

        let ipv6_single =
            BgpNexthop::Ipv6Single(Ipv6Addr::from_str("2001:db8::1").unwrap());
        assert_eq!(ipv6_single.byte_len(), 16);

        let ipv6_double = BgpNexthop::Ipv6Double((
            Ipv6Addr::from_str("2001:db8::1").unwrap(),
            Ipv6Addr::from_str("fe80::1").unwrap(),
        ));
        assert_eq!(ipv6_double.byte_len(), 32);
    }

    // =========================================================================
    // MpReachNlri tests
    // =========================================================================

    #[test]
    fn mp_reach_nlri_ipv4_unicast() {
        let nh = BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1));
        let nlri = vec![
            rdb::Prefix4::new(Ipv4Addr::new(10, 0, 0, 0), 8),
            rdb::Prefix4::new(Ipv4Addr::new(172, 16, 0, 0), 12),
        ];

        let mp_reach = MpReachNlri::ipv4_unicast(nh, nlri.clone());

        assert_eq!(mp_reach.afi(), Afi::Ipv4);
        assert_eq!(mp_reach.safi(), Safi::Unicast);
        assert_eq!(mp_reach.nexthop(), &nh);
        assert_eq!(mp_reach.len(), 2);

        // Verify inner struct
        if let MpReachNlri::Ipv4Unicast(inner) = &mp_reach {
            assert_eq!(inner.nlri, nlri);
        } else {
            panic!("Expected Ipv4Unicast variant");
        }
    }

    #[test]
    fn mp_reach_nlri_ipv6_unicast() {
        let nh =
            BgpNexthop::Ipv6Single(Ipv6Addr::from_str("2001:db8::1").unwrap());
        let nlri = vec![
            rdb::Prefix6::new(Ipv6Addr::from_str("2001:db8:1::").unwrap(), 48),
            rdb::Prefix6::new(Ipv6Addr::from_str("2001:db8:2::").unwrap(), 48),
        ];

        let mp_reach = MpReachNlri::ipv6_unicast(nh, nlri.clone());

        assert_eq!(mp_reach.afi(), Afi::Ipv6);
        assert_eq!(mp_reach.safi(), Safi::Unicast);
        assert_eq!(mp_reach.nexthop(), &nh);
        assert_eq!(mp_reach.len(), 2);

        // Verify inner struct
        if let MpReachNlri::Ipv6Unicast(inner) = &mp_reach {
            assert_eq!(inner.nlri, nlri);
        } else {
            panic!("Expected Ipv6Unicast variant");
        }
    }

    #[test]
    fn mp_reach_nlri_round_trip() {
        let nh =
            BgpNexthop::Ipv6Single(Ipv6Addr::from_str("2001:db8::1").unwrap());
        let nlri = vec![rdb::Prefix6::new(
            Ipv6Addr::from_str("2001:db8:1::").unwrap(),
            48,
        )];

        let original = MpReachNlri::ipv6_unicast(nh, nlri.clone());
        let wire = original.to_wire().expect("to_wire should succeed");
        let (remaining, parsed) =
            MpReachNlri::from_wire(&wire).expect("from_wire should succeed");

        assert!(remaining.is_empty(), "all bytes should be consumed");
        assert_eq!(original.afi(), parsed.afi());
        assert_eq!(original.safi(), parsed.safi());
        assert_eq!(original.nexthop(), parsed.nexthop());

        // Verify the NLRI matches
        if let (
            MpReachNlri::Ipv6Unicast(orig_inner),
            MpReachNlri::Ipv6Unicast(parsed_inner),
        ) = (&original, &parsed)
        {
            assert_eq!(orig_inner.nlri, parsed_inner.nlri);
        } else {
            panic!("Expected both to be Ipv6Unicast variants");
        }
    }

    // =========================================================================
    // MpUnreachNlri tests
    // =========================================================================

    #[test]
    fn mp_unreach_nlri_ipv6_unicast() {
        let withdrawn = vec![
            rdb::Prefix6::new(Ipv6Addr::from_str("2001:db8:1::").unwrap(), 48),
            rdb::Prefix6::new(Ipv6Addr::from_str("2001:db8:2::").unwrap(), 48),
        ];

        let mp_unreach = MpUnreachNlri::ipv6_unicast(withdrawn.clone());

        assert_eq!(mp_unreach.afi(), Afi::Ipv6);
        assert_eq!(mp_unreach.safi(), Safi::Unicast);
        assert_eq!(mp_unreach.len(), 2);

        // Verify inner struct
        if let MpUnreachNlri::Ipv6Unicast(inner) = &mp_unreach {
            assert_eq!(inner.withdrawn, withdrawn);
        } else {
            panic!("Expected Ipv6Unicast variant");
        }
    }

    #[test]
    fn mp_unreach_nlri_round_trip() {
        let withdrawn = vec![rdb::Prefix6::new(
            Ipv6Addr::from_str("2001:db8:dead::").unwrap(),
            48,
        )];

        let original = MpUnreachNlri::ipv6_unicast(withdrawn.clone());
        let wire = original.to_wire().expect("to_wire should succeed");
        let (remaining, parsed) =
            MpUnreachNlri::from_wire(&wire).expect("from_wire should succeed");

        assert!(remaining.is_empty(), "all bytes should be consumed");
        assert_eq!(original.afi(), parsed.afi());
        assert_eq!(original.safi(), parsed.safi());

        // Verify the withdrawn prefixes match
        if let (
            MpUnreachNlri::Ipv6Unicast(orig_inner),
            MpUnreachNlri::Ipv6Unicast(parsed_inner),
        ) = (&original, &parsed)
        {
            assert_eq!(orig_inner.withdrawn, parsed_inner.withdrawn);
        } else {
            panic!("Expected both to be Ipv6Unicast variants");
        }
    }

    // =========================================================================
    // RFC 7606 validation tests
    // =========================================================================

    /// Test that MP-BGP attributes are always encoded first in the wire format,
    /// regardless of their position in the path_attributes vector.
    ///
    /// RFC 7606 Section 5.1 requires:
    /// "The MP_REACH_NLRI or MP_UNREACH_NLRI attribute (if present) SHALL
    ///  be encoded as the very first path attribute in an UPDATE message."
    #[test]
    fn mp_bgp_attributes_encoded_first() {
        let mp_reach = MpReachNlri::ipv6_unicast(
            BgpNexthop::Ipv6Single(Ipv6Addr::from_str("2001:db8::1").unwrap()),
            vec![],
        );

        // Create an UpdateMessage with MP-BGP attribute NOT first in the vector
        let update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![
                PathAttribute {
                    typ: PathAttributeType {
                        flags: path_attribute_flags::TRANSITIVE,
                        type_code: PathAttributeTypeCode::Origin,
                    },
                    value: PathAttributeValue::Origin(PathOrigin::Igp),
                },
                PathAttribute {
                    typ: PathAttributeType {
                        flags: path_attribute_flags::OPTIONAL,
                        type_code: PathAttributeTypeCode::MpReachNlri,
                    },
                    value: PathAttributeValue::MpReachNlri(mp_reach),
                },
            ],
            nlri: vec![],
            treat_as_withdraw: false,
            errors: vec![],
        };

        // Encode to wire format
        let wire = update.to_wire().expect("encoding should succeed");

        // Skip withdrawn routes length (2 bytes) and empty withdrawn routes (0 bytes)
        // Skip path attributes length (2 bytes)
        // First path attribute should be MP_REACH_NLRI
        let path_attrs_start = 4; // 2 (withdrawn len) + 0 (withdrawn) + 2 (attrs len)

        // Read the first attribute's type code (flags byte + type code byte)
        let first_attr_type_code = wire[path_attrs_start + 1];
        assert_eq!(
            first_attr_type_code,
            PathAttributeTypeCode::MpReachNlri as u8,
            "MP_REACH_NLRI should be encoded as the first path attribute"
        );
    }

    /// Test that decoding accepts both traditional NLRI and MP-BGP encoding
    /// in the same UPDATE message (RFC 7606 Section 5.1 interoperability).
    #[test]
    fn decoding_accepts_mixed_nlri_encoding() {
        // Create an UPDATE with both traditional NLRI and MP_REACH_NLRI
        let mp_reach = MpReachNlri::ipv6_unicast(
            BgpNexthop::Ipv6Single(Ipv6Addr::from_str("2001:db8::1").unwrap()),
            vec![rdb::Prefix6::new(
                Ipv6Addr::from_str("2001:db8::").unwrap(),
                32,
            )],
        );

        let update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![PathAttribute {
                typ: PathAttributeType {
                    flags: path_attribute_flags::OPTIONAL,
                    type_code: PathAttributeTypeCode::MpReachNlri,
                },
                value: PathAttributeValue::MpReachNlri(mp_reach),
            }],
            nlri: vec![rdb::Prefix4::new(Ipv4Addr::new(10, 0, 0, 0), 8)],
            treat_as_withdraw: false,
            errors: vec![],
        };

        // Encode to wire and decode back - should succeed
        let wire = update.to_wire().expect("encoding should succeed");
        let decoded = UpdateMessage::from_wire(&wire);
        assert!(
            decoded.is_ok(),
            "decoding mixed traditional+MP-BGP should succeed"
        );

        let decoded = decoded.unwrap();
        // Verify both encodings are present
        assert_eq!(decoded.nlri.len(), 1, "traditional NLRI should be present");
        assert!(
            decoded
                .path_attributes
                .iter()
                .any(|a| matches!(a.value, PathAttributeValue::MpReachNlri(_))),
            "MP_REACH_NLRI should be present"
        );
    }

    /// Test that decoding accepts both MP_REACH_NLRI and MP_UNREACH_NLRI
    /// in the same UPDATE message (RFC 7606 Section 5.1 interoperability).
    #[test]
    fn decoding_accepts_reach_and_unreach_together() {
        let mp_reach = MpReachNlri::ipv6_unicast(
            BgpNexthop::Ipv6Single(Ipv6Addr::from_str("2001:db8::1").unwrap()),
            vec![rdb::Prefix6::new(
                Ipv6Addr::from_str("2001:db8:1::").unwrap(),
                48,
            )],
        );

        let mp_unreach = MpUnreachNlri::ipv6_unicast(vec![rdb::Prefix6::new(
            Ipv6Addr::from_str("2001:db8:2::").unwrap(),
            48,
        )]);

        let update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![
                PathAttribute {
                    typ: PathAttributeType {
                        flags: path_attribute_flags::OPTIONAL,
                        type_code: PathAttributeTypeCode::MpReachNlri,
                    },
                    value: PathAttributeValue::MpReachNlri(mp_reach),
                },
                PathAttribute {
                    typ: PathAttributeType {
                        flags: path_attribute_flags::OPTIONAL,
                        type_code: PathAttributeTypeCode::MpUnreachNlri,
                    },
                    value: PathAttributeValue::MpUnreachNlri(mp_unreach),
                },
            ],
            nlri: vec![],
            treat_as_withdraw: false,
            errors: vec![],
        };

        // Encode to wire and decode back - should succeed
        let wire = update.to_wire().expect("encoding should succeed");
        let decoded = UpdateMessage::from_wire(&wire);
        assert!(
            decoded.is_ok(),
            "decoding MP_REACH + MP_UNREACH together should succeed"
        );

        let decoded = decoded.unwrap();
        // Verify both are present
        let has_reach = decoded
            .path_attributes
            .iter()
            .any(|a| matches!(a.value, PathAttributeValue::MpReachNlri(_)));
        let has_unreach = decoded
            .path_attributes
            .iter()
            .any(|a| matches!(a.value, PathAttributeValue::MpUnreachNlri(_)));
        assert!(has_reach, "MP_REACH_NLRI should be present");
        assert!(has_unreach, "MP_UNREACH_NLRI should be present");
    }

    /// Test that duplicate non-MP-BGP path attributes are deduplicated during
    /// decoding, keeping only the first occurrence (RFC 7606 Section 3g).
    #[test]
    fn decoding_deduplicates_non_mp_attributes() {
        // Manually construct wire bytes with duplicate ORIGIN attributes
        // to test deduplication during parsing
        let mut wire = Vec::new();

        // Withdrawn routes length (0)
        wire.extend_from_slice(&0u16.to_be_bytes());

        // Path attributes: two ORIGIN attributes (second should be discarded)
        let attrs = vec![
            // First ORIGIN attribute (IGP = 0)
            path_attribute_flags::TRANSITIVE, // flags
            PathAttributeTypeCode::Origin as u8, // type
            1,                                // length
            PathOrigin::Igp as u8,            // value
            // Second ORIGIN attribute (EGP = 1) - should be discarded
            path_attribute_flags::TRANSITIVE,
            PathAttributeTypeCode::Origin as u8,
            1,
            PathOrigin::Egp as u8,
        ];

        // Path attributes length
        wire.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        wire.extend_from_slice(&attrs);

        // NLRI (empty)

        let decoded = UpdateMessage::from_wire(&wire);
        assert!(decoded.is_ok(), "decoding should succeed");

        let decoded = decoded.unwrap();

        // Should only have one ORIGIN attribute (the first one, IGP)
        let origins: Vec<_> = decoded
            .path_attributes
            .iter()
            .filter_map(|a| match &a.value {
                PathAttributeValue::Origin(o) => Some(*o),
                _ => None,
            })
            .collect();

        assert_eq!(
            origins.len(),
            1,
            "should have exactly one ORIGIN after deduplication"
        );
        assert_eq!(
            origins[0],
            PathOrigin::Igp,
            "should keep the first ORIGIN (IGP), not the second (EGP)"
        );
    }

    /// Tests for RFC 7606 attribute error actions.
    mod rfc7606_attribute_actions {
        use crate::messages::{
            AttributeAction, PathAttributeType, PathAttributeTypeCode,
            path_attribute_flags,
        };

        /// Helper to construct PathAttributeType for testing
        fn make_typ(
            type_code: PathAttributeTypeCode,
            flags: u8,
        ) -> PathAttributeType {
            PathAttributeType { flags, type_code }
        }

        #[test]
        fn well_known_mandatory_returns_treat_as_withdraw() {
            // ORIGIN, AS_PATH, NEXT_HOP are well-known mandatory
            // RFC 7606 Section 7.1-7.3: errors should result in treat-as-withdraw
            let well_known_flags = path_attribute_flags::TRANSITIVE;

            assert_eq!(
                make_typ(PathAttributeTypeCode::Origin, well_known_flags)
                    .error_action(),
                AttributeAction::TreatAsWithdraw,
                "ORIGIN errors should treat-as-withdraw"
            );
            assert_eq!(
                make_typ(PathAttributeTypeCode::AsPath, well_known_flags)
                    .error_action(),
                AttributeAction::TreatAsWithdraw,
                "AS_PATH errors should treat-as-withdraw"
            );
            assert_eq!(
                make_typ(PathAttributeTypeCode::NextHop, well_known_flags)
                    .error_action(),
                AttributeAction::TreatAsWithdraw,
                "NEXT_HOP errors should treat-as-withdraw"
            );
        }

        #[test]
        fn multi_exit_disc_returns_treat_as_withdraw() {
            // RFC 7606 Section 7.4: MED affects route selection
            let optional_flags = path_attribute_flags::OPTIONAL;

            assert_eq!(
                make_typ(PathAttributeTypeCode::MultiExitDisc, optional_flags)
                    .error_action(),
                AttributeAction::TreatAsWithdraw,
                "MULTI_EXIT_DISC errors should treat-as-withdraw"
            );
        }

        #[test]
        fn local_pref_returns_treat_as_withdraw() {
            // RFC 7606 Section 7.5: LOCAL_PREF affects route selection
            let well_known_flags = path_attribute_flags::TRANSITIVE;

            assert_eq!(
                make_typ(PathAttributeTypeCode::LocalPref, well_known_flags)
                    .error_action(),
                AttributeAction::TreatAsWithdraw,
                "LOCAL_PREF errors should treat-as-withdraw"
            );
        }

        #[test]
        fn communities_returns_treat_as_withdraw() {
            // RFC 7606 Section 7.8: Communities affect policy/route selection
            let optional_transitive_flags = path_attribute_flags::OPTIONAL
                | path_attribute_flags::TRANSITIVE;

            assert_eq!(
                make_typ(
                    PathAttributeTypeCode::Communities,
                    optional_transitive_flags
                )
                .error_action(),
                AttributeAction::TreatAsWithdraw,
                "Communities errors should treat-as-withdraw"
            );
        }

        #[test]
        fn as4_path_returns_treat_as_withdraw() {
            // AS4_PATH is treated same as AS_PATH
            let optional_transitive_flags = path_attribute_flags::OPTIONAL
                | path_attribute_flags::TRANSITIVE;

            assert_eq!(
                make_typ(
                    PathAttributeTypeCode::As4Path,
                    optional_transitive_flags
                )
                .error_action(),
                AttributeAction::TreatAsWithdraw,
                "AS4_PATH errors should treat-as-withdraw"
            );
        }

        #[test]
        fn atomic_aggregate_returns_discard() {
            // RFC 7606 Section 7.6: ATOMIC_AGGREGATE is informational only
            let well_known_flags = path_attribute_flags::TRANSITIVE;

            assert_eq!(
                make_typ(
                    PathAttributeTypeCode::AtomicAggregate,
                    well_known_flags
                )
                .error_action(),
                AttributeAction::Discard,
                "ATOMIC_AGGREGATE errors should be discarded"
            );
        }

        #[test]
        fn aggregator_returns_discard() {
            // RFC 7606 Section 7.7: AGGREGATOR is informational only
            let optional_transitive_flags = path_attribute_flags::OPTIONAL
                | path_attribute_flags::TRANSITIVE;

            assert_eq!(
                make_typ(
                    PathAttributeTypeCode::Aggregator,
                    optional_transitive_flags
                )
                .error_action(),
                AttributeAction::Discard,
                "AGGREGATOR errors should be discarded"
            );
            assert_eq!(
                make_typ(
                    PathAttributeTypeCode::As4Aggregator,
                    optional_transitive_flags
                )
                .error_action(),
                AttributeAction::Discard,
                "AS4_AGGREGATOR errors should be discarded"
            );
        }

        #[test]
        fn mp_bgp_returns_session_reset() {
            // MP-BGP errors should cause session reset since we never
            // negotiate AFI/SAFIs we don't support
            let optional_flags = path_attribute_flags::OPTIONAL;

            assert_eq!(
                make_typ(PathAttributeTypeCode::MpReachNlri, optional_flags)
                    .error_action(),
                AttributeAction::SessionReset,
                "MP_REACH_NLRI errors should cause session reset"
            );
            assert_eq!(
                make_typ(PathAttributeTypeCode::MpUnreachNlri, optional_flags)
                    .error_action(),
                AttributeAction::SessionReset,
                "MP_UNREACH_NLRI errors should cause session reset"
            );
        }
    }

    /// Tests for RFC 7606 attribute flag validation.
    mod rfc7606_flag_validation {
        use crate::messages::{
            AttributeAction, PathAttributeType, PathAttributeTypeCode,
            UpdateParseErrorReason, path_attribute_flags,
            validate_attribute_flags,
        };

        /// Helper to construct PathAttributeType for testing
        fn make_typ(
            type_code: PathAttributeTypeCode,
            flags: u8,
        ) -> PathAttributeType {
            PathAttributeType { flags, type_code }
        }

        #[test]
        fn well_known_attributes_require_transitive_not_optional() {
            // Well-known mandatory/discretionary: Optional=0, Transitive=1
            let correct_flags = path_attribute_flags::TRANSITIVE;

            // Should accept correct flags
            assert!(
                validate_attribute_flags(&make_typ(
                    PathAttributeTypeCode::Origin,
                    correct_flags
                ))
                .is_ok(),
                "ORIGIN with correct flags should be valid"
            );
            assert!(
                validate_attribute_flags(&make_typ(
                    PathAttributeTypeCode::AsPath,
                    correct_flags
                ))
                .is_ok(),
                "AS_PATH with correct flags should be valid"
            );
            assert!(
                validate_attribute_flags(&make_typ(
                    PathAttributeTypeCode::NextHop,
                    correct_flags
                ))
                .is_ok(),
                "NEXT_HOP with correct flags should be valid"
            );
            assert!(
                validate_attribute_flags(&make_typ(
                    PathAttributeTypeCode::LocalPref,
                    correct_flags
                ))
                .is_ok(),
                "LOCAL_PREF with correct flags should be valid"
            );
            assert!(
                validate_attribute_flags(&make_typ(
                    PathAttributeTypeCode::AtomicAggregate,
                    correct_flags
                ))
                .is_ok(),
                "ATOMIC_AGGREGATE with correct flags should be valid"
            );

            // Should reject Optional flag being set
            let optional_flags = path_attribute_flags::OPTIONAL
                | path_attribute_flags::TRANSITIVE;
            let result = validate_attribute_flags(&make_typ(
                PathAttributeTypeCode::Origin,
                optional_flags,
            ));
            assert!(result.is_err(), "ORIGIN with Optional flag should fail");
            let (reason, _action) = result.unwrap_err();
            assert!(
                matches!(
                    reason,
                    UpdateParseErrorReason::InvalidAttributeFlags { .. }
                ),
                "should return InvalidAttributeFlags error"
            );

            // Should reject missing Transitive flag
            let no_transitive_flags = 0u8;
            let result = validate_attribute_flags(&make_typ(
                PathAttributeTypeCode::AsPath,
                no_transitive_flags,
            ));
            assert!(
                result.is_err(),
                "AS_PATH without Transitive flag should fail"
            );
        }

        #[test]
        fn optional_non_transitive_attributes_require_optional_not_transitive()
        {
            // Optional non-transitive: Optional=1, Transitive=0
            let correct_flags = path_attribute_flags::OPTIONAL;

            // Should accept correct flags
            assert!(
                validate_attribute_flags(&make_typ(
                    PathAttributeTypeCode::MultiExitDisc,
                    correct_flags
                ))
                .is_ok(),
                "MULTI_EXIT_DISC with correct flags should be valid"
            );
            assert!(
                validate_attribute_flags(&make_typ(
                    PathAttributeTypeCode::MpReachNlri,
                    correct_flags
                ))
                .is_ok(),
                "MP_REACH_NLRI with correct flags should be valid"
            );
            assert!(
                validate_attribute_flags(&make_typ(
                    PathAttributeTypeCode::MpUnreachNlri,
                    correct_flags
                ))
                .is_ok(),
                "MP_UNREACH_NLRI with correct flags should be valid"
            );

            // Should reject Transitive flag being set
            let transitive_flags = path_attribute_flags::OPTIONAL
                | path_attribute_flags::TRANSITIVE;
            let result = validate_attribute_flags(&make_typ(
                PathAttributeTypeCode::MultiExitDisc,
                transitive_flags,
            ));
            assert!(
                result.is_err(),
                "MULTI_EXIT_DISC with Transitive flag should fail"
            );

            // Should reject missing Optional flag
            let no_optional_flags = 0u8;
            let result = validate_attribute_flags(&make_typ(
                PathAttributeTypeCode::MpReachNlri,
                no_optional_flags,
            ));
            assert!(
                result.is_err(),
                "MP_REACH_NLRI without Optional flag should fail"
            );
        }

        #[test]
        fn optional_transitive_attributes_require_both_flags() {
            // Optional transitive: Optional=1, Transitive=1
            let correct_flags = path_attribute_flags::OPTIONAL
                | path_attribute_flags::TRANSITIVE;

            // Should accept correct flags
            assert!(
                validate_attribute_flags(&make_typ(
                    PathAttributeTypeCode::Aggregator,
                    correct_flags
                ))
                .is_ok(),
                "AGGREGATOR with correct flags should be valid"
            );
            assert!(
                validate_attribute_flags(&make_typ(
                    PathAttributeTypeCode::Communities,
                    correct_flags
                ))
                .is_ok(),
                "Communities with correct flags should be valid"
            );
            assert!(
                validate_attribute_flags(&make_typ(
                    PathAttributeTypeCode::As4Path,
                    correct_flags
                ))
                .is_ok(),
                "AS4_PATH with correct flags should be valid"
            );
            assert!(
                validate_attribute_flags(&make_typ(
                    PathAttributeTypeCode::As4Aggregator,
                    correct_flags
                ))
                .is_ok(),
                "AS4_AGGREGATOR with correct flags should be valid"
            );

            // Should reject missing Optional flag
            let no_optional_flags = path_attribute_flags::TRANSITIVE;
            let result = validate_attribute_flags(&make_typ(
                PathAttributeTypeCode::Communities,
                no_optional_flags,
            ));
            assert!(
                result.is_err(),
                "Communities without Optional flag should fail"
            );

            // Should reject missing Transitive flag
            let no_transitive_flags = path_attribute_flags::OPTIONAL;
            let result = validate_attribute_flags(&make_typ(
                PathAttributeTypeCode::Aggregator,
                no_transitive_flags,
            ));
            assert!(
                result.is_err(),
                "AGGREGATOR without Transitive flag should fail"
            );
        }

        #[test]
        fn invalid_flags_returns_correct_error_details() {
            let bad_flags = path_attribute_flags::OPTIONAL; // Wrong for ORIGIN
            let result = validate_attribute_flags(&make_typ(
                PathAttributeTypeCode::Origin,
                bad_flags,
            ));

            let (reason, action) = result.expect_err("should return error");

            match reason {
                UpdateParseErrorReason::InvalidAttributeFlags {
                    type_code,
                    flags,
                } => {
                    assert_eq!(
                        type_code,
                        PathAttributeTypeCode::Origin as u8,
                        "should include the attribute type code"
                    );
                    assert_eq!(
                        flags, bad_flags,
                        "should include the invalid flags"
                    );
                }
                _ => panic!("expected InvalidAttributeFlags error"),
            }

            assert_eq!(
                action,
                AttributeAction::TreatAsWithdraw,
                "ORIGIN flag errors should treat-as-withdraw"
            );
        }
    }

    /// Tests for RFC 7606 error collection behavior.
    /// Verifies that multiple errors are collected and parsing continues
    /// after non-fatal (TreatAsWithdraw/Discard) errors.
    mod rfc7606_error_collection {
        use crate::messages::{
            AttributeAction, PathAttributeTypeCode, UpdateMessage,
            UpdateParseErrorReason, path_attribute_flags,
        };

        /// Build an UPDATE message wire format with the given path attributes bytes.
        /// Handles the withdrawn and path attrs length headers automatically.
        fn build_update_wire(path_attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            // Withdrawn routes length (0)
            buf.extend_from_slice(&0u16.to_be_bytes());
            // Path attributes length
            buf.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
            buf.extend_from_slice(path_attrs);
            buf.extend_from_slice(nlri);
            buf
        }

        /// Helper to build a valid ORIGIN attribute (IGP).
        fn origin_attr() -> Vec<u8> {
            vec![
                path_attribute_flags::TRANSITIVE, // flags (0x40)
                PathAttributeTypeCode::Origin as u8, // type 1
                1,                                // length
                0,                                // IGP
            ]
        }

        /// Helper to build a valid AS_PATH attribute with single AS.
        fn as_path_attr(asn: u32) -> Vec<u8> {
            let mut attr = vec![
                path_attribute_flags::TRANSITIVE, // flags (0x40)
                PathAttributeTypeCode::AsPath as u8, // type 2
                6, // length: 1 (segment type) + 1 (count) + 4 (ASN)
                2, // AS_SEQUENCE
                1, // 1 ASN in sequence
            ];
            attr.extend_from_slice(&asn.to_be_bytes());
            attr
        }

        /// Helper to build a valid NEXT_HOP attribute.
        fn next_hop_attr(ip: [u8; 4]) -> Vec<u8> {
            let mut attr = vec![
                path_attribute_flags::TRANSITIVE, // flags (0x40)
                PathAttributeTypeCode::NextHop as u8, // type 3
                4,                                // length
            ];
            attr.extend_from_slice(&ip);
            attr
        }

        /// Helper to build a malformed NEXT_HOP attribute (wrong length).
        /// NEXT_HOP requires exactly 4 bytes for IPv4.
        fn bad_next_hop_attr() -> Vec<u8> {
            vec![
                path_attribute_flags::TRANSITIVE, // flags (0x40)
                PathAttributeTypeCode::NextHop as u8, // type 3
                16,                               // length - WRONG, should be 4
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                192,
                0,
                2,
                1, // 16 bytes
            ]
        }

        /// Helper to build a malformed MULTI_EXIT_DISC attribute (wrong length).
        /// MED requires exactly 4 bytes.
        fn bad_med_attr() -> Vec<u8> {
            vec![
                path_attribute_flags::OPTIONAL, // flags (0x80)
                PathAttributeTypeCode::MultiExitDisc as u8, // type 4
                2,                              // length - WRONG, should be 4
                0,
                100, // only 2 bytes
            ]
        }

        /// Helper to build a malformed AGGREGATOR attribute (wrong length).
        /// AGGREGATOR requires 6 bytes (2-byte AS + 4-byte IP) or 8 bytes (4-byte AS).
        fn bad_aggregator_attr() -> Vec<u8> {
            vec![
                path_attribute_flags::OPTIONAL
                    | path_attribute_flags::TRANSITIVE, // 0xC0
                PathAttributeTypeCode::Aggregator as u8, // type 7
                3,                                       // length - WRONG
                0,
                100,
                1, // only 3 bytes
            ]
        }

        /// Helper to build a malformed ORIGIN attribute (invalid value).
        fn bad_origin_attr() -> Vec<u8> {
            vec![
                path_attribute_flags::TRANSITIVE, // flags (0x40)
                PathAttributeTypeCode::Origin as u8, // type 1
                1,                                // length
                99, // INVALID - must be 0, 1, or 2
            ]
        }

        /// Helper to build NLRI for a /24 prefix.
        fn nlri_prefix(a: u8, b: u8, c: u8) -> Vec<u8> {
            vec![24, a, b, c]
        }

        #[test]
        fn multiple_treat_as_withdraw_errors_collected() {
            // Construct UPDATE with multiple TreatAsWithdraw errors:
            // - Bad ORIGIN (invalid value)
            // - Bad NEXT_HOP (wrong length)
            // - Bad MED (wrong length)
            // Plus mandatory attribute validation adds MissingAttribute errors
            // for ORIGIN and NEXT_HOP since the malformed ones don't count.
            let mut attrs = Vec::new();
            attrs.extend(bad_origin_attr()); // TreatAsWithdraw (parse error)
            attrs.extend(as_path_attr(65000)); // Valid
            attrs.extend(bad_next_hop_attr()); // TreatAsWithdraw (parse error)
            attrs.extend(bad_med_attr()); // TreatAsWithdraw (parse error)

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = UpdateMessage::from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with errors collected"
            );
            let msg = result.unwrap();

            assert!(msg.treat_as_withdraw, "treat_as_withdraw should be true");

            // 3 parse errors + 2 missing attr errors (ORIGIN, NEXT_HOP)
            assert_eq!(
                msg.errors.len(),
                5,
                "Expected 5 errors (3 parse + 2 missing), got {}: {:?}",
                msg.errors.len(),
                msg.errors
            );

            // Verify parse errors are present
            assert!(
                msg.errors.iter().any(|(r, _)| matches!(
                    r,
                    UpdateParseErrorReason::InvalidOriginValue { value: 99 }
                )),
                "Should have InvalidOriginValue error"
            );
            assert!(
                msg.errors.iter().any(|(r, _)| matches!(
                    r,
                    UpdateParseErrorReason::MalformedNextHop {
                        expected: 4,
                        got: 16
                    }
                )),
                "Should have MalformedNextHop error"
            );

            // Verify MissingAttribute errors for ORIGIN and NEXT_HOP
            assert!(
                msg.errors.iter().any(|(r, _)| matches!(
                    r,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::Origin
                    }
                )),
                "Should have MissingAttribute error for Origin"
            );
            assert!(
                msg.errors.iter().any(|(r, _)| matches!(
                    r,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::NextHop
                    }
                )),
                "Should have MissingAttribute error for NextHop"
            );

            // Valid AS_PATH should still be parsed
            assert_eq!(
                msg.path_attributes.len(),
                1,
                "Only valid AS_PATH should be in parsed attributes"
            );
        }

        #[test]
        fn discard_errors_collected_without_treat_as_withdraw() {
            // AGGREGATOR errors result in Discard action (not TreatAsWithdraw)
            // because AGGREGATOR is informational only.
            let mut attrs = Vec::new();
            attrs.extend(origin_attr()); // Valid
            attrs.extend(as_path_attr(65000)); // Valid
            attrs.extend(next_hop_attr([192, 0, 2, 1])); // Valid
            attrs.extend(bad_aggregator_attr()); // Discard

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = UpdateMessage::from_wire(&wire);

            assert!(result.is_ok(), "Parsing should succeed");
            let msg = result.unwrap();

            assert!(
                !msg.treat_as_withdraw,
                "treat_as_withdraw should be false (Discard doesn't set it)"
            );

            assert_eq!(msg.errors.len(), 1, "Expected 1 error (AGGREGATOR)");

            let (reason, action) = &msg.errors[0];
            assert!(
                matches!(action, AttributeAction::Discard),
                "AGGREGATOR error should be Discard, got {:?}",
                action
            );
            // The actual error type may vary based on how parsing fails
            // (UnrecognizedMandatoryAttribute, AttributeLengthError, or AttributeParseError)
            assert!(
                matches!(reason, UpdateParseErrorReason::AttributeLengthError { .. } |
                         UpdateParseErrorReason::AttributeParseError { .. } |
                         UpdateParseErrorReason::UnrecognizedMandatoryAttribute { .. }),
                "Error should be one of the attribute error types, got {:?}",
                reason
            );

            // All valid attributes should be parsed
            assert_eq!(
                msg.path_attributes.len(),
                3,
                "ORIGIN, AS_PATH, NEXT_HOP should all be parsed"
            );
        }

        #[test]
        fn mixed_treat_as_withdraw_and_discard_errors() {
            // Test that both TreatAsWithdraw and Discard errors are collected,
            // and treat_as_withdraw is true when any TaW error is present.
            // bad_next_hop also triggers MissingAttribute for NEXT_HOP.
            let mut attrs = Vec::new();
            attrs.extend(origin_attr()); // Valid
            attrs.extend(bad_aggregator_attr()); // Discard
            attrs.extend(as_path_attr(65000)); // Valid
            attrs.extend(bad_next_hop_attr()); // TreatAsWithdraw (parse error)
            attrs.extend(bad_med_attr()); // TreatAsWithdraw

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = UpdateMessage::from_wire(&wire);

            assert!(result.is_ok(), "Parsing should succeed");
            let msg = result.unwrap();

            assert!(
                msg.treat_as_withdraw,
                "treat_as_withdraw should be true (TaW errors present)"
            );

            // 3 parse errors + 1 MissingAttribute for NEXT_HOP
            assert_eq!(
                msg.errors.len(),
                4,
                "Expected 4 errors (3 parse + 1 missing), got {}: {:?}",
                msg.errors.len(),
                msg.errors
            );

            // Verify the different error types are present
            assert!(
                msg.errors
                    .iter()
                    .any(|(_, a)| matches!(a, AttributeAction::Discard)),
                "Should have at least one Discard error"
            );
            assert!(
                msg.errors.iter().any(|(r, _)| matches!(
                    r,
                    UpdateParseErrorReason::MalformedNextHop { .. }
                )),
                "Should have MalformedNextHop error"
            );
            assert!(
                msg.errors.iter().any(|(r, _)| matches!(
                    r,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::NextHop
                    }
                )),
                "Should have MissingAttribute error for NextHop"
            );

            // Valid ORIGIN and AS_PATH should be parsed
            assert_eq!(
                msg.path_attributes.len(),
                2,
                "ORIGIN and AS_PATH should be parsed"
            );
        }

        #[test]
        fn valid_attributes_after_errors_still_parsed() {
            // Verify that valid attributes appearing AFTER errors are still parsed.
            // Bad ORIGIN causes both a parse error and a MissingAttribute error.
            let mut attrs = Vec::new();
            attrs.extend(bad_origin_attr()); // TreatAsWithdraw - first
            attrs.extend(as_path_attr(65000)); // Valid - after error
            attrs.extend(next_hop_attr([192, 0, 2, 1])); // Valid - after error

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = UpdateMessage::from_wire(&wire);

            assert!(result.is_ok(), "Parsing should succeed");
            let msg = result.unwrap();

            assert!(msg.treat_as_withdraw, "treat_as_withdraw should be true");
            // 1 parse error (InvalidOriginValue) + 1 MissingAttribute (Origin)
            assert_eq!(
                msg.errors.len(),
                2,
                "ORIGIN parse error + MissingAttribute, got: {:?}",
                msg.errors
            );

            // Both valid attributes after the error should be parsed
            assert_eq!(
                msg.path_attributes.len(),
                2,
                "AS_PATH and NEXT_HOP should both be parsed after ORIGIN error"
            );
        }

        #[test]
        fn no_errors_when_all_attributes_valid() {
            // Baseline test: verify no errors when all attributes are valid.
            let mut attrs = Vec::new();
            attrs.extend(origin_attr());
            attrs.extend(as_path_attr(65000));
            attrs.extend(next_hop_attr([192, 0, 2, 1]));

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = UpdateMessage::from_wire(&wire);

            assert!(result.is_ok(), "Parsing should succeed");
            let msg = result.unwrap();

            assert!(
                !msg.treat_as_withdraw,
                "treat_as_withdraw should be false"
            );
            assert!(msg.errors.is_empty(), "No errors expected");
            assert_eq!(msg.path_attributes.len(), 3, "All 3 attributes parsed");
        }

        #[test]
        fn flag_validation_error_collected() {
            // Test that flag validation errors (from validate_attribute_flags)
            // are also collected as non-fatal errors when the action is not SessionReset.
            //
            // ORIGIN with Optional flag set is invalid (well-known must not be Optional)
            // and results in TreatAsWithdraw.
            // The flag-invalid ORIGIN also triggers MissingAttribute since it's skipped.
            // ORIGIN with wrong flags (Optional set, should not be)
            let mut attrs = vec![
                path_attribute_flags::OPTIONAL
                    | path_attribute_flags::TRANSITIVE, // 0xC0 - wrong!
                PathAttributeTypeCode::Origin as u8,
                1, // length
                0, // IGP value
            ];

            // Valid AS_PATH after
            attrs.extend(as_path_attr(65000));
            attrs.extend(next_hop_attr([192, 0, 2, 1]));

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = UpdateMessage::from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with flag error collected"
            );
            let msg = result.unwrap();

            assert!(
                msg.treat_as_withdraw,
                "Flag errors on ORIGIN cause TreatAsWithdraw"
            );
            // 1 flag error + 1 MissingAttribute for Origin (skipped due to bad flags)
            assert_eq!(
                msg.errors.len(),
                2,
                "Flag error + MissingAttribute, got: {:?}",
                msg.errors
            );

            assert!(
                msg.errors.iter().any(|(r, _)| matches!(
                    r,
                    UpdateParseErrorReason::InvalidAttributeFlags { .. }
                )),
                "Should have InvalidAttributeFlags error"
            );
            assert!(
                msg.errors.iter().any(|(r, _)| matches!(
                    r,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::Origin
                    }
                )),
                "Should have MissingAttribute error for Origin"
            );

            // AS_PATH and NEXT_HOP should still be parsed
            assert_eq!(
                msg.path_attributes.len(),
                2,
                "AS_PATH and NEXT_HOP parsed"
            );
        }
    }

    /// Tests for mandatory attribute validation.
    /// RFC 4271 requires ORIGIN, AS_PATH, and NEXT_HOP for traditional BGP UPDATEs.
    /// RFC 4760 makes NEXT_HOP optional when MP_REACH_NLRI is present (nexthop is in MP attr).
    mod mandatory_attribute_validation {
        use std::net::Ipv6Addr;
        use std::str::FromStr;

        use crate::messages::{
            BgpNexthop, MpReachNlri, MpUnreachNlri, PathAttributeTypeCode,
            PathAttributeValue, UpdateMessage, UpdateParseErrorReason,
            path_attribute_flags,
        };

        /// Build an UPDATE message wire format with the given path attributes bytes.
        fn build_update_wire(path_attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&0u16.to_be_bytes()); // withdrawn length
            buf.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes());
            buf.extend_from_slice(path_attrs);
            buf.extend_from_slice(nlri);
            buf
        }

        fn origin_attr() -> Vec<u8> {
            vec![
                path_attribute_flags::TRANSITIVE,
                PathAttributeTypeCode::Origin as u8,
                1,
                0, // IGP
            ]
        }

        fn as_path_attr(asn: u32) -> Vec<u8> {
            let mut attr = vec![
                path_attribute_flags::TRANSITIVE,
                PathAttributeTypeCode::AsPath as u8,
                6,
                2, // AS_SEQUENCE
                1, // 1 ASN
            ];
            attr.extend_from_slice(&asn.to_be_bytes());
            attr
        }

        fn next_hop_attr(ip: [u8; 4]) -> Vec<u8> {
            let mut attr = vec![
                path_attribute_flags::TRANSITIVE,
                PathAttributeTypeCode::NextHop as u8,
                4,
            ];
            attr.extend_from_slice(&ip);
            attr
        }

        fn mp_reach_ipv6_attr() -> Vec<u8> {
            // Build MP_REACH_NLRI for IPv6 unicast with nexthop and one prefix
            let mp_reach = MpReachNlri::ipv6_unicast(
                BgpNexthop::Ipv6Single(
                    Ipv6Addr::from_str("2001:db8::1").unwrap(),
                ),
                vec![rdb::Prefix6::new(
                    Ipv6Addr::from_str("2001:db8:1::").unwrap(),
                    48,
                )],
            );
            let value_bytes =
                mp_reach.to_wire().expect("MP_REACH_NLRI encoding");

            let mut attr = vec![
                path_attribute_flags::OPTIONAL,
                PathAttributeTypeCode::MpReachNlri as u8,
            ];
            // Use extended length if needed
            if value_bytes.len() > 255 {
                attr[0] |= path_attribute_flags::EXTENDED_LENGTH;
                attr.extend_from_slice(
                    &(value_bytes.len() as u16).to_be_bytes(),
                );
            } else {
                attr.push(value_bytes.len() as u8);
            }
            attr.extend_from_slice(&value_bytes);
            attr
        }

        fn nlri_prefix(a: u8, b: u8, c: u8) -> Vec<u8> {
            vec![24, a, b, c]
        }

        // =====================================================================
        // MP-BGP: NEXT_HOP optional with MP_REACH_NLRI, no mandatory attrs
        // for MP_UNREACH_NLRI-only UPDATEs
        // =====================================================================

        #[test]
        fn mp_bgp_update_without_next_hop_succeeds() {
            // When MP_REACH_NLRI is present, the nexthop is carried in the MP
            // attribute, so the traditional NEXT_HOP attribute is not required.
            let mut attrs = Vec::new();
            attrs.extend(origin_attr());
            attrs.extend(as_path_attr(65000));
            attrs.extend(mp_reach_ipv6_attr()); // Has nexthop inside
            // No NEXT_HOP attribute - this is OK for MP-BGP

            // No traditional NLRI either (all NLRI is in MP_REACH_NLRI)
            let wire = build_update_wire(&attrs, &[]);
            let result = UpdateMessage::from_wire(&wire);

            assert!(
                result.is_ok(),
                "MP-BGP UPDATE without NEXT_HOP should succeed: {:?}",
                result.err()
            );
            let msg = result.unwrap();
            assert!(!msg.treat_as_withdraw, "Should not be treat-as-withdraw");
            assert!(
                msg.errors.is_empty(),
                "Should have no errors, got: {:?}",
                msg.errors
            );
        }

        #[test]
        fn mp_bgp_update_with_traditional_nlri_requires_next_hop() {
            // Even with MP_REACH_NLRI present, if there's traditional NLRI,
            // NEXT_HOP is still required for those prefixes.
            let mut attrs = Vec::new();
            attrs.extend(origin_attr());
            attrs.extend(as_path_attr(65000));
            attrs.extend(mp_reach_ipv6_attr());
            // No NEXT_HOP, but we have traditional NLRI

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = UpdateMessage::from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with error collected"
            );
            let msg = result.unwrap();
            assert!(
                msg.treat_as_withdraw,
                "Missing NEXT_HOP with traditional NLRI should treat-as-withdraw"
            );
            assert!(
                msg.errors.iter().any(|(reason, _)| matches!(
                    reason,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::NextHop
                    }
                )),
                "Should have MissingAttribute error for NEXT_HOP, got: {:?}",
                msg.errors
            );
        }

        #[test]
        fn mp_unreach_only_update_does_not_require_mandatory_attrs() {
            // An UPDATE that only carries MP_UNREACH_NLRI (MP-BGP withdrawals)
            // doesn't need mandatory attributes because there's no reachable NLRI.
            let mp_unreach =
                MpUnreachNlri::ipv6_unicast(vec![rdb::Prefix6::new(
                    Ipv6Addr::from_str("2001:db8:1::").unwrap(),
                    48,
                )]);
            let value_bytes =
                mp_unreach.to_wire().expect("MP_UNREACH_NLRI encoding");

            let mut attrs = vec![
                path_attribute_flags::OPTIONAL,
                PathAttributeTypeCode::MpUnreachNlri as u8,
            ];
            if value_bytes.len() > 255 {
                attrs[0] |= path_attribute_flags::EXTENDED_LENGTH;
                attrs.extend_from_slice(
                    &(value_bytes.len() as u16).to_be_bytes(),
                );
            } else {
                attrs.push(value_bytes.len() as u8);
            }
            attrs.extend_from_slice(&value_bytes);

            // No traditional withdrawn, no traditional NLRI
            let wire = build_update_wire(&attrs, &[]);
            let result = UpdateMessage::from_wire(&wire);

            assert!(
                result.is_ok(),
                "MP_UNREACH-only UPDATE should succeed: {:?}",
                result.err()
            );
            let msg = result.unwrap();
            assert!(!msg.treat_as_withdraw, "Should not be treat-as-withdraw");
            assert!(
                msg.errors.is_empty(),
                "Should have no errors for MP_UNREACH-only UPDATE, got: {:?}",
                msg.errors
            );

            // Verify MP_UNREACH_NLRI was parsed
            assert!(
                msg.path_attributes.iter().any(|a| matches!(
                    a.value,
                    PathAttributeValue::MpUnreachNlri(_)
                )),
                "MP_UNREACH_NLRI should be present in parsed attributes"
            );
        }

        // =====================================================================
        // Traditional BGP: All three mandatory attributes required
        // =====================================================================

        #[test]
        fn traditional_update_without_next_hop_errors() {
            // Traditional UPDATE with NLRI requires NEXT_HOP
            let mut attrs = Vec::new();
            attrs.extend(origin_attr());
            attrs.extend(as_path_attr(65000));
            // Missing NEXT_HOP

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = UpdateMessage::from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with error collected"
            );
            let msg = result.unwrap();
            assert!(
                msg.treat_as_withdraw,
                "Missing NEXT_HOP should trigger treat-as-withdraw"
            );
            assert!(
                msg.errors.iter().any(|(reason, _)| matches!(
                    reason,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::NextHop
                    }
                )),
                "Should have MissingAttribute error for NEXT_HOP, got: {:?}",
                msg.errors
            );
        }

        #[test]
        fn traditional_update_without_origin_errors() {
            // Traditional UPDATE requires ORIGIN
            let mut attrs = Vec::new();
            // Missing ORIGIN
            attrs.extend(as_path_attr(65000));
            attrs.extend(next_hop_attr([192, 0, 2, 1]));

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = UpdateMessage::from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with error collected"
            );
            let msg = result.unwrap();
            assert!(
                msg.treat_as_withdraw,
                "Missing ORIGIN should trigger treat-as-withdraw"
            );
            assert!(
                msg.errors.iter().any(|(reason, _)| matches!(
                    reason,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::Origin
                    }
                )),
                "Should have MissingAttribute error for ORIGIN, got: {:?}",
                msg.errors
            );
        }

        #[test]
        fn traditional_update_without_as_path_errors() {
            // Traditional UPDATE requires AS_PATH
            let mut attrs = Vec::new();
            attrs.extend(origin_attr());
            // Missing AS_PATH
            attrs.extend(next_hop_attr([192, 0, 2, 1]));

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = UpdateMessage::from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with error collected"
            );
            let msg = result.unwrap();
            assert!(
                msg.treat_as_withdraw,
                "Missing AS_PATH should trigger treat-as-withdraw"
            );
            assert!(
                msg.errors.iter().any(|(reason, _)| matches!(
                    reason,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::AsPath
                    }
                )),
                "Should have MissingAttribute error for AS_PATH, got: {:?}",
                msg.errors
            );
        }

        #[test]
        fn traditional_update_missing_multiple_mandatory_attrs() {
            // Missing both ORIGIN and AS_PATH - should collect both errors
            let mut attrs = Vec::new();
            // Only NEXT_HOP, missing ORIGIN and AS_PATH
            attrs.extend(next_hop_attr([192, 0, 2, 1]));

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = UpdateMessage::from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with errors collected"
            );
            let msg = result.unwrap();
            assert!(
                msg.treat_as_withdraw,
                "Missing mandatory attrs should trigger treat-as-withdraw"
            );
            assert!(
                msg.errors.iter().any(|(reason, _)| matches!(
                    reason,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::Origin
                    }
                )),
                "Should have MissingAttribute error for ORIGIN"
            );
            assert!(
                msg.errors.iter().any(|(reason, _)| matches!(
                    reason,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::AsPath
                    }
                )),
                "Should have MissingAttribute error for AS_PATH"
            );
        }

        #[test]
        fn withdraw_only_update_does_not_require_mandatory_attrs() {
            // An UPDATE that only withdraws routes doesn't need mandatory attrs
            // because there's no NLRI to apply them to.
            let mut buf = Vec::new();
            // Withdrawn routes: 198.51.100.0/24
            let withdrawn = nlri_prefix(198, 51, 100);
            buf.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
            buf.extend_from_slice(&withdrawn);
            // No path attributes
            buf.extend_from_slice(&0u16.to_be_bytes());
            // No NLRI

            let result = UpdateMessage::from_wire(&buf);

            assert!(
                result.is_ok(),
                "Withdraw-only UPDATE should succeed: {:?}",
                result.err()
            );
            let msg = result.unwrap();
            assert!(!msg.treat_as_withdraw, "Should not be treat-as-withdraw");
            assert!(
                msg.errors.is_empty(),
                "Should have no errors for withdraw-only UPDATE"
            );
        }

        #[test]
        fn empty_update_does_not_require_mandatory_attrs() {
            // An UPDATE with no NLRI and no withdrawn routes (keepalive-like)
            // doesn't need mandatory attributes.
            let wire = build_update_wire(&[], &[]);
            let result = UpdateMessage::from_wire(&wire);

            assert!(
                result.is_ok(),
                "Empty UPDATE should succeed: {:?}",
                result.err()
            );
            let msg = result.unwrap();
            assert!(!msg.treat_as_withdraw, "Should not be treat-as-withdraw");
            assert!(
                msg.errors.is_empty(),
                "Should have no errors for empty UPDATE"
            );
        }
    }
}
