use crate::error::Error;
use nom::{
    bytes::complete::{tag, take},
    number::complete::{be_u16, be_u32, u8 as parse_u8},
};
use num_enum::TryFromPrimitive;
use std::net::IpAddr;

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
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Message {
    Open(OpenMessage),
    Update(UpdateMessage),
    Notification(NotificationMessage),
    KeepAlive,
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
const MARKER: [u8; 16] = [1u8; 16];

impl Header {
    /// Create a new BGP message header. Length must be between 19 and 4096 per
    /// RFC 4271 §4.1.
    pub fn new(length: u16, typ: MessageType) -> Result<Header, Error> {
        if length < 19 {
            return Err(Error::TooSmall);
        }
        if length > 4096 {
            return Err(Error::TooLarge);
        }
        Ok(Header { length, typ })
    }

    /// Serialize the header to wire format.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = vec![1u8; 16];
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
#[derive(Debug, PartialEq, Eq, Clone)]
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
            parameters: vec![Capability::FourOctetAs { asn }.into()],
        }
    }

    /// Serilize an open message to wire format.
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
            return Err(Error::TooLarge);
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
            return Err(Error::TooSmall);
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
#[derive(Debug, PartialEq, Eq, Clone)]
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
            return Err(Error::TooLarge);
        }
        let len = withdrawn.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&withdrawn);

        // path attributes
        let attrs = self.path_attrs_to_wire()?;
        if attrs.len() > u16::MAX as usize {
            return Err(Error::TooLarge);
        }
        let len = attrs.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&attrs);

        // nlri
        buf.extend_from_slice(&self.nlri_to_wire()?);

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
                p.typ.flags & PathAttributeFlags::ExtendedLength as u8 != 0,
            )?);
        }
        Ok(buf)
    }

    fn nlri_to_wire(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        for n in &self.nlri {
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
        loop {
            if buf.is_empty() {
                break;
            }
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
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Prefix {
    pub value: Vec<u8>,
}

impl Prefix {
    fn to_wire(&self) -> Result<Vec<u8>, Error> {
        if self.value.len() > u8::MAX as usize {
            return Err(Error::TooLarge);
        }
        let mut buf = vec![self.value.len() as u8];
        buf.extend_from_slice(&self.value);
        Ok(buf)
    }

    fn from_wire(input: &[u8]) -> Result<(&[u8], Prefix), Error> {
        let (input, len) = parse_u8(input)?;
        let (input, value) = take(len)(input)?;
        Ok((
            input,
            Prefix {
                value: value.to_owned(),
            },
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PathAttribute {
    pub typ: PathAttributeType,
    pub value: PathAttributeValue,
}

impl PathAttribute {
    pub fn to_wire(&self, extended_length: bool) -> Result<Vec<u8>, Error> {
        let mut buf = self.typ.to_wire();
        let val = &self.value.to_wire()?;
        if extended_length {
            if val.len() > u16::MAX as usize {
                return Err(Error::TooLarge);
            }
            let len = val.len() as u16;
            buf.extend_from_slice(&len.to_be_bytes())
        } else {
            if val.len() > u8::MAX as usize {
                return Err(Error::TooLarge);
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
            if typ.flags & PathAttributeFlags::ExtendedLength as u8 != 0 {
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PathAttributeType {
    pub flags: u8,
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

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[repr(u8)]
pub enum PathAttributeFlags {
    Optional = 0b10000000,
    Transitive = 0b01000000,
    Partial = 0b00100000,
    ExtendedLength = 0b00010000,
}

impl std::ops::BitOr<PathAttributeFlags> for PathAttributeFlags {
    type Output = u8;
    fn bitor(self, other: PathAttributeFlags) -> u8 {
        self as u8 | other as u8
    }
}

impl std::ops::BitAnd<PathAttributeFlags> for PathAttributeFlags {
    type Output = u8;
    fn bitand(self, other: PathAttributeFlags) -> u8 {
        self as u8 & other as u8
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum PathAttributeTypeCode {
    /// RFC 4271
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    MultiExitDisc = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,

    /// RFC 6793
    As4Path = 17,
    As4Aggregator = 18,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PathAttributeValue {
    Origin(PathOrigin),
    AsPath(Vec<AsPathSegment>),
    NextHop(IpAddr),
    MultiExitDisc(u32),
    LocalPref(u32),
    Aggregator([u8; 6]),
    As4Path(Vec<As4PathSegment>),
    As4Aggregator([u8; 8]),
}

impl PathAttributeValue {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Origin(_) => todo!(),
            Self::AsPath(_) => todo!(),
            Self::NextHop(_) => todo!(),
            Self::MultiExitDisc(_) => todo!(),
            Self::LocalPref(_) => todo!(),
            Self::Aggregator(_) => todo!(),
            Self::As4Path(segments) => {
                let mut buf = Vec::new();
                for s in segments {
                    buf.extend_from_slice(&s.to_wire()?);
                }
                Ok(buf)
            }
            Self::As4Aggregator(_) => todo!(),
        }
    }

    pub fn from_wire(
        mut input: &[u8],
        type_code: PathAttributeTypeCode,
    ) -> Result<PathAttributeValue, Error> {
        match type_code {
            PathAttributeTypeCode::Origin => todo!(),
            PathAttributeTypeCode::AsPath => todo!(),
            PathAttributeTypeCode::NextHop => todo!(),
            PathAttributeTypeCode::MultiExitDisc => todo!(),
            PathAttributeTypeCode::LocalPref => todo!(),
            PathAttributeTypeCode::AtomicAggregate => todo!(),
            PathAttributeTypeCode::Aggregator => todo!(),
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
            PathAttributeTypeCode::As4Aggregator => todo!(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PathOrigin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AsPathSegment {
    pub typ: AsPathType,
    pub value: Vec<u16>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct As4PathSegment {
    pub typ: AsPathType,
    pub value: Vec<u32>,
}

impl As4PathSegment {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        if self.value.len() > u8::MAX as usize {
            return Err(Error::TooLarge);
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

#[derive(Debug, PartialEq, Eq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum AsPathType {
    AsSet = 1,
    AsSequence = 2,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NotificationMessage {
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Vec<u8>,
}

impl NotificationMessage {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        todo!();
    }
    pub fn from_wire(_input: &[u8]) -> Result<NotificationMessage, Error> {
        todo!();
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Header,
    Open,
    Update,
    HoldTimerExpired,
    Fsm,
    Cease,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HeaderErrorSubcode {
    ConnectionNotSynchronized,
    BadMessageLength,
    BadMessageType,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpenErrorSubcode {
    UnsupportedVersionNumber,
    BadPeerAS,
    BadBgpIdentifier,
    UnsupportedOptionalParameter,
    Deprecated,
    UnacceptableHoldTime,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UpdateErrorSubcode {
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

/// The IANA/IETF currently defines the following optional parameter types.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OptionalParameter {
    /// Code 0
    Reserved,

    /// Code 1: RFC 4217, RFC 5492 (deprecated)
    Authentication, //TODO

    /// Code 2: RFC 5492
    Capability(Capability),

    Unassigned,

    /// Code 255: RFC 9072
    ExtendedLength, //TODO
}

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum OptionalParameterCode {
    Reserved = 0,
    Authentication = 1,
    Capability = 2,
    ExtendedLength = 255,
}

impl From<Capability> for OptionalParameter {
    fn from(c: Capability) -> OptionalParameter {
        OptionalParameter::Capability(c)
    }
}

impl OptionalParameter {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Reserved => Err(Error::Reserved),
            Self::Unassigned => Err(Error::Unassigned(0)),
            Self::Authentication => todo!(),
            Self::Capability(c) => {
                let mut buf = vec![OptionalParameterCode::Capability as u8];
                let cbuf = c.to_wire()?;
                buf.push(cbuf.len() as u8);
                buf.extend_from_slice(&cbuf);
                Ok(buf)
            }
            Self::ExtendedLength => todo!(),
        }
    }

    pub fn from_wire(
        input: &[u8],
    ) -> Result<(&[u8], OptionalParameter), Error> {
        let (input, code) = parse_u8(input)?;
        let code = OptionalParameterCode::try_from(code)?;
        let (input, len) = parse_u8(input)?;
        let (input, capability_input) = take(len)(input)?;

        match code {
            OptionalParameterCode::Reserved => Err(Error::Reserved),
            OptionalParameterCode::Authentication => todo!(),
            OptionalParameterCode::Capability => {
                let (_, cap) = Capability::from_wire(capability_input)?;
                Ok((input, cap.into()))
            }
            OptionalParameterCode::ExtendedLength => todo!(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Capability {
    /// RFC 2858 TODO
    MultiprotocolExtensions {},

    /// RFC 2918 TODO
    RouteRefresh {},

    /// RFC 5291 TODO
    OutboundRouteFiltering {},

    /// RFC 8277 (deprecated) TODO
    MultipleRoutesToDestination {},

    /// RFC 8950 TODO
    ExtendedNextHopEncoding {},

    /// RFC 8654 TODO
    BGPExtendedMessage {},

    /// RFC 8205 TODO
    BgpSec {},

    /// RFC 8277 TODO
    MultipleLabels {},

    /// RFC 9234 TODO
    BgpRole {},

    /// RFC 4724 TODO
    GracefulRestart {},

    /// RFC 6793
    FourOctetAs {
        asn: u32,
    },

    /// draft-ietf-idr-dynamic-cap TODO
    DynamicCapability {},

    /// draft-ietf-idr-bgp-multisession TODO
    MultisessionBgp {},

    /// RFC 7911 TODO
    AddPath {},

    /// RFC 7313 TODO
    EnhancedRouteRefresh {},

    /// draft-uttaro-idr-bgp-persistence TODO
    LongLivedGracefulRestart {},

    /// draft-ietf-idr-rpd-04 TODO
    RoutingPolicyDistribution {},

    /// draft-walton-bgp-hostname-capability TODO
    Fqdn {},

    /// RFC 8810 (deprecated) TODO
    PrestandardRouteRefresh {},

    /// RFC 8810 (deprecated) TODO
    PrestandardOrfAndPd {},

    /// RFC 8810 (deprecated) TODO
    PrestandardOutboundRouteFiltering {},

    /// RFC 8810 (deprecated) TODO
    PrestandardMultisession {},

    /// RFC 8810 (deprecated) TODO
    PrestandardFqdn {},

    /// RFC 8810 (deprecated) TODO
    PrestandardOpereationalMessage {},

    /// RFC 8810
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
            Self::MultiprotocolExtensions {} => todo!(),
            Self::RouteRefresh {} => todo!(),
            Self::OutboundRouteFiltering {} => todo!(),
            Self::MultipleRoutesToDestination {} => todo!(),
            Self::ExtendedNextHopEncoding {} => todo!(),
            Self::BGPExtendedMessage {} => todo!(),
            Self::BgpSec {} => todo!(),
            Self::MultipleLabels {} => todo!(),
            Self::BgpRole {} => todo!(),
            Self::GracefulRestart {} => todo!(),
            Self::FourOctetAs { asn } => {
                let mut buf = vec![CapabilityCode::FourOctetAs as u8, 4];
                buf.extend_from_slice(&asn.to_be_bytes());
                Ok(buf)
            }
            Self::DynamicCapability {} => todo!(),
            Self::MultisessionBgp {} => todo!(),
            Self::AddPath {} => todo!(),
            Self::EnhancedRouteRefresh {} => todo!(),
            Self::LongLivedGracefulRestart {} => todo!(),
            Self::RoutingPolicyDistribution {} => todo!(),
            Self::Fqdn {} => todo!(),
            Self::PrestandardRouteRefresh {} => todo!(),
            Self::PrestandardOrfAndPd {} => todo!(),
            Self::PrestandardOutboundRouteFiltering {} => todo!(),
            Self::PrestandardMultisession {} => todo!(),
            Self::PrestandardFqdn {} => todo!(),
            Self::PrestandardOpereationalMessage {} => todo!(),
            Self::Experimental { code: _ } => Err(Error::Experimental),
            Self::Unassigned { code } => Err(Error::Unassigned(*code)),
            Self::Reserved { code: _ } => Err(Error::Reserved),
        }
    }

    pub fn from_wire(input: &[u8]) -> Result<(&[u8], Capability), Error> {
        let (input, code) = parse_u8(input)?;
        let code = CapabilityCode::try_from(code)?;
        let (input, len) = parse_u8(input)?;
        if input.len() < len as usize {
            return Err(Error::Eom);
        }

        match code {
            CapabilityCode::MultiprotocolExtensions => todo!(),
            CapabilityCode::RouteRefresh => todo!(),
            CapabilityCode::OutboundRouteFiltering => todo!(),
            CapabilityCode::MultipleRoutesToDestination => todo!(),
            CapabilityCode::ExtendedNextHopEncoding => todo!(),
            CapabilityCode::BGPExtendedMessage => todo!(),
            CapabilityCode::BgpSec => todo!(),
            CapabilityCode::MultipleLabels => todo!(),
            CapabilityCode::BgpRole => todo!(),
            CapabilityCode::GracefulRestart => todo!(),
            CapabilityCode::FourOctetAs => {
                let (input, asn) = be_u32(input)?;
                Ok((input, Capability::FourOctetAs { asn }))
            }
            CapabilityCode::DynamicCapability => todo!(),
            CapabilityCode::MultisessionBgp => todo!(),
            CapabilityCode::AddPath => todo!(),
            CapabilityCode::EnhancedRouteRefresh => todo!(),
            CapabilityCode::LongLivedGracefulRestart => todo!(),
            CapabilityCode::RoutingPolicyDistribution => todo!(),
            CapabilityCode::Fqdn => todo!(),
            CapabilityCode::PrestandardRouteRefresh => todo!(),
            CapabilityCode::PrestandardOrfAndPd => todo!(),
            CapabilityCode::PrestandardOutboundRouteFiltering => todo!(),
            CapabilityCode::PrestandardMultisession => todo!(),
            CapabilityCode::PrestandardFqdn => todo!(),
            CapabilityCode::PrestandardOpereationalMessage => todo!(),
            CapabilityCode::Experimental0 => Err(Error::Experimental),
            CapabilityCode::Experimental1 => Err(Error::Experimental),
            CapabilityCode::Experimental2 => Err(Error::Experimental),
            CapabilityCode::Experimental3 => Err(Error::Experimental),
            CapabilityCode::Experimental4 => Err(Error::Experimental),
            CapabilityCode::Experimental5 => Err(Error::Experimental),
            CapabilityCode::Experimental6 => Err(Error::Experimental),
            CapabilityCode::Experimental7 => Err(Error::Experimental),
            CapabilityCode::Experimental8 => Err(Error::Experimental),
            CapabilityCode::Experimental9 => Err(Error::Experimental),
            CapabilityCode::Experimental10 => Err(Error::Experimental),
            CapabilityCode::Experimental11 => Err(Error::Experimental),
            CapabilityCode::Experimental12 => Err(Error::Experimental),
            CapabilityCode::Experimental13 => Err(Error::Experimental),
            CapabilityCode::Experimental14 => Err(Error::Experimental),
            CapabilityCode::Experimental15 => Err(Error::Experimental),
            CapabilityCode::Experimental16 => Err(Error::Experimental),
            CapabilityCode::Experimental17 => Err(Error::Experimental),
            CapabilityCode::Experimental18 => Err(Error::Experimental),
            CapabilityCode::Experimental19 => Err(Error::Experimental),
            CapabilityCode::Experimental20 => Err(Error::Experimental),
            CapabilityCode::Experimental21 => Err(Error::Experimental),
            CapabilityCode::Experimental22 => Err(Error::Experimental),
            CapabilityCode::Experimental23 => Err(Error::Experimental),
            CapabilityCode::Experimental24 => Err(Error::Experimental),
            CapabilityCode::Experimental25 => Err(Error::Experimental),
            CapabilityCode::Experimental26 => Err(Error::Experimental),
            CapabilityCode::Experimental27 => Err(Error::Experimental),
            CapabilityCode::Experimental28 => Err(Error::Experimental),
            CapabilityCode::Experimental29 => Err(Error::Experimental),
            CapabilityCode::Experimental30 => Err(Error::Experimental),
            CapabilityCode::Experimental31 => Err(Error::Experimental),
            CapabilityCode::Experimental32 => Err(Error::Experimental),
            CapabilityCode::Experimental33 => Err(Error::Experimental),
            CapabilityCode::Experimental34 => Err(Error::Experimental),
            CapabilityCode::Experimental35 => Err(Error::Experimental),
            CapabilityCode::Experimental36 => Err(Error::Experimental),
            CapabilityCode::Experimental37 => Err(Error::Experimental),
            CapabilityCode::Experimental38 => Err(Error::Experimental),
            CapabilityCode::Experimental39 => Err(Error::Experimental),
            CapabilityCode::Experimental40 => Err(Error::Experimental),
            CapabilityCode::Experimental41 => Err(Error::Experimental),
            CapabilityCode::Experimental42 => Err(Error::Experimental),
            CapabilityCode::Experimental43 => Err(Error::Experimental),
            CapabilityCode::Experimental44 => Err(Error::Experimental),
            CapabilityCode::Experimental45 => Err(Error::Experimental),
            CapabilityCode::Experimental46 => Err(Error::Experimental),
            CapabilityCode::Experimental47 => Err(Error::Experimental),
            CapabilityCode::Experimental48 => Err(Error::Experimental),
            CapabilityCode::Experimental49 => Err(Error::Experimental),
            CapabilityCode::Experimental50 => Err(Error::Experimental),
            CapabilityCode::Experimental51 => Err(Error::Experimental),
            CapabilityCode::Reserved => Err(Error::Reserved),
        }
    }
}

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
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
    PrestandardOpereationalMessage = 185,

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
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // marker
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
                value: vec![0x20, 0x00, 0x17, 0x01, 0xc],
            }],
            path_attributes: vec![PathAttribute {
                typ: PathAttributeType {
                    flags: PathAttributeFlags::Optional
                        | PathAttributeFlags::Partial,
                    type_code: PathAttributeTypeCode::As4Path,
                },
                value: PathAttributeValue::As4Path(vec![As4PathSegment {
                    typ: AsPathType::AsSequence,
                    value: vec![395849, 123456, 987654, 111111],
                }]),
            }],
            nlri: vec![
                Prefix {
                    value: vec![0x20, 0x00, 0x17, 0x01, 0xd],
                },
                Prefix {
                    value: vec![0x20, 0x00, 0x17, 0x01, 0xe],
                },
            ],
        };

        let buf = um0.to_wire().expect("update message to wire");
        println!("buf: {}", buf.hex_dump());

        let um1 =
            UpdateMessage::from_wire(&buf).expect("update message from wire");
        assert_eq!(um0, um1);
    }
}
