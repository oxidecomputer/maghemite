use crate::error::Error;
use nom::{
    bytes::complete::{tag, take},
    number::complete::{be_u16, be_u32, u8 as parse_u8},
};
use num_enum::TryFromPrimitive;
use std::net::{IpAddr, Ipv4Addr};

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

impl From<&Message> for MessageType {
    fn from(m: &Message) -> Self {
        match m {
            Message::Open(_) => Self::Open,
            Message::Update(_) => Self::Update,
            Message::Notification(_) => Self::Notification,
            Message::KeepAlive => Self::KeepAlive,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Message {
    Open(OpenMessage),
    Update(UpdateMessage),
    Notification(NotificationMessage),
    KeepAlive,
}

impl Message {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Open(m) => m.to_wire(),
            Self::Update(m) => m.to_wire(),
            Self::Notification(m) => m.to_wire(),
            Self::KeepAlive => Ok(Vec::new()),
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
            parameters: vec![OptionalParameter::Capabilities(vec![
                Capability::FourOctetAs { asn },
            ])],
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

    pub fn nexthop4(&self) -> Option<Ipv4Addr> {
        for a in &self.path_attributes {
            match a.value {
                PathAttributeValue::NextHop(IpAddr::V4(addr)) => {
                    return Some(addr);
                }
                _ => continue,
            }
        }
        None
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Prefix {
    pub length: u8,
    pub value: Vec<u8>,
}

impl Prefix {
    fn to_wire(&self) -> Result<Vec<u8>, Error> {
        if self.value.len() > u8::MAX as usize {
            return Err(Error::TooLarge);
        }
        let mut buf = vec![self.length];
        buf.extend_from_slice(&self.value);
        Ok(buf)
    }

    fn from_wire(input: &[u8]) -> Result<(&[u8], Prefix), Error> {
        let (input, len) = parse_u8(input)?;
        let (input, value) = take(len >> 3)(input)?;
        Ok((
            input,
            Prefix {
                value: value.to_owned(),
                length: len,
            },
        ))
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

impl From<&Prefix> for rdb::Prefix4 {
    fn from(p: &Prefix) -> Self {
        let v = &p.value;
        match p.length {
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
    //MpReachNlri(MpReachNlri), //TODO for IPv6
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
    pub error_code: ErrorCode,
    pub error_subcode: ErrorSubcode,

    /*
     * Implementation notes for later on the data field ...
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
            ErrorCode::Cease => ErrorSubcode::Cease(error_subcode),
        };
        Ok(NotificationMessage {
            error_code,
            error_subcode,
            data: input.to_owned(),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum ErrorCode {
    Header = 1,
    Open,
    Update,
    HoldTimerExpired,
    Fsm,
    Cease,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ErrorSubcode {
    Header(HeaderErrorSubcode),
    Open(OpenErrorSubcode),
    Update(UpdateErrorSubcode),
    HoldTime(u8),
    Fsm(u8),
    Cease(u8),
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

impl ErrorSubcode {
    fn as_u8(&self) -> u8 {
        match self {
            Self::Header(h) => *h as u8,
            Self::Open(o) => *o as u8,
            Self::Update(u) => *u as u8,
            Self::HoldTime(x) => *x,
            Self::Fsm(x) => *x,
            Self::Cease(x) => *x,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum HeaderErrorSubcode {
    ConnectionNotSynchronized = 1,
    BadMessageLength,
    BadMessageType,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum OpenErrorSubcode {
    UnsupportedVersionNumber = 1,
    BadPeerAS,
    BadBgpIdentifier,
    UnsupportedOptionalParameter,
    Deprecated,
    UnacceptableHoldTime,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum UpdateErrorSubcode {
    MalformedAttributeList = 1,
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
    Capabilities(Vec<Capability>),

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

/* XXX
impl From<Capability> for OptionalParameter {
    fn from(c: Capability) -> OptionalParameter {
        OptionalParameter::Capability(c)
    }
}
*/

impl OptionalParameter {
    pub fn to_wire(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Reserved => Err(Error::Reserved),
            Self::Unassigned => Err(Error::Unassigned(0)),
            Self::Authentication => todo!(),
            Self::Capabilities(cs) => {
                let mut buf = vec![OptionalParameterCode::Capabilities as u8];
                for c in cs {
                    let cbuf = c.to_wire()?;
                    buf.push(cbuf.len() as u8);
                    buf.extend_from_slice(&cbuf);
                }
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
        let (input, mut cap_input) = take(len)(input)?;

        match code {
            OptionalParameterCode::Reserved => Err(Error::Reserved),
            OptionalParameterCode::Authentication => todo!(),
            OptionalParameterCode::Capabilities => {
                let mut result = Vec::new();
                while !cap_input.is_empty() {
                    let (out, cap) = Capability::from_wire(cap_input)?;
                    result.push(cap);
                    cap_input = out;
                }
                Ok((input, OptionalParameter::Capabilities(result)))
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
        let len = len as usize;
        if input.len() < len {
            return Err(Error::Eom);
        }

        match code {
            CapabilityCode::MultiprotocolExtensions => {
                //TODO
                Ok((&input[len..], Capability::MultiprotocolExtensions {}))
            }
            CapabilityCode::RouteRefresh => {
                //TODO
                Ok((&input[len..], Capability::RouteRefresh {}))
            }
            CapabilityCode::OutboundRouteFiltering => todo!(),
            CapabilityCode::MultipleRoutesToDestination => todo!(),
            CapabilityCode::ExtendedNextHopEncoding => todo!(),
            CapabilityCode::BGPExtendedMessage => todo!(),
            CapabilityCode::BgpSec => todo!(),
            CapabilityCode::MultipleLabels => todo!(),
            CapabilityCode::BgpRole => todo!(),
            CapabilityCode::GracefulRestart => {
                //TODO
                Ok((&input[len..], Capability::GracefulRestart {}))
            }
            CapabilityCode::FourOctetAs => {
                let (input, asn) = be_u32(input)?;
                Ok((input, Capability::FourOctetAs { asn }))
            }
            CapabilityCode::DynamicCapability => todo!(),
            CapabilityCode::MultisessionBgp => todo!(),
            CapabilityCode::AddPath => {
                //TODO
                Ok((&input[len..], Capability::AddPath {}))
            }
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
}
