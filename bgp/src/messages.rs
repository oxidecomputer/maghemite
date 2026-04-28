// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{BGP_VERSION, error::Error};
use nom::{
    bytes::complete::take,
    number::complete::{be_u8, be_u16, be_u32, u8 as parse_u8},
};
use path_attribute_flags::*;
pub use rdb::types::Prefix;
use rdb::types::{AddressFamily, Prefix4, Prefix6};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashSet},
    fmt::{Display, Formatter},
    net::{Ipv4Addr, Ipv6Addr},
};

pub use bgp_types::messages::MAX_MESSAGE_SIZE;

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

pub use bgp_types_versions::parse::{
    AttributeAction, NlriSection, UpdateParseErrorReason,
};

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
    pub fn into_reason(self, section: NlriSection) -> UpdateParseErrorReason {
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
        let n = usize::from(self.length).div_ceil(8);
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

        let byte_count = usize::from(len).div_ceil(8);
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
        let n = usize::from(self.length).div_ceil(8);
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

        let byte_count = usize::from(len).div_ceil(8);
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

pub use bgp_types::messages::MessageType;

pub use bgp_types::messages::Message;
pub use bgp_types::messages::MessageKind;
pub use bgp_types_versions::error::MessageConvertError;

/// Free-fn replacement for `Message::to_wire`. Lives here because the
/// `bgp::error::Error` return type prevents this from being an inherent
/// method on the migrated type (orphan-rule case 2).
pub fn message_to_wire(m: &Message) -> Result<Vec<u8>, Error> {
    match m {
        Message::Open(om) => open_message_to_wire(om),
        Message::Update(um) => update_message_to_wire(um),
        Message::Notification(nm) => notification_message_to_wire(nm),
        Message::KeepAlive => Ok(Vec::new()),
        Message::RouteRefresh(rr) => Ok(route_refresh_message_to_wire(rr)),
    }
}

pub use bgp_types::messages::Header;

pub use bgp_types::messages::{AS_TRANS, BGP4, OpenMessage};

/// Serialize an open message to wire format.
pub fn open_message_to_wire(om: &OpenMessage) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();

    // version
    buf.push(om.version);

    // as
    buf.extend_from_slice(&om.asn.to_be_bytes());

    // hold time
    buf.extend_from_slice(&om.hold_time.to_be_bytes());

    // id
    buf.extend_from_slice(&om.id.to_be_bytes());

    // opt param len
    let opt_buf = open_message_parameters_to_wire(om)?;
    if opt_buf.len() > u8::MAX as usize {
        return Err(Error::TooLarge("open message optional parameters".into()));
    }
    buf.push(opt_buf.len() as u8);
    buf.extend_from_slice(&opt_buf);

    Ok(buf)
}

fn open_message_parameters_to_wire(om: &OpenMessage) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    for p in &om.parameters {
        buf.extend_from_slice(&optional_parameter_to_wire(p)?);
    }
    Ok(buf)
}

/// Deserialize an open message from wire format.
pub fn open_message_from_wire(input: &[u8]) -> Result<OpenMessage, Error> {
    // RFC 4271 §4.2: OPEN minimum 10 bytes body
    // (1 version + 2 ASN + 2 hold_time + 4 ID + 1 opt_param_len)
    if input.len() < 10 {
        return Err(Error::TooSmall("open message body".into()));
    }

    let (input, version) = parse_u8(input)?;
    if version != BGP_VERSION {
        return Err(Error::BadVersion(version));
    }

    let (input, asn) = be_u16(input)?;
    let (input, hold_time) = be_u16(input)?;

    let (input, id) = be_u32(input)?;
    if id == 0 {
        return Err(Error::BadBgpIdentifier(Ipv4Addr::from_bits(id)));
    }

    let (input, param_len) = parse_u8(input)?;
    let param_len = usize::from(param_len);

    if input.len() < param_len {
        return Err(Error::TooSmall("open message optional parameters".into()));
    }

    let parameters = open_message_parameters_from_wire(&input[..param_len])?;

    Ok(OpenMessage {
        version,
        asn,
        hold_time,
        id,
        parameters,
    })
}

pub fn open_message_parameters_from_wire(
    mut buf: &[u8],
) -> Result<Vec<OptionalParameter>, Error> {
    let mut result = Vec::new();

    while !buf.is_empty() {
        let (out, param) = optional_parameter_from_wire(buf)?;
        result.push(param);
        buf = out;
    }

    Ok(result)
}

pub use bgp_types::messages::Tlv;

pub use bgp_types::messages::UpdateMessage;

/// Returns true if any of the parse errors collected by [`update_message_from_wire`]
/// indicates the message should be treated as withdrawn (RFC 7606).
pub fn treat_as_withdraw(
    errors: &[(UpdateParseErrorReason, AttributeAction)],
) -> bool {
    errors
        .iter()
        .any(|(_, action)| matches!(action, AttributeAction::TreatAsWithdraw))
}

/// Free-fn replacement for `UpdateMessage::to_wire`. Lives here because the
/// `bgp::error::Error` return type prevents this from being an inherent
/// method on the migrated type (orphan-rule case 2).
pub fn update_message_to_wire(msg: &UpdateMessage) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();

    // withdrawn
    let withdrawn = update_message_withdrawn_to_wire(msg)?;
    if withdrawn.len() > u16::MAX as usize {
        return Err(Error::TooLarge(
            "update: too many withdrawn prefixes".into(),
        ));
    }
    let len = withdrawn.len() as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&withdrawn);

    // path attributes
    let attrs = update_message_path_attrs_to_wire(msg)?;
    if attrs.len() > u16::MAX as usize {
        return Err(Error::TooLarge("update: too many path attributes".into()));
    }
    let len = attrs.len() as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&attrs);

    // nlri
    buf.extend_from_slice(&update_message_nlri_to_wire(msg)?);

    if buf.len() > MAX_MESSAGE_SIZE {
        return Err(Error::TooLarge("update exceeds max message size".into()));
    }

    Ok(buf)
}

fn update_message_withdrawn_to_wire(
    msg: &UpdateMessage,
) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    for w in &msg.withdrawn {
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
fn update_message_path_attrs_to_wire(
    msg: &UpdateMessage,
) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();

    // Encode MP-BGP attributes first (RFC 7606 Section 5.1 requirement)
    for p in &msg.path_attributes {
        if matches!(
            p.value,
            PathAttributeValue::MpReachNlri(_)
                | PathAttributeValue::MpUnreachNlri(_)
        ) {
            buf.extend_from_slice(&path_attribute_to_wire(
                p,
                p.typ.flags & path_attribute_flags::EXTENDED_LENGTH != 0,
            )?);
        }
    }

    // Then encode all other attributes
    for p in &msg.path_attributes {
        if !matches!(
            p.value,
            PathAttributeValue::MpReachNlri(_)
                | PathAttributeValue::MpUnreachNlri(_)
        ) {
            buf.extend_from_slice(&path_attribute_to_wire(
                p,
                p.typ.flags & path_attribute_flags::EXTENDED_LENGTH != 0,
            )?);
        }
    }

    Ok(buf)
}

fn update_message_nlri_to_wire(msg: &UpdateMessage) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    for n in &msg.nlri {
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
/// Returns `Ok(UpdateMessage)` on success (errors collected on
/// `msg.errors` may be non-empty containing TreatAsWithdraw / Discard
/// reasons), or `Err(UpdateParseError)` for fatal errors requiring session
/// reset.
pub fn update_message_from_wire(
    input: &[u8],
) -> Result<UpdateMessage, UpdateParseError> {
    // RFC 4271 §4.3: UPDATE minimum 4 bytes body
    // (2 bytes withdrawn length + 2 bytes path attributes length)
    if input.len() < 4 {
        return Err(UpdateParseError {
            error_code: ErrorCode::Header,
            error_subcode: ErrorSubcode::Header(
                HeaderErrorSubcode::BadMessageLength,
            ),
            reason: UpdateParseErrorReason::MessageTooShort {
                expected_min: 4,
                got: input.len(),
            },
        });
    }

    // 1. Parse withdrawn routes length and extract bytes
    let (input, len) =
        be_u16::<_, nom::error::Error<&[u8]>>(input).map_err(|e| {
            UpdateParseError {
                error_code: ErrorCode::Update,
                error_subcode: ErrorSubcode::Update(
                    UpdateErrorSubcode::MalformedAttributeList,
                ),
                reason: UpdateParseErrorReason::Other {
                    detail: format!("failed to parse withdrawn length: {e}"),
                },
            }
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
    let withdrawn = match update_message_prefixes4_from_wire(withdrawn_input) {
        Ok(w) => w,
        Err(e) => {
            return Err(UpdateParseError {
                error_code: ErrorCode::Update,
                error_subcode: ErrorSubcode::Update(
                    UpdateErrorSubcode::InvalidNetworkField,
                ),
                reason: e.into_reason(NlriSection::Withdrawn),
            });
        }
    };

    // 3. Parse path attributes length and extract bytes
    let (input, len) =
        be_u16::<_, nom::error::Error<&[u8]>>(input).map_err(|e| {
            UpdateParseError {
                error_code: ErrorCode::Update,
                error_subcode: ErrorSubcode::Update(
                    UpdateErrorSubcode::MalformedAttributeList,
                ),
                reason: UpdateParseErrorReason::Other {
                    detail: format!(
                        "failed to parse path attributes length: {e}"
                    ),
                },
            }
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
    } = update_message_path_attrs_from_wire(attrs_input)?;

    // 6. Parse NLRI (remaining bytes)
    //    Even if attrs had errors, we need NLRI for TreatAsWithdraw
    let nlri = match update_message_prefixes4_from_wire(input) {
        Ok(n) => n,
        Err(e) => {
            // NLRI parse failure = SessionReset (strongest action)
            return Err(UpdateParseError {
                error_code: ErrorCode::Update,
                error_subcode: ErrorSubcode::Update(
                    UpdateErrorSubcode::InvalidNetworkField,
                ),
                reason: e.into_reason(NlriSection::Nlri),
            });
        }
    };

    // 7. Validate mandatory attributes (RFC 4271 Section 5.1.2)
    //    Only required when UPDATE carries reachability information (NLRI).
    //    Missing mandatory attrs = TreatAsWithdraw per RFC 7606.
    let mut errors = attr_errors;

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
                PathAttributeValue::AsPath(_) | PathAttributeValue::As4Path(_)
            )
        });
        if !has_as_path {
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
        errors,
    })
}

/// Parse prefixes from wire format.
/// Dispatches to the appropriate version-specific parser.
pub fn update_message_prefixes_from_wire(
    buf: &[u8],
    afi: AddressFamily,
) -> Result<Vec<Prefix>, PrefixParseError> {
    match afi {
        AddressFamily::Ipv4 => update_message_prefixes4_from_wire(buf)
            .map(|v| v.into_iter().map(Prefix::V4).collect()),
        AddressFamily::Ipv6 => update_message_prefixes6_from_wire(buf)
            .map(|v| v.into_iter().map(Prefix::V6).collect()),
    }
}

/// Parse IPv4 prefixes from wire format.
pub fn update_message_prefixes4_from_wire(
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
pub fn update_message_prefixes6_from_wire(
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
fn update_message_path_attrs_from_wire(
    mut buf: &[u8],
) -> Result<ParsedPathAttrs, UpdateParseError> {
    type NomErr<'a> = nom::error::Error<&'a [u8]>;
    type ParseRes<'a, T> =
        std::result::Result<(&'a [u8], T), nom::Err<NomErr<'a>>>;

    fn take_bytes<'a>(buf: &'a [u8], n: usize) -> ParseRes<'a, &'a [u8]> {
        take(n)(buf)
    }

    fn parse_u8<'a>(input: &'a [u8]) -> ParseRes<'a, u8> {
        nom::number::complete::u8(input)
    }

    fn parse_u16<'a>(input: &'a [u8]) -> ParseRes<'a, u16> {
        nom::number::complete::be_u16(input)
    }

    let mut result = Vec::new();
    let mut errors = Vec::new();
    let mut seen_types: HashSet<u8> = HashSet::new();
    let mut has_mp_reach = false;
    let mut has_mp_unreach = false;

    loop {
        if buf.is_empty() {
            break;
        }

        // ===== FRAMING: Parse attribute header (type + length) =====

        // 1. Parse 2-byte type header (flags + type_code)
        let (remaining, type_bytes) = match take_bytes(buf, 2) {
            Ok((r, t)) => (r, t),
            Err(e) => {
                // Can't even read type header - fatal framing error
                return Err(UpdateParseError {
                    error_code: ErrorCode::Update,
                    error_subcode: ErrorSubcode::Update(
                        UpdateErrorSubcode::MalformedAttributeList,
                    ),
                    reason: UpdateParseErrorReason::AttributeParseError {
                        type_code: None,
                        detail: format!("failed to read attribute type: {e}"),
                    },
                });
            }
        };

        // 2. Parse flags and type_code from the 2 bytes separately
        // We need to handle unknown type codes per RFC 4271 Section 4.3
        let flags_byte = type_bytes[0];
        let type_code_u8 = type_bytes[1];

        // Try to parse as a known type code
        let typ = match PathAttributeTypeCode::try_from(type_code_u8) {
            Ok(code) => {
                // Known type code - construct PathAttributeType
                PathAttributeType {
                    flags: flags_byte,
                    type_code: code,
                }
            }
            Err(_) => {
                // Unknown type code - check Optional flag per RFC 4271
                // Section 4.3. We must parse the length regardless to skip
                // the attribute correctly
                let optional = (flags_byte & OPTIONAL) != 0;

                // Parse length based on EXTENDED_LENGTH flag
                let (remaining, len) = if flags_byte & EXTENDED_LENGTH != 0 {
                    match parse_u16(remaining) {
                        Ok((r, l)) => (r, usize::from(l)),
                        Err(e) => {
                            // If we fail to parse the length, we have to
                            // bail out since we can't skip this attr.
                            return Err(UpdateParseError {
                                    error_code: ErrorCode::Update,
                                    error_subcode: ErrorSubcode::Update(
                                        UpdateErrorSubcode::MalformedAttributeList,
                                    ),
                                    reason: UpdateParseErrorReason::AttributeParseError {
                                        type_code: Some(type_code_u8),
                                        detail: format!(
                                            "failed to read extended length: {e}"
                                        ),
                                    },
                                });
                        }
                    }
                } else {
                    match parse_u8(remaining) {
                        Ok((r, l)) => (r, usize::from(l)),
                        Err(e) => {
                            // If we fail to parse the length, we have to
                            // bail out since we can't skip this attr.
                            return Err(UpdateParseError {
                                    error_code: ErrorCode::Update,
                                    error_subcode: ErrorSubcode::Update(
                                        UpdateErrorSubcode::MalformedAttributeList,
                                    ),
                                    reason: UpdateParseErrorReason::AttributeParseError {
                                        type_code: Some(type_code_u8),
                                        detail: format!("failed to read length: {e}"),
                                    },
                                });
                        }
                    }
                };

                // Skip the attribute value
                let (remaining, _) = match take_bytes(remaining, len) {
                    Ok((r, v)) => (r, v),
                    Err(e) => {
                        return Err(UpdateParseError {
                            error_code: ErrorCode::Update,
                            error_subcode: ErrorSubcode::Update(
                                UpdateErrorSubcode::MalformedAttributeList,
                            ),
                            reason:
                                UpdateParseErrorReason::AttributeParseError {
                                    type_code: Some(type_code_u8),
                                    detail: format!(
                                        "attribute truncated: declared {} bytes, {e}",
                                        len
                                    ),
                                },
                        });
                    }
                };

                // Update buf to next attribute
                buf = remaining;

                // Handle unknown attribute based on Optional flag
                if optional {
                    // Optional unknown attribute - discard per RFC 4271 Section 4.3
                    // Record the error and continue to next attribute
                    errors.push((
                            UpdateParseErrorReason::AttributeParseError {
                                type_code: Some(type_code_u8),
                                detail: format!(
                                    "unknown optional attribute type code: {type_code_u8}"
                                ),
                            },
                            AttributeAction::Discard,
                        ));
                    continue;
                } else {
                    // Mandatory unknown attribute - Session Reset per RFC 4271 Section 4.3
                    return Err(UpdateParseError {
                            error_code: ErrorCode::Update,
                            error_subcode: ErrorSubcode::Update(
                                UpdateErrorSubcode::MalformedAttributeList,
                            ),
                            reason: UpdateParseErrorReason::UnrecognizedMandatoryAttribute {
                                type_code: type_code_u8,
                            },
                        });
                }
            }
        };

        // 3. Validate attribute flags (RFC 7606 Section 3c)
        //    Even if flag validation fails, we need to parse the length to skip
        //    the attribute. Track the error but continue to length parsing.
        let flag_error = validate_attribute_flags(&typ).err();

        // 4. Parse length (1 or 2 bytes depending on EXTENDED_LENGTH flag)
        let (remaining, len) = if typ.flags
            & path_attribute_flags::EXTENDED_LENGTH
            != 0
        {
            match parse_u16(remaining) {
                Ok((r, l)) => (r, usize::from(l)),
                Err(e) => {
                    // Can't read extended length - fatal framing error
                    return Err(UpdateParseError {
                        error_code: ErrorCode::Update,
                        error_subcode: ErrorSubcode::Update(
                            UpdateErrorSubcode::MalformedAttributeList,
                        ),
                        reason: UpdateParseErrorReason::AttributeParseError {
                            type_code: Some(type_code_u8),
                            detail: format!(
                                "failed to read extended length: {e}"
                            ),
                        },
                    });
                }
            }
        } else {
            match parse_u8(remaining) {
                Ok((r, l)) => (r, usize::from(l)),
                Err(e) => {
                    // Can't read length - fatal framing error
                    return Err(UpdateParseError {
                        error_code: ErrorCode::Update,
                        error_subcode: ErrorSubcode::Update(
                            UpdateErrorSubcode::MalformedAttributeList,
                        ),
                        reason: UpdateParseErrorReason::AttributeParseError {
                            type_code: Some(type_code_u8),
                            detail: format!("failed to read length: {e}"),
                        },
                    });
                }
            }
        };

        // 5. Extract `len` bytes for the attribute value
        let (remaining, value_bytes) = match take_bytes(remaining, len) {
            Ok((r, v)) => (r, v),
            Err(e) => {
                // Declared length exceeds available bytes - fatal framing error
                // RFC 7606 Section 4 says use treat-as-withdraw, but we can't
                // reliably locate the next attribute, so this is a structural
                // error in the UPDATE message itself (too few bytes overall)
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

        // ===== RFC 7606 Section 4: Validate zero-length attributes =====
        // Only AS_PATH and ATOMIC_AGGREGATE may have zero length.
        // All other attributes with zero length are a syntax error (treat-as-withdraw).
        if len == 0 {
            match typ.type_code {
                PathAttributeTypeCode::AsPath
                | PathAttributeTypeCode::AtomicAggregate => {
                    // These are allowed to have zero length
                }
                _ => {
                    // All other attributes must have non-zero length
                    let reason = UpdateParseErrorReason::AttributeLengthError {
                        type_code: typ.type_code,
                        expected: 1, // At least 1 byte needed for meaningful data
                        got: 0,
                    };
                    errors.push((reason, AttributeAction::TreatAsWithdraw));
                    continue;
                }
            }
        }

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
        match path_attribute_from_bytes(typ.clone(), value_bytes) {
            Ok(pa) => {
                // ===== DUPLICATE DETECTION =====
                let is_mp_reach =
                    pa.typ.type_code == PathAttributeTypeCode::MpReachNlri;
                let is_mp_unreach =
                    pa.typ.type_code == PathAttributeTypeCode::MpUnreachNlri;

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
                            reason:
                                UpdateParseErrorReason::DuplicateMpUnreachNlri,
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
                } else {
                    // Discard duplicate non-MP-BGP attribute per RFC 7606 3(g)
                    errors.push((
                        UpdateParseErrorReason::DuplicateAttribute {
                            type_code: type_code_u8,
                        },
                        AttributeAction::Discard,
                    ));
                }
            }
            Err(reason) => {
                // Value parsing failed - determine action based on attribute type
                let action = path_attribute_type_error_action(&typ);

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
    })
}

/// Free-fn replacement for `UpdateMessage::nexthop`. Lives here because the
/// `bgp::error::Error` return type prevents this from being an inherent
/// method on the migrated type (orphan-rule case 2).
pub fn update_message_nexthop(
    msg: &UpdateMessage,
) -> Result<BgpNexthop, Error> {
    // Find MP_REACH_NLRI if present
    match msg.path_attributes.iter().find_map(|a| match &a.value {
        PathAttributeValue::MpReachNlri(mp) => Some(mp),
        _ => None,
    }) {
        // This Update is MP-BGP, nexthop is already parsed
        Some(mp) => Ok(*mp.nexthop()),
        // This Update is not MP-BGP, use the NEXT_HOP attribute
        None => msg
            .nexthop4()
            .map(|n4| n4.into())
            .ok_or(Error::MissingNexthop),
    }
}

/// A self-describing BGP path attribute
pub use bgp_types::messages::PathAttribute;

/// Free-fn replacement for `PathAttribute::to_wire`. Lives here because the
/// `bgp::error::Error` return type prevents this from being an inherent
/// method on the migrated type.
pub fn path_attribute_to_wire(
    attr: &PathAttribute,
    extended_length: bool,
) -> Result<Vec<u8>, Error> {
    let mut buf = path_attribute_type_to_wire(&attr.typ);
    let val = &path_attribute_value_to_wire(&attr.value)?;
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
fn path_attribute_from_bytes(
    typ: PathAttributeType,
    value_bytes: &[u8],
) -> Result<PathAttribute, UpdateParseErrorReason> {
    let value = path_attribute_value_from_wire(value_bytes, typ.type_code)?;
    Ok(PathAttribute { typ, value })
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
    let optional = typ.flags & OPTIONAL != 0;
    let transitive = typ.flags & TRANSITIVE != 0;
    let partial = typ.flags & PARTIAL != 0;

    // RFC 4271 Section 4.3:
    // The Partial bit (bit 2) is only meaningful when Transitive (bit 1) is
    // set. i.e. If Transitive=0, Partial MUST be 0.
    if !transitive && partial {
        let reason = UpdateParseErrorReason::InvalidAttributeFlags {
            type_code: typ.type_code.into(),
            flags: typ.flags,
        };
        // RFC 7606 Section 3.c: Attribute flag errors must use treat-as-withdraw
        return Err((reason, AttributeAction::TreatAsWithdraw));
    }

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
            type_code: typ.type_code.into(),
            flags: typ.flags,
        };
        // RFC 7606 Section 3.c: Attribute flag errors must use treat-as-withdraw
        return Err((reason, AttributeAction::TreatAsWithdraw));
    }

    Ok(())
}

pub use bgp_types::messages::PathAttributeType;

/// Free-fn replacement for the inherent `PathAttributeType::to_wire`. The
/// matching `from_wire` is inlined in `UpdateMessage::path_attrs_from_wire`
/// (which produces `UpdateParseError`, not `bgp::error::Error`).
fn path_attribute_type_to_wire(typ: &PathAttributeType) -> Vec<u8> {
    vec![typ.flags, typ.type_code.into()]
}

/// Determine RFC 7606 action for errors on this attribute type.
///
/// RFC 7606 specifies different error handling actions for different
/// attribute types:
/// - Session Reset: Critical errors that prevent reliable parsing
/// - Treat-as-withdraw: Errors in route-affecting attributes
/// - Attribute Discard: Errors in informational-only attributes
pub fn path_attribute_type_error_action(
    typ: &PathAttributeType,
) -> AttributeAction {
    match typ.type_code {
        // Well-known mandatory attributes (RFC 7606 Section 7.1-7.3)
        PathAttributeTypeCode::Origin
        | PathAttributeTypeCode::AsPath
        | PathAttributeTypeCode::NextHop => AttributeAction::TreatAsWithdraw,

        // MP-BGP attributes: SessionReset on any error because we never
        // negotiate AFI/SAFIs we don't support, so receiving one we can't
        // parse is a protocol violation.
        PathAttributeTypeCode::MpReachNlri
        | PathAttributeTypeCode::MpUnreachNlri => AttributeAction::SessionReset,

        // MULTI_EXIT_DISC (RFC 7606 Section 7.4): affects route selection
        PathAttributeTypeCode::MultiExitDisc => {
            AttributeAction::TreatAsWithdraw
        }

        // LOCAL_PREF (RFC 7606 Section 7.5): affects route selection.
        // Note: From eBGP peers this should be discarded, but that requires
        // session context. For now, treat as withdraw for safety.
        PathAttributeTypeCode::LocalPref => AttributeAction::TreatAsWithdraw,

        // Communities (RFC 7606 Section 7.8): affects policy/route selection
        PathAttributeTypeCode::Communities => AttributeAction::TreatAsWithdraw,

        // AS4_PATH: same as AS_PATH, affects loop detection and route
        // selection.
        PathAttributeTypeCode::As4Path => AttributeAction::TreatAsWithdraw,

        // ATOMIC_AGGREGATE (RFC 7606 Section 7.6): informational only.
        // AGGREGATOR (RFC 7606 Section 7.7): informational only.
        // AS4_AGGREGATOR: same as AGGREGATOR.
        // These don't affect route selection, so discard is safe.
        PathAttributeTypeCode::AtomicAggregate
        | PathAttributeTypeCode::Aggregator
        | PathAttributeTypeCode::As4Aggregator => AttributeAction::Discard,
    }
}

pub use bgp_types::messages::path_attribute_flags;

pub use bgp_types::messages::PathAttributeTypeCode;

pub use bgp_types::messages::{Aggregator, As4Aggregator};

pub use bgp_types::messages::PathAttributeValue;

/// Free-fn replacement for `PathAttributeValue::to_wire`. Lives here because
/// some sub-cases (`As4PathSegment::to_wire`, `MpUnreachNlri::to_wire`) emit
/// `bgp::error::Error`, which is bgp-local.
pub fn path_attribute_value_to_wire(
    value: &PathAttributeValue,
) -> Result<Vec<u8>, Error> {
    match value {
        PathAttributeValue::Origin(x) => Ok(vec![(*x).into()]),
        PathAttributeValue::AsPath(segments) => {
            let mut buf = Vec::new();
            for s in segments {
                buf.push(s.typ.into());
                buf.push(s.value.len() as u8);
                for v in &s.value {
                    buf.extend_from_slice(&v.to_be_bytes());
                }
            }
            Ok(buf)
        }
        PathAttributeValue::NextHop(addr) => Ok(addr.octets().into()),
        PathAttributeValue::As4Path(segments) => {
            let mut buf = Vec::new();
            for s in segments {
                buf.extend_from_slice(&as4_path_segment_to_wire(s)?);
            }
            Ok(buf)
        }
        PathAttributeValue::Communities(communities) => {
            let mut buf = Vec::new();
            for community in communities {
                buf.extend_from_slice(&u32::from(*community).to_be_bytes());
            }
            Ok(buf)
        }
        PathAttributeValue::LocalPref(v) => Ok(v.to_be_bytes().into()),
        PathAttributeValue::MultiExitDisc(v) => Ok(v.to_be_bytes().into()),
        PathAttributeValue::Aggregator(agg) => Ok(agg.to_wire()),
        PathAttributeValue::As4Aggregator(agg) => Ok(agg.to_wire()),
        PathAttributeValue::AtomicAggregate => Ok(Vec::new()),
        PathAttributeValue::MpReachNlri(mp) => Ok(mp_reach_nlri_to_wire(mp)),
        PathAttributeValue::MpUnreachNlri(mp) => mp_unreach_nlri_to_wire(mp),
    }
}

pub fn path_attribute_value_from_wire(
    mut input: &[u8],
    type_code: PathAttributeTypeCode,
) -> Result<PathAttributeValue, UpdateParseErrorReason> {
    // Helper type aliases and functions for nom parsers
    type NomErr<'a> = nom::error::Error<&'a [u8]>;
    type ParseRes<'a, T> =
        std::result::Result<(&'a [u8], T), nom::Err<NomErr<'a>>>;

    fn parse_u8<'a>(input: &'a [u8]) -> ParseRes<'a, u8> {
        be_u8(input)
    }

    fn parse_u32<'a>(input: &'a [u8]) -> ParseRes<'a, u32> {
        be_u32(input)
    }

    fn take_bytes<'a>(input: &'a [u8], n: usize) -> ParseRes<'a, &'a [u8]> {
        take(n)(input)
    }

    // RFC 7606 §3: Zero-length attributes only valid for AS_PATH and ATOMIC_AGGREGATE
    if input.is_empty() {
        match type_code {
            PathAttributeTypeCode::AsPath
            | PathAttributeTypeCode::AtomicAggregate => {
                // These attributes are allowed to be zero-length
            }
            _ => {
                return Err(UpdateParseErrorReason::AttributeLengthError {
                    type_code,
                    expected: 1, // Most attributes require at least 1 byte
                    got: 0,
                });
            }
        }
    }

    match type_code {
        PathAttributeTypeCode::Origin => {
            // RFC 4271 §5.1.2: ORIGIN must be exactly 1 octet
            if input.len() != 1 {
                return Err(UpdateParseErrorReason::AttributeLengthError {
                    type_code: PathAttributeTypeCode::Origin,
                    expected: 1,
                    got: input.len(),
                });
            }
            let (_input, origin) = parse_u8(input).map_err(|e| {
                UpdateParseErrorReason::AttributeParseError {
                    type_code: Some(type_code.into()),
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
                    as4_path_segment_from_wire(input).map_err(|e| {
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
            let (_input, b) = take_bytes(input, 4).map_err(|e| {
                UpdateParseErrorReason::AttributeParseError {
                    type_code: Some(type_code.into()),
                    detail: format!("{e}"),
                }
            })?;
            Ok(PathAttributeValue::NextHop(Ipv4Addr::new(
                b[0], b[1], b[2], b[3],
            )))
        }
        PathAttributeTypeCode::MultiExitDisc => {
            // RFC 4271 §5.1.5: MULTI_EXIT_DISC must be exactly 4 octets
            if input.len() != 4 {
                return Err(UpdateParseErrorReason::AttributeLengthError {
                    type_code: PathAttributeTypeCode::MultiExitDisc,
                    expected: 4,
                    got: input.len(),
                });
            }
            let (_input, v) = parse_u32(input).map_err(|e| {
                UpdateParseErrorReason::AttributeParseError {
                    type_code: Some(type_code.into()),
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
                    as4_path_segment_from_wire(input).map_err(|e| {
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
            // RFC 4271 §5.1.9 (via RFC 1997): COMMUNITIES length must be multiple of 4
            if !input.len().is_multiple_of(4) {
                return Err(UpdateParseErrorReason::Other {
                    detail: format!(
                        "COMMUNITIES attribute length must be multiple of 4, got {}",
                        input.len()
                    ),
                });
            }
            let mut communities = Vec::new();
            loop {
                if input.is_empty() {
                    break;
                }
                let (out, v) = be_u32::<_, NomErr<'_>>(input).map_err(|e| {
                    UpdateParseErrorReason::AttributeParseError {
                        type_code: Some(type_code.into()),
                        detail: format!("{e}"),
                    }
                })?;
                communities.push(Community::from(v));
                input = out;
            }
            Ok(PathAttributeValue::Communities(communities))
        }
        PathAttributeTypeCode::LocalPref => {
            // RFC 4271 §5.1.6: LOCAL_PREF must be exactly 4 octets
            if input.len() != 4 {
                return Err(UpdateParseErrorReason::AttributeLengthError {
                    type_code: PathAttributeTypeCode::LocalPref,
                    expected: 4,
                    got: input.len(),
                });
            }
            let (_input, v) = parse_u32(input).map_err(|e| {
                UpdateParseErrorReason::AttributeParseError {
                    type_code: Some(type_code.into()),
                    detail: format!("{e}"),
                }
            })?;
            Ok(PathAttributeValue::LocalPref(v))
        }
        PathAttributeTypeCode::MpReachNlri => {
            let (_remaining, mp_reach) = mp_reach_nlri_from_wire(input)?;
            Ok(PathAttributeValue::MpReachNlri(mp_reach))
        }
        PathAttributeTypeCode::MpUnreachNlri => {
            let (_remaining, mp_unreach) = mp_unreach_nlri_from_wire(input)?;
            Ok(PathAttributeValue::MpUnreachNlri(mp_unreach))
        }
        PathAttributeTypeCode::AtomicAggregate => {
            // RFC 4271 §5.1.7: ATOMIC_AGGREGATE must be zero-length
            // (This is also checked earlier at function entry for zero-length validation)
            if !input.is_empty() {
                return Err(UpdateParseErrorReason::AttributeLengthError {
                    type_code: PathAttributeTypeCode::AtomicAggregate,
                    expected: 0,
                    got: input.len(),
                });
            }
            Ok(PathAttributeValue::AtomicAggregate)
        }
        PathAttributeTypeCode::Aggregator => {
            // RFC 4271 §5.1.8: AGGREGATOR must be exactly 6 octets
            // (2 octets AS number + 4 octets IP address)
            if input.len() != 6 {
                return Err(UpdateParseErrorReason::AttributeLengthError {
                    type_code: PathAttributeTypeCode::Aggregator,
                    expected: 6,
                    got: input.len(),
                });
            }
            let agg = Aggregator::from_wire(input).map_err(|e| {
                UpdateParseErrorReason::AttributeParseError {
                    type_code: Some(type_code.into()),
                    detail: e,
                }
            })?;
            Ok(PathAttributeValue::Aggregator(agg))
        }
        PathAttributeTypeCode::As4Aggregator => {
            // RFC 6793: AS4_AGGREGATOR must be exactly 8 octets
            // (4 octets AS number + 4 octets IP address)
            if input.len() != 8 {
                return Err(UpdateParseErrorReason::AttributeLengthError {
                    type_code: PathAttributeTypeCode::As4Aggregator,
                    expected: 8,
                    got: input.len(),
                });
            }
            let agg = As4Aggregator::from_wire(input).map_err(|e| {
                UpdateParseErrorReason::AttributeParseError {
                    type_code: Some(type_code.into()),
                    detail: e,
                }
            })?;
            Ok(PathAttributeValue::As4Aggregator(agg))
        }
    }
}

pub use bgp_types::messages::Community;

/// An enumeration indicating the origin type of a path.
pub use bgp_types::messages::PathOrigin;

// A self describing segment found in path sets and sequences.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AsPathSegment {
    // Indicates if this segment is a part of a set or sequence.
    pub typ: AsPathType,
    // AS numbers in the segment.
    pub value: Vec<u16>,
}

pub use bgp_types::messages::As4PathSegment;

/// Free-fn replacement for `As4PathSegment::to_wire`. Returns
/// `bgp::error::Error` (specifically `Error::TooLarge`).
pub fn as4_path_segment_to_wire(
    seg: &As4PathSegment,
) -> Result<Vec<u8>, Error> {
    if seg.value.len() > u8::MAX as usize {
        return Err(Error::TooLarge("AS4 path segment".into()));
    }
    let mut buf = vec![seg.typ.into(), seg.value.len() as u8];
    for v in &seg.value {
        buf.extend_from_slice(&v.to_be_bytes());
    }
    Ok(buf)
}

pub fn as4_path_segment_from_wire(
    input: &[u8],
) -> Result<(&[u8], As4PathSegment), Error> {
    let (input, typ) = parse_u8(input)?;
    let typ = AsPathType::try_from(typ)?;

    let (input, len_u8) = parse_u8(input)?;

    // RFC 4271 §5.1.3: check for overflow when calculating byte length from
    // segment count. Each AS number is 4 bytes, so byte_len = len_u8 * 4.
    // Note: this is technically safe (max 255 * 4 = 1020), but we validate
    // for defense-in-depth.
    let byte_len = usize::from(len_u8).checked_mul(4).ok_or_else(|| {
        Error::TooLarge("AS path segment length calculation overflow".into())
    })?;

    let mut segment = As4PathSegment {
        typ,
        value: Vec::new(),
    };
    if byte_len == 0 {
        return Ok((input, segment));
    }

    let (input, mut value_input) = take(byte_len)(input)?;
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

pub use bgp_types::messages::AsPathType;

pub use bgp_types::messages::Ipv6DoubleNexthop;

pub use bgp_types::messages::BgpNexthop;

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

pub use bgp_types::messages::{
    MpReachIpv4Unicast, MpReachIpv6Unicast, MpReachNlri, MpUnreachIpv4Unicast,
    MpUnreachIpv6Unicast, MpUnreachNlri,
};

/// Free-fn replacement for `MpReachNlri::to_wire`. Stays in `bgp` because it
/// calls the bgp-local `BgpWireFormat<Prefix4>` impl on `Prefix4`/`Prefix6`.
pub fn mp_reach_nlri_to_wire(mp: &MpReachNlri) -> Vec<u8> {
    let mut buf = Vec::new();

    // AFI (2 bytes)
    buf.extend_from_slice(&u16::from(mp.afi()).to_be_bytes());

    // SAFI (1 byte)
    buf.push(mp.safi().into());

    // Next-hop
    let nh = mp.nexthop();
    buf.push(nh.byte_len()); // Next-hop length
    buf.extend_from_slice(&nh.to_bytes());

    // Reserved (1 byte from RFC 4760 §3, historically "Number of SNPAs")
    let reserved = match mp {
        MpReachNlri::Ipv4Unicast(inner) => inner.reserved,
        MpReachNlri::Ipv6Unicast(inner) => inner.reserved,
    };
    buf.push(reserved);

    // NLRI
    match mp {
        MpReachNlri::Ipv4Unicast(inner) => {
            for prefix in &inner.nlri {
                buf.extend_from_slice(&prefix.to_wire());
            }
        }
        MpReachNlri::Ipv6Unicast(inner) => {
            for prefix in &inner.nlri {
                buf.extend_from_slice(&prefix.to_wire());
            }
        }
    }

    buf
}

/// Free-fn replacement for `MpReachNlri::from_wire`. Stays in `bgp` because
/// it produces `UpdateParseErrorReason`.
pub fn mp_reach_nlri_from_wire(
    input: &[u8],
) -> Result<(&[u8], MpReachNlri), UpdateParseErrorReason> {
    type NomErr<'a> = nom::error::Error<&'a [u8]>;
    type ParseRes<'a, T> =
        std::result::Result<(&'a [u8], T), nom::Err<NomErr<'a>>>;

    fn parse_u16<'a>(input: &'a [u8]) -> ParseRes<'a, u16> {
        be_u16(input)
    }

    fn parse_u8<'a>(input: &'a [u8]) -> ParseRes<'a, u8> {
        be_u8(input)
    }

    // Parse AFI (2 bytes)
    let (input, afi_raw) = parse_u16(input).map_err(|e| {
        UpdateParseErrorReason::AttributeParseError {
            type_code: Some(PathAttributeTypeCode::MpReachNlri.into()),
            detail: format!("failed to parse AFI: {e}"),
        }
    })?;
    let afi = Afi::try_from(afi_raw).map_err(|_| {
        UpdateParseErrorReason::UnsupportedAfiSafi {
            afi: afi_raw,
            safi: 0,
        }
    })?;

    // Parse SAFI (1 byte)
    let (input, safi_raw) = parse_u8(input).map_err(|e| {
        UpdateParseErrorReason::AttributeParseError {
            type_code: Some(PathAttributeTypeCode::MpReachNlri.into()),
            detail: format!("failed to parse SAFI: {e}"),
        }
    })?;
    if Safi::try_from(safi_raw).is_err() {
        return Err(UpdateParseErrorReason::UnsupportedAfiSafi {
            afi: afi_raw,
            safi: safi_raw,
        });
    }

    // Parse Next-hop Length (1 byte)
    let (input, nh_len) = parse_u8(input).map_err(|e| {
        UpdateParseErrorReason::AttributeParseError {
            type_code: Some(PathAttributeTypeCode::MpReachNlri.into()),
            detail: format!("failed to parse next-hop length: {e}"),
        }
    })?;

    // Extract next-hop bytes
    if input.len() < usize::from(nh_len) {
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
    let nh_bytes = &input[..usize::from(nh_len)];
    let input = &input[usize::from(nh_len)..];

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
                got: usize::from(nh_len),
            }
        })?;

    // Parse Reserved byte (1 byte from RFC 4760 §3).
    // RFC 4760 §3: "This field is reserved for future use. It MUST be set to
    // 0 by the sender and MUST be ignored by the receiver."
    // Historical note: in RFC 2858 (obsoleted by RFC 4760), this was
    // "Number of SNPAs". Store the value for session layer validation /
    // logging, but don't error here.
    let (input, reserved) = parse_u8(input).map_err(|e| {
        UpdateParseErrorReason::AttributeParseError {
            type_code: Some(PathAttributeTypeCode::MpReachNlri.into()),
            detail: format!("failed to parse reserved byte: {e}"),
        }
    })?;

    // Parse NLRI based on AFI
    match afi {
        Afi::Ipv4 => {
            let nlri = prefixes4_from_wire(input)
                .map_err(|e| e.into_reason(NlriSection::MpReach))?;
            Ok((
                &[],
                MpReachNlri::Ipv4Unicast(MpReachIpv4Unicast {
                    nexthop,
                    reserved,
                    nlri,
                }),
            ))
        }
        Afi::Ipv6 => {
            let nlri = prefixes6_from_wire(input)
                .map_err(|e| e.into_reason(NlriSection::MpReach))?;
            Ok((
                &[],
                MpReachNlri::Ipv6Unicast(MpReachIpv6Unicast {
                    nexthop,
                    reserved,
                    nlri,
                }),
            ))
        }
    }
}

/// Free-fn replacement for `MpUnreachNlri::to_wire`. Returns
/// `bgp::error::Error` (signature retained for source compatibility; the
/// function body is currently infallible).
pub fn mp_unreach_nlri_to_wire(mp: &MpUnreachNlri) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();

    // AFI (2 bytes)
    buf.extend_from_slice(&u16::from(mp.afi()).to_be_bytes());

    // SAFI (1 byte)
    buf.push(mp.safi().into());

    // Withdrawn routes
    match mp {
        MpUnreachNlri::Ipv4Unicast(inner) => {
            for prefix in &inner.withdrawn {
                buf.extend_from_slice(&prefix.to_wire());
            }
        }
        MpUnreachNlri::Ipv6Unicast(inner) => {
            for prefix in &inner.withdrawn {
                buf.extend_from_slice(&prefix.to_wire());
            }
        }
    }

    Ok(buf)
}

/// Free-fn replacement for `MpUnreachNlri::from_wire`.
pub fn mp_unreach_nlri_from_wire(
    input: &[u8],
) -> Result<(&[u8], MpUnreachNlri), UpdateParseErrorReason> {
    type NomErr<'a> = nom::error::Error<&'a [u8]>;
    type ParseRes<'a, T> =
        std::result::Result<(&'a [u8], T), nom::Err<NomErr<'a>>>;

    fn parse_u16<'a>(input: &'a [u8]) -> ParseRes<'a, u16> {
        be_u16(input)
    }

    fn parse_u8<'a>(input: &'a [u8]) -> ParseRes<'a, u8> {
        be_u8(input)
    }

    // Parse AFI (2 bytes)
    let (input, afi_raw) = parse_u16(input).map_err(|e| {
        UpdateParseErrorReason::AttributeParseError {
            type_code: Some(PathAttributeTypeCode::MpUnreachNlri.into()),
            detail: format!("failed to parse AFI: {e}"),
        }
    })?;
    let afi = Afi::try_from(afi_raw).map_err(|_| {
        UpdateParseErrorReason::UnsupportedAfiSafi {
            afi: afi_raw,
            safi: 0,
        }
    })?;

    // Parse SAFI (1 byte)
    let (input, safi_raw) = parse_u8(input).map_err(|e| {
        UpdateParseErrorReason::AttributeParseError {
            type_code: Some(PathAttributeTypeCode::MpUnreachNlri.into()),
            detail: format!("failed to parse SAFI: {e}"),
        }
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
                .map_err(|e| e.into_reason(NlriSection::MpUnreach))?;
            Ok((
                &[],
                MpUnreachNlri::Ipv4Unicast(MpUnreachIpv4Unicast { withdrawn }),
            ))
        }
        Afi::Ipv6 => {
            let withdrawn = prefixes6_from_wire(input)
                .map_err(|e| e.into_reason(NlriSection::MpUnreach))?;
            Ok((
                &[],
                MpUnreachNlri::Ipv6Unicast(MpUnreachIpv6Unicast { withdrawn }),
            ))
        }
    }
}

pub use bgp_types::messages::{NotificationMessage, RouteRefreshMessage};

pub fn notification_message_to_wire(
    nm: &NotificationMessage,
) -> Result<Vec<u8>, Error> {
    let buf =
        vec![nm.error_code.into(), error_subcode_as_u8(&nm.error_subcode)];
    //TODO data, see comment above on data field
    Ok(buf)
}

pub fn notification_message_from_wire(
    input: &[u8],
) -> Result<NotificationMessage, Error> {
    // RFC 4271 §4.5: NOTIFICATION minimum 2 bytes body
    // (1 error code + 1 error subcode, plus 0 or more bytes of data)
    if input.len() < 2 {
        return Err(Error::TooSmall("notification message body".to_string()));
    }

    let (input, error_code) = parse_u8(input)?;
    let error_code = ErrorCode::try_from(error_code)?;

    let (input, error_subcode) = parse_u8(input)?;
    let error_subcode = match error_code {
        ErrorCode::Header => {
            HeaderErrorSubcode::try_from(error_subcode)?.into()
        }
        ErrorCode::Open => OpenErrorSubcode::try_from(error_subcode)?.into(),
        ErrorCode::Update => {
            UpdateErrorSubcode::try_from(error_subcode)?.into()
        }
        ErrorCode::HoldTimerExpired => ErrorSubcode::HoldTime(error_subcode),
        ErrorCode::Fsm => ErrorSubcode::Fsm(error_subcode),
        ErrorCode::Cease => CeaseErrorSubcode::try_from(error_subcode)?.into(),
    };
    Ok(NotificationMessage {
        error_code,
        error_subcode,
        data: input.to_owned(),
    })
}

pub fn route_refresh_message_to_wire(rr: &RouteRefreshMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&rr.afi.to_be_bytes());
    buf.push(0); // reserved
    buf.push(rr.safi);
    buf
}

pub fn route_refresh_message_from_wire(
    input: &[u8],
) -> Result<RouteRefreshMessage, Error> {
    let (input, afi) = be_u16(input)?;
    let (input, _reserved) = parse_u8(input)?;
    let (_, safi) = parse_u8(input)?;
    Ok(RouteRefreshMessage { afi, safi })
}

pub use bgp_types::messages::ErrorCode;

pub use bgp_types::messages::ErrorSubcode;

/// Free-fn replacement for the inherent `ErrorSubcode::as_u8` method (the
/// type now lives in `bgp-types-versions`). Crate-private; used by
/// `NotificationMessage::to_wire` here in `bgp`.
pub(crate) fn error_subcode_as_u8(s: &ErrorSubcode) -> u8 {
    match s {
        ErrorSubcode::Header(h) => (*h).into(),
        ErrorSubcode::Open(o) => (*o).into(),
        ErrorSubcode::Update(u) => (*u).into(),
        ErrorSubcode::HoldTime(x) => *x,
        ErrorSubcode::Fsm(x) => *x,
        ErrorSubcode::Cease(x) => (*x).into(),
    }
}

pub use bgp_types::messages::HeaderErrorSubcode;

pub use bgp_types::messages::OpenErrorSubcode;

pub use bgp_types::messages::UpdateErrorSubcode;

pub use bgp_types::messages::CeaseErrorSubcode;

pub use bgp_types::messages::OptionalParameter;
pub use bgp_types::messages::OptionalParameterCode;

/// Free-fn replacement for the inherent `OptionalParameter::to_wire` method.
/// Lives here because the body returns `bgp::error::Error`, which is
/// bgp-local; the type itself moved to `bgp-types-versions`.
pub fn optional_parameter_to_wire(
    p: &OptionalParameter,
) -> Result<Vec<u8>, Error> {
    match p {
        OptionalParameter::Reserved => Err(Error::ReservedOptionalParameter),
        OptionalParameter::Unassigned => Err(Error::Unassigned(0)),
        OptionalParameter::Capabilities(cs) => {
            let mut buf = vec![u8::from(OptionalParameterCode::Capabilities)];
            let mut csbuf = Vec::new();
            for c in cs {
                let cbuf = capability_to_wire(c)?;
                csbuf.extend_from_slice(&cbuf);
            }
            buf.push(csbuf.len() as u8);
            buf.extend_from_slice(&csbuf);
            Ok(buf)
        }
        x => Err(Error::UnsupportedOptionalParameter(x.clone())),
    }
}

/// Free-fn replacement for the inherent `OptionalParameter::from_wire` method.
pub fn optional_parameter_from_wire(
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
                let (out, cap) = capability_from_wire(cap_input)?;
                result.insert(cap);
                cap_input = out;
            }
            Ok((input, OptionalParameter::Capabilities(result)))
        }
        x => Err(Error::UnsupportedOptionalParameterCode(x)),
    }
}

pub use bgp_types::messages::{AddPathElement, ExtendedNexthopElement};

// An issue tracking the TODOs below is here
// <https://github.com/oxidecomputer/maghemite/issues/80>

pub use bgp_types::messages::Capability;

/// Free-fn replacement for the inherent `Capability::to_wire` method. Lives
/// here because the body returns `bgp::error::Error`, which is bgp-local.
pub fn capability_to_wire(c: &Capability) -> Result<Vec<u8>, Error> {
    match c {
        Capability::MultiprotocolExtensions { afi, safi } => {
            let mut buf =
                vec![CapabilityCode::MultiprotocolExtensions.into(), 4];
            buf.extend_from_slice(&afi.to_be_bytes());
            buf.push(0);
            buf.push(*safi);
            Ok(buf)
        }
        Capability::RouteRefresh {} => {
            let buf = vec![CapabilityCode::RouteRefresh.into(), 0];
            Ok(buf)
        }
        Capability::GracefulRestart {} => {
            //TODO audit
            let buf = vec![CapabilityCode::GracefulRestart.into(), 0];
            Ok(buf)
        }
        Capability::FourOctetAs { asn } => {
            let mut buf = vec![CapabilityCode::FourOctetAs.into(), 4];
            buf.extend_from_slice(&asn.to_be_bytes());
            Ok(buf)
        }
        Capability::AddPath { elements } => {
            let len = u8::try_from(elements.len() * 4).map_err(|_| {
                Error::TooLarge(format!(
                    "AddPath capability has too many elements: {} elements",
                    elements.len()
                ))
            })?;
            let mut buf = vec![CapabilityCode::AddPath.into(), len];
            for e in elements {
                buf.extend_from_slice(&e.afi.to_be_bytes());
                buf.push(e.safi);
                buf.push(e.send_receive);
            }
            Ok(buf)
        }
        Capability::EnhancedRouteRefresh {} => {
            //TODO audit
            let buf = vec![CapabilityCode::EnhancedRouteRefresh.into(), 0];
            Ok(buf)
        }
        Capability::ExtendedNextHopEncoding { elements } => {
            let mut buf = vec![
                CapabilityCode::ExtendedNextHopEncoding as u8,
                (elements.len() * 6) as u8,
            ];
            for e in elements {
                buf.extend_from_slice(&e.afi.to_be_bytes());
                buf.extend_from_slice(&e.safi.to_be_bytes());
                buf.extend_from_slice(&e.nh_afi.to_be_bytes());
            }
            Ok(buf)
        }
        Capability::Experimental { code: _ } => Err(Error::Experimental),
        Capability::Unassigned { code } => Err(Error::Unassigned(*code)),
        Capability::Reserved { code: _ } => Err(Error::ReservedCapability),
        x => Err(Error::UnsupportedCapability(x.clone())),
    }
}

/// Free-fn replacement for the inherent `Capability::from_wire` method.
pub fn capability_from_wire(
    input: &[u8],
) -> Result<(&[u8], Capability), Error> {
    let (input, code) = parse_u8(input)?;
    let (input, len) = parse_u8(input)?;
    let len = usize::from(len);
    if input.len() < len {
        return Err(Error::Eom);
    }
    let code = match CapabilityCode::try_from(code) {
        Ok(code) => code,
        Err(_) => {
            return Ok((&input[len..], Capability::Unassigned { code }));
        }
    };
    let (cap_data, remaining) = input.split_at(len);
    let mut input = cap_data;

    let cap = match code {
        CapabilityCode::MultiprotocolExtensions => {
            let (input, afi) = be_u16(input)?;
            let (input, _) = be_u8(input)?;
            let (_, safi) = be_u8(input)?;
            Capability::MultiprotocolExtensions { afi, safi }
        }
        CapabilityCode::RouteRefresh => Capability::RouteRefresh {},
        CapabilityCode::GracefulRestart => {
            //TODO handle for real
            Capability::GracefulRestart {}
        }
        CapabilityCode::FourOctetAs => {
            let (_, asn) = be_u32(input)?;
            Capability::FourOctetAs { asn }
        }
        CapabilityCode::AddPath => {
            let mut elements = BTreeSet::new();
            while !input.is_empty() {
                let (rem, afi) = be_u16(input)?;
                let (rem, safi) = be_u8(rem)?;
                let (rem, send_receive) = be_u8(rem)?;
                elements.insert(AddPathElement {
                    afi,
                    safi,
                    send_receive,
                });
                input = rem;
            }
            Capability::AddPath { elements }
        }
        CapabilityCode::EnhancedRouteRefresh => {
            //TODO handle for real
            Capability::EnhancedRouteRefresh {}
        }
        CapabilityCode::Fqdn => {
            //TODO handle for real
            Capability::Fqdn {}
        }
        CapabilityCode::PrestandardRouteRefresh => {
            //TODO handle for real
            Capability::PrestandardRouteRefresh {}
        }
        CapabilityCode::BGPExtendedMessage => {
            //TODO handle for real
            Capability::BGPExtendedMessage {}
        }
        CapabilityCode::LongLivedGracefulRestart => {
            //TODO handle for real
            Capability::LongLivedGracefulRestart {}
        }
        CapabilityCode::MultipleRoutesToDestination => {
            //TODO handle for real
            Capability::MultipleRoutesToDestination {}
        }
        CapabilityCode::ExtendedNextHopEncoding => {
            let mut elements = Vec::new();
            while !input.is_empty() {
                let (rem, afi) = be_u16(input)?;
                let (rem, safi) = be_u16(rem)?;
                let (rem, nh_afi) = be_u16(rem)?;
                elements.push(ExtendedNexthopElement { afi, safi, nh_afi });
                input = rem;
            }
            Capability::ExtendedNextHopEncoding { elements }
        }
        CapabilityCode::OutboundRouteFiltering => {
            //TODO handle for real
            Capability::OutboundRouteFiltering {}
        }
        CapabilityCode::BgpSec => {
            //TODO handle for real
            Capability::BgpSec {}
        }
        CapabilityCode::MultipleLabels => {
            //TODO handle for real
            Capability::MultipleLabels {}
        }
        CapabilityCode::BgpRole => {
            //TODO handle for real
            Capability::BgpRole {}
        }
        CapabilityCode::DynamicCapability => {
            //TODO handle for real
            Capability::DynamicCapability {}
        }
        CapabilityCode::MultisessionBgp => {
            //TODO handle for real
            Capability::MultisessionBgp {}
        }
        CapabilityCode::RoutingPolicyDistribution => {
            //TODO handle for real
            Capability::RoutingPolicyDistribution {}
        }
        CapabilityCode::PrestandardOrfAndPd => {
            //TODO handle for real
            Capability::PrestandardOrfAndPd {}
        }
        CapabilityCode::PrestandardOutboundRouteFiltering => {
            //TODO handle for real
            Capability::PrestandardOutboundRouteFiltering {}
        }
        CapabilityCode::PrestandardMultisession => {
            //TODO handle for real
            Capability::PrestandardMultisession {}
        }
        CapabilityCode::PrestandardFqdn => {
            //TODO handle for real
            Capability::PrestandardFqdn {}
        }
        CapabilityCode::PrestandardOperationalMessage => {
            //TODO handle for real
            Capability::PrestandardOperationalMessage {}
        }
        CapabilityCode::Experimental0 => Capability::Experimental { code: 0 },
        CapabilityCode::Experimental1 => Capability::Experimental { code: 1 },
        CapabilityCode::Experimental2 => Capability::Experimental { code: 2 },
        CapabilityCode::Experimental3 => Capability::Experimental { code: 3 },
        CapabilityCode::Experimental4 => Capability::Experimental { code: 4 },
        CapabilityCode::Experimental5 => Capability::Experimental { code: 5 },
        CapabilityCode::Experimental6 => Capability::Experimental { code: 6 },
        CapabilityCode::Experimental7 => Capability::Experimental { code: 7 },
        CapabilityCode::Experimental8 => Capability::Experimental { code: 8 },
        CapabilityCode::Experimental9 => Capability::Experimental { code: 9 },
        CapabilityCode::Experimental10 => Capability::Experimental { code: 10 },
        CapabilityCode::Experimental11 => Capability::Experimental { code: 11 },
        CapabilityCode::Experimental12 => Capability::Experimental { code: 12 },
        CapabilityCode::Experimental13 => Capability::Experimental { code: 13 },
        CapabilityCode::Experimental14 => Capability::Experimental { code: 14 },
        CapabilityCode::Experimental15 => Capability::Experimental { code: 15 },
        CapabilityCode::Experimental16 => Capability::Experimental { code: 16 },
        CapabilityCode::Experimental17 => Capability::Experimental { code: 17 },
        CapabilityCode::Experimental18 => Capability::Experimental { code: 18 },
        CapabilityCode::Experimental19 => Capability::Experimental { code: 19 },
        CapabilityCode::Experimental20 => Capability::Experimental { code: 20 },
        CapabilityCode::Experimental21 => Capability::Experimental { code: 21 },
        CapabilityCode::Experimental22 => Capability::Experimental { code: 22 },
        CapabilityCode::Experimental23 => Capability::Experimental { code: 23 },
        CapabilityCode::Experimental24 => Capability::Experimental { code: 24 },
        CapabilityCode::Experimental25 => Capability::Experimental { code: 25 },
        CapabilityCode::Experimental26 => Capability::Experimental { code: 26 },
        CapabilityCode::Experimental27 => Capability::Experimental { code: 27 },
        CapabilityCode::Experimental28 => Capability::Experimental { code: 28 },
        CapabilityCode::Experimental29 => Capability::Experimental { code: 29 },
        CapabilityCode::Experimental30 => Capability::Experimental { code: 30 },
        CapabilityCode::Experimental31 => Capability::Experimental { code: 31 },
        CapabilityCode::Experimental32 => Capability::Experimental { code: 32 },
        CapabilityCode::Experimental33 => Capability::Experimental { code: 33 },
        CapabilityCode::Experimental34 => Capability::Experimental { code: 34 },
        CapabilityCode::Experimental35 => Capability::Experimental { code: 35 },
        CapabilityCode::Experimental36 => Capability::Experimental { code: 36 },
        CapabilityCode::Experimental37 => Capability::Experimental { code: 37 },
        CapabilityCode::Experimental38 => Capability::Experimental { code: 38 },
        CapabilityCode::Experimental39 => Capability::Experimental { code: 39 },
        CapabilityCode::Experimental40 => Capability::Experimental { code: 40 },
        CapabilityCode::Experimental41 => Capability::Experimental { code: 41 },
        CapabilityCode::Experimental42 => Capability::Experimental { code: 42 },
        CapabilityCode::Experimental43 => Capability::Experimental { code: 43 },
        CapabilityCode::Experimental44 => Capability::Experimental { code: 44 },
        CapabilityCode::Experimental45 => Capability::Experimental { code: 45 },
        CapabilityCode::Experimental46 => Capability::Experimental { code: 46 },
        CapabilityCode::Experimental47 => Capability::Experimental { code: 47 },
        CapabilityCode::Experimental48 => Capability::Experimental { code: 48 },
        CapabilityCode::Experimental49 => Capability::Experimental { code: 49 },
        CapabilityCode::Experimental50 => Capability::Experimental { code: 50 },
        CapabilityCode::Experimental51 => Capability::Experimental { code: 51 },
        CapabilityCode::Reserved => Capability::Reserved { code: 0 },
    };
    Ok((remaining, cap))
}

pub use bgp_types::messages::CapabilityCode;

pub use bgp_types::messages::{Afi, Safi};

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

// `UpdateParseErrorReason`, `AttributeAction`, and `NlriSection` now live in
// `bgp_types_versions::parse` (re-exported above). Their `Display` impls
// live alongside the type definitions in that crate.

/// Parsed path attributes from wire format.
///
/// Note: Existence of this struct means no fatal (SessionReset) errors occurred.
/// The parse may still have collected non-fatal errors that require
/// TreatAsWithdraw or Discard handling.
pub struct ParsedPathAttrs {
    /// Successfully parsed attributes
    pub attrs: Vec<PathAttribute>,
    /// All non-fatal errors collected during parsing.
    /// Use the treat_as_withdraw() method to check if any TreatAsWithdraw errors occurred.
    pub errors: Vec<(UpdateParseErrorReason, AttributeAction)>,
}

impl ParsedPathAttrs {
    /// Returns true if a TreatAsWithdraw error occurred during parsing.
    pub fn treat_as_withdraw(&self) -> bool {
        self.errors.iter().any(|(_, action)| {
            matches!(action, AttributeAction::TreatAsWithdraw)
        })
    }
}

/// Fatal UPDATE parse error requiring session reset.
///
/// Returned by `update_message_from_wire()` when the error cannot be handled
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
            "{}/{}: {}",
            self.error_code, self.error_subcode, self.reason
        )
    }
}

/// All possible reasons for OPEN parse errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenParseErrorReason {
    /// BGP-ID is invalid (must be non-zero)
    BadBgpIdentifier { id: Ipv4Addr },
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
            Self::BadBgpIdentifier { id } => {
                write!(f, "bad bgp identifier: {id}")
            }
            Self::InvalidVersion { version } => {
                write!(f, "unsupported version: {version}")
            }
            Self::InvalidHoldTime { hold_time } => {
                write!(f, "invalid hold time: {hold_time}")
            }
            Self::UnsupportedCapability { code } => {
                write!(f, "unsupported capability: {code}")
            }
            Self::TooSmall { field } => {
                write!(f, "message too small for {field}")
            }
            Self::Other { detail } => write!(f, "{detail}"),
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
            "{}/{}: {}",
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
            "{}/{}: {}",
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
            "{}/{}: {}",
            self.error_code, self.error_subcode, self.reason
        )
    }
}

/// A header-level parse error (e.g. bad message length per RFC 4271 §4.1).
#[derive(Debug, Clone)]
pub struct HeaderParseError {
    pub error_code: ErrorCode,
    pub error_subcode: ErrorSubcode,
    pub length: u16,
}

impl Display for HeaderParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}: bad message length {}",
            self.error_code, self.error_subcode, self.length
        )
    }
}

/// Wrapper enum identifying which message type caused a fatal parse error.
///
/// Used by the connection layer to send `ConnectionEvent::ParseError` to the
/// session FSM. All variants represent fatal errors requiring session reset.
#[derive(Debug, Clone)]
pub enum MessageParseError {
    Header(HeaderParseError),
    Update(UpdateParseError),
    Open(OpenParseError),
    Notification(NotificationParseError),
    RouteRefresh(RouteRefreshParseError),
}

impl MessageParseError {
    /// Returns a human-readable description of the error for logging/history.
    pub fn description(&self) -> String {
        match self {
            Self::Header(e) => format!("HEADER: {}", e),
            Self::Update(e) => format!("UPDATE: {}", e),
            Self::Open(e) => format!("OPEN: {}", e),
            Self::Notification(e) => format!("NOTIFICATION: {}", e),
            Self::RouteRefresh(e) => format!("ROUTE_REFRESH: {}", e),
        }
    }

    /// Returns the error codes for sending a NOTIFICATION message.
    pub fn error_codes(&self) -> (ErrorCode, ErrorSubcode) {
        match self {
            Self::Header(e) => (e.error_code, e.error_subcode),
            Self::Update(e) => (e.error_code, e.error_subcode),
            Self::Open(e) => (e.error_code, e.error_subcode),
            Self::Notification(e) => (e.error_code, e.error_subcode),
            Self::RouteRefresh(e) => (e.error_code, e.error_subcode),
        }
    }

    /// Returns the message type that caused the error.
    pub fn message_type(&self) -> &'static str {
        match self {
            Self::Header(_) => "HEADER",
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

// `AttributeAction` now lives in `bgp_types_versions::parse` (re-exported above).

// ============================================================================
// API Compatibility Types (VERSION_INITIAL / v1.0.0)
// ============================================================================
// These types maintain backward compatibility with the INITIAL API version.
// They are now defined in `bgp_types_versions::v1::messages` and re-exported
// here under their historical `*V1` names. The `From<current> for *V1` impls
// live alongside the type definitions in `bgp_types_versions::impls::messages`.

pub use bgp_types_versions::v1::messages::{
    PathAttribute as PathAttributeV1, PathAttributeType as PathAttributeTypeV1,
    PathAttributeTypeCode as PathAttributeTypeCodeV1,
    PathAttributeValue as PathAttributeValueV1, Prefix as PrefixV1,
};

/// V1 UpdateMessage type for API compatibility.
///
/// Uses PrefixV1 for NLRI and withdrawn prefixes, PathAttributeV1 for
/// attributes. Lives in `bgp` because UpdateMessage itself has not yet
/// migrated.
#[derive(
    Debug, PartialEq, Eq, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct UpdateMessageV1 {
    pub withdrawn: Vec<PrefixV1>,
    pub path_attributes: Vec<PathAttributeV1>,
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
            // Filter out attributes that don't have v1 equivalents (MP-BGP,
            // AtomicAggregate).
            path_attributes: msg
                .path_attributes
                .into_iter()
                .filter_map(Option::<PathAttributeV1>::from)
                .collect(),
            nlri: msg
                .nlri
                .into_iter()
                .map(|p| PrefixV1::from(Prefix::V4(p)))
                .collect(),
        }
    }
}

/// V1 Message enum for API compatibility. Lives in `bgp` because Message
/// itself has not yet migrated.
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
    use rdb::Prefix;
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
        let om0 = OpenMessage::new4(395849, 0x1234, 0xaabbccdd, false);

        let buf = open_message_to_wire(&om0).expect("open message to wire");
        println!("buf: {}", buf.hex_dump());

        let om1 = open_message_from_wire(&buf).expect("open message from wire");
        assert_eq!(om0, om1);
    }

    #[test]
    fn open_round_trip_extended_nexthop() {
        let om0 = OpenMessage::new4(395849, 0x1234, 0xaabbccdd, true);

        let buf = open_message_to_wire(&om0).expect("open message to wire");
        println!("buf: {}", buf.hex_dump());

        let om1 = open_message_from_wire(&buf).expect("open message from wire");
        assert_eq!(om0, om1);
    }

    #[test]
    fn update_round_trip() {
        let um0 = UpdateMessage {
            withdrawn: vec![Prefix4::new(
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
                Prefix4::new(std::net::Ipv4Addr::new(0, 23, 1, 13), 32),
                Prefix4::new(std::net::Ipv4Addr::new(0, 23, 1, 14), 32),
            ],
            errors: vec![],
        };

        let buf = update_message_to_wire(&um0).expect("update message to wire");
        println!("buf: {}", buf.hex_dump());

        let um1 =
            update_message_from_wire(&buf).expect("update message from wire");
        assert_eq!(um0, um1);
    }

    #[test]
    fn notification_round_trip() {
        // Note: NotificationMessage::to_wire() does not yet serialize the data field
        // (see TODO in the impl), so we test with empty data.
        let nm0 = NotificationMessage {
            error_code: ErrorCode::Update,
            error_subcode: ErrorSubcode::Update(
                UpdateErrorSubcode::InvalidOriginAttribute,
            ),
            data: vec![],
        };

        let buf = notification_message_to_wire(&nm0)
            .expect("notification message to wire");
        let nm1 = notification_message_from_wire(&buf)
            .expect("notification message from wire");

        assert_eq!(nm0.error_code, nm1.error_code);
        assert_eq!(nm0.error_subcode, nm1.error_subcode);
        assert_eq!(nm0.data, nm1.data);
    }

    #[test]
    fn route_refresh_round_trip() {
        // IPv4 Unicast route refresh
        let rr0 = RouteRefreshMessage {
            afi: Afi::Ipv4.into(),
            safi: Safi::Unicast.into(),
        };

        let buf = route_refresh_message_to_wire(&rr0);
        let rr1 = route_refresh_message_from_wire(&buf)
            .expect("route refresh from wire");
        assert_eq!(rr0, rr1);

        // IPv6 Unicast route refresh
        let rr2 = RouteRefreshMessage {
            afi: Afi::Ipv6.into(),
            safi: Safi::Unicast.into(),
        };

        let buf = route_refresh_message_to_wire(&rr2);
        let rr3 = route_refresh_message_from_wire(&buf)
            .expect("route refresh from wire");
        assert_eq!(rr2, rr3);
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
                    Prefix::V4(Prefix4::new(
                        Ipv4Addr::from(octets),
                        test_case.prefix_length,
                    ))
                }
                AddressFamily::Ipv6 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&test_case.input_bytes);
                    Prefix::V6(Prefix6::new(
                        Ipv6Addr::from(octets),
                        test_case.prefix_length,
                    ))
                }
            };

            match test_case.address_family {
                AddressFamily::Ipv4 => {
                    if let Prefix::V4(rdb_prefix4) = prefix {
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
                    if let Prefix::V6(rdb_prefix6) = prefix {
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
        let result = update_message_from_wire(&buf);
        assert!(result.is_ok(), "Expected Ok with treat_as_withdraw set");

        let msg = result.unwrap();
        let errs = msg.errors.clone();
        assert!(
            treat_as_withdraw(&errs),
            "Expected treat_as_withdraw to be true for bad NEXT_HOP length"
        );

        // Verify errors: MalformedNextHop parse error + MissingAttribute
        // (malformed NEXT_HOP doesn't count as present for mandatory attr check)
        assert_eq!(errs.len(), 2, "Expected two errors");

        // First error: MalformedNextHop from parsing
        let (reason, action) = &errs[0];
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
        let (reason2, action2) = &errs[1];
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
        assert_eq!(
            nh,
            BgpNexthop::Ipv6Double(Ipv6DoubleNexthop { global, link_local })
        );
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
        // Test that nh_bytes.len() != nh_len is always rejected.
        // The function checks bytes.len() == nh_len first before parsing.

        // IPv4: 4 bytes provided, but nh_len claims 8
        let bytes = [192, 0, 2, 1];
        let result = BgpNexthop::from_bytes(&bytes, 8, Afi::Ipv4);
        assert!(
            result.is_err(),
            "IPv4: should reject when nh_len > bytes.len()"
        );

        // IPv6 single: 16 bytes provided, but nh_len claims 32
        let bytes = [0u8; 16];
        let result = BgpNexthop::from_bytes(&bytes, 32, Afi::Ipv6);
        assert!(
            result.is_err(),
            "IPv6 single: should reject when nh_len > bytes.len()"
        );

        // IPv6: 32 bytes provided, but nh_len claims 16 (mismatch)
        let bytes = [0u8; 32];
        let result = BgpNexthop::from_bytes(&bytes, 16, Afi::Ipv6);
        assert!(
            result.is_err(),
            "IPv6: should reject when nh_len != bytes.len()"
        );

        // IPv6 double: 32 bytes provided, but nh_len claims 48
        let bytes = [0u8; 32];
        let result = BgpNexthop::from_bytes(&bytes, 48, Afi::Ipv6);
        assert!(
            result.is_err(),
            "IPv6 double: should reject when nh_len > bytes.len()"
        );
    }

    #[test]
    fn bgp_nexthop_byte_len() {
        let ipv4 = BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(ipv4.byte_len(), 4);

        let ipv6_single =
            BgpNexthop::Ipv6Single(Ipv6Addr::from_str("2001:db8::1").unwrap());
        assert_eq!(ipv6_single.byte_len(), 16);

        let ipv6_double = BgpNexthop::Ipv6Double(Ipv6DoubleNexthop {
            global: Ipv6Addr::from_str("2001:db8::1").unwrap(),
            link_local: Ipv6Addr::from_str("fe80::1").unwrap(),
        });
        assert_eq!(ipv6_double.byte_len(), 32);
    }

    #[test]
    fn bgp_nexthop_round_trip() {
        // Test all BgpNexthop variants survive encoding/decoding

        // IPv4
        let ipv4 = BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1));
        let wire = ipv4.to_bytes();
        let decoded =
            BgpNexthop::from_bytes(&wire, wire.len() as u8, Afi::Ipv4)
                .expect("IPv4 should decode");
        assert_eq!(ipv4, decoded, "IPv4 nexthop should round-trip");

        // IPv6 single
        let ipv6_single =
            BgpNexthop::Ipv6Single(Ipv6Addr::from_str("2001:db8::1").unwrap());
        let wire = ipv6_single.to_bytes();
        let decoded =
            BgpNexthop::from_bytes(&wire, wire.len() as u8, Afi::Ipv6)
                .expect("IPv6 single should decode");
        assert_eq!(
            ipv6_single, decoded,
            "IPv6 single nexthop should round-trip"
        );

        // IPv6 double
        let ipv6_double = BgpNexthop::Ipv6Double(Ipv6DoubleNexthop {
            global: Ipv6Addr::from_str("2001:db8::1").unwrap(),
            link_local: Ipv6Addr::from_str("fe80::1").unwrap(),
        });
        let wire = ipv6_double.to_bytes();
        let decoded =
            BgpNexthop::from_bytes(&wire, wire.len() as u8, Afi::Ipv6)
                .expect("IPv6 double should decode");
        assert_eq!(
            ipv6_double, decoded,
            "IPv6 double nexthop should round-trip"
        );
    }

    // =========================================================================
    // MpReachNlri tests
    // =========================================================================

    #[test]
    fn mp_reach_nlri_ipv4_unicast() {
        let nh = BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1));
        let nlri = vec![
            Prefix4::new(Ipv4Addr::new(10, 0, 0, 0), 8),
            Prefix4::new(Ipv4Addr::new(172, 16, 0, 0), 12),
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
            Prefix6::new(Ipv6Addr::from_str("2001:db8:1::").unwrap(), 48),
            Prefix6::new(Ipv6Addr::from_str("2001:db8:2::").unwrap(), 48),
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
        let nlri = vec![Prefix6::new(
            Ipv6Addr::from_str("2001:db8:1::").unwrap(),
            48,
        )];

        let original = MpReachNlri::ipv6_unicast(nh, nlri.clone());
        let wire = mp_reach_nlri_to_wire(&original);
        let (remaining, parsed) =
            mp_reach_nlri_from_wire(&wire).expect("from_wire should succeed");

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
    fn mp_unreach_nlri_ipv4_unicast() {
        let withdrawn = vec![
            Prefix4::new(Ipv4Addr::new(10, 0, 0, 0), 8),
            Prefix4::new(Ipv4Addr::new(172, 16, 0, 0), 12),
        ];

        let mp_unreach = MpUnreachNlri::ipv4_unicast(withdrawn.clone());

        assert_eq!(mp_unreach.afi(), Afi::Ipv4);
        assert_eq!(mp_unreach.safi(), Safi::Unicast);
        assert_eq!(mp_unreach.len(), 2);

        // Verify inner struct
        if let MpUnreachNlri::Ipv4Unicast(inner) = &mp_unreach {
            assert_eq!(inner.withdrawn, withdrawn);
        } else {
            panic!("Expected Ipv4Unicast variant");
        }
    }

    #[test]
    fn mp_unreach_nlri_ipv6_unicast() {
        let withdrawn = vec![
            Prefix6::new(Ipv6Addr::from_str("2001:db8:1::").unwrap(), 48),
            Prefix6::new(Ipv6Addr::from_str("2001:db8:2::").unwrap(), 48),
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
        let withdrawn = vec![Prefix6::new(
            Ipv6Addr::from_str("2001:db8:dead::").unwrap(),
            48,
        )];

        let original = MpUnreachNlri::ipv6_unicast(withdrawn.clone());
        let wire =
            mp_unreach_nlri_to_wire(&original).expect("to_wire should succeed");
        let (remaining, parsed) =
            mp_unreach_nlri_from_wire(&wire).expect("from_wire should succeed");

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
            errors: vec![],
        };

        // Encode to wire format
        let wire =
            update_message_to_wire(&update).expect("encoding should succeed");

        // Skip withdrawn routes length (2 bytes) and empty withdrawn routes (0 bytes)
        // Skip path attributes length (2 bytes)
        // First path attribute should be MP_REACH_NLRI
        let path_attrs_start = 4; // 2 (withdrawn len) + 0 (withdrawn) + 2 (attrs len)

        // Read the first attribute's type code (flags byte + type code byte)
        let first_attr_type_code = wire[path_attrs_start + 1];
        assert_eq!(
            first_attr_type_code,
            u8::from(PathAttributeTypeCode::MpReachNlri),
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
            vec![Prefix6::new(Ipv6Addr::from_str("2001:db8::").unwrap(), 32)],
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
            nlri: vec![Prefix4::new(Ipv4Addr::new(10, 0, 0, 0), 8)],
            errors: vec![],
        };

        // Encode to wire and decode back - should succeed
        let wire =
            update_message_to_wire(&update).expect("encoding should succeed");
        let decoded = update_message_from_wire(&wire);
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
            vec![Prefix6::new(
                Ipv6Addr::from_str("2001:db8:1::").unwrap(),
                48,
            )],
        );

        let mp_unreach = MpUnreachNlri::ipv6_unicast(vec![Prefix6::new(
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
            errors: vec![],
        };

        // Encode to wire and decode back - should succeed
        let wire =
            update_message_to_wire(&update).expect("encoding should succeed");
        let decoded = update_message_from_wire(&wire);
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

    /// Test that we can handle IPv4 Unicast routes encoded using both methods:
    /// traditional NLRI/withdrawn fields AND MP-BGP path attributes in the same UPDATE.
    #[test]
    fn ipv4_unicast_dual_encoding() {
        // Traditional IPv4 prefixes
        let traditional_nlri =
            vec![Prefix4::new(Ipv4Addr::new(10, 0, 0, 0), 8)];
        let traditional_withdrawn =
            vec![Prefix4::new(Ipv4Addr::new(192, 168, 0, 0), 16)];

        // MP-BGP IPv4 prefixes (different from traditional)
        let mp_nlri = vec![Prefix4::new(Ipv4Addr::new(172, 16, 0, 0), 12)];
        let mp_withdrawn = vec![Prefix4::new(Ipv4Addr::new(10, 10, 0, 0), 16)];

        let mp_reach = MpReachNlri::ipv4_unicast(
            BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            mp_nlri.clone(),
        );
        let mp_unreach = MpUnreachNlri::ipv4_unicast(mp_withdrawn.clone());

        let update = UpdateMessage {
            withdrawn: traditional_withdrawn.clone(),
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
            nlri: traditional_nlri.clone(),
            errors: vec![],
        };

        // Round-trip through wire format
        let wire =
            update_message_to_wire(&update).expect("encoding should succeed");
        let decoded =
            update_message_from_wire(&wire).expect("decoding should succeed");

        // Verify traditional encoding is preserved
        assert_eq!(
            decoded.nlri, traditional_nlri,
            "traditional NLRI should be preserved"
        );
        assert_eq!(
            decoded.withdrawn, traditional_withdrawn,
            "traditional withdrawn should be preserved"
        );

        // Verify MP-BGP encoding is preserved
        let decoded_mp_reach = decoded
            .path_attributes
            .iter()
            .find_map(|a| match &a.value {
                PathAttributeValue::MpReachNlri(MpReachNlri::Ipv4Unicast(
                    inner,
                )) => Some(inner.nlri.clone()),
                _ => None,
            })
            .expect("MP_REACH_NLRI should be present");
        assert_eq!(
            decoded_mp_reach, mp_nlri,
            "MP-BGP NLRI should be preserved"
        );

        let decoded_mp_unreach = decoded
            .path_attributes
            .iter()
            .find_map(|a| match &a.value {
                PathAttributeValue::MpUnreachNlri(
                    MpUnreachNlri::Ipv4Unicast(inner),
                ) => Some(inner.withdrawn.clone()),
                _ => None,
            })
            .expect("MP_UNREACH_NLRI should be present");
        assert_eq!(
            decoded_mp_unreach, mp_withdrawn,
            "MP-BGP withdrawn should be preserved"
        );
    }

    /// Test that an empty UPDATE message (End-of-RIB marker) can be encoded and decoded.
    ///
    /// Per RFC 4724 Section 2, an End-of-RIB marker is an UPDATE message with:
    /// - No withdrawn routes
    /// - No path attributes (for traditional IPv4)
    /// - No NLRI
    ///
    /// For MP-BGP, End-of-RIB uses an UPDATE with only MP_UNREACH_NLRI containing
    /// zero withdrawn routes.
    #[test]
    fn empty_update_end_of_rib() {
        // Traditional IPv4 End-of-RIB: completely empty UPDATE
        let empty_update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![],
            nlri: vec![],
            errors: vec![],
        };

        let wire = update_message_to_wire(&empty_update)
            .expect("encoding should succeed");
        let decoded =
            update_message_from_wire(&wire).expect("decoding should succeed");

        assert!(decoded.withdrawn.is_empty(), "withdrawn should be empty");
        assert!(
            decoded.path_attributes.is_empty(),
            "path_attributes should be empty"
        );
        assert!(decoded.nlri.is_empty(), "nlri should be empty");

        // MP-BGP IPv6 End-of-RIB: UPDATE with MP_UNREACH_NLRI containing zero prefixes
        let mp_eor = MpUnreachNlri::ipv6_unicast(vec![]);
        let mp_eor_update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![PathAttribute {
                typ: PathAttributeType {
                    flags: path_attribute_flags::OPTIONAL,
                    type_code: PathAttributeTypeCode::MpUnreachNlri,
                },
                value: PathAttributeValue::MpUnreachNlri(mp_eor),
            }],
            nlri: vec![],
            errors: vec![],
        };

        let wire = update_message_to_wire(&mp_eor_update)
            .expect("encoding should succeed");
        let decoded =
            update_message_from_wire(&wire).expect("decoding should succeed");

        // Verify MP_UNREACH_NLRI is present with zero prefixes
        let mp_unreach = decoded
            .path_attributes
            .iter()
            .find_map(|a| match &a.value {
                PathAttributeValue::MpUnreachNlri(u) => Some(u),
                _ => None,
            })
            .expect("MP_UNREACH_NLRI should be present");
        assert_eq!(
            mp_unreach.len(),
            0,
            "MP_UNREACH_NLRI should have 0 prefixes"
        );
        assert_eq!(mp_unreach.afi(), Afi::Ipv6);
        assert_eq!(mp_unreach.safi(), Safi::Unicast);

        // MP-BGP IPv4 Unicast End-of-RIB: UPDATE with MP_UNREACH_NLRI for IPv4
        let mp_eor_v4 = MpUnreachNlri::ipv4_unicast(vec![]);
        let mp_eor_v4_update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![PathAttribute {
                typ: PathAttributeType {
                    flags: path_attribute_flags::OPTIONAL,
                    type_code: PathAttributeTypeCode::MpUnreachNlri,
                },
                value: PathAttributeValue::MpUnreachNlri(mp_eor_v4),
            }],
            nlri: vec![],
            errors: vec![],
        };

        let wire = update_message_to_wire(&mp_eor_v4_update)
            .expect("encoding should succeed");
        let decoded =
            update_message_from_wire(&wire).expect("decoding should succeed");

        // Verify MP_UNREACH_NLRI is present with zero prefixes and correct AFI/SAFI
        let mp_unreach_v4 = decoded
            .path_attributes
            .iter()
            .find_map(|a| match &a.value {
                PathAttributeValue::MpUnreachNlri(u) => Some(u),
                _ => None,
            })
            .expect("MP_UNREACH_NLRI should be present for IPv4 EOR");
        assert_eq!(
            mp_unreach_v4.len(),
            0,
            "MP_UNREACH_NLRI should have 0 prefixes"
        );
        assert_eq!(mp_unreach_v4.afi(), Afi::Ipv4);
        assert_eq!(mp_unreach_v4.safi(), Safi::Unicast);
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
            u8::from(PathAttributeTypeCode::Origin), // type
            1,                                // length
            u8::from(PathOrigin::Igp),        // value
            // Second ORIGIN attribute (EGP = 1) - should be discarded
            path_attribute_flags::TRANSITIVE,
            u8::from(PathAttributeTypeCode::Origin),
            1,
            u8::from(PathOrigin::Egp),
        ];

        // Path attributes length
        wire.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        wire.extend_from_slice(&attrs);

        // NLRI (empty)

        let decoded = update_message_from_wire(&wire);
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
            path_attribute_flags, path_attribute_type_error_action,
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
                path_attribute_type_error_action(&make_typ(
                    PathAttributeTypeCode::Origin,
                    well_known_flags
                )),
                AttributeAction::TreatAsWithdraw,
                "ORIGIN errors should treat-as-withdraw"
            );
            assert_eq!(
                path_attribute_type_error_action(&make_typ(
                    PathAttributeTypeCode::AsPath,
                    well_known_flags
                )),
                AttributeAction::TreatAsWithdraw,
                "AS_PATH errors should treat-as-withdraw"
            );
            assert_eq!(
                path_attribute_type_error_action(&make_typ(
                    PathAttributeTypeCode::NextHop,
                    well_known_flags
                )),
                AttributeAction::TreatAsWithdraw,
                "NEXT_HOP errors should treat-as-withdraw"
            );
        }

        #[test]
        fn multi_exit_disc_returns_treat_as_withdraw() {
            // RFC 7606 Section 7.4: MED affects route selection
            let optional_flags = path_attribute_flags::OPTIONAL;

            assert_eq!(
                path_attribute_type_error_action(&make_typ(
                    PathAttributeTypeCode::MultiExitDisc,
                    optional_flags
                )),
                AttributeAction::TreatAsWithdraw,
                "MULTI_EXIT_DISC errors should treat-as-withdraw"
            );
        }

        #[test]
        fn local_pref_returns_treat_as_withdraw() {
            // RFC 7606 Section 7.5: LOCAL_PREF affects route selection
            let well_known_flags = path_attribute_flags::TRANSITIVE;

            assert_eq!(
                path_attribute_type_error_action(&make_typ(
                    PathAttributeTypeCode::LocalPref,
                    well_known_flags
                )),
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
                path_attribute_type_error_action(&make_typ(
                    PathAttributeTypeCode::Communities,
                    optional_transitive_flags
                )),
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
                path_attribute_type_error_action(&make_typ(
                    PathAttributeTypeCode::As4Path,
                    optional_transitive_flags
                )),
                AttributeAction::TreatAsWithdraw,
                "AS4_PATH errors should treat-as-withdraw"
            );
        }

        #[test]
        fn atomic_aggregate_returns_discard() {
            // RFC 7606 Section 7.6: ATOMIC_AGGREGATE is informational only
            let well_known_flags = path_attribute_flags::TRANSITIVE;

            assert_eq!(
                path_attribute_type_error_action(&make_typ(
                    PathAttributeTypeCode::AtomicAggregate,
                    well_known_flags
                )),
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
                path_attribute_type_error_action(&make_typ(
                    PathAttributeTypeCode::Aggregator,
                    optional_transitive_flags
                )),
                AttributeAction::Discard,
                "AGGREGATOR errors should be discarded"
            );
            assert_eq!(
                path_attribute_type_error_action(&make_typ(
                    PathAttributeTypeCode::As4Aggregator,
                    optional_transitive_flags
                )),
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
                path_attribute_type_error_action(&make_typ(
                    PathAttributeTypeCode::MpReachNlri,
                    optional_flags
                )),
                AttributeAction::SessionReset,
                "MP_REACH_NLRI errors should cause session reset"
            );
            assert_eq!(
                path_attribute_type_error_action(&make_typ(
                    PathAttributeTypeCode::MpUnreachNlri,
                    optional_flags
                )),
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
                        u8::from(PathAttributeTypeCode::Origin),
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
            AttributeAction, PathAttributeTypeCode, UpdateParseErrorReason,
            path_attribute_flags, treat_as_withdraw, update_message_from_wire,
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
                u8::from(PathAttributeTypeCode::Origin), // type 1
                1,                                // length
                0,                                // IGP
            ]
        }

        /// Helper to build a valid AS_PATH attribute with single AS.
        fn as_path_attr(asn: u32) -> Vec<u8> {
            let mut attr = vec![
                path_attribute_flags::TRANSITIVE, // flags (0x40)
                u8::from(PathAttributeTypeCode::AsPath), // type 2
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
                u8::from(PathAttributeTypeCode::NextHop), // type 3
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
                u8::from(PathAttributeTypeCode::NextHop), // type 3
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
                u8::from(PathAttributeTypeCode::MultiExitDisc), // type 4
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
                u8::from(PathAttributeTypeCode::Aggregator), // type 7
                3,                                           // length - WRONG
                0,
                100,
                1, // only 3 bytes
            ]
        }

        /// Helper to build a malformed ORIGIN attribute (invalid value).
        fn bad_origin_attr() -> Vec<u8> {
            vec![
                path_attribute_flags::TRANSITIVE, // flags (0x40)
                u8::from(PathAttributeTypeCode::Origin), // type 1
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
            let result = update_message_from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with errors collected"
            );
            let msg = result.unwrap();
            let errs = msg.errors.clone();

            assert!(
                treat_as_withdraw(&errs),
                "treat_as_withdraw should be true"
            );

            // 3 parse errors + 2 missing attr errors (ORIGIN, NEXT_HOP)
            assert_eq!(
                errs.len(),
                5,
                "Expected 5 errors (3 parse + 2 missing), got {}: {:?}",
                errs.len(),
                errs
            );

            // Verify parse errors are present
            assert!(
                errs.iter().any(|(r, _)| matches!(
                    r,
                    UpdateParseErrorReason::InvalidOriginValue { value: 99 }
                )),
                "Should have InvalidOriginValue error"
            );
            assert!(
                errs.iter().any(|(r, _)| matches!(
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
                errs.iter().any(|(r, _)| matches!(
                    r,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::Origin
                    }
                )),
                "Should have MissingAttribute error for Origin"
            );
            assert!(
                errs.iter().any(|(r, _)| matches!(
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
            let result = update_message_from_wire(&wire);

            assert!(result.is_ok(), "Parsing should succeed");
            let msg = result.unwrap();
            let errs = msg.errors.clone();

            assert!(
                !treat_as_withdraw(&errs),
                "treat_as_withdraw should be false (Discard doesn't set it)"
            );

            assert_eq!(errs.len(), 1, "Expected 1 error (AGGREGATOR)");

            let (reason, action) = &errs[0];
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
            let result = update_message_from_wire(&wire);

            assert!(result.is_ok(), "Parsing should succeed");
            let msg = result.unwrap();
            let errs = msg.errors.clone();

            assert!(
                treat_as_withdraw(&errs),
                "treat_as_withdraw should be true (TaW errors present)"
            );

            // 3 parse errors + 1 MissingAttribute for NEXT_HOP
            assert_eq!(
                errs.len(),
                4,
                "Expected 4 errors (3 parse + 1 missing), got {}: {:?}",
                errs.len(),
                errs
            );

            // Verify the different error types are present
            assert!(
                errs.iter()
                    .any(|(_, a)| matches!(a, AttributeAction::Discard)),
                "Should have at least one Discard error"
            );
            assert!(
                errs.iter().any(|(r, _)| matches!(
                    r,
                    UpdateParseErrorReason::MalformedNextHop { .. }
                )),
                "Should have MalformedNextHop error"
            );
            assert!(
                errs.iter().any(|(r, _)| matches!(
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
            let result = update_message_from_wire(&wire);

            assert!(result.is_ok(), "Parsing should succeed");
            let msg = result.unwrap();
            let errs = msg.errors.clone();

            assert!(
                treat_as_withdraw(&errs),
                "treat_as_withdraw should be true"
            );
            // 1 parse error (InvalidOriginValue) + 1 MissingAttribute (Origin)
            assert_eq!(
                errs.len(),
                2,
                "ORIGIN parse error + MissingAttribute, got: {:?}",
                errs
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
            let result = update_message_from_wire(&wire);

            assert!(result.is_ok(), "Parsing should succeed");
            let msg = result.unwrap();
            let errs = msg.errors.clone();

            assert!(
                !treat_as_withdraw(&errs),
                "treat_as_withdraw should be false"
            );
            assert!(errs.is_empty(), "No errors expected");
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
                u8::from(PathAttributeTypeCode::Origin),
                1, // length
                0, // IGP value
            ];

            // Valid AS_PATH after
            attrs.extend(as_path_attr(65000));
            attrs.extend(next_hop_attr([192, 0, 2, 1]));

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = update_message_from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with flag error collected"
            );
            let msg = result.unwrap();
            let errs = msg.errors.clone();

            assert!(
                treat_as_withdraw(&errs),
                "Flag errors on ORIGIN cause TreatAsWithdraw"
            );
            // 1 flag error + 1 MissingAttribute for Origin (skipped due to bad flags)
            assert_eq!(
                errs.len(),
                2,
                "Flag error + MissingAttribute, got: {:?}",
                errs
            );

            assert!(
                errs.iter().any(|(r, _)| matches!(
                    r,
                    UpdateParseErrorReason::InvalidAttributeFlags { .. }
                )),
                "Should have InvalidAttributeFlags error"
            );
            assert!(
                errs.iter().any(|(r, _)| matches!(
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
        use std::net::{Ipv4Addr, Ipv6Addr};
        use std::str::FromStr;

        use crate::messages::{
            Aggregator, As4Aggregator, BgpNexthop, Error, MpReachNlri,
            MpUnreachNlri, PathAttributeTypeCode, PathAttributeValue,
            UpdateParseErrorReason, mp_reach_nlri_to_wire,
            mp_unreach_nlri_to_wire, notification_message_from_wire,
            open_message_from_wire, path_attribute_flags,
            path_attribute_value_from_wire, path_attribute_value_to_wire,
            treat_as_withdraw, update_message_from_wire,
        };
        use rdb::Prefix6;

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
                u8::from(PathAttributeTypeCode::Origin),
                1,
                0, // IGP
            ]
        }

        fn as_path_attr(asn: u32) -> Vec<u8> {
            let mut attr = vec![
                path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::AsPath),
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
                u8::from(PathAttributeTypeCode::NextHop),
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
                vec![Prefix6::new(
                    Ipv6Addr::from_str("2001:db8:1::").unwrap(),
                    48,
                )],
            );
            let value_bytes = mp_reach_nlri_to_wire(&mp_reach);

            let mut attr = vec![
                path_attribute_flags::OPTIONAL,
                u8::from(PathAttributeTypeCode::MpReachNlri),
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
            let result = update_message_from_wire(&wire);

            assert!(
                result.is_ok(),
                "MP-BGP UPDATE without NEXT_HOP should succeed: {:?}",
                result.err()
            );
            let _msg = result.unwrap();
            let errs = _msg.errors.clone();
            assert!(
                !treat_as_withdraw(&errs),
                "Should not be treat-as-withdraw"
            );
            assert!(errs.is_empty(), "Should have no errors, got: {:?}", errs);
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
            let result = update_message_from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with error collected"
            );
            let _msg = result.unwrap();
            let errs = _msg.errors.clone();
            assert!(
                treat_as_withdraw(&errs),
                "Missing NEXT_HOP with traditional NLRI should treat-as-withdraw"
            );
            assert!(
                errs.iter().any(|(reason, _)| matches!(
                    reason,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::NextHop
                    }
                )),
                "Should have MissingAttribute error for NEXT_HOP, got: {:?}",
                errs
            );
        }

        #[test]
        fn mp_unreach_only_update_does_not_require_mandatory_attrs() {
            // An UPDATE that only carries MP_UNREACH_NLRI (MP-BGP withdrawals)
            // doesn't need mandatory attributes because there's no reachable NLRI.
            let mp_unreach = MpUnreachNlri::ipv6_unicast(vec![Prefix6::new(
                Ipv6Addr::from_str("2001:db8:1::").unwrap(),
                48,
            )]);
            let value_bytes = mp_unreach_nlri_to_wire(&mp_unreach)
                .expect("MP_UNREACH_NLRI encoding");

            let mut attrs = vec![
                path_attribute_flags::OPTIONAL,
                u8::from(PathAttributeTypeCode::MpUnreachNlri),
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
            let result = update_message_from_wire(&wire);

            assert!(
                result.is_ok(),
                "MP_UNREACH-only UPDATE should succeed: {:?}",
                result.err()
            );
            let msg = result.unwrap();
            let errs = msg.errors.clone();
            assert!(
                !treat_as_withdraw(&errs),
                "Should not be treat-as-withdraw"
            );
            assert!(
                errs.is_empty(),
                "Should have no errors for MP_UNREACH-only UPDATE, got: {:?}",
                errs
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
            let result = update_message_from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with error collected"
            );
            let _msg = result.unwrap();
            let errs = _msg.errors.clone();
            assert!(
                treat_as_withdraw(&errs),
                "Missing NEXT_HOP should trigger treat-as-withdraw"
            );
            assert!(
                errs.iter().any(|(reason, _)| matches!(
                    reason,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::NextHop
                    }
                )),
                "Should have MissingAttribute error for NEXT_HOP, got: {:?}",
                errs
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
            let result = update_message_from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with error collected"
            );
            let _msg = result.unwrap();
            let errs = _msg.errors.clone();
            assert!(
                treat_as_withdraw(&errs),
                "Missing ORIGIN should trigger treat-as-withdraw"
            );
            assert!(
                errs.iter().any(|(reason, _)| matches!(
                    reason,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::Origin
                    }
                )),
                "Should have MissingAttribute error for ORIGIN, got: {:?}",
                errs
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
            let result = update_message_from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with error collected"
            );
            let _msg = result.unwrap();
            let errs = _msg.errors.clone();
            assert!(
                treat_as_withdraw(&errs),
                "Missing AS_PATH should trigger treat-as-withdraw"
            );
            assert!(
                errs.iter().any(|(reason, _)| matches!(
                    reason,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::AsPath
                    }
                )),
                "Should have MissingAttribute error for AS_PATH, got: {:?}",
                errs
            );
        }

        #[test]
        fn traditional_update_missing_multiple_mandatory_attrs() {
            // Missing both ORIGIN and AS_PATH - should collect both errors
            let mut attrs = Vec::new();
            // Only NEXT_HOP, missing ORIGIN and AS_PATH
            attrs.extend(next_hop_attr([192, 0, 2, 1]));

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = update_message_from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with errors collected"
            );
            let _msg = result.unwrap();
            let errs = _msg.errors.clone();
            assert!(
                treat_as_withdraw(&errs),
                "Missing mandatory attrs should trigger treat-as-withdraw"
            );
            assert!(
                errs.iter().any(|(reason, _)| matches!(
                    reason,
                    UpdateParseErrorReason::MissingAttribute {
                        type_code: PathAttributeTypeCode::Origin
                    }
                )),
                "Should have MissingAttribute error for ORIGIN"
            );
            assert!(
                errs.iter().any(|(reason, _)| matches!(
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

            let result = update_message_from_wire(&buf);

            assert!(
                result.is_ok(),
                "Withdraw-only UPDATE should succeed: {:?}",
                result.err()
            );
            let _msg = result.unwrap();
            let errs = _msg.errors.clone();
            assert!(
                !treat_as_withdraw(&errs),
                "Should not be treat-as-withdraw"
            );
            assert!(
                errs.is_empty(),
                "Should have no errors for withdraw-only UPDATE"
            );
        }

        #[test]
        fn empty_update_does_not_require_mandatory_attrs() {
            // An UPDATE with no NLRI and no withdrawn routes (keepalive-like)
            // doesn't need mandatory attributes.
            let wire = build_update_wire(&[], &[]);
            let result = update_message_from_wire(&wire);

            assert!(
                result.is_ok(),
                "Empty UPDATE should succeed: {:?}",
                result.err()
            );
            let _msg = result.unwrap();
            let errs = _msg.errors.clone();
            assert!(
                !treat_as_withdraw(&errs),
                "Should not be treat-as-withdraw"
            );
            assert!(errs.is_empty(), "Should have no errors for empty UPDATE");
        }

        // =====================================================================
        // Phase 2 - Message Length Validation Tests
        // =====================================================================

        #[test]
        fn open_message_too_short() {
            // OPEN message with insufficient body (< 10 bytes)
            let input = vec![1, 0, 0]; // Only 3 bytes (need 10 minimum)
            let result = open_message_from_wire(&input);
            assert!(result.is_err(), "OPEN with too short body should fail");
            match result {
                Err(Error::TooSmall(msg)) => {
                    assert!(msg.contains("open message body"));
                }
                other => panic!("Expected TooSmall error, got: {:?}", other),
            }
        }

        #[test]
        fn update_message_minimum_length() {
            // UPDATE message with exactly 4 bytes (minimum valid)
            // 2 bytes withdrawn length (0) + 2 bytes path attributes length (0)
            let input = vec![0u8, 0, 0, 0];
            let result = update_message_from_wire(&input);
            assert!(
                result.is_ok(),
                "UPDATE with minimum 4 bytes should succeed: {:?}",
                result.err()
            );
        }

        #[test]
        fn update_message_too_short() {
            // UPDATE message with only 3 bytes (< 4 minimum)
            let input = vec![0u8, 0, 0];
            let result = update_message_from_wire(&input);
            assert!(result.is_err(), "UPDATE with < 4 bytes should fail");
            match result {
                Err(err) => {
                    assert!(matches!(
                        err.reason,
                        UpdateParseErrorReason::MessageTooShort { .. }
                    ));
                }
                Ok(_) => panic!("Expected error for too-short UPDATE"),
            }
        }

        #[test]
        fn notification_message_minimum_length() {
            // NOTIFICATION message with exactly 2 bytes (error code + subcode)
            let input = vec![1, 1]; // Error code 1, subcode 1
            let result = notification_message_from_wire(&input);
            assert!(
                result.is_ok(),
                "NOTIFICATION with minimum 2 bytes should succeed"
            );
        }

        #[test]
        fn notification_message_too_short() {
            // NOTIFICATION message with only 1 byte (< 2 minimum)
            let input = vec![1u8];
            let result = notification_message_from_wire(&input);
            assert!(result.is_err(), "NOTIFICATION with < 2 bytes should fail");
        }

        // =====================================================================
        // Phase 3 - Aggregator and AtomicAggregate Tests
        // =====================================================================

        #[test]
        fn aggregator_structure_parsing() {
            let asn = 65000u16;
            let address = Ipv4Addr::new(192, 0, 2, 1);
            let agg = Aggregator { asn, address };

            // Test to_wire and from_wire round-trip
            let wire = agg.to_wire();
            assert_eq!(wire.len(), 6, "AGGREGATOR should serialize to 6 bytes");

            let parsed = Aggregator::from_wire(&wire)
                .expect("Should parse valid AGGREGATOR wire format");
            assert_eq!(parsed.asn, asn, "ASN should match");
            assert_eq!(parsed.address, address, "Address should match");
        }

        #[test]
        fn aggregator_wire_format() {
            let wire = vec![0xFDu8, 0xE8, 192, 0, 2, 1]; // ASN 65000 in big-endian
            let agg = Aggregator::from_wire(&wire)
                .expect("Should parse valid wire format");
            assert_eq!(agg.asn, 65000);
            assert_eq!(agg.address, Ipv4Addr::new(192, 0, 2, 1));
        }

        #[test]
        fn aggregator_invalid_length() {
            // Too short
            let wire = vec![0xFDu8, 0xE8, 192, 0, 2];
            let result = Aggregator::from_wire(&wire);
            assert!(result.is_err(), "AGGREGATOR with 5 bytes should fail");

            // Too long
            let wire = vec![0xFDu8, 0xE8, 192, 0, 2, 1, 2];
            let result = Aggregator::from_wire(&wire);
            assert!(result.is_err(), "AGGREGATOR with 7 bytes should fail");
        }

        #[test]
        fn aggregator_display() {
            let agg = Aggregator {
                asn: 65000,
                address: Ipv4Addr::new(192, 0, 2, 1),
            };
            let display = format!("{}", agg);
            assert_eq!(display, "AS65000 (192.0.2.1)");
        }

        #[test]
        fn as4_aggregator_structure_parsing() {
            let asn = 4200000000u32;
            let address = Ipv4Addr::new(203, 0, 113, 1);
            let agg = As4Aggregator { asn, address };

            // Test to_wire and from_wire round-trip
            let wire = agg.to_wire();
            assert_eq!(
                wire.len(),
                8,
                "AS4_AGGREGATOR should serialize to 8 bytes"
            );

            let parsed = As4Aggregator::from_wire(&wire)
                .expect("Should parse valid AS4_AGGREGATOR wire format");
            assert_eq!(parsed.asn, asn, "ASN should match");
            assert_eq!(parsed.address, address, "Address should match");
        }

        #[test]
        fn as4_aggregator_wire_format() {
            let asn = 4200000000u32;
            let mut wire = asn.to_be_bytes().to_vec();
            wire.extend_from_slice(&[203, 0, 113, 1]);

            let agg = As4Aggregator::from_wire(&wire)
                .expect("Should parse valid wire format");
            assert_eq!(agg.asn, asn);
            assert_eq!(agg.address, Ipv4Addr::new(203, 0, 113, 1));
        }

        #[test]
        fn as4_aggregator_invalid_length() {
            // Too short
            let wire = vec![0xFAu8, 0x0Du8, 0x18, 0x00, 203, 0, 113];
            let result = As4Aggregator::from_wire(&wire);
            assert!(result.is_err(), "AS4_AGGREGATOR with 7 bytes should fail");

            // Too long
            let wire = vec![0xFAu8, 0x0Du8, 0x18, 0x00, 203, 0, 113, 1, 2];
            let result = As4Aggregator::from_wire(&wire);
            assert!(result.is_err(), "AS4_AGGREGATOR with 9 bytes should fail");
        }

        #[test]
        fn as4_aggregator_display() {
            let agg = As4Aggregator {
                asn: 4200000000,
                address: Ipv4Addr::new(203, 0, 113, 1),
            };
            let display = format!("{}", agg);
            assert_eq!(display, "AS4200000000 (203.0.113.1)");
        }

        #[test]
        fn atomic_aggregate_zero_length() {
            // ATOMIC_AGGREGATE must be exactly zero bytes
            let input: &[u8] = &[];
            let result = path_attribute_value_from_wire(
                input,
                PathAttributeTypeCode::AtomicAggregate,
            );
            assert!(
                result.is_ok(),
                "Zero-length ATOMIC_AGGREGATE should parse: {:?}",
                result.err()
            );
            match result.unwrap() {
                PathAttributeValue::AtomicAggregate => {}
                other => panic!("Expected AtomicAggregate, got: {:?}", other),
            }
        }

        #[test]
        fn atomic_aggregate_non_zero_length_error() {
            // ATOMIC_AGGREGATE with any data should fail
            let input = vec![1u8];
            let result = path_attribute_value_from_wire(
                &input,
                PathAttributeTypeCode::AtomicAggregate,
            );
            assert!(
                result.is_err(),
                "Non-zero length ATOMIC_AGGREGATE should fail"
            );
            match result {
                Err(UpdateParseErrorReason::AttributeLengthError {
                    expected,
                    got,
                    ..
                }) => {
                    assert_eq!(expected, 0);
                    assert_eq!(got, 1);
                }
                other => {
                    panic!("Expected AttributeLengthError, got: {:?}", other)
                }
            }
        }

        #[test]
        fn atomic_aggregate_to_wire() {
            let attr = PathAttributeValue::AtomicAggregate;
            let wire =
                path_attribute_value_to_wire(&attr).expect("Should serialize");
            assert_eq!(
                wire.len(),
                0,
                "ATOMIC_AGGREGATE should serialize to empty"
            );
        }

        #[test]
        fn aggregator_in_update_message() {
            // Test AGGREGATOR attribute in a complete UPDATE message
            let mut attrs = Vec::new();

            // ORIGIN
            attrs.extend([
                path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::Origin),
                1,
                0, // IGP
            ]);

            // AS_PATH (empty)
            attrs.extend([
                path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::AsPath),
                0, // empty
            ]);

            // NEXT_HOP
            attrs.extend([
                path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::NextHop),
                4,
                192,
                0,
                2,
                1,
            ]);

            // AGGREGATOR
            attrs.extend([
                path_attribute_flags::OPTIONAL
                    | path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::Aggregator),
                6,
                0xFDu8,
                0xE8, // ASN 65000
                192,
                0,
                2,
                1, // Address
            ]);

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = update_message_from_wire(&wire);

            assert!(result.is_ok(), "Should parse UPDATE with AGGREGATOR");
            let msg = result.unwrap();

            // Find AGGREGATOR attribute
            let agg_attr = msg
                .path_attributes
                .iter()
                .find(|attr| {
                    matches!(attr.value, PathAttributeValue::Aggregator(_))
                })
                .expect("Should have AGGREGATOR attribute");

            match &agg_attr.value {
                PathAttributeValue::Aggregator(agg) => {
                    assert_eq!(agg.asn, 65000);
                    assert_eq!(agg.address, Ipv4Addr::new(192, 0, 2, 1));
                }
                _ => panic!("Wrong attribute type"),
            }
        }

        #[test]
        fn atomic_aggregate_in_update_message() {
            // Test ATOMIC_AGGREGATE attribute in a complete UPDATE message
            let mut attrs = Vec::new();

            // ORIGIN
            attrs.extend([
                path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::Origin),
                1,
                0, // IGP
            ]);

            // AS_PATH
            attrs.extend([
                path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::AsPath),
                0,
            ]);

            // NEXT_HOP
            attrs.extend([
                path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::NextHop),
                4,
                192,
                0,
                2,
                1,
            ]);

            // ATOMIC_AGGREGATE (zero-length)
            attrs.extend([
                path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::AtomicAggregate),
                0, // zero-length
            ]);

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = update_message_from_wire(&wire);

            assert!(
                result.is_ok(),
                "Should parse UPDATE with ATOMIC_AGGREGATE"
            );
            let msg = result.unwrap();

            // Find ATOMIC_AGGREGATE attribute
            let atomic_attr = msg
                .path_attributes
                .iter()
                .find(|attr| {
                    matches!(attr.value, PathAttributeValue::AtomicAggregate)
                })
                .expect("Should have ATOMIC_AGGREGATE attribute");

            assert!(matches!(
                atomic_attr.value,
                PathAttributeValue::AtomicAggregate
            ));
        }

        #[test]
        fn aggregator_length_validation_in_parsing() {
            // Test that length validation happens during parsing
            let mut attrs = Vec::new();

            // ORIGIN
            attrs.extend([
                path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::Origin),
                1,
                0,
            ]);

            // AS_PATH
            attrs.extend([
                path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::AsPath),
                0,
            ]);

            // NEXT_HOP
            attrs.extend([
                path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::NextHop),
                4,
                192,
                0,
                2,
                1,
            ]);

            // AGGREGATOR with WRONG length (5 bytes instead of 6)
            attrs.extend([
                path_attribute_flags::OPTIONAL
                    | path_attribute_flags::TRANSITIVE,
                u8::from(PathAttributeTypeCode::Aggregator),
                5, // WRONG!
                0xFDu8,
                0xE8,
                192,
                0,
                2, // Missing last octet
            ]);

            let wire = build_update_wire(&attrs, &nlri_prefix(198, 51, 100));
            let result = update_message_from_wire(&wire);

            assert!(
                result.is_ok(),
                "Parsing should succeed with error collected"
            );
            let _msg = result.unwrap();
            let errs = _msg.errors.clone();

            // Should have AttributeLengthError for AGGREGATOR
            assert!(
                errs.iter().any(|(reason, _)| matches!(
                    reason,
                    UpdateParseErrorReason::AttributeLengthError {
                        type_code: PathAttributeTypeCode::Aggregator,
                        ..
                    }
                )),
                "Should have AttributeLengthError for AGGREGATOR"
            );
        }
    }

    mod header_tests {
        use crate::messages::{Header, MessageType};

        #[test]
        fn new_rejects_length_too_small() {
            let result = Header::new(18, MessageType::KeepAlive);
            assert!(result.is_err());
        }

        #[test]
        fn new_rejects_length_too_large() {
            let result = Header::new(4097, MessageType::Update);
            assert!(result.is_err());
        }

        #[test]
        fn new_accepts_minimum_length() {
            let hdr = Header::new(19, MessageType::KeepAlive).unwrap();
            assert_eq!(hdr.length, 19);
        }

        #[test]
        fn new_accepts_maximum_length() {
            let hdr = Header::new(4096, MessageType::Update).unwrap();
            assert_eq!(hdr.length, 4096);
        }

        #[test]
        fn roundtrip_keepalive_header() {
            let hdr = Header::new(19, MessageType::KeepAlive).unwrap();
            let wire = hdr.to_wire();
            assert_eq!(wire.len(), Header::WIRE_SIZE);
            let parsed = Header::from_wire(&wire).unwrap();
            assert_eq!(parsed.length, 19);
            assert_eq!(parsed.typ, MessageType::KeepAlive);
        }

        #[test]
        fn roundtrip_max_length_header() {
            let hdr = Header::new(4096, MessageType::Update).unwrap();
            let wire = hdr.to_wire();
            let parsed = Header::from_wire(&wire).unwrap();
            assert_eq!(parsed.length, 4096);
            assert_eq!(parsed.typ, MessageType::Update);
        }

        // Header::from_wire intentionally does not validate length
        // bounds. Length validation is performed by the connection
        // layer (recv_msg) so it can send an appropriate NOTIFICATION.
        #[test]
        fn from_wire_parses_oversized_length() {
            let hdr = Header {
                length: 8192,
                typ: MessageType::Update,
            };
            let wire = hdr.to_wire();
            let parsed = Header::from_wire(&wire).unwrap();
            assert_eq!(parsed.length, 8192);
        }

        #[test]
        fn from_wire_parses_undersized_length() {
            let hdr = Header {
                length: 10,
                typ: MessageType::KeepAlive,
            };
            let wire = hdr.to_wire();
            let parsed = Header::from_wire(&wire).unwrap();
            assert_eq!(parsed.length, 10);
        }

        #[test]
        fn from_wire_rejects_bad_marker() {
            let hdr = Header::new(19, MessageType::KeepAlive).unwrap();
            let mut wire = hdr.to_wire();
            wire[0] = 0x00; // corrupt marker
            assert!(Header::from_wire(&wire).is_err());
        }
    }

    /// Exhaustive test: duplicate ORIGIN attributes are deduplicated to
    /// the first occurrence. PathOrigin has 3 variants, so 9 cases total.
    #[test]
    fn duplicate_origin_attrs_deduplicated() {
        let origins =
            [PathOrigin::Igp, PathOrigin::Egp, PathOrigin::Incomplete];
        for origin1 in origins {
            for origin2 in origins {
                let mut wire = Vec::new();
                wire.extend_from_slice(&0u16.to_be_bytes());

                let attrs = vec![
                    path_attribute_flags::TRANSITIVE,
                    PathAttributeTypeCode::Origin as u8,
                    1,
                    origin1 as u8,
                    path_attribute_flags::TRANSITIVE,
                    PathAttributeTypeCode::Origin as u8,
                    1,
                    origin2 as u8,
                ];

                wire.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
                wire.extend_from_slice(&attrs);

                let decoded =
                    update_message_from_wire(&wire).expect("should decode");

                let decoded_origins: Vec<_> = decoded
                    .path_attributes
                    .iter()
                    .filter_map(|a| match &a.value {
                        PathAttributeValue::Origin(o) => Some(*o),
                        _ => None,
                    })
                    .collect();

                assert_eq!(
                    decoded_origins.len(),
                    1,
                    "origin1={origin1:?} origin2={origin2:?}: \
                     expected exactly one ORIGIN after dedup",
                );
                assert_eq!(
                    decoded_origins[0], origin1,
                    "origin1={origin1:?} origin2={origin2:?}: \
                     should keep first ORIGIN value",
                );
            }
        }
    }
}
