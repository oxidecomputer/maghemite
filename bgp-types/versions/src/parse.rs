// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Internal parse-error carriers for BGP UPDATE message decoding.
//!
//! These types are deliberately *not* part of any versioned API surface and
//! are *not* re-exported via `latest.rs` or the `bgp-types` facade. They are
//! carried on `UpdateMessage::errors` (a `#[serde(skip)] #[schemars(skip)]`
//! field) purely for internal RFC 7606 treat-as-withdraw / discard signaling
//! between the decoder in the `bgp` crate and its consumers.

use crate::v4::messages::PathAttributeTypeCode;
use std::fmt::{Display, Formatter};

/// NLRI section identifier for error context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NlriSection {
    /// Withdrawn routes section
    Withdrawn,
    /// IPv4 NLRI section (non-MP-BGP)
    Nlri,
    /// MP_REACH_NLRI attribute
    MpReach,
    /// MP_UNREACH_NLRI attribute
    MpUnreach,
}

impl Display for NlriSection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Withdrawn => write!(f, "withdrawn"),
            Self::Nlri => write!(f, "nlri"),
            Self::MpReach => write!(f, "mp_reach"),
            Self::MpUnreach => write!(f, "mp_unreach"),
        }
    }
}

/// All possible reasons for UPDATE parse errors.
///
/// This enum codifies error reasons instead of using strings, providing
/// type safety and consistent error messages via the Display impl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateParseErrorReason {
    // Frame structure errors (fatal)
    /// UPDATE message body is too short for frame structure parsing
    MessageTooShort { expected_min: usize, got: usize },
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
    /// Duplicate non-MP-BGP attribute (discarded per RFC 7606 3(g))
    DuplicateAttribute { type_code: u8 },
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
        /// Which section the error occurred in
        section: NlriSection,
    },
    /// Prefix length exceeds maximum for address family (32 for IPv4, 128 for IPv6)
    InvalidNlriMask {
        section: NlriSection,
        length: u8,
        max: u8,
    },
    /// Not enough bytes for declared prefix length
    TruncatedNlri {
        section: NlriSection,
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
            Self::MessageTooShort { expected_min, got } => {
                write!(
                    f,
                    "UPDATE message too short: expected minimum {}, got {}",
                    expected_min, got
                )
            }
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
            Self::DuplicateAttribute { type_code } => {
                write!(f, "duplicate attribute type {}", type_code)
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
