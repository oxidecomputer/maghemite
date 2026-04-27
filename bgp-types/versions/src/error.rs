// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Wire-format parse errors emitted while decoding BGP messages.
//!
//! These error variants are reachable purely from leaf parse paths over the
//! versioned wire-message types. Session-time errors that pull in protocol
//! types stay in `bgp::error::Error`; that type wraps `WireError` via a
//! `#[from]` variant so `?` propagation is unchanged.

use std::net::Ipv4Addr;

use num_enum::TryFromPrimitiveError;

use crate::v1::messages::{
    AsPathType, CapabilityCode, CeaseErrorSubcode, ErrorCode,
    HeaderErrorSubcode, MessageType, OpenErrorSubcode, OptionalParameterCode,
    PathOrigin, UpdateErrorSubcode,
};
use crate::v4::messages::PathAttributeTypeCode;

#[derive(thiserror::Error, Debug)]
pub enum WireError {
    #[error("too small")]
    TooSmall(String),

    #[error("too large")]
    TooLarge(String),

    #[error("no marker")]
    NoMarker,

    #[error("invalid message type")]
    InvalidMessageType(u8),

    #[error("bad version: {0}")]
    BadVersion(u8),

    #[error("bad bgp identifier: {0}")]
    BadBgpIdentifier(Ipv4Addr),

    #[error("reserved capability")]
    ReservedCapability,

    #[error("reserved capability code")]
    ReservedCapabilityCode,

    #[error("reserved optional parameter")]
    ReservedOptionalParameter,

    #[error("unassigned")]
    Unassigned(u8),

    #[error("experimental")]
    Experimental,

    #[error("invalid code")]
    InvalidCode(u8),

    #[error("bad length")]
    BadLength { expected: u8, found: u8 },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("unexpected end of input")]
    Eom,

    #[error("Message type error")]
    MessageType(#[from] TryFromPrimitiveError<MessageType>),

    #[error("Optional parameter code error")]
    OptionalParameterCode(#[from] TryFromPrimitiveError<OptionalParameterCode>),

    #[error("Capability code error")]
    CapabilityCode(#[from] TryFromPrimitiveError<CapabilityCode>),

    #[error("Path attribute type code error")]
    PathAttributeCode(#[from] TryFromPrimitiveError<PathAttributeTypeCode>),

    #[error("AS path type error")]
    AsPathType(#[from] TryFromPrimitiveError<AsPathType>),

    #[error("Error code")]
    ErrorCode(#[from] TryFromPrimitiveError<ErrorCode>),

    #[error("Header error subcode")]
    HeaderSubcode(#[from] TryFromPrimitiveError<HeaderErrorSubcode>),

    #[error("Open error subcode")]
    OpenSubcode(#[from] TryFromPrimitiveError<OpenErrorSubcode>),

    #[error("Update error subcode")]
    UpdateSubcode(#[from] TryFromPrimitiveError<UpdateErrorSubcode>),

    #[error("Cease error subcode")]
    CeaseSubcode(#[from] TryFromPrimitiveError<CeaseErrorSubcode>),

    #[error("Path origin error")]
    PathOrigin(#[from] TryFromPrimitiveError<PathOrigin>),

    #[error("message parse error")]
    Parse(nom::Err<(Vec<u8>, nom::error::ErrorKind)>),

    #[error("Malformed attribute list: {0}")]
    MalformedAttributeList(String),

    #[error("Invalid NLRI prefix: {0:?}")]
    InvalidNlriPrefix(Vec<u8>),

    #[error("Invalid prefix length {0}, max is {1}")]
    InvalidPrefixLength(u8, u8),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),
}

impl<'a> From<nom::Err<(&'a [u8], nom::error::ErrorKind)>> for WireError {
    fn from(e: nom::Err<(&'a [u8], nom::error::ErrorKind)>) -> WireError {
        WireError::Parse(e.to_owned())
    }
}
