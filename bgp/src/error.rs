// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{fmt::Display, net::IpAddr};

use num_enum::TryFromPrimitiveError;
use rdb::Prefix4;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("too small")]
    TooSmall(String),

    #[error("too large")]
    TooLarge(String),

    #[error("no marker")]
    NoMarker,

    #[error("invalid message type")]
    InvalidMessageType(u8),

    #[error("bad version")]
    BadVersion,

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

    #[error("io {0}")]
    Io(#[from] std::io::Error),

    #[error("channel recv {0}")]
    ChannelRecv(#[from] std::sync::mpsc::RecvError),

    #[error("timeout")]
    Timeout,

    #[error("disconnected")]
    Disconnected,

    #[error("channel send {0}")]
    ChannelSend(String),

    #[error("unexpected end of input")]
    Eom,

    #[error("Message type error")]
    MessageType(#[from] TryFromPrimitiveError<crate::messages::MessageType>),

    #[error("Optional parameter code error")]
    OptionalParameterCode(
        #[from] TryFromPrimitiveError<crate::messages::OptionalParameterCode>,
    ),

    #[error("Capability code error")]
    CapabilityCode(
        #[from] TryFromPrimitiveError<crate::messages::CapabilityCode>,
    ),

    #[error("Path attribute type code error")]
    PathAttributeCode(
        #[from] TryFromPrimitiveError<crate::messages::PathAttributeTypeCode>,
    ),

    #[error("AS path type error")]
    AsPathType(#[from] TryFromPrimitiveError<crate::messages::AsPathType>),

    #[error("Error code")]
    ErrorCode(#[from] TryFromPrimitiveError<crate::messages::ErrorCode>),

    #[error("Header error subcode")]
    HeaderSubcode(
        #[from] TryFromPrimitiveError<crate::messages::HeaderErrorSubcode>,
    ),

    #[error("Open error subcode")]
    OpenSubcode(
        #[from] TryFromPrimitiveError<crate::messages::OpenErrorSubcode>,
    ),

    #[error("Update error subcode")]
    UpdateSubcode(
        #[from] TryFromPrimitiveError<crate::messages::UpdateErrorSubcode>,
    ),

    #[error("Cease error subcode")]
    CeaseSubcode(
        #[from] TryFromPrimitiveError<crate::messages::CeaseErrorSubcode>,
    ),

    #[error("Path origin error")]
    PathOrigin(#[from] TryFromPrimitiveError<crate::messages::PathOrigin>),

    #[error("message parse error")]
    Parse(nom::Err<(Vec<u8>, nom::error::ErrorKind)>),

    #[error("Channel connect error")]
    ChannelConnect,

    #[error("Attempt to send a message when not connected")]
    NotConnected,

    #[error("Connection attempt from unknown peer: {0}")]
    UnknownPeer(IpAddr),

    #[error("Session for peer already exists")]
    PeerExists,

    #[error("Capability code not supported {0:?}")]
    UnsupportedCapabilityCode(crate::messages::CapabilityCode),

    #[error("Capability not supported {0:?}")]
    UnsupportedCapability(crate::messages::Capability),

    #[error("Path attribute value not supported {0:?}")]
    UnsupportedPathAttributeValue(crate::messages::PathAttributeValue),

    #[error("Path attribute type code not supported {0:?}")]
    UnsupportedPathAttributeTypeCode(crate::messages::PathAttributeTypeCode),

    #[error("Unsupported optional parameter {0:?}")]
    UnsupportedOptionalParameter(crate::messages::OptionalParameter),

    #[error("Unsupported optional parameter code {0:?}")]
    UnsupportedOptionalParameterCode(crate::messages::OptionalParameterCode),

    #[error("Self loop detected")]
    SelfLoopDetected,

    #[error("AS path missing")]
    MissingAsPath,

    #[error("AS path is empty")]
    EmptyAsPath,

    #[error("Enforce-first-AS check failed: expected: {0}, found: {1:?}")]
    EnforceAsFirst(u32, Vec<u32>),

    #[error("Invalid address")]
    InvalidAddress(String),

    #[error("Datastore error {0}")]
    Datastore(#[from] rdb::error::Error),

    #[error("Internal communication error {0}")]
    InternalCommunication(String),

    #[error("Unexpected ASN {0}")]
    UnexpectedAsn(ExpectationMismatch<u32>),

    #[error("Hold time too small")]
    HoldTimeTooSmall,

    #[error("Invalid NLRI prefix")]
    InvalidNlriPrefix(Prefix4),

    #[error("Nexthop cannot equal prefix")]
    NexthopSelf(IpAddr),

    #[error("Nexthop missing")]
    MissingNexthop,

    #[error("Drop due to user defined policy")]
    PolicyCheckFailed,

    #[error("Policy error {0}")]
    PolicyError(#[from] crate::policy::Error),

    #[error("Message conversion: {0}")]
    MessageConversion(#[from] crate::messages::MessageConvertError),
}

#[derive(Debug)]
pub struct ExpectationMismatch<T: Display> {
    pub expected: T,
    pub got: T,
}

impl<T: Display> Display for ExpectationMismatch<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "expected: {} got: {}", self.expected, self.got)
    }
}

impl<'a> From<nom::Err<(&'a [u8], nom::error::ErrorKind)>> for Error {
    fn from(e: nom::Err<(&'a [u8], nom::error::ErrorKind)>) -> Error {
        Error::Parse(e.to_owned())
    }
}
