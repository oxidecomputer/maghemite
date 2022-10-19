use num_enum::TryFromPrimitiveError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("too small")]
    TooSmall,
    #[error("too large")]
    TooLarge,
    #[error("no marker")]
    NoMarker,
    #[error("invalid message type")]
    InvalidMessageType(u8),
    #[error("bad version")]
    BadVersion,
    #[error("reserved")]
    Reserved,
    #[error("unassigned")]
    Unassigned(u8),
    #[error("experimental")]
    Experimental,
    #[error("invalid code")]
    InvalidCode(u8),
    #[error("bad length")]
    BadLength { expected: u8, found: u8 },

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

    #[error("message parse error")]
    Parse(nom::Err<(Vec<u8>, nom::error::ErrorKind)>),
}

impl<'a> From<nom::Err<(&'a [u8], nom::error::ErrorKind)>> for Error {
    fn from(e: nom::Err<(&'a [u8], nom::error::ErrorKind)>) -> Error {
        Error::Parse(e.to_owned())
    }
}