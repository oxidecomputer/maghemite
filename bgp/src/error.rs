#[derive(Debug)]
pub enum Error {
    TooSmall,
    TooLarge,
    NoMarker,
    InvalidMessageType(u8),
    BadVersion,
    Reserved,
    Unassigned(u8),
    Experimental,
    InvalidCode(u8),
    BadLength { expected: u8, found: u8 },
}
