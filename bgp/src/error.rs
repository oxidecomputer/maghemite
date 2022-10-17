pub enum Error {
    TooSmall,
    TooLarge,
    NoMarker,
    InvalidMessageType(u8),
    BadVersion,
    Reserved,
    Unassigned,
    Experimental,
    InvalidCode(u8),
    BadLength,
}
