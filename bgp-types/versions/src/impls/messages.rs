// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Display and conversion impls for the versioned BGP wire-message types.

use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nom::{
    bytes::complete::tag,
    number::complete::{be_u16, u8 as parse_u8},
};
use num_enum::TryFromPrimitive;
use rdb_types_versions::v1::AddressFamily;

use crate::error::WireError;
use crate::v1::messages::{
    AddPathElement, CeaseErrorSubcode, ErrorCode, Header, HeaderErrorSubcode,
    MAX_MESSAGE_SIZE, MessageType, OpenErrorSubcode, PathOrigin, Safi,
    UpdateErrorSubcode,
};
use crate::v4::messages::{
    Afi, BgpNexthop, ExtendedNexthopElement, Ipv6DoubleNexthop,
};

/// According to RFC 4271 §4.1 the header marker is all ones.
const MARKER: [u8; 16] = [0xFFu8; 16];

impl Header {
    /// Create a new BGP message header. Length must be between 19 and 4096 per
    /// RFC 4271 §4.1.
    pub fn new(length: u16, typ: MessageType) -> Result<Header, WireError> {
        if usize::from(length) < Header::WIRE_SIZE {
            return Err(WireError::TooSmall("message header length".into()));
        }
        if usize::from(length) > MAX_MESSAGE_SIZE {
            return Err(WireError::TooLarge("message header length".into()));
        }
        Ok(Header { length, typ })
    }

    /// Serialize the header to wire format.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = MARKER.to_vec();
        buf.extend_from_slice(&self.length.to_be_bytes());
        buf.push(self.typ.into());
        buf
    }

    /// Deserialize a header from wire format.
    pub fn from_wire(input: &[u8]) -> Result<Header, WireError> {
        let (input, _) = tag(&MARKER[..])(input)?;
        let (input, length) = be_u16(input)?;
        let (_, typ) = parse_u8(input)?;
        let typ = MessageType::try_from(typ)?;
        Ok(Header { length, typ })
    }
}

impl Display for AddPathElement {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "AddPathElement {{ afi: {}, safi: {}, send_receive: {} }}",
            match Afi::try_from_primitive(self.afi) {
                Ok(x) => x.to_string(),
                _ => self.afi.to_string(),
            },
            match Safi::try_from_primitive(self.safi) {
                Ok(x) => x.to_string(),
                _ => self.safi.to_string(),
            },
            self.send_receive
        )
    }
}

impl ExtendedNexthopElement {
    pub fn is_v4_over_v6(&self) -> bool {
        self == &ExtendedNexthopElement {
            afi: Afi::Ipv4.into(),
            safi: u8::from(Safi::Unicast).into(),
            nh_afi: Afi::Ipv6.into(),
        }
    }
    pub fn is_v6_over_v4(&self) -> bool {
        self == &ExtendedNexthopElement {
            afi: Afi::Ipv6.into(),
            safi: u8::from(Safi::Unicast).into(),
            nh_afi: Afi::Ipv4.into(),
        }
    }
}

impl Display for ExtendedNexthopElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "safi={}/afi={}/nh_afi={}",
            self.afi, self.safi, self.nh_afi
        )
    }
}

impl BgpNexthop {
    /// Parse next-hop from raw bytes based on AFI and length.
    ///
    /// Per RFC 4760 and RFC 2545:
    /// - IPv4: 4 bytes (single IPv4 address)
    /// - IPv6: 16 bytes (single global unicast) or 32 bytes (global + link-local)
    pub fn from_bytes(
        nh_bytes: &[u8],
        nh_len: u8,
        afi: Afi,
    ) -> Result<Self, WireError> {
        if nh_bytes.len() != usize::from(nh_len) {
            return Err(WireError::InvalidAddress(format!(
                "next-hop bytes length {} doesn't match nh_len {}",
                nh_bytes.len(),
                nh_len
            )));
        }

        // SAFETY: The length check above guarantees nh_bytes.len() == nh_len.
        // Each match arm below only matches when nh_len equals the exact size
        // needed for copy_from_slice, so all slice operations are bounds-safe.
        match (afi, nh_len) {
            (Afi::Ipv4, 4) => {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(nh_bytes);
                Ok(BgpNexthop::Ipv4(Ipv4Addr::from(bytes)))
            }
            (Afi::Ipv4 | Afi::Ipv6, 16) => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(nh_bytes);
                Ok(BgpNexthop::Ipv6Single(Ipv6Addr::from(bytes)))
            }
            (Afi::Ipv4 | Afi::Ipv6, 32) => {
                let mut bytes1 = [0u8; 16];
                let mut bytes2 = [0u8; 16];
                bytes1.copy_from_slice(&nh_bytes[..16]);
                bytes2.copy_from_slice(&nh_bytes[16..32]);
                Ok(BgpNexthop::Ipv6Double(Ipv6DoubleNexthop {
                    global: Ipv6Addr::from(bytes1),
                    link_local: Ipv6Addr::from(bytes2),
                }))
            }
            _ => Err(WireError::InvalidAddress(format!(
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
            BgpNexthop::Ipv6Double(addrs) => addrs
                .global
                .octets()
                .into_iter()
                .chain(addrs.link_local.octets())
                .collect(),
        }
    }
}

impl Display for BgpNexthop {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BgpNexthop::Ipv4(a4) => write!(f, "{a4}"),
            BgpNexthop::Ipv6Single(a6) => write!(f, "{a6}"),
            BgpNexthop::Ipv6Double(addrs) => {
                write!(f, "({}, {})", addrs.global, addrs.link_local)
            }
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

impl From<IpAddr> for BgpNexthop {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ip4) => BgpNexthop::Ipv4(ip4),
            IpAddr::V6(ip6) => BgpNexthop::Ipv6Single(ip6),
        }
    }
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

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let val: u8 = (*self).into();
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

impl Display for HeaderErrorSubcode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let val: u8 = (*self).into();
        match self {
            HeaderErrorSubcode::Unspecific => write!(f, "{val} (Unspecific)"),
            HeaderErrorSubcode::ConnectionNotSynchronized => {
                write!(f, "{val} (Connection Not Synchronized)")
            }
            HeaderErrorSubcode::BadMessageLength => {
                write!(f, "{val} (Bad Message Length)")
            }
            HeaderErrorSubcode::BadMessageType => {
                write!(f, "{val} (Bad Message Type)")
            }
        }
    }
}

impl Display for OpenErrorSubcode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let val: u8 = (*self).into();
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

impl Display for UpdateErrorSubcode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let val: u8 = (*self).into();
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

impl Display for CeaseErrorSubcode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let val: u8 = (*self).into();
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
