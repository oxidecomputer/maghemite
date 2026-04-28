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
use std::collections::BTreeSet;

use crate::v1::messages::{
    AS_TRANS, AddPathElement, AsPathType, BGP4, Capability, CapabilityCode,
    CeaseErrorSubcode, ErrorCode, ErrorSubcode, Header, HeaderErrorSubcode,
    MAX_MESSAGE_SIZE, MessageKind, MessageType, NotificationMessage,
    OpenErrorSubcode, OpenMessage, OptionalParameter,
    PathAttribute as PathAttributeV1, PathAttributeType as PathAttributeTypeV1,
    PathAttributeTypeCode as PathAttributeTypeCodeV1,
    PathAttributeValue as PathAttributeValueV1, PathOrigin,
    RouteRefreshMessage, Safi, UpdateErrorSubcode,
};
use crate::v4::messages::{
    Afi, Aggregator, As4Aggregator, As4PathSegment, BgpNexthop,
    ExtendedNexthopElement, Ipv6DoubleNexthop, MpReachIpv4Unicast,
    MpReachIpv6Unicast, MpReachNlri, MpUnreachIpv4Unicast,
    MpUnreachIpv6Unicast, MpUnreachNlri, PathAttribute, PathAttributeType,
    PathAttributeTypeCode, PathAttributeValue, path_attribute_flags,
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

impl Display for MessageKind {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            MessageKind::Open => write!(f, "open"),
            MessageKind::Update => write!(f, "update"),
            MessageKind::Notification => write!(f, "notification"),
            MessageKind::KeepAlive => write!(f, "keepalive"),
            MessageKind::RouteRefresh => write!(f, "route_refresh"),
        }
    }
}

impl slog::Value for MessageKind {
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

// ============================================================================
// v4 PathAttribute family inherent methods, Display impls, and conversions.
// ============================================================================

impl Aggregator {
    /// Parse AGGREGATOR from wire format (6 bytes: 2-byte ASN + 4-byte IP).
    pub fn from_wire(input: &[u8]) -> Result<Self, String> {
        if input.len() != 6 {
            return Err(format!(
                "AGGREGATOR attribute length must be 6, got {}",
                input.len()
            ));
        }
        let asn = u16::from_be_bytes([input[0], input[1]]);
        let address = Ipv4Addr::new(input[2], input[3], input[4], input[5]);
        Ok(Aggregator { asn, address })
    }

    /// Serialize AGGREGATOR to wire format.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(6);
        buf.extend_from_slice(&self.asn.to_be_bytes());
        buf.extend_from_slice(&self.address.octets());
        buf
    }

    /// Serialize AGGREGATOR to fixed-size byte array.
    pub fn to_bytes(&self) -> [u8; 6] {
        let asn_bytes = self.asn.to_be_bytes();
        let addr_bytes = self.address.octets();
        [
            asn_bytes[0],
            asn_bytes[1],
            addr_bytes[0],
            addr_bytes[1],
            addr_bytes[2],
            addr_bytes[3],
        ]
    }
}

impl Display for Aggregator {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "AS{} ({})", self.asn, self.address)
    }
}

impl As4Aggregator {
    /// Parse AS4_AGGREGATOR from wire format (8 bytes: 4-byte ASN + 4-byte IP).
    pub fn from_wire(input: &[u8]) -> Result<Self, String> {
        if input.len() != 8 {
            return Err(format!(
                "AS4_AGGREGATOR attribute length must be 8, got {}",
                input.len()
            ));
        }
        let asn = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
        let address = Ipv4Addr::new(input[4], input[5], input[6], input[7]);
        Ok(As4Aggregator { asn, address })
    }

    /// Serialize AS4_AGGREGATOR to wire format.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&self.asn.to_be_bytes());
        buf.extend_from_slice(&self.address.octets());
        buf
    }

    /// Serialize AS4_AGGREGATOR to fixed-size byte array.
    pub fn to_bytes(&self) -> [u8; 8] {
        let asn_bytes = self.asn.to_be_bytes();
        let addr_bytes = self.address.octets();
        [
            asn_bytes[0],
            asn_bytes[1],
            asn_bytes[2],
            asn_bytes[3],
            addr_bytes[0],
            addr_bytes[1],
            addr_bytes[2],
            addr_bytes[3],
        ]
    }
}

impl Display for As4Aggregator {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "AS{} ({})", self.asn, self.address)
    }
}

impl Display for As4PathSegment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.typ {
            // Wrap an AS-SET in curly braces
            AsPathType::AsSet => {
                let set = self
                    .value
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                write!(f, "{{ {set} }}")
            }
            // Wrap an AS-SEQUENCE in nothing
            AsPathType::AsSequence => {
                let seq = self
                    .value
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                write!(f, "{seq}")
            }
        }
    }
}

impl MpReachNlri {
    /// Returns the AFI for this MP_REACH_NLRI.
    pub fn afi(&self) -> Afi {
        match self {
            Self::Ipv4Unicast(_) => Afi::Ipv4,
            Self::Ipv6Unicast(_) => Afi::Ipv6,
        }
    }

    /// Returns the SAFI for this MP_REACH_NLRI (always Unicast).
    pub fn safi(&self) -> Safi {
        Safi::Unicast
    }

    /// Returns the next-hop for this MP_REACH_NLRI.
    pub fn nexthop(&self) -> &BgpNexthop {
        match self {
            Self::Ipv4Unicast(inner) => &inner.nexthop,
            Self::Ipv6Unicast(inner) => &inner.nexthop,
        }
    }

    /// Returns true if there are no prefixes in this MP_REACH_NLRI.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Ipv4Unicast(inner) => inner.nlri.is_empty(),
            Self::Ipv6Unicast(inner) => inner.nlri.is_empty(),
        }
    }

    /// Returns the number of prefixes in this MP_REACH_NLRI.
    pub fn len(&self) -> usize {
        match self {
            Self::Ipv4Unicast(inner) => inner.nlri.len(),
            Self::Ipv6Unicast(inner) => inner.nlri.len(),
        }
    }

    /// Create an IPv4 Unicast MP_REACH_NLRI.
    pub fn ipv4_unicast(
        nexthop: BgpNexthop,
        nlri: Vec<rdb_types_versions::v1::prefix::Prefix4>,
    ) -> Self {
        Self::Ipv4Unicast(MpReachIpv4Unicast {
            nexthop,
            reserved: 0, // Always send 0 per RFC 4760
            nlri,
        })
    }

    /// Create an IPv6 Unicast MP_REACH_NLRI.
    pub fn ipv6_unicast(
        nexthop: BgpNexthop,
        nlri: Vec<rdb_types_versions::v1::prefix::Prefix6>,
    ) -> Self {
        Self::Ipv6Unicast(MpReachIpv6Unicast {
            nexthop,
            reserved: 0,
            nlri,
        })
    }
}

impl Display for MpReachNlri {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4Unicast(inner) => write!(
                f,
                "MpReachNlri::Ipv4Unicast[nh={}, nlri={}]",
                inner.nexthop,
                inner.nlri.len()
            ),
            Self::Ipv6Unicast(inner) => write!(
                f,
                "MpReachNlri::Ipv6Unicast[nh={}, nlri={}]",
                inner.nexthop,
                inner.nlri.len()
            ),
        }
    }
}

impl MpUnreachNlri {
    pub fn afi(&self) -> Afi {
        match self {
            Self::Ipv4Unicast(_) => Afi::Ipv4,
            Self::Ipv6Unicast(_) => Afi::Ipv6,
        }
    }

    pub fn safi(&self) -> Safi {
        Safi::Unicast
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Ipv4Unicast(inner) => inner.withdrawn.is_empty(),
            Self::Ipv6Unicast(inner) => inner.withdrawn.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Ipv4Unicast(inner) => inner.withdrawn.len(),
            Self::Ipv6Unicast(inner) => inner.withdrawn.len(),
        }
    }

    /// Create an IPv4 Unicast MP_UNREACH_NLRI.
    pub fn ipv4_unicast(
        withdrawn: Vec<rdb_types_versions::v1::prefix::Prefix4>,
    ) -> Self {
        Self::Ipv4Unicast(MpUnreachIpv4Unicast { withdrawn })
    }

    /// Create an IPv6 Unicast MP_UNREACH_NLRI.
    pub fn ipv6_unicast(
        withdrawn: Vec<rdb_types_versions::v1::prefix::Prefix6>,
    ) -> Self {
        Self::Ipv6Unicast(MpUnreachIpv6Unicast { withdrawn })
    }
}

impl Display for MpUnreachNlri {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4Unicast(inner) => write!(
                f,
                "MpUnreachNlri::Ipv4Unicast[withdrawn={}]",
                inner.withdrawn.len()
            ),
            Self::Ipv6Unicast(inner) => write!(
                f,
                "MpUnreachNlri::Ipv6Unicast[withdrawn={}]",
                inner.withdrawn.len()
            ),
        }
    }
}

impl Display for PathAttributeValue {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PathAttributeValue::Origin(po) => write!(f, "origin: {po}"),
            PathAttributeValue::AsPath(path_segs) => {
                let path = path_segs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                write!(f, "as-path: [{path}]")
            }
            PathAttributeValue::NextHop(nh) => write!(f, "next-hop: {nh}"),
            PathAttributeValue::MultiExitDisc(med) => write!(f, "med: {med}"),
            PathAttributeValue::LocalPref(pref) => {
                write!(f, "local-pref: {pref}")
            }
            PathAttributeValue::Aggregator(agg) => {
                write!(f, "aggregator: {agg}")
            }
            PathAttributeValue::Communities(comms) => {
                let comms = comms
                    .iter()
                    .map(|c| u32::from(*c).to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                write!(f, "communities: [{comms}]")
            }
            PathAttributeValue::AtomicAggregate => {
                write!(f, "atomic-aggregate")
            }
            PathAttributeValue::MpReachNlri(reach) => {
                write!(f, "mp-reach-nlri: {reach}")
            }
            PathAttributeValue::MpUnreachNlri(unreach) => {
                write!(f, "mp-unreach-nlri: {unreach}")
            }
            PathAttributeValue::As4Path(path_segs) => {
                let path = path_segs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                write!(f, "as4-path: [{path}]")
            }
            PathAttributeValue::As4Aggregator(agg) => {
                write!(f, "as4-aggregator: {agg}")
            }
        }
    }
}

impl From<&PathAttributeValue> for PathAttributeTypeCode {
    fn from(v: &PathAttributeValue) -> Self {
        match v {
            PathAttributeValue::Origin(_) => PathAttributeTypeCode::Origin,
            PathAttributeValue::AsPath(_) => PathAttributeTypeCode::AsPath,
            PathAttributeValue::NextHop(_) => PathAttributeTypeCode::NextHop,
            PathAttributeValue::MultiExitDisc(_) => {
                PathAttributeTypeCode::MultiExitDisc
            }
            PathAttributeValue::LocalPref(_) => {
                PathAttributeTypeCode::LocalPref
            }
            PathAttributeValue::Aggregator(_) => {
                PathAttributeTypeCode::Aggregator
            }
            PathAttributeValue::Communities(_) => {
                PathAttributeTypeCode::Communities
            }
            PathAttributeValue::AtomicAggregate => {
                PathAttributeTypeCode::AtomicAggregate
            }
            PathAttributeValue::MpReachNlri(_) => {
                PathAttributeTypeCode::MpReachNlri
            }
            PathAttributeValue::MpUnreachNlri(_) => {
                PathAttributeTypeCode::MpUnreachNlri
            }
            // RFC 4893: when 4-byte ASNs are negotiated, As4Path is encoded
            // under the AsPath type code on the wire.
            PathAttributeValue::As4Path(_) => PathAttributeTypeCode::AsPath,
            PathAttributeValue::As4Aggregator(_) => {
                PathAttributeTypeCode::As4Aggregator
            }
        }
    }
}

impl From<PathAttributeValue> for PathAttributeTypeCode {
    fn from(v: PathAttributeValue) -> Self {
        Self::from(&v)
    }
}

impl From<PathAttributeValue> for PathAttribute {
    fn from(v: PathAttributeValue) -> Self {
        let flags = match v {
            PathAttributeValue::Origin(_)
            | PathAttributeValue::AsPath(_)
            | PathAttributeValue::As4Path(_)
            | PathAttributeValue::NextHop(_)
            | PathAttributeValue::LocalPref(_) => {
                path_attribute_flags::TRANSITIVE
            }
            PathAttributeValue::Communities(_) => {
                path_attribute_flags::OPTIONAL
                    | path_attribute_flags::TRANSITIVE
            }
            _ => path_attribute_flags::OPTIONAL,
        };
        Self {
            typ: PathAttributeType {
                flags,
                type_code: PathAttributeTypeCode::from(&v),
            },
            value: v,
        }
    }
}

// ----------------------------------------------------------------------------
// Cross-version conversions: v4 (current) → v1 (compat shapes).
// ----------------------------------------------------------------------------

impl From<rdb_types_versions::v1::prefix::Prefix>
    for crate::v1::messages::Prefix
{
    fn from(prefix: rdb_types_versions::v1::prefix::Prefix) -> Self {
        // Convert new Prefix enum to old struct format using wire format:
        // length byte followed by prefix octets.
        // Prefix4/Prefix6 wire format: 1-byte length + ceil(length/8) octets.
        // We use direct encoding here to avoid a circular dep on
        // bgp::messages::BgpWireFormat.
        match prefix {
            rdb_types_versions::v1::prefix::Prefix::V4(p) => {
                let length = p.length;
                let octet_count = (length as usize).div_ceil(8);
                let octets = p.value.octets();
                let value = octets[..octet_count].to_vec();
                Self { length, value }
            }
            rdb_types_versions::v1::prefix::Prefix::V6(p) => {
                let length = p.length;
                let octet_count = (length as usize).div_ceil(8);
                let octets = p.value.octets();
                let value = octets[..octet_count].to_vec();
                Self { length, value }
            }
        }
    }
}

impl From<PathAttributeTypeCode> for PathAttributeTypeCodeV1 {
    fn from(code: PathAttributeTypeCode) -> Self {
        match code {
            PathAttributeTypeCode::Origin => PathAttributeTypeCodeV1::Origin,
            PathAttributeTypeCode::AsPath => PathAttributeTypeCodeV1::AsPath,
            PathAttributeTypeCode::NextHop => PathAttributeTypeCodeV1::NextHop,
            PathAttributeTypeCode::MultiExitDisc => {
                PathAttributeTypeCodeV1::MultiExitDisc
            }
            PathAttributeTypeCode::LocalPref => {
                PathAttributeTypeCodeV1::LocalPref
            }
            PathAttributeTypeCode::AtomicAggregate => {
                PathAttributeTypeCodeV1::AtomicAggregate
            }
            PathAttributeTypeCode::Aggregator => {
                PathAttributeTypeCodeV1::Aggregator
            }
            PathAttributeTypeCode::Communities => {
                PathAttributeTypeCodeV1::Communities
            }
            // MP-BGP type codes have no v1 equivalent; map to As4Path as a
            // fallback (they are filtered out before this conversion runs in
            // the value-level mapping).
            PathAttributeTypeCode::MpReachNlri
            | PathAttributeTypeCode::MpUnreachNlri => {
                PathAttributeTypeCodeV1::As4Path
            }
            PathAttributeTypeCode::As4Path => PathAttributeTypeCodeV1::As4Path,
            PathAttributeTypeCode::As4Aggregator => {
                PathAttributeTypeCodeV1::As4Aggregator
            }
        }
    }
}

impl From<PathAttributeType> for PathAttributeTypeV1 {
    fn from(t: PathAttributeType) -> Self {
        Self {
            flags: t.flags,
            type_code: PathAttributeTypeCodeV1::from(t.type_code),
        }
    }
}

impl From<PathAttributeValue> for Option<PathAttributeValueV1> {
    fn from(val: PathAttributeValue) -> Self {
        match val {
            PathAttributeValue::Origin(o) => {
                Some(PathAttributeValueV1::Origin(o))
            }
            PathAttributeValue::AsPath(p) => {
                Some(PathAttributeValueV1::AsPath(p))
            }
            PathAttributeValue::NextHop(nh) => {
                Some(PathAttributeValueV1::NextHop(IpAddr::V4(nh)))
            }
            PathAttributeValue::MultiExitDisc(m) => {
                Some(PathAttributeValueV1::MultiExitDisc(m))
            }
            PathAttributeValue::LocalPref(l) => {
                Some(PathAttributeValueV1::LocalPref(l))
            }
            PathAttributeValue::Aggregator(a) => {
                Some(PathAttributeValueV1::Aggregator(a.to_bytes()))
            }
            PathAttributeValue::Communities(c) => {
                Some(PathAttributeValueV1::Communities(c))
            }
            // AtomicAggregate / MP-BGP attributes have no v1 representation.
            PathAttributeValue::AtomicAggregate
            | PathAttributeValue::MpReachNlri(_)
            | PathAttributeValue::MpUnreachNlri(_) => None,
            PathAttributeValue::As4Path(p) => {
                Some(PathAttributeValueV1::As4Path(p))
            }
            PathAttributeValue::As4Aggregator(a) => {
                Some(PathAttributeValueV1::As4Aggregator(a.to_bytes()))
            }
        }
    }
}

impl From<PathAttribute> for Option<PathAttributeV1> {
    fn from(attr: PathAttribute) -> Self {
        let value_opt: Option<PathAttributeValueV1> = attr.value.into();
        value_opt.map(|value| PathAttributeV1 {
            typ: PathAttributeTypeV1::from(attr.typ),
            value,
        })
    }
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

impl From<CeaseErrorSubcode> for ErrorSubcode {
    fn from(x: CeaseErrorSubcode) -> ErrorSubcode {
        ErrorSubcode::Cease(x)
    }
}

impl Display for ErrorSubcode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ErrorSubcode::Header(header_error_subcode) => {
                write!(f, "{header_error_subcode}")
            }
            ErrorSubcode::Open(open_error_subcode) => {
                write!(f, "{open_error_subcode}")
            }
            ErrorSubcode::Update(update_error_subcode) => {
                write!(f, "{update_error_subcode}")
            }
            ErrorSubcode::HoldTime(i) => write!(f, "{i}"),
            ErrorSubcode::Fsm(i) => write!(f, "{i}"),
            ErrorSubcode::Cease(cease_error_subcode) => {
                write!(f, "{cease_error_subcode}")
            }
        }
    }
}

impl Display for OptionalParameter {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            OptionalParameter::Reserved => write!(f, "Reserved (0)"),
            OptionalParameter::Authentication => {
                write!(f, "Authentication (1)")
            }
            OptionalParameter::Capabilities(caps) => {
                let mut cap_string = String::new();
                for cap in caps {
                    cap_string.push_str(&format!("{cap}, "));
                }
                write!(f, "Capabilities [ {cap_string}]")
            }
            OptionalParameter::Unassigned => write!(f, "Unassigned"),
            OptionalParameter::ExtendedLength => {
                write!(f, "Extended Length (255)")
            }
        }
    }
}

impl Display for Capability {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Capability::MultiprotocolExtensions { afi, safi } => {
                write!(f, "MP-Extensions {afi}/{safi}")
            }
            Capability::RouteRefresh {} => {
                write!(f, "Route Refresh")
            }
            Capability::OutboundRouteFiltering {} => {
                write!(f, "ORF")
            }
            Capability::MultipleRoutesToDestination {} => {
                write!(f, "Multiple Routes to Destination")
            }
            Capability::ExtendedNextHopEncoding { elements } => {
                let elements = elements
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "Extended Next Hop Encoding {elements}")
            }
            Capability::BGPExtendedMessage {} => {
                write!(f, "BGP Extended Message")
            }
            Capability::BgpSec {} => {
                write!(f, "BGP Sec")
            }
            Capability::MultipleLabels {} => {
                write!(f, "Multiple Labels")
            }
            Capability::BgpRole {} => {
                write!(f, "BGP Role")
            }
            Capability::GracefulRestart {} => {
                write!(f, "Graceful Restart")
            }
            Capability::FourOctetAs { asn } => {
                write!(f, "Four Octet ASN {asn}")
            }
            Capability::DynamicCapability {} => {
                write!(f, "Dynamic Capability")
            }
            Capability::MultisessionBgp {} => {
                write!(f, "Multi-session BGP")
            }
            Capability::AddPath { elements } => {
                let mut elements_string = String::new();
                for e in elements {
                    elements_string.push_str(&format!("{e}, "));
                }
                write!(f, "AddPath [ {elements_string}]")
            }
            Capability::EnhancedRouteRefresh {} => {
                write!(f, "Enhanced Route Refresh")
            }
            Capability::LongLivedGracefulRestart {} => {
                write!(f, "Long-Lived Graceful Restart")
            }
            Capability::RoutingPolicyDistribution {} => {
                write!(f, "Routing Policy Distribution")
            }
            Capability::Fqdn {} => {
                write!(f, "FQDN")
            }
            Capability::PrestandardRouteRefresh {} => {
                write!(f, "Route Refresh (Prestandard)")
            }
            Capability::PrestandardOrfAndPd {} => {
                write!(f, "ORF / Policy Distribution (Prestandard)")
            }
            Capability::PrestandardOutboundRouteFiltering {} => {
                write!(f, "ORF (Prestandard)")
            }
            Capability::PrestandardMultisession {} => {
                write!(f, "Multi-session BGP (Prestandard)")
            }
            Capability::PrestandardFqdn {} => {
                write!(f, "FQDN (Prestandard)")
            }
            Capability::PrestandardOperationalMessage {} => {
                write!(f, "Operational Message (Prestandard)")
            }
            Capability::Experimental { code } => {
                write!(f, "Experimental ({code})")
            }
            Capability::Unassigned { code } => {
                write!(f, "Unassigned ({code})")
            }
            Capability::Reserved { code } => {
                write!(f, "Reserved ({code})")
            }
        }
    }
}

impl Capability {
    /// Helper function to generate an IPv4 Unicast MP-BGP capability.
    pub fn ipv4_unicast() -> Self {
        Self::MultiprotocolExtensions {
            afi: crate::v4::messages::Afi::Ipv4.into(),
            safi: Safi::Unicast.into(),
        }
    }

    /// Helper function to generate an IPv6 Unicast MP-BGP capability.
    pub fn ipv6_unicast() -> Self {
        Self::MultiprotocolExtensions {
            afi: crate::v4::messages::Afi::Ipv6.into(),
            safi: Safi::Unicast.into(),
        }
    }

    pub fn extended_nh_v4_over_v6(&self) -> bool {
        if let Self::ExtendedNextHopEncoding { elements } = self {
            elements.iter().any(|x| x.is_v4_over_v6())
        } else {
            false
        }
    }

    pub fn extended_nh_v6_over_v4(&self) -> bool {
        if let Self::ExtendedNextHopEncoding { elements } = self {
            elements.iter().any(|x| x.is_v6_over_v4())
        } else {
            false
        }
    }
}

impl From<Capability> for CapabilityCode {
    fn from(value: Capability) -> CapabilityCode {
        match value {
            Capability::MultiprotocolExtensions { afi: _, safi: _ } => {
                CapabilityCode::MultiprotocolExtensions
            }
            Capability::RouteRefresh {} => CapabilityCode::RouteRefresh,
            Capability::OutboundRouteFiltering {} => {
                CapabilityCode::OutboundRouteFiltering
            }
            Capability::MultipleRoutesToDestination {} => {
                CapabilityCode::MultipleRoutesToDestination
            }
            Capability::ExtendedNextHopEncoding { elements: _ } => {
                CapabilityCode::ExtendedNextHopEncoding
            }
            Capability::BGPExtendedMessage {} => {
                CapabilityCode::BGPExtendedMessage
            }
            Capability::BgpSec {} => CapabilityCode::BgpSec,
            Capability::MultipleLabels {} => CapabilityCode::MultipleLabels,
            Capability::BgpRole {} => CapabilityCode::BgpRole,
            Capability::GracefulRestart {} => CapabilityCode::GracefulRestart,
            Capability::FourOctetAs { asn: _ } => CapabilityCode::FourOctetAs,
            Capability::DynamicCapability {} => {
                CapabilityCode::DynamicCapability
            }
            Capability::MultisessionBgp {} => CapabilityCode::MultisessionBgp,
            Capability::AddPath { elements: _ } => CapabilityCode::AddPath,
            Capability::EnhancedRouteRefresh {} => {
                CapabilityCode::EnhancedRouteRefresh
            }
            Capability::LongLivedGracefulRestart {} => {
                CapabilityCode::LongLivedGracefulRestart
            }
            Capability::RoutingPolicyDistribution {} => {
                CapabilityCode::RoutingPolicyDistribution
            }
            Capability::Fqdn {} => CapabilityCode::Fqdn,
            Capability::PrestandardRouteRefresh {} => {
                CapabilityCode::PrestandardRouteRefresh
            }
            Capability::PrestandardOrfAndPd {} => {
                CapabilityCode::PrestandardOrfAndPd
            }
            Capability::PrestandardOutboundRouteFiltering {} => {
                CapabilityCode::PrestandardOutboundRouteFiltering
            }
            Capability::PrestandardMultisession {} => {
                CapabilityCode::PrestandardMultisession
            }
            Capability::PrestandardFqdn {} => CapabilityCode::PrestandardFqdn,
            Capability::PrestandardOperationalMessage {} => {
                CapabilityCode::PrestandardOperationalMessage
            }
            Capability::Experimental { code } => match code {
                0 => CapabilityCode::Experimental0,
                1 => CapabilityCode::Experimental1,
                2 => CapabilityCode::Experimental2,
                3 => CapabilityCode::Experimental3,
                4 => CapabilityCode::Experimental4,
                5 => CapabilityCode::Experimental5,
                6 => CapabilityCode::Experimental6,
                7 => CapabilityCode::Experimental7,
                8 => CapabilityCode::Experimental8,
                9 => CapabilityCode::Experimental9,
                10 => CapabilityCode::Experimental10,
                11 => CapabilityCode::Experimental11,
                12 => CapabilityCode::Experimental12,
                13 => CapabilityCode::Experimental13,
                14 => CapabilityCode::Experimental14,
                15 => CapabilityCode::Experimental15,
                16 => CapabilityCode::Experimental16,
                17 => CapabilityCode::Experimental17,
                18 => CapabilityCode::Experimental18,
                19 => CapabilityCode::Experimental19,
                20 => CapabilityCode::Experimental20,
                21 => CapabilityCode::Experimental21,
                22 => CapabilityCode::Experimental22,
                23 => CapabilityCode::Experimental23,
                24 => CapabilityCode::Experimental24,
                25 => CapabilityCode::Experimental25,
                26 => CapabilityCode::Experimental26,
                27 => CapabilityCode::Experimental27,
                28 => CapabilityCode::Experimental28,
                29 => CapabilityCode::Experimental29,
                30 => CapabilityCode::Experimental30,
                31 => CapabilityCode::Experimental31,
                32 => CapabilityCode::Experimental32,
                33 => CapabilityCode::Experimental33,
                34 => CapabilityCode::Experimental34,
                35 => CapabilityCode::Experimental35,
                36 => CapabilityCode::Experimental36,
                37 => CapabilityCode::Experimental37,
                38 => CapabilityCode::Experimental38,
                39 => CapabilityCode::Experimental39,
                40 => CapabilityCode::Experimental40,
                41 => CapabilityCode::Experimental41,
                42 => CapabilityCode::Experimental42,
                43 => CapabilityCode::Experimental43,
                44 => CapabilityCode::Experimental44,
                45 => CapabilityCode::Experimental45,
                46 => CapabilityCode::Experimental46,
                47 => CapabilityCode::Experimental47,
                48 => CapabilityCode::Experimental48,
                49 => CapabilityCode::Experimental49,
                50 => CapabilityCode::Experimental50,
                51 => CapabilityCode::Experimental51,
                _ => CapabilityCode::Experimental0,
            },
            Capability::Unassigned { code: _ } => CapabilityCode::Reserved,
            Capability::Reserved { code: _ } => CapabilityCode::Reserved,
        }
    }
}

impl OpenMessage {
    /// Create a new open message for a sender with a 2-byte ASN
    pub fn new2(
        asn: u16,
        hold_time: u16,
        id: u32,
        extended_nexthop: bool,
    ) -> OpenMessage {
        let parameters = if extended_nexthop {
            let caps = BTreeSet::from([Capability::ExtendedNextHopEncoding {
                elements: vec![ExtendedNexthopElement {
                    afi: Afi::Ipv4.into(),
                    safi: u8::from(Safi::Unicast).into(),
                    nh_afi: Afi::Ipv6.into(),
                }],
            }]);
            vec![OptionalParameter::Capabilities(caps)]
        } else {
            Vec::default()
        };
        OpenMessage {
            version: BGP4,
            asn,
            hold_time,
            id,
            parameters,
        }
    }

    /// Create a new open message for a sender with a 4-byte ASN
    pub fn new4(
        asn: u32,
        hold_time: u16,
        id: u32,
        extended_nexthop: bool,
    ) -> OpenMessage {
        let mut params = BTreeSet::from([Capability::FourOctetAs { asn }]);
        if extended_nexthop {
            params.insert(Capability::ExtendedNextHopEncoding {
                elements: vec![ExtendedNexthopElement {
                    afi: Afi::Ipv4.into(),
                    safi: u8::from(Safi::Unicast).into(),
                    nh_afi: Afi::Ipv6.into(),
                }],
            });
        }
        OpenMessage {
            version: BGP4,
            asn: u16::try_from(asn).unwrap_or(AS_TRANS),
            hold_time,
            id,
            parameters: vec![OptionalParameter::Capabilities(params)],
        }
    }

    pub fn add_capabilities(&mut self, capabilities: &BTreeSet<Capability>) {
        if capabilities.is_empty() {
            return;
        }
        for p in &mut self.parameters {
            if let OptionalParameter::Capabilities(cs) = p {
                cs.extend(capabilities.iter().cloned());
                return;
            }
        }
        self.parameters
            .push(OptionalParameter::Capabilities(capabilities.clone()));
    }

    pub fn get_capabilities(&self) -> BTreeSet<Capability> {
        let mut result = BTreeSet::new();
        for p in self.parameters.iter() {
            if let OptionalParameter::Capabilities(caps) = p {
                result.extend(caps.clone().into_iter());
            }
        }
        result
    }

    pub fn has_capability(&self, code: CapabilityCode) -> bool {
        self.get_capabilities()
            .into_iter()
            .any(|x| CapabilityCode::from(x) == code)
    }

    pub fn asn(&self) -> u32 {
        let mut remote_asn = u32::from(self.asn);
        for p in &self.parameters {
            if let OptionalParameter::Capabilities(caps) = p {
                for c in caps {
                    if let Capability::FourOctetAs { asn } = c {
                        remote_asn = *asn;
                    }
                }
            }
        }
        remote_asn
    }
}

impl Display for OpenMessage {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let param_string = self
            .parameters
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            f,
            "Open [ version: {}, asn: {}, hold_time: {}, id: {}, parameters: [ {param_string}] ]",
            self.version, self.asn, self.hold_time, self.id
        )
    }
}

impl Display for NotificationMessage {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "Notification [ error_code: {}, error_subcode: {}, data: {:?} ]",
            self.error_code, self.error_subcode, self.data
        )
    }
}

impl Display for RouteRefreshMessage {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "Route Refresh [ afi: {}, safi: {} ]",
            self.afi, self.safi
        )
    }
}
