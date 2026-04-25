// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Display and conversion impls for the versioned BGP wire-message types.

use std::fmt::{Display, Formatter};

use rdb_types_versions::v1::AddressFamily;

use crate::v1::messages::{
    CeaseErrorSubcode, ErrorCode, HeaderErrorSubcode, OpenErrorSubcode,
    PathOrigin, Safi, UpdateErrorSubcode,
};
use crate::v4::messages::Afi;

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
