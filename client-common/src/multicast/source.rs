// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multicast source addresses for API and protocol types.
//!
//! The admin API and DDM share this source validation, without forcing a
//! dependency on `mg-api-types`. The enclosing route or protocol type owns
//! source/group IP family matching and the requirement for an SSM source.
//!
//! Validation used during deserialization is part of that wire version's
//! contract. Changes require a new version with upgrade and downgrade
//! conversions. The older decoder must retain its validation rules.

// TODO: replace with a validated multicast source newtype in oxnet, shared
// with dendrite's dpd-types validation and omicron's source checks.

use std::fmt::{self, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The reason an address cannot serve as a multicast `(S,G)` source.
///
/// The rules are validated in variant order. An address that breaks more
/// than one rule only reports the first hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidMulticastSource {
    /// `0.0.0.0` or `::`.
    Unspecified,

    /// `127.0.0.0/8` or `::1`.
    Loopback,

    /// `255.255.255.255`, the limited broadcast address that [RFC 919] §7
    /// dictates must not be forwarded. IPv6 has no broadcast address, making
    /// this IPv4 only.
    ///
    /// [RFC 919]: https://www.rfc-editor.org/rfc/rfc919.html
    Broadcast,

    /// `169.254.0.0/16` ([RFC 3927]) or `fe80::/10` ([RFC 4291] §2.5.6).
    ///
    /// [RFC 3927]: https://www.rfc-editor.org/rfc/rfc3927.html
    /// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
    LinkLocal,

    /// `0.0.0.0/8`. [RFC 1122] §3.2.1.3 permits it as a source before a
    /// host learns its own address, but reverse-path forwarding cannot
    /// resolve it to an incoming interface.
    ///
    /// [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122.html
    ThisNetwork,

    /// The class E block `240.0.0.0/4`, which the IANA special-purpose
    /// registry ([RFC 6890]) marks "Source: False".
    ///
    /// [RFC 6890]: https://www.rfc-editor.org/rfc/rfc6890.html
    Reserved,
}

impl fmt::Display for InvalidMulticastSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => write!(f, "is the unspecified address"),
            Self::Loopback => write!(f, "is a loopback address"),
            Self::Broadcast => write!(f, "is the broadcast address"),
            Self::LinkLocal => write!(f, "is a link-local address"),
            Self::ThisNetwork => {
                write!(f, "is in 0.0.0.0/8 (this host on this network)")
            }
            Self::Reserved => {
                write!(f, "is in the reserved class E block (240.0.0.0/4)")
            }
        }
    }
}

/// The IPv6 representation of an embedded IPv4 address.
///
/// Both variants carry the IPv4 address within the low 32 bits and differ only
/// in the 96-bit prefix ahead of those bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbeddedIpv4 {
    /// The `::ffff:0:0/96` form, which represents an IPv4 node's address
    /// to an IPv6 application ([RFC 4291] §2.5.5.2).
    ///
    /// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
    Mapped,

    /// The `::/96` form, which [RFC 4291] §2.5.5.1 deprecates because the
    /// transition mechanisms that used it are obsolete.
    ///
    /// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
    Compatible,
}

impl fmt::Display for EmbeddedIpv4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapped => {
                write!(f, "IPv4-mapped (::ffff:0:0/96, RFC 4291 §2.5.5.2)")
            }
            Self::Compatible => {
                write!(f, "IPv4-compatible (::/96, RFC 4291 §2.5.5.1)")
            }
        }
    }
}

/// Errors raised while validating a multicast source address.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum MulticastSourceError {
    /// A source address is a multicast address (not a unicast one).
    #[error(
        "Source IP {0} must be a unicast address (multicast addresses are not \
         allowed)"
    )]
    NotUnicast(IpAddr),

    /// An IPv4 source address is invalid if it is loopback, broadcast,
    /// unspecified, link-local, in the "this host on this network" block
    /// `0.0.0.0/8`, or in the class E block `240.0.0.0/4`.
    #[error("Source IP {addr} {reason}, which is not a valid source address")]
    InvalidIpv4 {
        /// The rejected source address.
        addr: Ipv4Addr,
        /// The source rule that failed.
        reason: InvalidMulticastSource,
    },

    /// An IPv6 source address is invalid if it is loopback, unspecified, or
    /// link-local.
    #[error("Source IP {addr} {reason}, which is not a valid source address")]
    InvalidIpv6 {
        /// The rejected source address.
        addr: Ipv6Addr,
        /// The source rule that failed.
        reason: InvalidMulticastSource,
    },

    /// An IPv6 source address is invalid if it uses an IPv4-mapped
    /// ([RFC 4291] §2.5.5.2) or IPv4-compatible ([RFC 4291] §2.5.5.1)
    /// representation. Either form converts to an IPv4 address and would
    /// carry IPv4 semantics past the IPv4 source checks.
    ///
    /// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
    #[error(
        "Source IP {addr} embeds an IPv4 address, {form}, which is not a \
         valid IPv6 source address"
    )]
    Ipv4Embedded {
        /// The rejected source address.
        addr: Ipv6Addr,
        /// The embedded IPv4 form it uses.
        form: EmbeddedIpv4,
    },
}

/// A validated IPv4 unicast address for multicast source fields.
///
/// A source must be unicast and routable. IPv4 excludes loopback, broadcast
/// ([RFC 919] §7), the unspecified address, link-local ([RFC 3927]),
/// `0.0.0.0/8` ([RFC 1122] §3.2.1.3), and `240.0.0.0/4` ([RFC 6890]).
/// Private ranges ([RFC 1918]) are allowed because overlay guests can use
/// them.
///
/// [RFC 919]: https://www.rfc-editor.org/rfc/rfc919.html
/// [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122.html
/// [RFC 1918]: https://www.rfc-editor.org/rfc/rfc1918.html
/// [RFC 3927]: https://www.rfc-editor.org/rfc/rfc3927.html
/// [RFC 6890]: https://www.rfc-editor.org/rfc/rfc6890.html
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(try_from = "Ipv4Addr", into = "Ipv4Addr")]
#[schemars(transparent)]
pub struct UnicastAddrV4(Ipv4Addr);

impl UnicastAddrV4 {
    /// Create a validated IPv4 unicast address.
    ///
    /// # Errors
    ///
    /// Returns [`MulticastSourceError::NotUnicast`] for a multicast
    /// address, or [`MulticastSourceError::InvalidIpv4`] for the first
    /// [`InvalidMulticastSource`] rule the address hits.
    pub fn new(value: Ipv4Addr) -> Result<Self, MulticastSourceError> {
        let invalid = |reason| {
            Err(MulticastSourceError::InvalidIpv4 {
                addr: value,
                reason,
            })
        };
        if value.is_multicast() {
            return Err(MulticastSourceError::NotUnicast(IpAddr::V4(value)));
        }
        if value.is_unspecified() {
            return invalid(InvalidMulticastSource::Unspecified);
        }
        if value.is_loopback() {
            return invalid(InvalidMulticastSource::Loopback);
        }
        if value.is_broadcast() {
            return invalid(InvalidMulticastSource::Broadcast);
        }
        if value.is_link_local() {
            return invalid(InvalidMulticastSource::LinkLocal);
        }
        if value.octets()[0] == 0 {
            return invalid(InvalidMulticastSource::ThisNetwork);
        }
        if value.octets()[0] >= 240 {
            return invalid(InvalidMulticastSource::Reserved);
        }
        Ok(Self(value))
    }

    /// Return the inner IPv4 address.
    #[inline]
    pub const fn ip(&self) -> Ipv4Addr {
        self.0
    }
}

impl fmt::Display for UnicastAddrV4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<Ipv4Addr> for UnicastAddrV4 {
    type Error = MulticastSourceError;
    fn try_from(value: Ipv4Addr) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<UnicastAddrV4> for Ipv4Addr {
    fn from(addr: UnicastAddrV4) -> Self {
        addr.0
    }
}

impl From<UnicastAddrV4> for IpAddr {
    fn from(addr: UnicastAddrV4) -> Self {
        IpAddr::V4(addr.0)
    }
}

/// A validated IPv6 unicast address for multicast source fields.
///
/// A source must be unicast and routable. IPv6 excludes loopback, the
/// unspecified address, link-local ([RFC 4291] §2.5.6), and the IPv4-mapped
/// ([RFC 4291] §2.5.5.2) and IPv4-compatible ([RFC 4291] §2.5.5.1) forms.
/// ULA (`fc00::/7`, [RFC 4193]) is allowed because overlay guests can use it.
///
/// [RFC 4193]: https://www.rfc-editor.org/rfc/rfc4193.html
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(try_from = "Ipv6Addr", into = "Ipv6Addr")]
#[schemars(transparent)]
pub struct UnicastAddrV6(Ipv6Addr);

impl UnicastAddrV6 {
    /// Create a validated IPv6 unicast address.
    ///
    /// # Errors
    ///
    /// Returns [`MulticastSourceError::NotUnicast`] for a multicast
    /// address, [`MulticastSourceError::InvalidIpv6`] for the first
    /// [`InvalidMulticastSource`] rule the address hits, or
    /// [`MulticastSourceError::Ipv4Embedded`] for an IPv4-mapped or
    /// IPv4-compatible address.
    pub fn new(value: Ipv6Addr) -> Result<Self, MulticastSourceError> {
        let invalid = |reason| {
            Err(MulticastSourceError::InvalidIpv6 {
                addr: value,
                reason,
            })
        };
        if value.is_multicast() {
            return Err(MulticastSourceError::NotUnicast(IpAddr::V6(value)));
        }
        if value.is_unspecified() {
            return invalid(InvalidMulticastSource::Unspecified);
        }
        if value.is_loopback() {
            return invalid(InvalidMulticastSource::Loopback);
        }
        if value.is_unicast_link_local() {
            return invalid(InvalidMulticastSource::LinkLocal);
        }

        let embedded = match value.segments() {
            [0, 0, 0, 0, 0, 0xffff, ..] => Some(EmbeddedIpv4::Mapped),
            [0, 0, 0, 0, 0, 0, ..] => Some(EmbeddedIpv4::Compatible),
            _ => None,
        };
        if let Some(form) = embedded {
            return Err(MulticastSourceError::Ipv4Embedded {
                addr: value,
                form,
            });
        }
        Ok(Self(value))
    }

    /// Return the inner IPv6 address.
    #[inline]
    pub const fn ip(&self) -> Ipv6Addr {
        self.0
    }
}

impl fmt::Display for UnicastAddrV6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<Ipv6Addr> for UnicastAddrV6 {
    type Error = MulticastSourceError;
    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<UnicastAddrV6> for Ipv6Addr {
    fn from(addr: UnicastAddrV6) -> Self {
        addr.0
    }
}

impl From<UnicastAddrV6> for IpAddr {
    fn from(addr: UnicastAddrV6) -> Self {
        IpAddr::V6(addr.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicast_source_rejection_variants() {
        for (addr, expected) in [
            ("0.0.0.0", InvalidMulticastSource::Unspecified),
            ("127.0.0.1", InvalidMulticastSource::Loopback),
            ("255.255.255.255", InvalidMulticastSource::Broadcast),
            ("0.1.2.3", InvalidMulticastSource::ThisNetwork),
            ("169.254.10.1", InvalidMulticastSource::LinkLocal),
            ("240.0.0.1", InvalidMulticastSource::Reserved),
            ("255.255.255.254", InvalidMulticastSource::Reserved),
        ] {
            match UnicastAddrV4::new(addr.parse().unwrap()) {
                Err(MulticastSourceError::InvalidIpv4 { reason, .. }) => {
                    assert_eq!(reason, expected, "{addr}")
                }
                other => panic!("{addr} rejected as {other:?}"),
            }
        }

        for (addr, expected) in [
            ("::", InvalidMulticastSource::Unspecified),
            ("::1", InvalidMulticastSource::Loopback),
            ("fe80::1", InvalidMulticastSource::LinkLocal),
            ("febf:ffff::1", InvalidMulticastSource::LinkLocal),
        ] {
            match UnicastAddrV6::new(addr.parse().unwrap()) {
                Err(MulticastSourceError::InvalidIpv6 { reason, .. }) => {
                    assert_eq!(reason, expected, "{addr}")
                }
                other => panic!("{addr} rejected as {other:?}"),
            }
        }

        for (addr, expected) in [
            ("::ffff:192.0.2.1", EmbeddedIpv4::Mapped),
            ("::192.0.2.1", EmbeddedIpv4::Compatible),
        ] {
            match UnicastAddrV6::new(addr.parse().unwrap()) {
                Err(MulticastSourceError::Ipv4Embedded { form, .. }) => {
                    assert_eq!(form, expected, "{addr}")
                }
                other => panic!("{addr} rejected as {other:?}"),
            }
        }

        for addr in ["224.0.0.1", "224.9.9.9"] {
            assert!(
                matches!(
                    UnicastAddrV4::new(addr.parse().unwrap()),
                    Err(MulticastSourceError::NotUnicast(_))
                ),
                "{addr} should be rejected as non-unicast"
            );
        }

        for addr in ["ff0e::1", "ff0e::2"] {
            assert!(
                matches!(
                    UnicastAddrV6::new(addr.parse().unwrap()),
                    Err(MulticastSourceError::NotUnicast(_))
                ),
                "{addr} should be rejected as non-unicast"
            );
        }

        for addr in ["100.64.0.1", "223.255.255.255"] {
            assert!(
                UnicastAddrV4::new(addr.parse().unwrap()).is_ok(),
                "{addr} should be accepted as a source"
            );
        }
    }
}
