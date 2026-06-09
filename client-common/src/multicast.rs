// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Validated underlay multicast address shared across the routing suite.
//!
//! Lives in the cycle-free leaf crate so the API-types crates consumed by
//! Omicron can share a single definition without depending on
//! `omicron_common`, which would form a dependency cycle.

use crate::address::UNDERLAY_MULTICAST_SUBNET;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use thiserror::Error;

/// Error constructing an [`UnderlayMulticastIpv6`] address.
#[derive(Debug, Clone, Error)]
pub enum UnderlayMulticastError {
    /// The address is not within the underlay multicast subnet (ff04::/64).
    #[error(
        "underlay address {addr} is not within {UNDERLAY_MULTICAST_SUBNET}"
    )]
    NotInSubnet { addr: Ipv6Addr },

    /// The string could not be parsed as an IPv6 address.
    #[error("invalid IPv6 address: {0}")]
    InvalidIpv6(#[from] std::net::AddrParseError),
}

/// Error constructing an [`OverlayMulticast`] address.
#[derive(Debug, Clone, Error)]
pub enum OverlayMulticastError {
    /// The address is not a multicast address.
    #[error("overlay address {addr} is not a multicast address")]
    NotMulticast { addr: IpAddr },

    /// The string could not be parsed as an IP address.
    #[error("invalid IP address: {0}")]
    InvalidIp(#[from] std::net::AddrParseError),
}

/// A validated overlay multicast group address (IPv4 or IPv6).
///
/// The application-visible group an operator announces via DDM, e.g.
/// `233.252.0.1` or `ff0e::1`. The overlay group spans both address
/// families, so this type wraps [`IpAddr`] and enforces only that the
/// address is multicast: IPv4 `224.0.0.0/4` per [RFC 1112 §4] or IPv6
/// `ff00::/8` per [RFC 4291 §2.7]. Its admin-local underlay mapping is the
/// separately validated [`UnderlayMulticastIpv6`]. The mapping is defined by
/// [RFD 488].
///
/// [RFC 1112 §4]: https://www.rfc-editor.org/rfc/rfc1112#section-4
/// [RFC 4291 §2.7]: https://www.rfc-editor.org/rfc/rfc4291#section-2.7
/// [RFD 488]: https://rfd.shared.oxide.computer/rfd/488
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
#[serde(try_from = "IpAddr", into = "IpAddr")]
#[schemars(transparent)]
pub struct OverlayMulticast(IpAddr);

impl OverlayMulticast {
    /// Create a new validated overlay multicast address.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayMulticastError::NotMulticast`] if the address is not
    /// a multicast address.
    pub fn new(value: IpAddr) -> Result<Self, OverlayMulticastError> {
        if !value.is_multicast() {
            return Err(OverlayMulticastError::NotMulticast { addr: value });
        }
        Ok(Self(value))
    }

    /// Return the underlying IP address.
    #[inline]
    pub const fn ip(&self) -> IpAddr {
        self.0
    }
}

impl fmt::Display for OverlayMulticast {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<IpAddr> for OverlayMulticast {
    type Error = OverlayMulticastError;

    fn try_from(value: IpAddr) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<OverlayMulticast> for IpAddr {
    fn from(addr: OverlayMulticast) -> Self {
        addr.0
    }
}

impl FromStr for OverlayMulticast {
    type Err = OverlayMulticastError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr: IpAddr = s.parse()?;
        Self::new(addr)
    }
}

/// A validated underlay multicast IPv6 address within `ff04::/64`.
///
/// The Oxide rack maps overlay multicast groups 1:1 to admin-local scoped
/// IPv6 multicast addresses in `UNDERLAY_MULTICAST_SUBNET` (`ff04::/64`,
/// admin-local scope per [RFC 4291 §2.7]). The mapping is defined by
/// [RFD 488]. This type enforces the subnet invariant at construction
/// time.
///
/// [RFC 4291 §2.7]: https://www.rfc-editor.org/rfc/rfc4291#section-2.7
/// [RFD 488]: https://rfd.shared.oxide.computer/rfd/488
// TODO: `dpd_types::mcast::UnderlayMulticastIpv6` in dendrite carries an
// independent copy. Consolidate into `oxnet`, the cycle-free leaf crate that
// maghemite, dendrite, and omicron already share, so the duplication can be
// removed.
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
pub struct UnderlayMulticastIpv6(Ipv6Addr);

impl UnderlayMulticastIpv6 {
    /// Create a new validated underlay multicast address.
    ///
    /// # Errors
    ///
    /// Returns [`UnderlayMulticastError::NotInSubnet`] if the address is
    /// not within `UNDERLAY_MULTICAST_SUBNET` (ff04::/64).
    pub fn new(value: Ipv6Addr) -> Result<Self, UnderlayMulticastError> {
        if !UNDERLAY_MULTICAST_SUBNET.contains(value) {
            return Err(UnderlayMulticastError::NotInSubnet { addr: value });
        }
        Ok(Self(value))
    }

    /// Return the underlying IPv6 address.
    #[inline]
    pub const fn ip(&self) -> Ipv6Addr {
        self.0
    }
}

impl fmt::Display for UnderlayMulticastIpv6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<Ipv6Addr> for UnderlayMulticastIpv6 {
    type Error = UnderlayMulticastError;

    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<UnderlayMulticastIpv6> for Ipv6Addr {
    fn from(addr: UnderlayMulticastIpv6) -> Self {
        addr.0
    }
}

impl From<UnderlayMulticastIpv6> for IpAddr {
    fn from(addr: UnderlayMulticastIpv6) -> Self {
        IpAddr::V6(addr.0)
    }
}

impl FromStr for UnderlayMulticastIpv6 {
    type Err = UnderlayMulticastError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr: Ipv6Addr = s.parse()?;
        Self::new(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_accepts_v4_and_v6_multicast() {
        assert!(OverlayMulticast::new("233.252.0.1".parse().unwrap()).is_ok());
        assert!(OverlayMulticast::new("ff0e::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn overlay_rejects_unicast() {
        assert!(OverlayMulticast::new("192.0.2.1".parse().unwrap()).is_err());
        assert!(OverlayMulticast::new("2001:db8::1".parse().unwrap()).is_err());
    }

    #[test]
    fn overlay_serde_rejects_unicast() {
        let json =
            serde_json::to_string(&"192.0.2.1".parse::<IpAddr>().unwrap())
                .unwrap();
        let result: Result<OverlayMulticast, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn underlay_valid_ff04() {
        let addr = Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1);
        assert!(UnderlayMulticastIpv6::new(addr).is_ok());
    }

    #[test]
    fn underlay_rejects_non_admin_local() {
        // ff0e:: is global scope, not admin-local
        let addr = Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 1);
        assert!(UnderlayMulticastIpv6::new(addr).is_err());
    }

    #[test]
    fn underlay_rejects_unicast() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert!(UnderlayMulticastIpv6::new(addr).is_err());
    }

    #[test]
    fn underlay_serde_round_trip() {
        let addr = UnderlayMulticastIpv6::new(Ipv6Addr::new(
            0xff04, 0, 0, 0, 0, 0, 0, 42,
        ))
        .unwrap();
        let json = serde_json::to_string(&addr).unwrap();
        let back: UnderlayMulticastIpv6 = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, back);
    }

    #[test]
    fn underlay_serde_rejects_invalid() {
        // ff0e::1 serialized as an Ipv6Addr, then deserialized as
        // UnderlayMulticastIpv6 should fail via try_from.
        let json =
            serde_json::to_string(&Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 1))
                .unwrap();
        let result: Result<UnderlayMulticastIpv6, _> =
            serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn from_str_rejects_unparseable() {
        let result: Result<UnderlayMulticastIpv6, _> = "not-an-ip".parse();
        assert!(matches!(
            result,
            Err(UnderlayMulticastError::InvalidIpv6(_))
        ));
    }
}
