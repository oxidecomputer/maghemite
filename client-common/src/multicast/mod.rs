// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Validated overlay and underlay multicast addresses.

// TODO: replace with validated multicast newtypes in oxnet, shared with
// dendrite's dpd-types validation.

pub mod address;
pub mod group;

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use address::UNDERLAY_MULTICAST_SUBNET;
use group::{MulticastGroupError, validate_group};

/// Error constructing an [`UnderlayMulticastIpv6`] address.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UnderlayMulticastError {
    /// The address is not within the underlay multicast subnet
    /// (`ff04::/64`).
    #[error(
        "underlay address {addr} is not within {UNDERLAY_MULTICAST_SUBNET}"
    )]
    NotInSubnet { addr: Ipv6Addr },

    /// The string could not be parsed into an IPv6 address.
    #[error("invalid IPv6 address: {0}")]
    InvalidIpv6(#[from] std::net::AddrParseError),
}

/// Error constructing an [`OverlayMulticast`] address.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OverlayMulticastError {
    /// The address failed multicast group validation.
    #[error(transparent)]
    Group(#[from] MulticastGroupError),

    /// The string could not be parsed into an IP address.
    #[error("invalid IP address: {0}")]
    InvalidIp(#[from] std::net::AddrParseError),
}

/// A validated overlay multicast group address (IPv4 or IPv6).
///
/// This is the customer-visible group that an operator announces via DDM, e.g.
/// `233.252.0.1` or `ff0e::1`. The overlay group spans both address
/// families.
///
/// This type wraps an [`IpAddr`] and enforces the same group rules as
/// `MulticastAddrV4` and `MulticastAddrV6` in mg-api-types, via
/// [`group::validate_group`].
///
/// Its admin-local underlay mapping is validated separately as
/// [`UnderlayMulticastIpv6`]. [RFD 488] defines the mapping.
///
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
    /// Create a validated overlay multicast address.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayMulticastError::Group`] if the address fails
    /// multicast group validation.
    pub fn new(value: IpAddr) -> Result<Self, OverlayMulticastError> {
        validate_group(value)?;
        Ok(Self(value))
    }

    /// Return the inner IP address.
    #[inline]
    pub const fn ip(&self) -> IpAddr {
        self.0
    }
}

impl fmt::Display for OverlayMulticast {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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

/// A validated underlay multicast IPv6 address.
///
/// Underlay multicast addresses must be within the subnet allocated by Omicron
/// for rack-internal multicast traffic (`ff04::/64`). This is a subset of the
/// admin-local scope (`ff04::/16`) defined in [RFC 4291] §2.7. The Oxide rack
/// maps overlay multicast groups 1:1 into this subnet, as defined by
/// [RFD 488].
///
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
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
#[serde(try_from = "Ipv6Addr", into = "Ipv6Addr")]
#[schemars(transparent)]
pub struct UnderlayMulticastIpv6(Ipv6Addr);

impl UnderlayMulticastIpv6 {
    /// Create a validated underlay multicast IPv6 address.
    ///
    /// # Errors
    ///
    /// Returns [`UnderlayMulticastError::NotInSubnet`] if the address is
    /// not within [`UNDERLAY_MULTICAST_SUBNET`] (`ff04::/64`).
    ///
    /// [`UNDERLAY_MULTICAST_SUBNET`]: address::UNDERLAY_MULTICAST_SUBNET
    pub fn new(value: Ipv6Addr) -> Result<Self, UnderlayMulticastError> {
        if !UNDERLAY_MULTICAST_SUBNET.contains(value) {
            return Err(UnderlayMulticastError::NotInSubnet { addr: value });
        }
        Ok(Self(value))
    }

    /// Return the inner IPv6 address.
    #[inline]
    pub const fn ip(&self) -> Ipv6Addr {
        self.0
    }
}

impl fmt::Display for UnderlayMulticastIpv6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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
    fn overlay_serde_rejects_unicast() {
        let addr = "192.0.2.1".parse::<IpAddr>().unwrap();
        let json = serde_json::to_string(&addr).unwrap();
        let res: Result<OverlayMulticast, _> = serde_json::from_str(&json);
        assert!(res.is_err());
        assert!(matches!(
            OverlayMulticast::new(addr),
            Err(OverlayMulticastError::Group(
                MulticastGroupError::NotMulticast(a)
            )) if a == addr
        ));
    }

    #[test]
    fn overlay_applies_group_rules() {
        for addr in [
            "ff02::1",
            "224.0.0.0",
            "232.0.0.0",
            "ff04::1",
            "ff2e::1",
            "ff3e::4000:0",
        ] {
            assert!(
                matches!(
                    OverlayMulticast::new(addr.parse().unwrap()),
                    Err(OverlayMulticastError::Group(_))
                ),
                "{addr} should be rejected"
            );
        }

        for addr in ["233.252.0.1", "ff0e::1", "ff3e::8000:1"] {
            let ip: IpAddr = addr.parse().unwrap();
            assert_eq!(
                OverlayMulticast::new(ip)
                    .unwrap_or_else(|e| panic!(
                        "{addr} should be accepted: {e}"
                    ))
                    .ip(),
                ip
            );
        }
    }

    #[test]
    fn underlay_serde_rejects_outside_subnet() {
        // ff0e::1 serialized as an Ipv6Addr, then deserialized as
        // UnderlayMulticastIpv6, which should fail via try_from.
        let json =
            serde_json::to_string(&Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 1))
                .unwrap();
        let res: Result<UnderlayMulticastIpv6, _> = serde_json::from_str(&json);
        assert!(res.is_err());
    }

    #[test]
    fn underlay_multicast_ipv6_validates_subnet() {
        let parsed: UnderlayMulticastIpv6 = "ff04::1".parse().unwrap();
        assert_eq!(IpAddr::from(parsed), "ff04::1".parse::<IpAddr>().unwrap());

        for addr in ["ff04:0:0:1::1", "ff05::1", "2001:db8::1"] {
            assert!(
                matches!(
                    UnderlayMulticastIpv6::new(addr.parse().unwrap()),
                    Err(UnderlayMulticastError::NotInSubnet { .. })
                ),
                "{addr} should be rejected as outside ff04::/64"
            );
        }
    }
}
