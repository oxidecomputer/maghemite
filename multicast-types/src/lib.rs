// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Shared multicast wire types that need to be reachable from both
//! `mg-api-types` and `ddm-api-types` without creating a cycle through
//! `mg-common`.

use omicron_common::address::UNDERLAY_MULTICAST_SUBNET;
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
// independent copy. Consolidate into `omicron_common` to unify.
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

#[cfg(feature = "proptest")]
mod proptest_impls {
    use super::UnderlayMulticastIpv6;
    use omicron_common::address::IPV6_ADMIN_SCOPED_MULTICAST_PREFIX;
    use proptest::prelude::*;
    use std::net::Ipv6Addr;

    impl Arbitrary for UnderlayMulticastIpv6 {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            // Pack the lower 64 bits of the address from a random u64;
            // the upper 64 bits are fixed to the admin-scoped multicast
            // prefix (ff04::/64) so every generated value satisfies
            // `UnderlayMulticastIpv6::new`.
            any::<u64>()
                .prop_map(|bits| {
                    let addr = Ipv6Addr::new(
                        IPV6_ADMIN_SCOPED_MULTICAST_PREFIX,
                        0,
                        0,
                        0,
                        (bits >> 48) as u16,
                        (bits >> 32) as u16,
                        (bits >> 16) as u16,
                        bits as u16,
                    );
                    UnderlayMulticastIpv6::new(addr)
                        .expect("ff04::/64 address is always valid")
                })
                .boxed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn from_str_rejects_non_admin_local() {
        let result: Result<UnderlayMulticastIpv6, _> = "ff0e::1".parse();
        assert!(matches!(
            result,
            Err(UnderlayMulticastError::NotInSubnet { .. })
        ));
    }

    #[test]
    fn from_str_accepts_admin_local() {
        let parsed: UnderlayMulticastIpv6 = "ff04::1".parse().unwrap();
        assert_eq!(parsed.ip(), Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1));
    }
}
