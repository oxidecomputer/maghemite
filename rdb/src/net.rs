// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::net::IpAddr;

/// Reasons an [`IpAddr`] is rejected as a routing address.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidIpAddr {
    #[error("unspecified address")]
    Unspecified,
    #[error("loopback address")]
    Loopback,
    #[error("multicast address")]
    Multicast,
    #[error("IPv4 broadcast address")]
    Broadcast,
    #[error("IPv4-mapped IPv6 address")]
    Ipv4Mapped,
}

/// An [`IpAddr`] validated as usable for routing.
///
/// A `RouterIpAddr` is never the unspecified, loopback, multicast, or IPv4
/// broadcast address, or an IPv4-mapped IPv6 address. IPv6 unicast link-local
/// addresses are permitted: they are a valid nexthop and the lower half
/// resolves them to an egress interface.
///
/// Modeled on omicron's `RouterPeerIpAddr`; a candidate to lift into `oxnet`
/// and share across repositories (see oxidecomputer/maghemite#738).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    JsonSchema,
)]
#[serde(into = "IpAddr")]
#[schemars(transparent)]
pub struct RouterIpAddr(IpAddr);

impl RouterIpAddr {
    pub fn addr(&self) -> IpAddr {
        self.0
    }
}

impl TryFrom<IpAddr> for RouterIpAddr {
    type Error = InvalidIpAddr;

    fn try_from(addr: IpAddr) -> Result<Self, Self::Error> {
        if addr.is_unspecified() {
            return Err(InvalidIpAddr::Unspecified);
        }
        if addr.is_loopback() {
            return Err(InvalidIpAddr::Loopback);
        }
        if addr.is_multicast() {
            return Err(InvalidIpAddr::Multicast);
        }
        match addr {
            IpAddr::V4(v4) => {
                if v4.is_broadcast() {
                    return Err(InvalidIpAddr::Broadcast);
                }
            }
            IpAddr::V6(v6) => {
                if v6.to_ipv4_mapped().is_some() {
                    return Err(InvalidIpAddr::Ipv4Mapped);
                }
            }
        }
        Ok(Self(addr))
    }
}

impl From<RouterIpAddr> for IpAddr {
    fn from(addr: RouterIpAddr) -> Self {
        addr.0
    }
}

impl fmt::Display for RouterIpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'de> Deserialize<'de> for RouterIpAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let addr = IpAddr::deserialize(deserializer)?;
        Self::try_from(addr).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn accepts_routable_unicast() {
        for s in ["10.0.0.1", "192.168.1.1", "203.0.113.7", "2001:db8::1"] {
            assert!(
                RouterIpAddr::try_from(ip(s)).is_ok(),
                "expected {s} to be accepted"
            );
        }
    }

    #[test]
    fn rejects_unspecified() {
        assert_eq!(
            RouterIpAddr::try_from(IpAddr::from(Ipv4Addr::UNSPECIFIED)),
            Err(InvalidIpAddr::Unspecified)
        );
        assert_eq!(
            RouterIpAddr::try_from(IpAddr::from(Ipv6Addr::UNSPECIFIED)),
            Err(InvalidIpAddr::Unspecified)
        );
    }

    #[test]
    fn rejects_loopback() {
        assert_eq!(
            RouterIpAddr::try_from(ip("127.0.0.1")),
            Err(InvalidIpAddr::Loopback)
        );
        assert_eq!(
            RouterIpAddr::try_from(ip("::1")),
            Err(InvalidIpAddr::Loopback)
        );
    }

    #[test]
    fn rejects_multicast() {
        assert_eq!(
            RouterIpAddr::try_from(ip("224.0.0.1")),
            Err(InvalidIpAddr::Multicast)
        );
        assert_eq!(
            RouterIpAddr::try_from(ip("ff02::1")),
            Err(InvalidIpAddr::Multicast)
        );
    }

    #[test]
    fn rejects_v4_broadcast() {
        assert_eq!(
            RouterIpAddr::try_from(IpAddr::from(Ipv4Addr::BROADCAST)),
            Err(InvalidIpAddr::Broadcast)
        );
    }

    #[test]
    fn accepts_v6_link_local() {
        // Link-local nexthops are valid; the lower half resolves them to an
        // egress interface (e.g. BGP unnumbered, link-local static routes).
        assert!(RouterIpAddr::try_from(ip("fe80::1")).is_ok());
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6() {
        assert_eq!(
            RouterIpAddr::try_from(ip("::ffff:127.0.0.1")),
            Err(InvalidIpAddr::Ipv4Mapped)
        );
        assert_eq!(
            RouterIpAddr::try_from(ip("::ffff:10.0.0.1")),
            Err(InvalidIpAddr::Ipv4Mapped)
        );
    }

    #[test]
    fn deserialize_validates() {
        let ok: Result<RouterIpAddr, _> = serde_json::from_str("\"10.0.0.1\"");
        assert!(ok.is_ok());

        let bad: Result<RouterIpAddr, _> =
            serde_json::from_str("\"127.0.0.1\"");
        assert!(bad.is_err());
    }

    #[test]
    fn serialize_is_transparent() {
        let addr = RouterIpAddr::try_from(ip("10.0.0.1")).unwrap();
        assert_eq!(serde_json::to_string(&addr).unwrap(), "\"10.0.0.1\"");
    }
}
