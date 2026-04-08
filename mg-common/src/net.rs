// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Re-export so consumers of MulticastOrigin.vni don't need a direct
// omicron_common dependency.
pub use omicron_common::api::external::Vni;

use omicron_common::address::UNDERLAY_MULTICAST_SUBNET;
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use thiserror::Error;

fn default_multicast_vni() -> Vni {
    Vni::DEFAULT_MULTICAST_VNI
}

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

/// A validated underlay multicast IPv6 address within ff04::/64.
///
/// The Oxide rack maps overlay multicast groups 1:1 to admin-local scoped
/// IPv6 multicast addresses in `UNDERLAY_MULTICAST_SUBNET` (ff04::/64).
/// This type enforces that invariant at construction time.
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
    /// not within ff04::/64.
    pub fn new(value: Ipv6Addr) -> Result<Self, UnderlayMulticastError> {
        if !UNDERLAY_MULTICAST_SUBNET.contains(value) {
            return Err(UnderlayMulticastError::NotInSubnet { addr: value });
        }
        Ok(Self(value))
    }

    /// Returns the underlying IPv6 address.
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

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelOrigin {
    pub overlay_prefix: IpNet,
    pub boundary_addr: Ipv6Addr,
    pub vni: u32,
    #[serde(default)]
    pub metric: u64,
}

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 2. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV2 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelOriginV2 {
    pub overlay_prefix: IpPrefix,
    pub boundary_addr: Ipv6Addr,
    pub vni: u32,
    #[serde(default)]
    pub metric: u64,
}

impl From<TunnelOriginV2> for TunnelOrigin {
    fn from(value: TunnelOriginV2) -> Self {
        TunnelOrigin {
            overlay_prefix: match value.overlay_prefix {
                IpPrefix::V4(x) => {
                    IpNet::V4(Ipv4Net::new_unchecked(x.addr, x.len))
                }
                IpPrefix::V6(x) => {
                    IpNet::V6(Ipv6Net::new_unchecked(x.addr, x.len))
                }
            },
            boundary_addr: value.boundary_addr,
            vni: value.vni,
            metric: value.metric,
        }
    }
}

impl From<TunnelOrigin> for TunnelOriginV2 {
    fn from(value: TunnelOrigin) -> Self {
        TunnelOriginV2 {
            overlay_prefix: match value.overlay_prefix {
                IpNet::V4(x) => IpPrefix::V4(Ipv4Prefix {
                    addr: x.addr(),
                    len: x.width(),
                }),
                IpNet::V6(x) => IpPrefix::V6(Ipv6Prefix {
                    addr: x.addr(),
                    len: x.width(),
                }),
            },
            boundary_addr: value.boundary_addr,
            vni: value.vni,
            metric: value.metric,
        }
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct Ipv6Prefix {
    pub addr: Ipv6Addr,
    pub len: u8,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct Ipv4Prefix {
    pub addr: Ipv4Addr,
    pub len: u8,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum IpPrefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}

/// Origin information for a multicast group announcement.
///
/// This is analogous to TunnelOrigin but for multicast groups.
///
/// This represents a subscription to a multicast group that should be
/// advertised via DDM. The overlay_group is the application-visible multicast
/// address (e.g., 233.252.0.1 or ff0e::1), while underlay_group is the mapped
/// admin-local scoped IPv6 address (ff04::X) used in the underlay network.
#[derive(Debug, Clone, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MulticastOrigin {
    /// The overlay multicast group address (IPv4 or IPv6).
    /// This is the group address visible to applications.
    pub overlay_group: IpAddr,

    /// The underlay multicast group address (ff04::X).
    /// Validated at construction to be within ff04::/64.
    pub underlay_group: UnderlayMulticastIpv6,

    /// VNI for this multicast group (identifies the VPC/network context).
    #[serde(default = "default_multicast_vni")]
    pub vni: Vni,

    /// Metric for path selection (lower is better).
    ///
    /// Used for multi-rack replication optimization.
    /// Excluded from identity (Hash/Eq) so that metric changes update
    /// an existing entry rather than creating a duplicate.
    #[serde(default)]
    pub metric: u64,

    /// Optional source address for Source-Specific Multicast (S,G) routes.
    /// None for Any-Source Multicast (*,G) routes.
    #[serde(default)]
    pub source: Option<IpAddr>,
}

// Equality and hashing consider only the identity fields (overlay_group,
// underlay_group, vni, source), not metric. This allows metric updates to
// replace existing entries in HashSet-based collections without creating
// duplicates. This type is not used in ordered collections (BTreeSet).
// See #649 for why adding Ord here would require more care.
impl PartialEq for MulticastOrigin {
    fn eq(&self, other: &Self) -> bool {
        self.overlay_group == other.overlay_group
            && self.underlay_group == other.underlay_group
            && self.vni == other.vni
            && self.source == other.source
    }
}

impl std::hash::Hash for MulticastOrigin {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.overlay_group.hash(state);
        self.underlay_group.hash(state);
        self.vni.hash(state);
        self.source.hash(state);
    }
}

#[cfg(test)]
mod test {
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
    fn multicast_origin_rejects_bad_underlay() {
        let json = serde_json::json!({
            "overlay_group": "233.252.0.1",
            "underlay_group": "ff0e::1",
            "vni": 77
        });
        let result: Result<MulticastOrigin, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn multicast_origin_accepts_valid() {
        let json = serde_json::json!({
            "overlay_group": "233.252.0.1",
            "underlay_group": "ff04::1",
            "vni": 77
        });
        let origin: MulticastOrigin = serde_json::from_value(json).unwrap();
        assert_eq!(
            origin.underlay_group.ip(),
            Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1),
        );
    }
}
