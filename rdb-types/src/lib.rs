// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Core types for routing database operations, shared across maghemite components.
//!
//! This crate provides the fundamental types used for representing network prefixes
//! and routing information. It has minimal dependencies and can be used by clients
//! without pulling in the full RDB implementation.

#[cfg(feature = "clap")]
use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::{self, Formatter};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Hash, Eq, PartialEq, JsonSchema,
)]
pub struct Prefix4 {
    pub value: Ipv4Addr,
    pub length: u8,
}

impl PartialOrd for Prefix4 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Prefix4 {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.value != other.value {
            return self.value.cmp(&other.value);
        }
        self.length.cmp(&other.length)
    }
}

impl Prefix4 {
    const HOST_MASK: u8 = 32;

    /// Create a new `Prefix4` from an IP address and net mask.
    /// The newly created `Prefix4` will have its host bits zeroed upon creation
    /// e.g.
    /// ```
    /// use rdb_types::Prefix4;
    /// use std::net::Ipv4Addr;
    /// use std::str::FromStr;
    /// let p4 = Prefix4::new(Ipv4Addr::from_str("10.0.0.10").unwrap(), 24);
    /// assert_eq!(p4.value, Ipv4Addr::from_str("10.0.0.0").unwrap());
    /// ```
    pub fn new(ip: Ipv4Addr, length: u8) -> Self {
        let mut new = Self { value: ip, length };
        new.unset_host_bits();
        new
    }

    pub fn host_bits_are_unset(&self) -> bool {
        let mask = match self.length {
            0 => 0,
            _ => (!0u32) << (32 - self.length),
        };

        self.value.to_bits() & mask == self.value.to_bits()
    }

    pub fn unset_host_bits(&mut self) {
        let mask = match self.length {
            0 => 0,
            _ => (!0u32) << (32 - self.length),
        };

        self.value = Ipv4Addr::from_bits(self.value.to_bits() & mask)
    }

    /// Check if this prefix is contained within another prefix.
    /// Returns true if this prefix is equal to or more specific than the other.
    pub fn within(&self, other: &Prefix4) -> bool {
        // A less specific prefix cannot be within a more specific one
        if self.length < other.length {
            return false;
        }

        if other.length == 0 {
            // /0 contains everything
            return true;
        }

        // Create masks for comparison
        let shift_amount = 32 - other.length;
        let mask = !0u32 << shift_amount;

        let self_masked = self.value.to_bits() & mask;
        let other_masked = other.value.to_bits() & mask;

        self_masked == other_masked
    }

    /// Check if a prefix contains a subnet that is valid for use in the RIB.
    /// Currently this only checks if the prefix overlaps with Loopback
    /// (127.0.0.0/8) or Multicast (224.0.0.0/4) address space. We deliberately
    /// do not flag Class E (240.0.0.0/4) or Link-Local (169.254.0.0/16)
    /// ranges as invalid, as some networks have deployed these as if they were
    /// standard routable unicast addresses, which we need to handle.
    pub fn valid_for_rib(&self) -> bool {
        !(self.value.is_loopback()
            || self.value.is_multicast()
            || self.value.is_unspecified() && self.length == Self::HOST_MASK)
    }
}

impl fmt::Display for Prefix4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.value, self.length)
    }
}

impl FromStr for Prefix4 {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (value, length) =
            s.split_once('/').ok_or("malformed route key".to_string())?;

        Ok(Self {
            value: value
                .parse()
                .map_err(|_| "malformed ip addr".to_string())?,
            length: length
                .parse()
                .map_err(|_| "malformed length".to_string())?,
        })
    }
}

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Hash, Eq, PartialEq, JsonSchema,
)]
pub struct Prefix6 {
    pub value: Ipv6Addr,
    pub length: u8,
}

impl PartialOrd for Prefix6 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Prefix6 {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.value != other.value {
            return self.value.cmp(&other.value);
        }
        self.length.cmp(&other.length)
    }
}

impl fmt::Display for Prefix6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.value, self.length)
    }
}

impl Prefix6 {
    const HOST_MASK: u8 = 128;

    /// Create a new `Prefix6` from an IP address and net mask.
    /// The newly created `Prefix6` will have its host bits zeroed upon creation
    /// e.g.
    /// ```
    /// use rdb_types::Prefix6;
    /// use std::net::Ipv6Addr;
    /// use std::str::FromStr;
    /// let p6 = Prefix6::new(Ipv6Addr::from_str("2001:db8::1").unwrap(), 64);
    /// assert_eq!(p6.value, Ipv6Addr::from_str("2001:db8::").unwrap());
    /// ```
    pub fn new(ip: Ipv6Addr, length: u8) -> Self {
        let mut new = Self { value: ip, length };
        new.unset_host_bits();
        new
    }

    pub fn host_bits_are_unset(&self) -> bool {
        let mask = match self.length {
            0 => 0,
            _ => (!0u128) << (128 - self.length),
        };

        self.value.to_bits() & mask == self.value.to_bits()
    }

    pub fn unset_host_bits(&mut self) {
        let mask = match self.length {
            0 => 0,
            _ => (!0u128) << (128 - self.length),
        };

        self.value = Ipv6Addr::from_bits(self.value.to_bits() & mask)
    }

    /// Check if this prefix is contained within another prefix.
    /// Returns true if this prefix is equal to or more specific than the other.
    pub fn within(&self, other: &Prefix6) -> bool {
        // A less  specific prefix cannot be within a more specific one
        if self.length < other.length {
            return false;
        }

        if other.length == 0 {
            // /0 contains everything
            return true;
        }

        // Create masks for comparison
        let shift_amount = 128 - other.length;
        if shift_amount >= 128 {
            return false; // Invalid case
        }
        let mask = !0u128 << shift_amount;

        let self_masked = self.value.to_bits() & mask;
        let other_masked = other.value.to_bits() & mask;

        self_masked == other_masked
    }

    /// Check if a prefix contains a subnet that is valid for use in the RIB.
    /// Currently this only checks if the prefix carries the Unspecified or
    /// Loopback address (::/128 or ::1/128), Multicast (ff00::/8) or Link-Local
    /// Unicast (fe80::/10) address spaces.
    pub fn valid_for_rib(&self) -> bool {
        !(self.value.is_loopback()
            || self.value.is_multicast()
            || self.value.is_unicast_link_local()
            || self.value.is_unspecified() && self.length == Self::HOST_MASK)
    }
}

impl FromStr for Prefix6 {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (value, length) =
            s.split_once('/').ok_or("malformed route key".to_string())?;

        Ok(Self {
            value: value
                .parse()
                .map_err(|_| "malformed ip addr".to_string())?,
            length: length
                .parse()
                .map_err(|_| "malformed length".to_string())?,
        })
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    Hash,
    PartialEq,
    JsonSchema,
    PartialOrd,
    Ord,
)]
pub enum Prefix {
    V4(Prefix4),
    V6(Prefix6),
}

impl PartialEq<&Prefix> for oxnet::IpNet {
    fn eq(&self, other: &&Prefix) -> bool {
        match (self, other) {
            (Self::V4(a), Prefix::V4(b)) => {
                a.addr() == b.value && a.width() == b.length
            }
            (Self::V6(a), Prefix::V6(b)) => {
                a.addr() == b.value && a.width() == b.length
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Prefix::V4(p) => p.fmt(f),
            Prefix::V6(p) => p.fmt(f),
        }
    }
}

impl From<Prefix4> for Prefix {
    fn from(value: Prefix4) -> Self {
        Self::V4(value)
    }
}

impl From<Prefix6> for Prefix {
    fn from(value: Prefix6) -> Self {
        Self::V6(value)
    }
}

impl FromStr for Prefix {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(prefix4) = s.parse::<Prefix4>() {
            Ok(Self::V4(prefix4))
        } else if let Ok(prefix6) = s.parse::<Prefix6>() {
            Ok(Self::V6(prefix6))
        } else {
            Err("malformed prefix".to_string())
        }
    }
}

impl Prefix {
    pub fn new(ip: IpAddr, length: u8) -> Self {
        match ip {
            IpAddr::V4(ip4) => Self::V4(Prefix4::new(ip4, length)),
            IpAddr::V6(ip6) => Self::V6(Prefix6::new(ip6, length)),
        }
    }

    pub fn host_bits_are_unset(&self) -> bool {
        match self {
            Self::V4(p4) => p4.host_bits_are_unset(),
            Self::V6(p6) => p6.host_bits_are_unset(),
        }
    }

    pub fn unset_host_bits(&mut self) {
        match self {
            Self::V4(p4) => p4.unset_host_bits(),
            Self::V6(p6) => p6.unset_host_bits(),
        }
    }

    /// Check if this prefix is contained within another prefix.
    /// Returns true if this prefix is equal to or more specific than the other.
    /// Returns false for cross-family comparisons.
    pub fn within(&self, other: &Prefix) -> bool {
        match (self, other) {
            (Prefix::V4(a), Prefix::V4(b)) => a.within(b),
            (Prefix::V6(a), Prefix::V6(b)) => a.within(b),
            _ => false, // Cross-family always false
        }
    }

    /// Check if this prefix is IPv4.
    pub fn is_v4(&self) -> bool {
        matches!(self, Prefix::V4(_))
    }

    /// Check if a prefix contains a subnet that is valid for use in the RIB.
    pub fn valid_for_rib(&self) -> bool {
        match self {
            Prefix::V4(p4) => p4.valid_for_rib(),
            Prefix::V6(p6) => p6.valid_for_rib(),
        }
    }
}

/// Represents the address family (protocol version) for network routes.
///
/// This is the canonical source of truth for address family definitions across the
/// entire codebase. All routing-related components (RIB operations, BGP messages,
/// API filtering, CLI tools) use this single enum rather than defining their own.
///
/// # Semantics
///
/// When used in filtering contexts (e.g., database queries or API parameters),
/// `Option<AddressFamily>` is preferred:
/// - `None` = no filter (match all address families)
/// - `Some(Ipv4)` = IPv4 routes only
/// - `Some(Ipv6)` = IPv6 routes only
///
/// # Examples
///
/// ```
/// use rdb_types::AddressFamily;
///
/// let ipv4 = AddressFamily::Ipv4;
/// let ipv6 = AddressFamily::Ipv6;
///
/// // For filtering, use Option
/// let filter: Option<AddressFamily> = Some(AddressFamily::Ipv4);
/// let no_filter: Option<AddressFamily> = None; // matches all families
/// ```
#[derive(
    Clone,
    Copy,
    Eq,
    Debug,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[cfg_attr(feature = "clap", derive(ValueEnum))]
pub enum AddressFamily {
    /// Internet Protocol Version 4 (IPv4)
    Ipv4,
    /// Internet Protocol Version 6 (IPv6)
    Ipv6,
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ProtocolFilter {
    /// BGP routes only
    Bgp,
    /// Static routes only
    Static,
}
