// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multicast group address validation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use super::address::{
    IPV4_MULTICAST_RANGE, IPV6_MULTICAST_RANGE, UNDERLAY_MULTICAST_SUBNET,
    is_ssm_address,
};

/// Errors returned when validating a multicast group address.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum MulticastGroupError {
    /// The address is not a multicast address.
    #[error("Address {0} is not a multicast address")]
    NotMulticast(IpAddr),

    /// The IPv6 multicast scope value zero is reserved.
    #[error("Address {0} uses reserved IPv6 multicast scope 0")]
    ReservedIpv6Scope(IpAddr),

    /// The IPv6 multicast scope is interface-local or link-local, which a
    /// router must not forward beyond ([RFC 4291] §2.7).
    ///
    /// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
    #[error(
        "Address {0} has interface-local or link-local IPv6 multicast scope, \
         which routers must not forward beyond (RFC 4291 §2.7)"
    )]
    LocalIpv6Scope(IpAddr),

    /// The address is in the reserved `ff04::/64` underlay subnet for internal
    /// routing.
    #[error(
        "Address {0} is in the reserved underlay multicast subnet (ff04::/64, \
         within admin-local scope ff04::/16)"
    )]
    ReservedUnderlaySubnet(IpAddr),

    /// The address is reserved and never assigned to any multicast group:
    /// `224.0.0.0` ([RFC 1112] §4) or `ff0x::` ([RFC 4291] §2.7.1).
    ///
    /// [RFC 1112]: https://www.rfc-editor.org/rfc/rfc1112.html
    /// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
    #[error(
        "Address {0} is reserved and never assigned to a multicast group \
         (RFC 1112 §4, RFC 4291 §2.7.1)"
    )]
    ReservedBaseAddress(IpAddr),

    /// The IPv4 SSM null address `232.0.0.0` must not be used as a
    /// destination ([RFC 4607] §4.3).
    ///
    /// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
    #[error(
        "Address {0} is the reserved IPv4 SSM null address and must not be \
         used as a destination (RFC 4607 §4.3)"
    )]
    ReservedSsmNull(IpAddr),

    /// The IPv6 SSM address is the reserved null address of `ff3x::4000:0`
    /// ([RFC 4607] §4.3).
    ///
    /// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
    #[error(
        "Address {0} is the reserved IPv6 SSM null address ff3x::4000:0 and \
         must not be used as a destination (RFC 4607 §4.3)"
    )]
    InvalidIpv6Ssm(IpAddr),

    /// The prefix-based P flag is set without the T flag ([RFC 7371] §4.1.1,
    /// amending [RFC 3306] §4).
    ///
    /// [RFC 3306]: https://www.rfc-editor.org/rfc/rfc3306.html
    /// [RFC 7371]: https://www.rfc-editor.org/rfc/rfc7371.html
    #[error(
        "Address {addr} sets the P flag, but RFC 7371 §4.1.1 requires the T \
         flag to be set as well"
    )]
    MalformedPrefixBased {
        /// The rejected group address.
        addr: IpAddr,
    },

    /// The embedded rendezvous point (RP) R flag is set with an invalid flag
    /// combination, prefix length, RP interface ID, or derived RP address.
    /// [`InvalidEmbeddedRp`] names the rule that failed.
    #[error(
        "Address {addr} sets the R flag, but {reason} (RFC 3956, RFC 7371)"
    )]
    MalformedEmbeddedRp {
        /// The rejected group address.
        addr: IpAddr,
        /// The embedded-RP rule that failed.
        reason: InvalidEmbeddedRp,
    },
}

/// The reason an IPv6 group address with the R flag set cannot embed a
/// rendezvous point (RP) address ([RFC 7371] §4.2.2, §4.2.3; [RFC 3956] §4,
/// §6.3, §10).
///
/// The rules are validated in variant order. An address that breaks more
/// than one rule only reports the first hit.
///
/// [RFC 3956]: https://www.rfc-editor.org/rfc/rfc3956.html
/// [RFC 7371]: https://www.rfc-editor.org/rfc/rfc7371.html
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidEmbeddedRp {
    /// The P flag is not set ([RFC 7371] §4.2.2, §4.2.3).
    RequiresPrefixBased,
    /// The T flag is not set ([RFC 7371] §4.2.2, §4.2.3).
    RequiresTransient,
    /// The prefix length, carried here, is zero or greater than 64
    /// ([RFC 3956] §4).
    PrefixLengthOutOfRange(u8),
    /// The RP interface ID is zero ([RFC 3956] §6.3).
    ZeroInterfaceId,
    /// The derived RP address, carried here, is in `::/16`, link-local, or
    /// multicast space ([RFC 3956] §4, §10).
    ///
    /// The address is built from the group's network prefix and RP interface
    /// ID.
    UnusableAddress(Ipv6Addr),
}

impl std::fmt::Display for InvalidEmbeddedRp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequiresPrefixBased => write!(f, "the P flag is required"),
            Self::RequiresTransient => write!(f, "the T flag is required"),
            Self::PrefixLengthOutOfRange(plen) => write!(
                f,
                "the prefix length {plen} is outside the range 1 through 64"
            ),
            Self::ZeroInterfaceId => {
                write!(f, "the RP interface ID must be nonzero")
            }
            Self::UnusableAddress(rp) => write!(
                f,
                "the derived RP address {rp} is in ::/16, link-local, or \
                 multicast space"
            ),
        }
    }
}

// TODO: replace these group validators with a validated multicast newtype in
// oxnet, shared with dendrite's dpd-types validation.
const IPV4_RESERVED_BASE: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 0);
const IPV4_SSM_RESERVED_NULL: Ipv4Addr = Ipv4Addr::new(232, 0, 0, 0);
const IPV6_SSM_NULL_GROUP_ID: u32 = 0x4000_0000;
const IPV6_SCOPE_MASK: u16 = 0x000f;
const IPV6_SCOPE_RESERVED_ZERO: u16 = 0x0;
const IPV6_SCOPE_INTERFACE_LOCAL: u16 = 0x1;
const IPV6_SCOPE_LINK_LOCAL: u16 = 0x2;

// Flags field: the nibble above scope (RFC 4291 §2.7).
const IPV6_FLAGS_SHIFT: u16 = 4;
const IPV6_FLAGS_MASK: u16 = 0xf;
const IPV6_FLAG_TRANSIENT: u16 = 0x1;
const IPV6_FLAG_PREFIX_BASED: u16 = 0x2;
const IPV6_FLAG_EMBEDDED_RP: u16 = 0x4;

// RIID and prefix length in the second segment (RFC 3956 §3, RFC 3306 §4).
const IPV6_RIID_SHIFT: u16 = 8;
const IPV6_RIID_MASK: u16 = 0xf;
const IPV6_PREFIX_BASED_PLEN_MASK: u16 = 0xff;
const IPV6_PREFIX_BASED_MAX_PLEN: u16 = 64;

fn embedded_rp_address(segs: [u16; 8], plen: u16, riid: u16) -> Ipv6Addr {
    let mut rp = [0u16; 8];
    for (index, segment) in segs[2..6].iter().enumerate() {
        let offset = (index as u16) * 16;
        rp[index] = if offset >= plen {
            0
        } else if offset + 16 > plen {
            segment & (!0u16 << (16 - (plen - offset)))
        } else {
            *segment
        };
    }
    rp[7] = riid;
    Ipv6Addr::from(rp)
}

fn is_usable_rp_address(rp: Ipv6Addr) -> bool {
    let first = rp.segments()[0];
    first != 0 && first & 0xffc0 != 0xfe80 && first >> 8 != 0xff
}

/// Validate a multicast group address of either IP address family.
///
/// # Errors
///
/// Returns the [`MulticastGroupError`] from [`validate_group_v4`] or
/// [`validate_group_v6`].
pub fn validate_group(value: IpAddr) -> Result<(), MulticastGroupError> {
    match value {
        IpAddr::V4(v4) => validate_group_v4(v4),
        IpAddr::V6(v6) => validate_group_v6(v6),
    }
}

/// Validate an IPv4 multicast group address.
///
/// # Errors
///
/// Returns a [`MulticastGroupError`] for the first group rule the address
/// fails.
pub fn validate_group_v4(value: Ipv4Addr) -> Result<(), MulticastGroupError> {
    let addr = IpAddr::V4(value);
    if !IPV4_MULTICAST_RANGE.contains(value) {
        return Err(MulticastGroupError::NotMulticast(addr));
    }

    if value == IPV4_RESERVED_BASE {
        return Err(MulticastGroupError::ReservedBaseAddress(addr));
    }

    if value == IPV4_SSM_RESERVED_NULL {
        return Err(MulticastGroupError::ReservedSsmNull(addr));
    }

    Ok(())
}

/// Validate an IPv6 multicast group address.
///
/// # Errors
///
/// Returns a [`MulticastGroupError`] for the first group rule the address
/// fails.
pub fn validate_group_v6(value: Ipv6Addr) -> Result<(), MulticastGroupError> {
    let addr = IpAddr::V6(value);
    if !IPV6_MULTICAST_RANGE.contains(value) {
        return Err(MulticastGroupError::NotMulticast(addr));
    }

    // We classify on just the scope nibble. A /16 prefix comparison
    // encodes flags=0 and would accept, e.g., ff11::1 despite its
    // interface-local scope.
    let segs = value.segments();
    let scope = segs[0] & IPV6_SCOPE_MASK;
    match scope {
        IPV6_SCOPE_RESERVED_ZERO => {
            return Err(MulticastGroupError::ReservedIpv6Scope(addr));
        }
        IPV6_SCOPE_INTERFACE_LOCAL | IPV6_SCOPE_LINK_LOCAL => {
            return Err(MulticastGroupError::LocalIpv6Scope(addr));
        }
        _ => {}
    }

    if UNDERLAY_MULTICAST_SUBNET.contains(value) {
        return Err(MulticastGroupError::ReservedUnderlaySubnet(addr));
    }

    // With P set, the low octet of the 2nd segment is the prefix length.
    //
    // See RFC 3306 §4 and RFC 7371 §4.1.1.
    let flags = (segs[0] >> IPV6_FLAGS_SHIFT) & IPV6_FLAGS_MASK;
    let plen = segs[1] & IPV6_PREFIX_BASED_PLEN_MASK;

    if flags == 0 && segs[1..].iter().all(|seg| *seg == 0) {
        return Err(MulticastGroupError::ReservedBaseAddress(addr));
    }

    if flags & IPV6_FLAG_EMBEDDED_RP != 0 {
        let riid = (segs[1] >> IPV6_RIID_SHIFT) & IPV6_RIID_MASK;
        let malformed = |reason| {
            Err(MulticastGroupError::MalformedEmbeddedRp { addr, reason })
        };

        if flags & IPV6_FLAG_PREFIX_BASED == 0 {
            return malformed(InvalidEmbeddedRp::RequiresPrefixBased);
        }
        if flags & IPV6_FLAG_TRANSIENT == 0 {
            return malformed(InvalidEmbeddedRp::RequiresTransient);
        }
        if plen == 0 || plen > IPV6_PREFIX_BASED_MAX_PLEN {
            return malformed(InvalidEmbeddedRp::PrefixLengthOutOfRange(
                plen as u8,
            ));
        }
        if riid == 0 {
            return malformed(InvalidEmbeddedRp::ZeroInterfaceId);
        }
        let rp = embedded_rp_address(segs, plen, riid);
        if !is_usable_rp_address(rp) {
            return malformed(InvalidEmbeddedRp::UnusableAddress(rp));
        }
    } else if flags & IPV6_FLAG_PREFIX_BASED != 0
        && flags & IPV6_FLAG_TRANSIENT == 0
    {
        return Err(MulticastGroupError::MalformedPrefixBased { addr });
    }

    if is_ssm_address(IpAddr::V6(value)) {
        let within_prefix =
            segs[2] == 0 && segs[3] == 0 && segs[4] == 0 && segs[5] == 0;
        let group_id = (u32::from(segs[6]) << 16) | u32::from(segs[7]);
        if within_prefix && group_id == IPV6_SSM_NULL_GROUP_ID {
            return Err(MulticastGroupError::InvalidIpv6Ssm(addr));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_embedded_rp_address() {
        for (group, expected) in [
            ("ff7e:140:2001:db8:beef:feed::", "2001:db8:beef:feed::1"),
            ("ff7e:120:2001:db8::", "2001:db8::1"),
            ("ff7e:120:2001:db8:dead::", "2001:db8::1"),
            ("ff7e:130:2001:db8:beef::", "2001:db8:beef::1"),
            ("ff7e:128:2001:db8:beef::", "2001:db8:be00::1"),
        ] {
            let segs = group.parse::<Ipv6Addr>().unwrap().segments();
            let plen = segs[1] & IPV6_PREFIX_BASED_PLEN_MASK;
            let riid = (segs[1] >> IPV6_RIID_SHIFT) & IPV6_RIID_MASK;

            assert_eq!(
                embedded_rp_address(segs, plen, riid),
                expected.parse::<Ipv6Addr>().unwrap(),
                "{group} should derive RP {expected}"
            );
        }
    }

    #[test]
    fn rejects_malformed_embedded_rendezvous_point() {
        for (addr, expected) in [
            (
                "ff5e:140:2001:db8::1",
                InvalidEmbeddedRp::RequiresPrefixBased,
            ),
            ("ff6e:140:2001:db8::1", InvalidEmbeddedRp::RequiresTransient),
            (
                "ff7e:100:2001:db8::1",
                InvalidEmbeddedRp::PrefixLengthOutOfRange(0),
            ),
            (
                "ff7e:180:2001:db8::1",
                InvalidEmbeddedRp::PrefixLengthOutOfRange(128),
            ),
            ("ff7e:40:2001:db8::1", InvalidEmbeddedRp::ZeroInterfaceId),
            (
                "ff7e:140::1",
                InvalidEmbeddedRp::UnusableAddress(Ipv6Addr::LOCALHOST),
            ),
            (
                "ff7e:140:fe80::1",
                InvalidEmbeddedRp::UnusableAddress("fe80::1".parse().unwrap()),
            ),
            (
                "ff7e:140:ff00::1",
                InvalidEmbeddedRp::UnusableAddress("ff00::1".parse().unwrap()),
            ),
        ] {
            assert_eq!(
                validate_group_v6(addr.parse().unwrap()),
                Err(MulticastGroupError::MalformedEmbeddedRp {
                    addr: addr.parse::<IpAddr>().unwrap(),
                    reason: expected,
                }),
                "{addr} rejected for the wrong reason"
            );
        }
    }
}
