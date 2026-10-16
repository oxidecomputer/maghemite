// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multicast addressing constants.
//!
//! References: [RFC 4291] (IPv6 addressing), [RFC 4607] (SSM),
//! [RFC 5771] (IPv4 multicast), [RFC 7346] (IPv6 multicast scopes).
//!
//! [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
//! [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
//! [RFC 5771]: https://www.rfc-editor.org/rfc/rfc5771.html
//! [RFC 7346]: https://www.rfc-editor.org/rfc/rfc7346.html

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use oxnet::{Ipv4Net, Ipv6Net};

// TODO: replace with multicast constants and `is_ssm_address` in oxnet.

/// IPv4 Source-Specific Multicast (SSM) subnet (`232.0.0.0/8`) per
/// [RFC 4607] §1.
///
/// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
pub const IPV4_SSM_SUBNET: Ipv4Net =
    Ipv4Net::new_unchecked(Ipv4Addr::new(232, 0, 0, 0), 8);

const fn ipv6_ssm_subnet(scope: u16) -> Ipv6Net {
    Ipv6Net::new_unchecked(
        Ipv6Addr::new(0xff30 | scope, 0, 0, 0, 0, 0, 0, 0),
        32,
    )
}

/// IPv6 Source-Specific Multicast (SSM) subnets, one per scope field value.
///
/// [RFC 4607] §1 specifies "ff3x::/32 for each scope x", meaning one /32
/// block per scope (ff30::/32, ff31::/32, ..., ff3f::/32).
///
/// These blocks cannot be represented by a single CIDR: the scope nibble
/// precedes the 16 zero bits that complete each /32. In particular, ff3e:1::
/// is outside ff3e::/32, even though it is inside the broader ff30::/12
/// prefix.
///
/// These are the allocation blocks only. An address can be classified
/// via the [`is_ssm_address`] predicate, which also accepts the `ffbx`
/// (X flag set) form and the nonzero `ff2` and `rsvd` nibbles
/// ([RFC 7371] §4.1.1).
///
/// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
/// [RFC 7371]: https://www.rfc-editor.org/rfc/rfc7371.html
pub const IPV6_SSM_SUBNETS: [Ipv6Net; 16] = [
    ipv6_ssm_subnet(0x0),
    ipv6_ssm_subnet(0x1),
    ipv6_ssm_subnet(0x2),
    ipv6_ssm_subnet(0x3),
    ipv6_ssm_subnet(0x4),
    ipv6_ssm_subnet(0x5),
    ipv6_ssm_subnet(0x6),
    ipv6_ssm_subnet(0x7),
    ipv6_ssm_subnet(0x8),
    ipv6_ssm_subnet(0x9),
    ipv6_ssm_subnet(0xa),
    ipv6_ssm_subnet(0xb),
    ipv6_ssm_subnet(0xc),
    ipv6_ssm_subnet(0xd),
    ipv6_ssm_subnet(0xe),
    ipv6_ssm_subnet(0xf),
];

/// Check whether an address is a source-specific multicast one.
///
/// Classifying SSM addresses follows [RFC 4607] and [RFC 7371]:
///
/// - IPv4 SSM uses `232.0.0.0/8` ([RFC 4607] §1).
/// - IPv6 SSM covers `ff3x::/32` and `ffbx::/32`, the latter with the X flag
///   set.
/// - Both IPv6 ranges require R=0, P=T=1, and a zero prefix length
///   ([RFC 7371] §4.1.2). The `ff2` and `rsvd` nibbles lie between `scop`
///   and `plen` and are ignored on receipt ([RFC 7371] §4.1.1, [RFC 3956]
///   §3). This implementation masks both nibbles off before testing for
///   SSM-range membership, and an address that sets either of them is still
///   considered an SSM one.
///
/// [RFC 3956]: https://www.rfc-editor.org/rfc/rfc3956.html
/// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
/// [RFC 7371]: https://www.rfc-editor.org/rfc/rfc7371.html
pub fn is_ssm_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => IPV4_SSM_SUBNET.contains(addr),
        IpAddr::V6(addr) => {
            let segs = addr.segments();
            segs[0] & 0xff70 == 0xff30 && segs[1] & 0xff == 0
        }
    }
}

/// IPv4 multicast address range (224.0.0.0/4) per [RFC 5771].
///
/// [RFC 5771]: https://www.rfc-editor.org/rfc/rfc5771.html
pub const IPV4_MULTICAST_RANGE: Ipv4Net =
    Ipv4Net::new_unchecked(Ipv4Addr::new(224, 0, 0, 0), 4);

/// IPv4 link-local multicast subnet (224.0.0.0/24) per [RFC 5771] §4.
///
/// This is reserved for local network control protocols and never routed past
/// the local link.
///
/// [RFC 5771]: https://www.rfc-editor.org/rfc/rfc5771.html
pub const IPV4_LINK_LOCAL_MULTICAST_SUBNET: Ipv4Net =
    Ipv4Net::new_unchecked(Ipv4Addr::new(224, 0, 0, 0), 24);

/// IPv6 multicast address range (ff00::/8) per [RFC 4291].
///
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
pub const IPV6_MULTICAST_RANGE: Ipv6Net =
    Ipv6Net::new_unchecked(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8);

/// IPv6 multicast prefix (ff00::/8) value for scope checking per
/// [RFC 4291] §2.7.
///
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
pub const IPV6_MULTICAST_PREFIX: u16 = 0xff00;

/// Admin-local IPv6 multicast prefix (ff04::/16) as a `u16`, used for address
/// construction of underlay multicast addresses.
///
/// See [RFC 4291] §2.7 and [RFC 7346] for the multicast address format and
/// associated scope definitions.
///
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
/// [RFC 7346]: https://www.rfc-editor.org/rfc/rfc7346.html
pub const IPV6_ADMIN_SCOPED_MULTICAST_PREFIX: u16 = 0xff04;

/// Underlay multicast subnet (`ff04::/64`).
///
/// See [`crate::multicast::UnderlayMulticastIpv6`] for its role.
pub const UNDERLAY_MULTICAST_SUBNET: Ipv6Net = Ipv6Net::new_unchecked(
    Ipv6Addr::new(IPV6_ADMIN_SCOPED_MULTICAST_PREFIX, 0, 0, 0, 0, 0, 0, 0),
    64,
);

/// IPv6 interface-local multicast subnet (ff01::/16) per [RFC 4291] §2.7.
///
/// This scope never leaves the interface and is not routable.
///
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
pub const IPV6_INTERFACE_LOCAL_MULTICAST_SUBNET: Ipv6Net =
    Ipv6Net::new_unchecked(Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 0), 16);

/// IPv6 link-local multicast subnet (ff02::/16) per [RFC 4291] §2.7.
///
/// This scope is not routable past the local link.
///
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
pub const IPV6_LINK_LOCAL_MULTICAST_SUBNET: Ipv6Net =
    Ipv6Net::new_unchecked(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0), 16);

/// IPv6 reserved-scope multicast subnet (ff00::/16) per [RFC 4291] §2.7.
///
/// Scope 0 is reserved. Nodes must not originate packets to this scope and
/// must drop any they receive without sending an ICMP error.
///
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
pub const IPV6_RESERVED_SCOPE_MULTICAST_SUBNET: Ipv6Net =
    Ipv6Net::new_unchecked(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 16);

#[cfg(test)]
mod tests {
    use omicron_common::address as canonical;

    use super::*;

    /// Assert that each constant with an `omicron_common::address` counterpart
    /// is equivalent to it.
    ///
    /// TODO: remove this test once the constants move over to oxnet (see the
    /// module TODO).
    #[test]
    fn constants_match_canonical_values() {
        assert_eq!(IPV4_SSM_SUBNET, canonical::IPV4_SSM_SUBNET);
        assert_eq!(IPV4_MULTICAST_RANGE, canonical::IPV4_MULTICAST_RANGE);
        assert_eq!(
            IPV4_LINK_LOCAL_MULTICAST_SUBNET,
            canonical::IPV4_LINK_LOCAL_MULTICAST_SUBNET
        );
        assert_eq!(IPV6_MULTICAST_RANGE, canonical::IPV6_MULTICAST_RANGE);
        assert_eq!(IPV6_MULTICAST_PREFIX, canonical::IPV6_MULTICAST_PREFIX);
        assert_eq!(
            IPV6_ADMIN_SCOPED_MULTICAST_PREFIX,
            canonical::IPV6_ADMIN_SCOPED_MULTICAST_PREFIX
        );
        assert_eq!(
            UNDERLAY_MULTICAST_SUBNET,
            canonical::UNDERLAY_MULTICAST_SUBNET
        );
        assert_eq!(
            IPV6_INTERFACE_LOCAL_MULTICAST_SUBNET,
            canonical::IPV6_INTERFACE_LOCAL_MULTICAST_SUBNET
        );
        assert_eq!(
            IPV6_LINK_LOCAL_MULTICAST_SUBNET,
            canonical::IPV6_LINK_LOCAL_MULTICAST_SUBNET
        );
        assert_eq!(
            IPV6_RESERVED_SCOPE_MULTICAST_SUBNET,
            canonical::IPV6_RESERVED_SCOPE_MULTICAST_SUBNET
        );
    }

    #[test]
    fn detects_ssm_addresses() {
        for addr in [
            "232.0.0.1",
            "232.255.255.255",
            "ff3e::4000:1",
            "ff35::4000:1",
            "ffbe::4000:1",
            "ff3e:f000::4000:1",
            "ff3e:100::4000:1",
            "ff3e:0:0:1::8000:1",
        ] {
            assert!(
                is_ssm_address(addr.parse().unwrap()),
                "{addr} should be SSM"
            );
        }

        for addr in [
            "224.1.2.3",
            "231.0.0.1",
            "233.0.0.0",
            "ff0e::1",
            "ff05::1",
            "ffbe:20::4000:1",
            "ff3e:20::4000:1",
            "ff7e:140:2001:db8::1",
            "ff2e::1",
        ] {
            assert!(
                !is_ssm_address(addr.parse().unwrap()),
                "{addr} should not be SSM"
            );
        }
    }
}
