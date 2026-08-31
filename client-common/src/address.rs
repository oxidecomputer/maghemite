// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Multicast addressing constants shared across the routing suite.
//!
//! These mirror the canonical definitions in `omicron_common::address`.
//! They are duplicated here so the client and API-types crates consumed by
//! Omicron remain free of an Omicron dependency, which would otherwise form a
//! dependency cycle. These constants must be reachable at compile time from the
//! Omicron-free API-types crate because its newtypes validate addresses at
//! deserialization via `#[serde(try_from)]`.
//!
//! References: [RFC 4291] (IPv6 addressing), [RFC 4607] (SSM),
//! [RFC 5771] (IPv4 multicast), [RFC 7346] (IPv6 multicast scopes).
//!
//! [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291
//! [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607
//! [RFC 5771]: https://www.rfc-editor.org/rfc/rfc5771
//! [RFC 7346]: https://www.rfc-editor.org/rfc/rfc7346

use oxnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// TODO: Consolidate these constants and the `omicron_common::address`
// originals into `oxnet`, the cycle-free leaf crate that maghemite, dendrite,
// and omicron already share, so the duplication can be removed.

/// IPv4 Source-Specific Multicast (SSM) subnet (232.0.0.0/8) per RFC 4607 §1.
pub const IPV4_SSM_SUBNET: Ipv4Net =
    Ipv4Net::new_unchecked(Ipv4Addr::new(232, 0, 0, 0), 8);

/// Reserved IPv4 SSM subnet (232.0.0.0/24).
///
/// RFC 4607 §4.3 reserves 232.0.0.0 (must not be assigned to any
/// application) and notes that IANA holds 232.0.0.1 through 232.0.0.255
/// in reserve, so the entire first /24 is excluded from allocation.
pub const IPV4_SSM_RESERVED_SUBNET: Ipv4Net =
    Ipv4Net::new_unchecked(Ipv4Addr::new(232, 0, 0, 0), 24);

const fn ipv6_ssm_subnet(scope: u16) -> Ipv6Net {
    Ipv6Net::new_unchecked(
        Ipv6Addr::new(0xff30 | scope, 0, 0, 0, 0, 0, 0, 0),
        32,
    )
}

/// IPv6 Source-Specific Multicast (SSM) subnets, one per scope field value.
///
/// RFC 4607 §1 specifies "ff3x::/32 for each scope x", meaning one /32
/// block per scope (ff30::/32, ff31::/32, ..., ff3f::/32).
///
/// These blocks cannot be represented by one CIDR: the scope nibble precedes
/// the 16 zero bits that complete each /32. In particular, ff3e:1:: is outside
/// ff3e::/32 even though it is inside the broader ff30::/12 prefix.
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

/// Check if an IP is in the SSM (Source-Specific Multicast) range.
///
/// SSM ranges per RFC 4607 §1:
/// - IPv4: 232.0.0.0/8
/// - IPv6: ff3x::/32 (all SSM scopes)
///
/// The IPv6 check matches the exact per-scope /32 blocks, not ff30::/12.
/// A /12 match would also classify RFC 3306 unicast-prefix-based addresses
/// with a nonzero network prefix as SSM.
pub fn is_ssm_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => IPV4_SSM_SUBNET.contains(addr),
        IpAddr::V6(addr) => {
            IPV6_SSM_SUBNETS.iter().any(|subnet| subnet.contains(addr))
        }
    }
}

/// IPv4 multicast address range (224.0.0.0/4) per RFC 5771.
pub const IPV4_MULTICAST_RANGE: Ipv4Net =
    Ipv4Net::new_unchecked(Ipv4Addr::new(224, 0, 0, 0), 4);

/// IPv4 link-local multicast subnet (224.0.0.0/24) per RFC 5771 §4.
///
/// Reserved for local network control protocols and not routed beyond the
/// local link.
pub const IPV4_LINK_LOCAL_MULTICAST_SUBNET: Ipv4Net =
    Ipv4Net::new_unchecked(Ipv4Addr::new(224, 0, 0, 0), 24);

/// IPv6 multicast address range (ff00::/8) per RFC 4291.
pub const IPV6_MULTICAST_RANGE: Ipv6Net =
    Ipv6Net::new_unchecked(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8);

/// IPv6 multicast prefix (ff00::/8) value for scope checking per RFC 4291 §2.7.
pub const IPV6_MULTICAST_PREFIX: u16 = 0xff00;

/// Admin-local IPv6 multicast prefix (ff04::/16) as a u16 for address
/// construction and normalization of underlay multicast addresses.
///
/// See RFC 4291 §2.7 and RFC 7346 for the multicast address format and scope
/// definitions.
pub const IPV6_ADMIN_SCOPED_MULTICAST_PREFIX: u16 = 0xff04;

/// Fixed underlay admin-local IPv6 multicast subnet (ff04::/64).
///
/// Admin-local scope (4) is the smallest scope that must be administratively
/// configured per RFC 7346. The Oxide rack maps overlay multicast groups 1:1
/// into this /64.
pub const UNDERLAY_MULTICAST_SUBNET: Ipv6Net = Ipv6Net::new_unchecked(
    Ipv6Addr::new(IPV6_ADMIN_SCOPED_MULTICAST_PREFIX, 0, 0, 0, 0, 0, 0, 0),
    64,
);

/// IPv6 interface-local multicast subnet (ff01::/16) per RFC 4291 §2.7.
///
/// Not routable.
pub const IPV6_INTERFACE_LOCAL_MULTICAST_SUBNET: Ipv6Net =
    Ipv6Net::new_unchecked(Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 0), 16);

/// IPv6 link-local multicast subnet (ff02::/16) per RFC 4291 §2.7.
///
/// Not routable beyond the local link.
pub const IPV6_LINK_LOCAL_MULTICAST_SUBNET: Ipv6Net =
    Ipv6Net::new_unchecked(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0), 16);

/// IPv6 reserved-scope multicast subnet (ff00::/16) per RFC 4291 §2.7.
///
/// Scope 0 is reserved. Packets with this scope must not be originated and
/// must be silently dropped if received.
pub const IPV6_RESERVED_SCOPE_MULTICAST_SUBNET: Ipv6Net =
    Ipv6Net::new_unchecked(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 16);

#[cfg(test)]
mod tests {
    use omicron_common::address as canonical;

    use super::*;

    /// Assert each local constant equals its `omicron_common::address`
    /// original so the copies cannot drift from the source of truth.
    ///
    /// `omicron_common` is a dev-dependency only, so it does not appear in the
    /// normal dependency tree the no-omicron CI check inspects.
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
}
