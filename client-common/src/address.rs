// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
use std::net::{Ipv4Addr, Ipv6Addr};

// TODO: Consolidate these constants and the `omicron_common::address`
// originals into `oxnet`, the cycle-free leaf crate that maghemite, dendrite,
// and omicron already share, so the duplication can be removed.

/// IPv4 Source-Specific Multicast (SSM) subnet (232.0.0.0/8) per RFC 4607 §3.
pub const IPV4_SSM_SUBNET: Ipv4Net =
    Ipv4Net::new_unchecked(Ipv4Addr::new(232, 0, 0, 0), 8);

/// IPv6 Source-Specific Multicast (SSM) subnet.
///
/// RFC 4607 §3 specifies ff3x::/32, where the `x` nibble is the multicast
/// scope. We use /12 as an implementation convenience matching all per-scope
/// blocks (ff30:: through ff3f:ffff:..:ffff) with a single subnet, since all
/// SSM addresses share the first 12 bits (0xff prefix plus flag field 3).
/// This superset is used only for contains-based classification, not as an
/// allocation boundary.
pub const IPV6_SSM_SUBNET: Ipv6Net =
    Ipv6Net::new_unchecked(Ipv6Addr::new(0xff30, 0, 0, 0, 0, 0, 0, 0), 12);

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
        assert_eq!(IPV6_SSM_SUBNET, canonical::IPV6_SSM_SUBNET);
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
