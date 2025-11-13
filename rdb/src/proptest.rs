// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Property-based tests for Prefix types using proptest
//!
//! These tests verify key invariants of the Prefix types to ensure
//! correctness and consistency of prefix operations (excluding wire format
//! tests, which are in bgp/src/proptest.rs since they test BgpWireFormat).

use crate::types::{Prefix, Prefix4, Prefix6, StaticRouteKey};
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Strategy for generating valid IPv4 prefixes
fn ipv4_prefix_strategy() -> impl Strategy<Value = Prefix4> {
    (any::<u32>(), 0u8..=32u8).prop_map(|(addr_bits, length)| {
        Prefix4::new(Ipv4Addr::from(addr_bits), length)
    })
}

// Strategy for generating valid IPv6 prefixes
fn ipv6_prefix_strategy() -> impl Strategy<Value = Prefix6> {
    (any::<u128>(), 0u8..=128u8).prop_map(|(addr_bits, length)| {
        Prefix6::new(Ipv6Addr::from(addr_bits), length)
    })
}

// Strategy for generating IPv4 prefixes WITH host bits set (unnormalized)
fn ipv4_prefix_with_host_bits_strategy() -> impl Strategy<Value = Prefix4> {
    (any::<u32>(), 1u8..=31u8).prop_map(|(addr_bits, length)| {
        // Create a prefix with arbitrary bits, then ensure some host bits are set
        let addr = Ipv4Addr::from(addr_bits);
        // Don't call new() here - we want the unnormalized version
        Prefix4 {
            value: addr,
            length,
        }
    })
}

// Strategy for generating IPv6 prefixes WITH host bits set (unnormalized)
fn ipv6_prefix_with_host_bits_strategy() -> impl Strategy<Value = Prefix6> {
    (any::<u128>(), 1u8..=127u8).prop_map(|(addr_bits, length)| {
        // Create a prefix with arbitrary bits, then ensure some host bits are set
        let addr = Ipv6Addr::from(addr_bits);
        // Don't call new() here - we want the unnormalized version
        Prefix6 {
            value: addr,
            length,
        }
    })
}

// Strategy for generating StaticRouteKey with potentially unnormalized prefixes
fn static_route_key_strategy() -> impl Strategy<Value = StaticRouteKey> {
    (
        prop_oneof![
            ipv4_prefix_with_host_bits_strategy().prop_map(Prefix::V4),
            ipv6_prefix_with_host_bits_strategy().prop_map(Prefix::V6),
        ],
        prop_oneof![
            any::<u32>().prop_map(|v| IpAddr::V4(Ipv4Addr::from(v))),
            any::<u128>().prop_map(|v| IpAddr::V6(Ipv6Addr::from(v))),
        ],
        any::<Option<u16>>(),
        any::<u8>(),
    )
        .prop_map(|(prefix, nexthop, vlan_id, rib_priority)| {
            StaticRouteKey {
                prefix,
                nexthop,
                vlan_id,
                rib_priority,
            }
        })
}

proptest! {
    /// Property: IPv4 host bits are always unset after construction
    #[test]
    fn prop_ipv4_host_bits_always_unset(prefix in ipv4_prefix_strategy()) {
        prop_assert!(
            prefix.host_bits_are_unset(),
            "IPv4 prefix {prefix} should have host bits unset"
        );
    }

    /// Property: IPv6 host bits are always unset after construction
    #[test]
    fn prop_ipv6_host_bits_always_unset(prefix in ipv6_prefix_strategy()) {
        prop_assert!(
            prefix.host_bits_are_unset(),
            "IPv6 prefix {prefix} should have host bits unset"
        );
    }

    /// Property: IPv4 prefix is always within itself
    #[test]
    fn prop_ipv4_within_self(prefix in ipv4_prefix_strategy()) {
        prop_assert!(
            prefix.within(&prefix),
            "IPv4 prefix {prefix} should be within itself"
        );
    }

    /// Property: IPv6 prefix is always within itself
    #[test]
    fn prop_ipv6_within_self(prefix in ipv6_prefix_strategy()) {
        prop_assert!(
            prefix.within(&prefix),
            "IPv6 prefix {prefix} should be within itself"
        );
    }

    /// Property: IPv4 default route (0.0.0.0/0) contains all IPv4 prefixes
    #[test]
    fn prop_ipv4_default_contains_all(prefix in ipv4_prefix_strategy()) {
        let default = Prefix4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        prop_assert!(
            prefix.within(&default),
            "IPv4 prefix {prefix} should be within default route"
        );
    }

    /// Property: IPv6 default route (::/0) contains all IPv6 prefixes
    #[test]
    fn prop_ipv6_default_contains_all(prefix in ipv6_prefix_strategy()) {
        let default = Prefix6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0);
        prop_assert!(
            prefix.within(&default),
            "IPv6 prefix {prefix} should be within default route"
        );
    }

    /// Property: Prefix enum V4 is never within V6 and vice versa
    #[test]
    fn prop_prefix_enum_no_cross_family(p4 in ipv4_prefix_strategy(), p6 in ipv6_prefix_strategy()) {
        let v4 = Prefix::V4(p4);
        let v6 = Prefix::V6(p6);

        prop_assert!(!v4.within(&v6), "IPv4 should not be within IPv6");
        prop_assert!(!v6.within(&v4), "IPv6 should not be within IPv4");
    }

    /// Property: IPv4 prefix length bounds are validated (0-32)
    #[test]
    fn prop_ipv4_length_in_bounds(prefix in ipv4_prefix_strategy()) {
        prop_assert!(prefix.length <= 32u8, "IPv4 prefix length must be <= 32");
    }

    /// Property: IPv6 prefix length bounds are validated (0-128)
    #[test]
    fn prop_ipv6_length_in_bounds(prefix in ipv6_prefix_strategy()) {
        prop_assert!(prefix.length <= 128u8, "IPv6 prefix length must be <= 128");
    }

    /// Property: IPv4 host bits unset operation is idempotent
    #[test]
    fn prop_ipv4_unset_host_bits_idempotent(prefix in ipv4_prefix_strategy()) {
        let mut once = prefix;
        once.unset_host_bits();
        let twice = once;
        let mut twice_copy = twice;
        twice_copy.unset_host_bits();

        prop_assert_eq!(
            twice, twice_copy,
            "Unsetting host bits twice should be idempotent"
        );
    }

    /// Property: IPv6 host bits unset operation is idempotent
    #[test]
    fn prop_ipv6_unset_host_bits_idempotent(prefix in ipv6_prefix_strategy()) {
        let mut once = prefix;
        once.unset_host_bits();
        let twice = once;
        let mut twice_copy = twice;
        twice_copy.unset_host_bits();

        prop_assert_eq!(
            twice, twice_copy,
            "Unsetting host bits twice should be idempotent"
        );
    }

    /// Property: StaticRouteKey normalization is idempotent
    #[test]
    fn prop_static_route_key_normalization_idempotent(route in static_route_key_strategy()) {
        let mut once = route;
        once.prefix.unset_host_bits();

        let mut twice = once;
        twice.prefix.unset_host_bits();

        prop_assert_eq!(
            once, twice,
            "Normalizing StaticRouteKey twice should be idempotent"
        );
    }

    /// Property: After normalization, host bits are always unset
    #[test]
    fn prop_static_route_key_normalized_has_no_host_bits(route in static_route_key_strategy()) {
        let mut normalized = route;
        normalized.prefix.unset_host_bits();

        prop_assert!(
            normalized.prefix.host_bits_are_unset(),
            "Normalized StaticRouteKey should have no host bits set"
        );
    }

    /// Property: Normalization preserves prefix length
    #[test]
    fn prop_static_route_key_normalization_preserves_length(route in static_route_key_strategy()) {
        let original_length = match route.prefix {
            Prefix::V4(p) => p.length,
            Prefix::V6(p) => p.length,
        };

        let mut normalized = route;
        normalized.prefix.unset_host_bits();

        let normalized_length = match normalized.prefix {
            Prefix::V4(p) => p.length,
            Prefix::V6(p) => p.length,
        };

        prop_assert_eq!(
            original_length, normalized_length,
            "Normalization should preserve prefix length"
        );
    }

    /// Property: Normalization preserves nexthop, vlan_id, and rib_priority
    #[test]
    fn prop_static_route_key_normalization_preserves_fields(route in static_route_key_strategy()) {
        let mut normalized = route;
        normalized.prefix.unset_host_bits();

        prop_assert_eq!(
            route.nexthop, normalized.nexthop,
            "Normalization should preserve nexthop"
        );
        prop_assert_eq!(
            route.vlan_id, normalized.vlan_id,
            "Normalization should preserve vlan_id"
        );
        prop_assert_eq!(
            route.rib_priority, normalized.rib_priority,
            "Normalization should preserve rib_priority"
        );
    }

    /// Property: Two routes that differ only in host bits normalize to equal routes
    /// (if they have the same nexthop, vlan_id, and rib_priority)
    #[test]
    fn prop_static_route_key_deduplication(
        addr1 in any::<u32>(),
        addr2 in any::<u32>(),
        length in 1u8..=31u8,
        nexthop in any::<u32>(),
        vlan_id in any::<Option<u16>>(),
        rib_priority in any::<u8>(),
    ) {
        // Create two routes with different IPv4 addresses but same length
        let route1 = StaticRouteKey {
            prefix: Prefix::V4(Prefix4 { value: Ipv4Addr::from(addr1), length }),
            nexthop: IpAddr::V4(Ipv4Addr::from(nexthop)),
            vlan_id,
            rib_priority,
        };

        let route2 = StaticRouteKey {
            prefix: Prefix::V4(Prefix4 { value: Ipv4Addr::from(addr2), length }),
            nexthop: IpAddr::V4(Ipv4Addr::from(nexthop)),
            vlan_id,
            rib_priority,
        };

        let mut norm1 = route1;
        norm1.prefix.unset_host_bits();

        let mut norm2 = route2;
        norm2.prefix.unset_host_bits();

        // If the normalized prefixes are the same, the entire routes should be equal
        if norm1.prefix == norm2.prefix {
            prop_assert_eq!(
                norm1, norm2,
                "Routes with same normalized prefix and same nexthop/vlan/priority should be equal"
            );
        }
    }

    /// Property: StaticRouteKey normalization maintains Ord ordering consistency
    /// (normalized routes can be safely used in BTreeSet)
    #[test]
    fn prop_static_route_key_ord_consistency(route1 in static_route_key_strategy(), route2 in static_route_key_strategy()) {
        let mut norm1 = route1;
        norm1.prefix.unset_host_bits();

        let mut norm2 = route2;
        norm2.prefix.unset_host_bits();

        // If two normalized routes are equal, their ordering should be Equal
        if norm1 == norm2 {
            prop_assert_eq!(
                norm1.cmp(&norm2), std::cmp::Ordering::Equal,
                "Equal normalized routes should have Equal ordering"
            );
        }

        // Ordering should be consistent with equality
        if norm1 < norm2 {
            prop_assert_ne!(norm1, norm2, "Less-than routes should not be equal");
        }
        if norm1 > norm2 {
            prop_assert_ne!(norm1, norm2, "Greater-than routes should not be equal");
        }
    }
}
