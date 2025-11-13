// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Property-based tests for Prefix types using proptest
//!
//! These tests verify key invariants of the Prefix types to ensure
//! correctness and consistency of prefix operations (excluding wire format
//! tests, which are in bgp/src/proptest.rs since they test BgpWireFormat).

use crate::types::{Prefix, Prefix4, Prefix6};
use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

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
}
