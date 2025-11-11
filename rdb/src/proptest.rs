// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Property-based tests for Prefix types using proptest
//!
//! These tests verify key invariants of the Prefix types to ensure
//! correctness and consistency of prefix operations (excluding wire format
//! tests, which are in bgp/src/proptest.rs since they test BgpWireFormat).

#[cfg(test)]
mod proptest {
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

    // Strategy for generating raw IPv4 addresses and lengths (for testing new_unchecked)
    fn ipv4_raw_strategy() -> impl Strategy<Value = (Ipv4Addr, u8)> {
        (any::<u32>(), 0u8..=32u8).prop_map(|(addr_bits, length)| {
            (Ipv4Addr::from(addr_bits), length)
        })
    }

    // Strategy for generating raw IPv6 addresses and lengths (for testing new_unchecked)
    fn ipv6_raw_strategy() -> impl Strategy<Value = (Ipv6Addr, u8)> {
        (any::<u128>(), 0u8..=128u8).prop_map(|(addr_bits, length)| {
            (Ipv6Addr::from(addr_bits), length)
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

        /// Property: IPv4 new_unchecked preserves the exact address value
        #[test]
        fn prop_ipv4_new_unchecked_preserves_value((ip, length) in ipv4_raw_strategy()) {
            let prefix = Prefix4::new_unchecked(ip, length);
            prop_assert_eq!(
                prefix.value, ip,
                "new_unchecked should preserve exact address value (no host bit zeroing)"
            );
            prop_assert_eq!(
                prefix.length, length,
                "new_unchecked should preserve length"
            );
        }

        /// Property: IPv6 new_unchecked preserves the exact address value
        #[test]
        fn prop_ipv6_new_unchecked_preserves_value((ip, length) in ipv6_raw_strategy()) {
            let prefix = Prefix6::new_unchecked(ip, length);
            prop_assert_eq!(
                prefix.value, ip,
                "new_unchecked should preserve exact address value (no host bit zeroing)"
            );
            prop_assert_eq!(
                prefix.length, length,
                "new_unchecked should preserve length"
            );
        }

        /// Property: IPv4 new() and new_unchecked() + unset_host_bits() produce identical results
        #[test]
        fn prop_ipv4_new_equivalence_with_unchecked((ip, length) in ipv4_raw_strategy()) {
            // Create via new() - automatically normalizes
            let normalized = Prefix4::new(ip, length);

            // Create via new_unchecked() and then normalize manually
            let mut unchecked = Prefix4::new_unchecked(ip, length);
            unchecked.unset_host_bits();

            prop_assert_eq!(
                normalized, unchecked,
                "new(ip, len) should equal new_unchecked(ip, len) after unset_host_bits()"
            );
        }

        /// Property: IPv6 new() and new_unchecked() + unset_host_bits() produce identical results
        #[test]
        fn prop_ipv6_new_equivalence_with_unchecked((ip, length) in ipv6_raw_strategy()) {
            // Create via new() - automatically normalizes
            let normalized = Prefix6::new(ip, length);

            // Create via new_unchecked() and then normalize manually
            let mut unchecked = Prefix6::new_unchecked(ip, length);
            unchecked.unset_host_bits();

            prop_assert_eq!(
                normalized, unchecked,
                "new(ip, len) should equal new_unchecked(ip, len) after unset_host_bits()"
            );
        }

        /// Property: Prefix::new_unchecked preserves exact IPv4 address
        #[test]
        fn prop_prefix_enum_new_unchecked_v4((ip, length) in ipv4_raw_strategy()) {
            let prefix = Prefix::new_unchecked(ip.into(), length);
            match prefix {
                Prefix::V4(p4) => {
                    prop_assert_eq!(p4.value, ip, "new_unchecked should preserve IPv4 value");
                    prop_assert_eq!(p4.length, length, "new_unchecked should preserve length");
                }
                Prefix::V6(_) => {
                    prop_assert!(false, "Expected IPv4 variant");
                }
            }
        }

        /// Property: Prefix::new_unchecked preserves exact IPv6 address
        #[test]
        fn prop_prefix_enum_new_unchecked_v6((ip, length) in ipv6_raw_strategy()) {
            let prefix = Prefix::new_unchecked(ip.into(), length);
            match prefix {
                Prefix::V6(p6) => {
                    prop_assert_eq!(p6.value, ip, "new_unchecked should preserve IPv6 value");
                    prop_assert_eq!(p6.length, length, "new_unchecked should preserve length");
                }
                Prefix::V4(_) => {
                    prop_assert!(false, "Expected IPv6 variant");
                }
            }
        }

        /// Property: Prefix::new() and new_unchecked() + unset_host_bits() equivalence for IPv4
        #[test]
        fn prop_prefix_enum_new_equivalence_v4((ip, length) in ipv4_raw_strategy()) {
            let normalized = Prefix::new(ip.into(), length);

            let mut unchecked = Prefix::new_unchecked(ip.into(), length);
            // Match and normalize
            match &mut unchecked {
                Prefix::V4(p4) => p4.unset_host_bits(),
                Prefix::V6(_) => unreachable!("Expected V4"),
            }

            prop_assert_eq!(
                normalized, unchecked,
                "Prefix::new() should equal Prefix::new_unchecked() after normalization"
            );
        }

        /// Property: Prefix::new() and new_unchecked() + unset_host_bits() equivalence for IPv6
        #[test]
        fn prop_prefix_enum_new_equivalence_v6((ip, length) in ipv6_raw_strategy()) {
            let normalized = Prefix::new(ip.into(), length);

            let mut unchecked = Prefix::new_unchecked(ip.into(), length);
            // Match and normalize
            match &mut unchecked {
                Prefix::V6(p6) => p6.unset_host_bits(),
                Prefix::V4(_) => unreachable!("Expected V6"),
            }

            prop_assert_eq!(
                normalized, unchecked,
                "Prefix::new() should equal Prefix::new_unchecked() after normalization"
            );
        }
    }
}
