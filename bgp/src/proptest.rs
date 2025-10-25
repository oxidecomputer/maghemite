// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Property-based tests for BGP wire format using proptest
//!
//! These tests verify key invariants of prefix wire encoding/decoding to ensure
//! correctness and consistency of wire format operations.

use proptest::prelude::*;
use rdb::types::{BgpWireFormat, Prefix, Prefix4, Prefix6};
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
    /// Property: IPv4 wire format round-trip is identity
    #[test]
    fn prop_ipv4_wire_format_roundtrip(prefix in ipv4_prefix_strategy()) {
        let wire_bytes = prefix.to_wire().expect("should encode to wire");
        let (remaining, decoded) = Prefix4::from_wire(&wire_bytes)
            .expect("should decode from wire");

        prop_assert_eq!(decoded, prefix, "Decoded prefix should match original");
        prop_assert_eq!(remaining.len(), 0, "Should consume all bytes");
    }

    /// Property: IPv6 wire format round-trip is identity
    #[test]
    fn prop_ipv6_wire_format_roundtrip(prefix in ipv6_prefix_strategy()) {
        let wire_bytes = prefix.to_wire().expect("should encode to wire");
        let (remaining, decoded) = Prefix6::from_wire(&wire_bytes)
            .expect("should decode from wire");

        prop_assert_eq!(decoded, prefix, "Decoded prefix should match original");
        prop_assert_eq!(remaining.len(), 0, "Should consume all bytes");
    }

    /// Property: Prefix enum wire format round-trip with explicit IPv4 address family
    #[test]
    fn prop_prefix_enum_wire_format_roundtrip_v4(prefix4 in ipv4_prefix_strategy()) {
        let prefix = Prefix::V4(prefix4);
        let wire_bytes = prefix.to_wire().expect("should encode to wire");

        // Decode using the underlying IPv4 wire format
        let (remaining, decoded4) = Prefix4::from_wire(&wire_bytes)
            .expect("should decode from wire");
        let decoded = Prefix::V4(decoded4);

        prop_assert_eq!(decoded, prefix, "Decoded enum prefix should match original");
        prop_assert_eq!(remaining.len(), 0, "Should consume all bytes");
    }

    /// Property: Prefix enum wire format round-trip with explicit IPv6 address family
    #[test]
    fn prop_prefix_enum_wire_format_roundtrip_v6(prefix6 in ipv6_prefix_strategy()) {
        let prefix = Prefix::V6(prefix6);
        let wire_bytes = prefix.to_wire().expect("should encode to wire");

        // Decode using the underlying IPv6 wire format
        let (remaining, decoded6) = Prefix6::from_wire(&wire_bytes)
            .expect("should decode from wire");
        let decoded = Prefix::V6(decoded6);

        prop_assert_eq!(decoded, prefix, "Decoded enum prefix should match original");
        prop_assert_eq!(remaining.len(), 0, "Should consume all bytes");
    }
}
