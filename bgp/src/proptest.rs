// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Property-based tests for BGP wire format using proptest
//!
//! These tests verify key invariants of prefix wire encoding/decoding to ensure
//! correctness and consistency of wire format operations.

use crate::messages::BgpWireFormat;
use proptest::prelude::*;
use rdb::types::{Prefix4, Prefix6};
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
}
