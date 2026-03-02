// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Property-based tests for BGP wire format using proptest
//!
//! These tests verify key invariants of wire encoding/decoding to ensure
//! correctness and consistency of wire format operations for:
//! - Prefix4/Prefix6 encoding
//! - BgpNexthop encoding
//! - MpReach/MpUnreach (MP-BGP path attributes)
//! - UpdateMessage (complete BGP UPDATE messages)
//! - RFC 7606 compliance (attribute deduplication, MP-BGP ordering)

use crate::messages::{
    As4PathSegment, AsPathType, BgpNexthop, BgpWireFormat, Header,
    Ipv6DoubleNexthop, MAX_MESSAGE_SIZE, MpReachNlri, MpUnreachNlri,
    PathAttribute, PathAttributeType, PathAttributeTypeCode,
    PathAttributeValue, PathOrigin, UpdateMessage, path_attribute_flags,
    path_attrs_wire_len, split_prefixes_by_size,
};
use proptest::prelude::*;
use rdb::types::{Prefix4, Prefix6};
use std::net::{Ipv4Addr, Ipv6Addr};

// =============================================================================
// Prefix Strategies
// =============================================================================

/// Strategy for generating valid IPv4 prefixes
fn ipv4_prefix_strategy() -> impl Strategy<Value = Prefix4> {
    (any::<u32>(), 0u8..=32u8).prop_map(|(addr_bits, length)| {
        Prefix4::new(Ipv4Addr::from(addr_bits), length)
    })
}

/// Strategy for generating valid IPv6 prefixes
fn ipv6_prefix_strategy() -> impl Strategy<Value = Prefix6> {
    (any::<u128>(), 0u8..=128u8).prop_map(|(addr_bits, length)| {
        Prefix6::new(Ipv6Addr::from(addr_bits), length)
    })
}

/// Strategy for generating a vector of IPv4 prefixes (limited size for perf)
fn ipv4_prefixes_strategy() -> impl Strategy<Value = Vec<Prefix4>> {
    prop::collection::vec(ipv4_prefix_strategy(), 0..5)
}

/// Strategy for generating a vector of IPv6 prefixes (limited size for perf)
fn ipv6_prefixes_strategy() -> impl Strategy<Value = Vec<Prefix6>> {
    prop::collection::vec(ipv6_prefix_strategy(), 0..5)
}

// =============================================================================
// BgpNexthop Strategies
// =============================================================================

/// Strategy for generating IPv4 next-hops
fn nexthop_ipv4_strategy() -> impl Strategy<Value = BgpNexthop> {
    any::<u32>().prop_map(|bits| BgpNexthop::Ipv4(Ipv4Addr::from(bits)))
}

/// Strategy for generating IPv6 single next-hops
fn nexthop_ipv6_single_strategy() -> impl Strategy<Value = BgpNexthop> {
    any::<u128>().prop_map(|bits| BgpNexthop::Ipv6Single(Ipv6Addr::from(bits)))
}

/// Strategy for generating IPv6 double next-hops (global + link-local)
fn nexthop_ipv6_double_strategy() -> impl Strategy<Value = BgpNexthop> {
    (any::<u128>(), any::<u128>()).prop_map(|(global_bits, link_local_bits)| {
        BgpNexthop::Ipv6Double(Ipv6DoubleNexthop {
            global: Ipv6Addr::from(global_bits),
            link_local: Ipv6Addr::from(link_local_bits),
        })
    })
}

// =============================================================================
// Path Attribute Strategies
// =============================================================================

/// Strategy for generating PathOrigin values
fn path_origin_strategy() -> impl Strategy<Value = PathOrigin> {
    prop_oneof![
        Just(PathOrigin::Igp),
        Just(PathOrigin::Egp),
        Just(PathOrigin::Incomplete),
    ]
}

/// Strategy for generating AS path segments
fn as_path_segment_strategy() -> impl Strategy<Value = As4PathSegment> {
    (
        prop_oneof![Just(AsPathType::AsSet), Just(AsPathType::AsSequence)],
        prop::collection::vec(any::<u32>(), 1..5),
    )
        .prop_map(|(typ, value)| As4PathSegment { typ, value })
}

/// Strategy for generating AS paths (vector of segments)
fn as_path_strategy() -> impl Strategy<Value = Vec<As4PathSegment>> {
    prop::collection::vec(as_path_segment_strategy(), 0..3)
}

/// Strategy for generating a set of distinct traditional path attributes
/// (no duplicates by type code)
fn distinct_traditional_attrs_strategy()
-> impl Strategy<Value = Vec<PathAttribute>> {
    (
        prop::option::of(path_origin_strategy()),
        prop::option::of(as_path_strategy()),
        prop::option::of(any::<u32>()), // nexthop
        prop::option::of(any::<u32>()), // med
        prop::option::of(any::<u32>()), // local_pref
    )
        .prop_map(|(origin, as_path, nexthop, med, local_pref)| {
            let mut attrs = Vec::new();
            if let Some(o) = origin {
                attrs.push(PathAttribute::from(PathAttributeValue::Origin(o)));
            }
            if let Some(p) = as_path {
                attrs.push(PathAttribute::from(PathAttributeValue::AsPath(p)));
            }
            if let Some(nh) = nexthop {
                attrs.push(PathAttribute::from(PathAttributeValue::NextHop(
                    Ipv4Addr::from(nh),
                )));
            }
            if let Some(m) = med {
                attrs.push(PathAttribute::from(
                    PathAttributeValue::MultiExitDisc(m),
                ));
            }
            if let Some(lp) = local_pref {
                attrs.push(PathAttribute::from(PathAttributeValue::LocalPref(
                    lp,
                )));
            }
            attrs
        })
}

// =============================================================================
// MpReachNlri/MpUnreachNlri Strategies
// =============================================================================

/// Strategy for generating IPv4 MpReachNlri
fn mp_reach_v4_strategy() -> impl Strategy<Value = MpReachNlri> {
    (nexthop_ipv4_strategy(), ipv4_prefixes_strategy())
        .prop_map(|(nexthop, nlri)| MpReachNlri::ipv4_unicast(nexthop, nlri))
}

/// Strategy for generating IPv6 MpReachNlri with single next-hop
fn mp_reach_v6_single_strategy() -> impl Strategy<Value = MpReachNlri> {
    (nexthop_ipv6_single_strategy(), ipv6_prefixes_strategy())
        .prop_map(|(nexthop, nlri)| MpReachNlri::ipv6_unicast(nexthop, nlri))
}

/// Strategy for generating IPv6 MpReachNlri with double next-hop
fn mp_reach_v6_double_strategy() -> impl Strategy<Value = MpReachNlri> {
    (nexthop_ipv6_double_strategy(), ipv6_prefixes_strategy())
        .prop_map(|(nexthop, nlri)| MpReachNlri::ipv6_unicast(nexthop, nlri))
}

/// Strategy for generating any valid MpReachNlri
fn mp_reach_strategy() -> impl Strategy<Value = MpReachNlri> {
    prop_oneof![
        mp_reach_v4_strategy(),
        mp_reach_v6_single_strategy(),
        mp_reach_v6_double_strategy(),
    ]
}

/// Strategy for generating IPv4 MpUnreachNlri
fn mp_unreach_v4_strategy() -> impl Strategy<Value = MpUnreachNlri> {
    ipv4_prefixes_strategy().prop_map(MpUnreachNlri::ipv4_unicast)
}

/// Strategy for generating IPv6 MpUnreachNlri
fn mp_unreach_v6_strategy() -> impl Strategy<Value = MpUnreachNlri> {
    ipv6_prefixes_strategy().prop_map(MpUnreachNlri::ipv6_unicast)
}

/// Strategy for generating any valid MpUnreachNlri
fn mp_unreach_strategy() -> impl Strategy<Value = MpUnreachNlri> {
    prop_oneof![mp_unreach_v4_strategy(), mp_unreach_v6_strategy(),]
}

// =============================================================================
// UpdateMessage Strategies
// =============================================================================

/// Strategy for generating traditional IPv4-only UpdateMessage
fn update_traditional_strategy() -> impl Strategy<Value = UpdateMessage> {
    (
        ipv4_prefixes_strategy(),
        distinct_traditional_attrs_strategy(),
        ipv4_prefixes_strategy(),
    )
        .prop_map(|(withdrawn, path_attributes, nlri)| UpdateMessage {
            withdrawn,
            path_attributes,
            nlri,
            errors: vec![],
        })
}

/// Strategy for generating UpdateMessage with MP_REACH_NLRI
fn update_mp_reach_strategy() -> impl Strategy<Value = UpdateMessage> {
    (mp_reach_strategy(), distinct_traditional_attrs_strategy()).prop_map(
        |(mp_reach, mut attrs)| {
            attrs.push(PathAttribute {
                typ: PathAttributeType {
                    flags: path_attribute_flags::OPTIONAL,
                    type_code: PathAttributeTypeCode::MpReachNlri,
                },
                value: PathAttributeValue::MpReachNlri(mp_reach),
            });
            UpdateMessage {
                withdrawn: vec![],
                path_attributes: attrs,
                nlri: vec![],
                errors: vec![],
            }
        },
    )
}

/// Strategy for generating UpdateMessage with MP_UNREACH_NLRI
fn update_mp_unreach_strategy() -> impl Strategy<Value = UpdateMessage> {
    mp_unreach_strategy().prop_map(|mp_unreach| UpdateMessage {
        withdrawn: vec![],
        path_attributes: vec![PathAttribute {
            typ: PathAttributeType {
                flags: path_attribute_flags::OPTIONAL,
                type_code: PathAttributeTypeCode::MpUnreachNlri,
            },
            value: PathAttributeValue::MpUnreachNlri(mp_unreach),
        }],
        nlri: vec![],
        errors: vec![],
    })
}

/// Strategy for generating any valid UpdateMessage
fn update_strategy() -> impl Strategy<Value = UpdateMessage> {
    prop_oneof![
        update_traditional_strategy(),
        update_mp_reach_strategy(),
        update_mp_unreach_strategy(),
    ]
}

// =============================================================================
// Large-Prefix Strategies (for split_prefixes_by_size tests)
// =============================================================================

/// Strategy for generating enough IPv4 /24 prefixes to require chunking.
/// Each /24 prefix is 4 bytes on the wire. The max UPDATE body is 4077
/// bytes; with minimal overhead (~29 bytes) roughly 1012 prefixes fit,
/// so 1100+ always forces a split.
fn large_ipv4_prefixes_strategy() -> impl Strategy<Value = Vec<Prefix4>> {
    (1100u32..1500).prop_flat_map(|count| {
        Just(
            (0..count)
                .map(|i| Prefix4::new(Ipv4Addr::from(i << 8), 24))
                .collect(),
        )
    })
}

/// Strategy for generating enough IPv6 /48 prefixes to require chunking.
/// Each /48 prefix is 7 bytes on the wire. With ~29 bytes overhead
/// roughly 578 prefixes fit, so 600+ always forces a split.
fn large_ipv6_prefixes_strategy() -> impl Strategy<Value = Vec<Prefix6>> {
    (600u32..800).prop_flat_map(|count| {
        Just(
            (0..count as u128)
                .map(|i| Prefix6::new(Ipv6Addr::from(i << 80), 48))
                .collect(),
        )
    })
}

// =============================================================================
// Property Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    // -------------------------------------------------------------------------
    // Prefix Round-Trip Tests
    // -------------------------------------------------------------------------

    /// Property: IPv4 wire format round-trip is identity
    #[test]
    fn prop_ipv4_wire_format_roundtrip(prefix in ipv4_prefix_strategy()) {
        let wire_bytes = prefix.to_wire();
        let (remaining, decoded) = Prefix4::from_wire(&wire_bytes)
            .expect("should decode from wire");

        prop_assert_eq!(decoded, prefix, "Decoded prefix should match original");
        prop_assert_eq!(remaining.len(), 0, "Should consume all bytes");
    }

    /// Property: IPv6 wire format round-trip is identity
    #[test]
    fn prop_ipv6_wire_format_roundtrip(prefix in ipv6_prefix_strategy()) {
        let wire_bytes = prefix.to_wire();
        let (remaining, decoded) = Prefix6::from_wire(&wire_bytes)
            .expect("should decode from wire");

        prop_assert_eq!(decoded, prefix, "Decoded prefix should match original");
        prop_assert_eq!(remaining.len(), 0, "Should consume all bytes");
    }

    /// Property: Multiple IPv4 prefixes round-trip through traditional UPDATE
    #[test]
    fn prop_ipv4_prefixes_roundtrip(prefixes in ipv4_prefixes_strategy()) {
        let update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![],
            nlri: prefixes.clone(),
            errors: vec![],
        };

        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        prop_assert_eq!(decoded.nlri, prefixes, "NLRI prefixes should round-trip");
    }

    /// Property: Multiple IPv4 withdrawn prefixes round-trip through traditional UPDATE
    #[test]
    fn prop_ipv4_withdrawn_roundtrip(prefixes in ipv4_prefixes_strategy()) {
        let update = UpdateMessage {
            withdrawn: prefixes.clone(),
            path_attributes: vec![],
            nlri: vec![],
            errors: vec![],
        };

        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        prop_assert_eq!(decoded.withdrawn, prefixes, "Withdrawn prefixes should round-trip");
    }

    /// Property: Multiple IPv6 prefixes round-trip through MP_REACH_NLRI
    #[test]
    fn prop_ipv6_prefixes_via_mp_reach(
        prefixes in ipv6_prefixes_strategy(),
        nexthop in nexthop_ipv6_single_strategy()
    ) {
        let mp_reach = MpReachNlri::ipv6_unicast(nexthop, prefixes.clone());

        let update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![PathAttribute {
                typ: PathAttributeType {
                    flags: path_attribute_flags::OPTIONAL,
                    type_code: PathAttributeTypeCode::MpReachNlri,
                },
                value: PathAttributeValue::MpReachNlri(mp_reach),
            }],
            nlri: vec![],
            errors: vec![],
        };

        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        // Extract MP_REACH_NLRI and verify prefixes
        let decoded_prefixes = decoded.path_attributes.iter()
            .find_map(|a| match &a.value {
                PathAttributeValue::MpReachNlri(MpReachNlri::Ipv6Unicast(inner)) => {
                    Some(inner.nlri.clone())
                }
                _ => None,
            })
            .expect("should have MP_REACH_NLRI with IPv6 NLRI");

        prop_assert_eq!(decoded_prefixes, prefixes, "IPv6 NLRI prefixes should round-trip");
    }

    /// Property: Multiple IPv6 withdrawn prefixes round-trip through MP_UNREACH_NLRI
    #[test]
    fn prop_ipv6_withdrawn_via_mp_unreach(prefixes in ipv6_prefixes_strategy()) {
        let mp_unreach = MpUnreachNlri::ipv6_unicast(prefixes.clone());

        let update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![PathAttribute {
                typ: PathAttributeType {
                    flags: path_attribute_flags::OPTIONAL,
                    type_code: PathAttributeTypeCode::MpUnreachNlri,
                },
                value: PathAttributeValue::MpUnreachNlri(mp_unreach),
            }],
            nlri: vec![],
            errors: vec![],
        };

        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        // Extract MP_UNREACH_NLRI and verify prefixes
        let decoded_prefixes = decoded.path_attributes.iter()
            .find_map(|a| match &a.value {
                PathAttributeValue::MpUnreachNlri(MpUnreachNlri::Ipv6Unicast(inner)) => {
                    Some(inner.withdrawn.clone())
                }
                _ => None,
            })
            .expect("should have MP_UNREACH_NLRI with IPv6 withdrawn");

        prop_assert_eq!(decoded_prefixes, prefixes, "IPv6 withdrawn prefixes should round-trip");
    }

    /// Property: Multiple IPv4 prefixes round-trip through MP_REACH_NLRI (MP-BGP encoding)
    #[test]
    fn prop_ipv4_prefixes_via_mp_reach(
        prefixes in ipv4_prefixes_strategy(),
        nexthop in nexthop_ipv4_strategy()
    ) {
        let mp_reach = MpReachNlri::ipv4_unicast(nexthop, prefixes.clone());

        let update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![PathAttribute {
                typ: PathAttributeType {
                    flags: path_attribute_flags::OPTIONAL,
                    type_code: PathAttributeTypeCode::MpReachNlri,
                },
                value: PathAttributeValue::MpReachNlri(mp_reach),
            }],
            nlri: vec![],
            errors: vec![],
        };

        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        // Extract MP_REACH_NLRI and verify prefixes
        let decoded_prefixes = decoded.path_attributes.iter()
            .find_map(|a| match &a.value {
                PathAttributeValue::MpReachNlri(MpReachNlri::Ipv4Unicast(inner)) => {
                    Some(inner.nlri.clone())
                }
                _ => None,
            })
            .expect("should have MP_REACH_NLRI with IPv4 NLRI");

        prop_assert_eq!(decoded_prefixes, prefixes, "IPv4 MP-BGP NLRI prefixes should round-trip");
    }

    /// Property: Multiple IPv4 withdrawn prefixes round-trip through MP_UNREACH_NLRI (MP-BGP encoding)
    #[test]
    fn prop_ipv4_withdrawn_via_mp_unreach(prefixes in ipv4_prefixes_strategy()) {
        let mp_unreach = MpUnreachNlri::ipv4_unicast(prefixes.clone());

        let update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![PathAttribute {
                typ: PathAttributeType {
                    flags: path_attribute_flags::OPTIONAL,
                    type_code: PathAttributeTypeCode::MpUnreachNlri,
                },
                value: PathAttributeValue::MpUnreachNlri(mp_unreach),
            }],
            nlri: vec![],
            errors: vec![],
        };

        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        // Extract MP_UNREACH_NLRI and verify prefixes
        let decoded_prefixes = decoded.path_attributes.iter()
            .find_map(|a| match &a.value {
                PathAttributeValue::MpUnreachNlri(MpUnreachNlri::Ipv4Unicast(inner)) => {
                    Some(inner.withdrawn.clone())
                }
                _ => None,
            })
            .expect("should have MP_UNREACH_NLRI with IPv4 withdrawn");

        prop_assert_eq!(decoded_prefixes, prefixes, "IPv4 MP-BGP withdrawn prefixes should round-trip");
    }

    // -------------------------------------------------------------------------
    // BgpNexthop Round-Trip Tests (via MpReachNlri)
    // -------------------------------------------------------------------------

    /// Property: BgpNexthop IPv4 round-trip through MpReachNlri preserves next-hop
    #[test]
    fn prop_nexthop_ipv4_via_mp_reach(nexthop in nexthop_ipv4_strategy()) {
        let mp_reach = MpReachNlri::ipv4_unicast(nexthop, vec![]);
        let attr = PathAttribute {
            typ: PathAttributeType {
                flags: path_attribute_flags::OPTIONAL,
                type_code: PathAttributeTypeCode::MpReachNlri,
            },
            value: PathAttributeValue::MpReachNlri(mp_reach),
        };

        let update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![attr],
            nlri: vec![],
            errors: vec![],
        };

        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        // Extract and verify the next-hop
        let decoded_nexthop = decoded.nexthop().expect("should have nexthop");
        prop_assert_eq!(decoded_nexthop, nexthop, "IPv4 nexthop should round-trip");
    }

    /// Property: BgpNexthop IPv6 single round-trip through MpReachNlri preserves next-hop
    #[test]
    fn prop_nexthop_ipv6_single_via_mp_reach(nexthop in nexthop_ipv6_single_strategy()) {
        let mp_reach = MpReachNlri::ipv6_unicast(nexthop, vec![]);
        let attr = PathAttribute {
            typ: PathAttributeType {
                flags: path_attribute_flags::OPTIONAL,
                type_code: PathAttributeTypeCode::MpReachNlri,
            },
            value: PathAttributeValue::MpReachNlri(mp_reach),
        };

        let update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![attr],
            nlri: vec![],
            errors: vec![],
        };

        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        let decoded_nexthop = decoded.nexthop().expect("should have nexthop");
        prop_assert_eq!(decoded_nexthop, nexthop, "IPv6 single nexthop should round-trip");
    }

    /// Property: BgpNexthop IPv6 double round-trip through MpReachNlri preserves next-hop
    #[test]
    fn prop_nexthop_ipv6_double_via_mp_reach(nexthop in nexthop_ipv6_double_strategy()) {
        let mp_reach = MpReachNlri::ipv6_unicast(nexthop, vec![]);
        let attr = PathAttribute {
            typ: PathAttributeType {
                flags: path_attribute_flags::OPTIONAL,
                type_code: PathAttributeTypeCode::MpReachNlri,
            },
            value: PathAttributeValue::MpReachNlri(mp_reach),
        };

        let update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: vec![attr],
            nlri: vec![],
            errors: vec![],
        };

        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        let decoded_nexthop = decoded.nexthop().expect("should have nexthop");
        prop_assert_eq!(decoded_nexthop, nexthop, "IPv6 double nexthop should round-trip");
    }

    // -------------------------------------------------------------------------
    // UpdateMessage Round-Trip Tests
    // -------------------------------------------------------------------------

    /// Property: Traditional UpdateMessage round-trip preserves structure
    #[test]
    fn prop_update_traditional_roundtrip(update in update_traditional_strategy()) {
        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        prop_assert_eq!(decoded.withdrawn, update.withdrawn);
        prop_assert_eq!(decoded.nlri, update.nlri);
        // Path attributes may be reordered but should have same count
        prop_assert_eq!(
            decoded.path_attributes.len(),
            update.path_attributes.len(),
            "Path attribute count should match"
        );
    }

    /// Property: MP-BGP UpdateMessage with MP_REACH_NLRI round-trip works
    #[test]
    fn prop_update_mp_reach_roundtrip(update in update_mp_reach_strategy()) {
        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        // Should have MP_REACH_NLRI attribute
        let has_mp_reach = decoded.path_attributes.iter().any(|a| {
            matches!(a.value, PathAttributeValue::MpReachNlri(_))
        });
        prop_assert!(has_mp_reach, "Decoded should have MP_REACH_NLRI");
    }

    /// Property: MP-BGP UpdateMessage with MP_UNREACH_NLRI round-trip works
    #[test]
    fn prop_update_mp_unreach_roundtrip(update in update_mp_unreach_strategy()) {
        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        // Should have MP_UNREACH_NLRI attribute
        let has_mp_unreach = decoded.path_attributes.iter().any(|a| {
            matches!(a.value, PathAttributeValue::MpUnreachNlri(_))
        });
        prop_assert!(has_mp_unreach, "Decoded should have MP_UNREACH_NLRI");
    }

    // -------------------------------------------------------------------------
    // RFC 7606 Compliance Tests
    // -------------------------------------------------------------------------

    /// Property: MP-BGP attributes are always encoded first (RFC 7606 Section 5.1)
    #[test]
    fn prop_mp_bgp_attrs_encoded_first(update in update_mp_reach_strategy()) {
        let wire = update.to_wire().expect("should encode");

        // Skip to path attributes section
        // Wire format: 2 bytes withdrawn len + withdrawn + 2 bytes attrs len + attrs + nlri
        let withdrawn_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
        let attrs_start = 2 + withdrawn_len + 2;

        if wire.len() > attrs_start + 1 {
            // First attribute's type code is at offset 1 (after flags byte)
            let first_type_code = wire[attrs_start + 1];

            prop_assert!(
                first_type_code == PathAttributeTypeCode::MpReachNlri as u8
                    || first_type_code == PathAttributeTypeCode::MpUnreachNlri as u8,
                "First path attribute should be MP-BGP when present, got type code {}",
                first_type_code
            );
        }
    }

    /// Property: Duplicate non-MP-BGP attributes are deduplicated to first occurrence
    #[test]
    fn prop_duplicate_attrs_deduplicated(
        origin1 in path_origin_strategy(),
        origin2 in path_origin_strategy()
    ) {
        // Manually construct wire bytes with duplicate ORIGIN attributes
        let mut wire = Vec::new();

        // Withdrawn routes length (0)
        wire.extend_from_slice(&0u16.to_be_bytes());

        // Path attributes: two ORIGIN attributes (second should be discarded)
        let attrs = vec![
            // First ORIGIN attribute
            path_attribute_flags::TRANSITIVE,
            PathAttributeTypeCode::Origin as u8,
            1, // length
            origin1 as u8,
            // Second ORIGIN attribute (should be discarded)
            path_attribute_flags::TRANSITIVE,
            PathAttributeTypeCode::Origin as u8,
            1, // length
            origin2 as u8,
        ];

        // Path attributes length
        wire.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        wire.extend_from_slice(&attrs);

        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        // Should only have one ORIGIN attribute
        let origins: Vec<_> = decoded.path_attributes.iter()
            .filter_map(|a| match &a.value {
                PathAttributeValue::Origin(o) => Some(*o),
                _ => None,
            })
            .collect();

        prop_assert_eq!(origins.len(), 1, "Should have exactly one ORIGIN after dedup");
        prop_assert_eq!(origins[0], origin1, "Should keep first ORIGIN value");
    }

    /// Property: Encoding then decoding produces semantically equivalent message
    #[test]
    fn prop_encode_decode_semantic_equivalence(update in update_strategy()) {
        let wire = update.to_wire().expect("should encode");
        let decoded = UpdateMessage::from_wire(&wire).expect("should decode");

        // Withdrawn and NLRI should be identical
        prop_assert_eq!(decoded.withdrawn, update.withdrawn);
        prop_assert_eq!(decoded.nlri, update.nlri);

        // Count of each attribute type should match
        // (may be reordered due to MP-BGP first encoding rule)
        for type_code in [
            PathAttributeTypeCode::Origin,
            PathAttributeTypeCode::AsPath,
            PathAttributeTypeCode::NextHop,
            PathAttributeTypeCode::MultiExitDisc,
            PathAttributeTypeCode::LocalPref,
            PathAttributeTypeCode::MpReachNlri,
            PathAttributeTypeCode::MpUnreachNlri,
        ] {
            let orig_count = update.path_attributes.iter()
                .filter(|a| a.typ.type_code == type_code)
                .count();
            let decoded_count = decoded.path_attributes.iter()
                .filter(|a| a.typ.type_code == type_code)
                .count();

            prop_assert_eq!(
                orig_count, decoded_count,
                "Attribute {:?} count should match", type_code
            );
        }
    }

    // -------------------------------------------------------------------------
    // IPv4 Encoding Equivalence Tests
    // -------------------------------------------------------------------------

    /// Property: Two UPDATE messages carrying the same IPv4 Unicast routes should
    /// be functionally equivalent regardless of whether they use traditional encoding
    /// (NLRI/withdrawn fields) or MP-BGP encoding (MP_REACH_NLRI/MP_UNREACH_NLRI).
    ///
    /// This test generates random IPv4 prefixes, encodes them using both methods,
    /// and verifies that the decoded routes are equivalent.
    #[test]
    fn prop_ipv4_traditional_vs_mp_bgp_equivalence(
        nlri_prefixes in ipv4_prefixes_strategy(),
        withdrawn_prefixes in ipv4_prefixes_strategy(),
        nexthop in nexthop_ipv4_strategy()
    ) {
        // Create UPDATE using traditional encoding
        let traditional_update = UpdateMessage {
            withdrawn: withdrawn_prefixes.clone(),
            path_attributes: vec![
                PathAttribute::from(PathAttributeValue::Origin(PathOrigin::Igp)),
                PathAttribute::from(PathAttributeValue::AsPath(vec![])),
                PathAttribute::from(PathAttributeValue::NextHop(
                    match nexthop {
                        BgpNexthop::Ipv4(addr) => addr,
                        _ => unreachable!("nexthop_ipv4_strategy only generates IPv4"),
                    }
                )),
            ],
            nlri: nlri_prefixes.clone(),
            errors: vec![],
        };

        // Create UPDATE using MP-BGP encoding
        let mp_reach = MpReachNlri::ipv4_unicast(nexthop, nlri_prefixes.clone());
        let mp_unreach = MpUnreachNlri::ipv4_unicast(withdrawn_prefixes.clone());

        let mut mp_attrs = vec![
            PathAttribute::from(PathAttributeValue::Origin(PathOrigin::Igp)),
            PathAttribute::from(PathAttributeValue::AsPath(vec![])),
        ];
        if !nlri_prefixes.is_empty() {
            mp_attrs.push(PathAttribute {
                typ: PathAttributeType {
                    flags: path_attribute_flags::OPTIONAL,
                    type_code: PathAttributeTypeCode::MpReachNlri,
                },
                value: PathAttributeValue::MpReachNlri(mp_reach),
            });
        }
        if !withdrawn_prefixes.is_empty() {
            mp_attrs.push(PathAttribute {
                typ: PathAttributeType {
                    flags: path_attribute_flags::OPTIONAL,
                    type_code: PathAttributeTypeCode::MpUnreachNlri,
                },
                value: PathAttributeValue::MpUnreachNlri(mp_unreach),
            });
        }

        let mp_bgp_update = UpdateMessage {
            withdrawn: vec![],
            path_attributes: mp_attrs,
            nlri: vec![],
            errors: vec![],
        };

        // Encode and decode both
        let traditional_wire = traditional_update.to_wire().expect("traditional encode");
        let mp_bgp_wire = mp_bgp_update.to_wire().expect("mp-bgp encode");

        let traditional_decoded = UpdateMessage::from_wire(&traditional_wire)
            .expect("traditional decode");
        let mp_bgp_decoded = UpdateMessage::from_wire(&mp_bgp_wire)
            .expect("mp-bgp decode");

        // Extract the effective NLRI from both (traditional uses nlri field,
        // MP-BGP uses MP_REACH_NLRI attribute)
        let traditional_effective_nlri = traditional_decoded.nlri.clone();
        let mp_bgp_effective_nlri: Vec<Prefix4> = mp_bgp_decoded
            .path_attributes
            .iter()
            .find_map(|a| match &a.value {
                PathAttributeValue::MpReachNlri(MpReachNlri::Ipv4Unicast(inner)) => {
                    Some(inner.nlri.clone())
                }
                _ => None,
            })
            .unwrap_or_default();

        // Extract the effective withdrawn from both
        let traditional_effective_withdrawn = traditional_decoded.withdrawn.clone();
        let mp_bgp_effective_withdrawn: Vec<Prefix4> = mp_bgp_decoded
            .path_attributes
            .iter()
            .find_map(|a| match &a.value {
                PathAttributeValue::MpUnreachNlri(MpUnreachNlri::Ipv4Unicast(inner)) => {
                    Some(inner.withdrawn.clone())
                }
                _ => None,
            })
            .unwrap_or_default();

        // The routes should be functionally equivalent
        prop_assert_eq!(
            traditional_effective_nlri, mp_bgp_effective_nlri,
            "NLRI prefixes should be equivalent regardless of encoding"
        );
        prop_assert_eq!(
            traditional_effective_withdrawn, mp_bgp_effective_withdrawn,
            "Withdrawn prefixes should be equivalent regardless of encoding"
        );
    }

    // -------------------------------------------------------------------------
    // split_prefixes_by_size Tests
    // -------------------------------------------------------------------------

    /// Property: IPv4 split preserves all prefixes across chunks.
    #[test]
    fn prop_v4_split_preserves_all_prefixes(
        prefixes in large_ipv4_prefixes_strategy()
    ) {
        let max_body = MAX_MESSAGE_SIZE - Header::WIRE_SIZE;
        let skeleton = UpdateMessage {
            path_attributes: vec![
                PathAttributeValue::NextHop(Ipv4Addr::UNSPECIFIED).into(),
            ],
            ..Default::default()
        };
        let available = max_body.saturating_sub(skeleton.wire_len());
        let original_count = prefixes.len();
        let chunks = split_prefixes_by_size(prefixes, available, Prefix4::wire_len);
        prop_assert!(chunks.len() >= 2, "expected 2+ chunks, got {}", chunks.len());
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        prop_assert_eq!(total, original_count);
    }

    /// Property: IPv6 split preserves all prefixes across chunks.
    #[test]
    fn prop_v6_split_preserves_all_prefixes(
        prefixes in large_ipv6_prefixes_strategy()
    ) {
        let max_body = MAX_MESSAGE_SIZE - Header::WIRE_SIZE;
        let skeleton = UpdateMessage {
            path_attributes: vec![
                PathAttributeValue::MpReachNlri(
                    MpReachNlri::ipv6_unicast(
                        BgpNexthop::Ipv6Single(Ipv6Addr::UNSPECIFIED),
                        vec![],
                    ),
                ).into(),
            ],
            ..Default::default()
        };
        let available = max_body.saturating_sub(skeleton.wire_len());
        let original_count = prefixes.len();
        let chunks = split_prefixes_by_size(prefixes, available, Prefix6::wire_len);
        prop_assert!(chunks.len() >= 2, "expected 2+ chunks, got {}", chunks.len());
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        prop_assert_eq!(total, original_count);
    }

    /// Property: Every IPv4 chunk fits within available space.
    #[test]
    fn prop_v4_all_chunks_within_available(
        prefixes in large_ipv4_prefixes_strategy()
    ) {
        let max_body = MAX_MESSAGE_SIZE - Header::WIRE_SIZE;
        let skeleton = UpdateMessage {
            path_attributes: vec![
                PathAttributeValue::NextHop(Ipv4Addr::UNSPECIFIED).into(),
            ],
            ..Default::default()
        };
        let available = max_body.saturating_sub(skeleton.wire_len());
        let chunks = split_prefixes_by_size(prefixes, available, Prefix4::wire_len);
        for (i, chunk) in chunks.iter().enumerate() {
            let size: usize = chunk.iter().map(Prefix4::wire_len).sum();
            prop_assert!(
                size <= available,
                "chunk {i} is {size} bytes, max is {available}",
            );
        }
    }

    /// Property: Every IPv6 chunk fits within available space.
    #[test]
    fn prop_v6_all_chunks_within_available(
        prefixes in large_ipv6_prefixes_strategy()
    ) {
        let max_body = MAX_MESSAGE_SIZE - Header::WIRE_SIZE;
        let skeleton = UpdateMessage {
            path_attributes: vec![
                PathAttributeValue::MpReachNlri(
                    MpReachNlri::ipv6_unicast(
                        BgpNexthop::Ipv6Single(Ipv6Addr::UNSPECIFIED),
                        vec![],
                    ),
                ).into(),
            ],
            ..Default::default()
        };
        let available = max_body.saturating_sub(skeleton.wire_len());
        let chunks = split_prefixes_by_size(prefixes, available, Prefix6::wire_len);
        for (i, chunk) in chunks.iter().enumerate() {
            let size: usize = chunk.iter().map(Prefix6::wire_len).sum();
            prop_assert!(
                size <= available,
                "chunk {i} is {size} bytes, max is {available}",
            );
        }
    }

    /// Property: Small IPv4 prefix vecs produce exactly 1 chunk.
    #[test]
    fn prop_small_v4_produces_single_chunk(
        prefixes in ipv4_prefixes_strategy()
    ) {
        let max_body = MAX_MESSAGE_SIZE - Header::WIRE_SIZE;
        let skeleton = UpdateMessage {
            path_attributes: vec![
                PathAttributeValue::NextHop(Ipv4Addr::UNSPECIFIED).into(),
            ],
            ..Default::default()
        };
        let available = max_body.saturating_sub(skeleton.wire_len());
        let chunks = split_prefixes_by_size(prefixes.clone(), available, Prefix4::wire_len);
        if !prefixes.is_empty() {
            prop_assert_eq!(chunks.len(), 1, "small prefix vec should not be split");
        }
    }

    /// Property: Small IPv6 prefix vecs produce exactly 1 chunk.
    #[test]
    fn prop_small_v6_produces_single_chunk(
        prefixes in ipv6_prefixes_strategy()
    ) {
        let max_body = MAX_MESSAGE_SIZE - Header::WIRE_SIZE;
        let skeleton = UpdateMessage {
            path_attributes: vec![
                PathAttributeValue::MpReachNlri(
                    MpReachNlri::ipv6_unicast(
                        BgpNexthop::Ipv6Single(Ipv6Addr::UNSPECIFIED),
                        vec![],
                    ),
                ).into(),
            ],
            ..Default::default()
        };
        let available = max_body.saturating_sub(skeleton.wire_len());
        let chunks = split_prefixes_by_size(prefixes.clone(), available, Prefix6::wire_len);
        if !prefixes.is_empty() {
            prop_assert_eq!(chunks.len(), 1, "small prefix vec should not be split");
        }
    }

    /// Property: Empty prefix vec produces no chunks.
    #[test]
    fn prop_empty_produces_no_chunks(_dummy in 0u8..1u8) {
        let chunks = split_prefixes_by_size(Vec::<Prefix4>::new(), 4000, Prefix4::wire_len);
        prop_assert_eq!(chunks.len(), 0, "empty vec should produce 0 chunks");
    }

    /// Property: path_attrs_wire_len matches sum of individual wire_len.
    #[test]
    fn prop_path_attrs_wire_len_consistent(
        attrs in distinct_traditional_attrs_strategy()
    ) {
        let expected: usize = attrs.iter().map(PathAttribute::wire_len).sum();
        prop_assert_eq!(path_attrs_wire_len(&attrs), expected);
    }

    /// Property: wire_len() matches the actual to_wire() output length.
    #[test]
    fn prop_wire_len_matches_to_wire(update in update_strategy()) {
        let expected = update.wire_len();
        let wire = update.to_wire().expect("should encode");
        prop_assert_eq!(
            wire.len(), expected,
            "wire_len() = {} but to_wire() produced {} bytes",
            expected, wire.len()
        );
    }
}
