// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Property-based tests for Prefix types using proptest
//!
//! These tests verify key invariants of the Prefix types to ensure
//! correctness and consistency of prefix operations (excluding wire format
//! tests, which are in bgp/src/proptest.rs since they test BgpWireFormat).

use crate::types::{
    MulticastAddrV4, MulticastAddrV6, MulticastRoute, MulticastRouteKey,
    MulticastSourceProtocol, StaticRouteKey, UnderlayMulticastIpv6,
    UnicastAddrV4, Vni,
};
use client_common::address::{
    IPV4_MULTICAST_RANGE, IPV6_INTERFACE_LOCAL_MULTICAST_SUBNET,
    IPV6_LINK_LOCAL_MULTICAST_SUBNET,
};
use mg_api_types::mrib::{
    admin_local_multicast_strategy, invalid_vni_strategy,
    ipv4_asm_group_strategy, ipv4_ssm_group_strategy, ipv4_unicast_strategy,
    ipv6_asm_group_strategy, ipv6_ssm_group_strategy,
    non_admin_local_multicast_strategy, routable_ipv6_unicast_strategy,
    valid_vni_strategy,
};
use mg_api_types::rdb::neighbor::{BgpNeighborInfo, BgpNeighborParameters};
use mg_api_types_versions::v1::rdb::prefix::{Prefix4, Prefix6};
use mg_api_types_versions::v4::bgp::policy::{
    ImportExportPolicy4, ImportExportPolicy6,
};
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
use proptest::{prelude::*, strategy::Just};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// Strategy for generating valid (normalized) IPv4 prefixes
fn ipv4_prefix_strategy() -> impl Strategy<Value = Ipv4Net> {
    (any::<u32>(), 0u8..=32u8).prop_map(|(addr_bits, length)| {
        let net = Ipv4Net::new_unchecked(Ipv4Addr::from(addr_bits), length);
        Ipv4Net::new_unchecked(net.prefix(), length)
    })
}

// Strategy for generating valid (normalized) IPv6 prefixes
fn ipv6_prefix_strategy() -> impl Strategy<Value = Ipv6Net> {
    (any::<u128>(), 0u8..=128u8).prop_map(|(addr_bits, length)| {
        let net = Ipv6Net::new_unchecked(Ipv6Addr::from(addr_bits), length);
        Ipv6Net::new_unchecked(net.prefix(), length)
    })
}

// Strategy for generating IPv4 prefixes WITH host bits set (unnormalized)
fn ipv4_prefix_with_host_bits_strategy() -> impl Strategy<Value = Ipv4Net> {
    (any::<u32>(), 1u8..=31u8).prop_map(|(addr_bits, length)| {
        // new_unchecked preserves host bits
        Ipv4Net::new_unchecked(Ipv4Addr::from(addr_bits), length)
    })
}

// Strategy for generating IPv6 prefixes WITH host bits set (unnormalized)
fn ipv6_prefix_with_host_bits_strategy() -> impl Strategy<Value = Ipv6Net> {
    (any::<u128>(), 1u8..=127u8).prop_map(|(addr_bits, length)| {
        Ipv6Net::new_unchecked(Ipv6Addr::from(addr_bits), length)
    })
}

// Strategy for generating StaticRouteKey with potentially unnormalized prefixes
fn static_route_key_strategy() -> impl Strategy<Value = StaticRouteKey> {
    (
        prop_oneof![
            ipv4_prefix_with_host_bits_strategy().prop_map(IpNet::V4),
            ipv6_prefix_with_host_bits_strategy().prop_map(IpNet::V6),
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

// Strategy for generating valid SocketAddr for BGP neighbor configuration
fn socket_addr_strategy() -> impl Strategy<Value = SocketAddr> {
    prop_oneof![
        (any::<u32>(), any::<u16>()).prop_map(|(addr_bits, port)| {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr_bits)), port)
        }),
        (any::<u128>(), any::<u16>()).prop_map(|(addr_bits, port)| {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr_bits)), port)
        }),
    ]
}

// Strategy for generating valid v1 Prefix4 (for policy types)
fn v1_prefix4_strategy() -> impl Strategy<Value = Prefix4> {
    (any::<u32>(), 0u8..=32u8).prop_map(|(addr_bits, length)| {
        Prefix4::new(Ipv4Addr::from(addr_bits), length)
    })
}

// Strategy for generating valid v1 Prefix6 (for policy types)
fn v1_prefix6_strategy() -> impl Strategy<Value = Prefix6> {
    (any::<u128>(), 0u8..=128u8).prop_map(|(addr_bits, length)| {
        Prefix6::new(Ipv6Addr::from(addr_bits), length)
    })
}

// Strategy for generating IPv4 import/export policies
fn ipv4_policy_strategy() -> impl Strategy<Value = ImportExportPolicy4> {
    prop_oneof![
        Just(ImportExportPolicy4::NoFiltering),
        // Empty Allow set (tests serialization of empty BTreeSet)
        Just(ImportExportPolicy4::Allow(std::collections::BTreeSet::new())),
        // Allow with one IPv4 prefix
        v1_prefix4_strategy().prop_map(|prefix| {
            let mut set = std::collections::BTreeSet::new();
            set.insert(prefix);
            ImportExportPolicy4::Allow(set)
        }),
        // Allow with multiple IPv4 prefixes
        prop::collection::vec(v1_prefix4_strategy(), 1..5).prop_map(
            |prefixes| {
                let set: std::collections::BTreeSet<_> =
                    prefixes.into_iter().collect();
                ImportExportPolicy4::Allow(set)
            }
        ),
    ]
}

// Strategy for generating IPv6 import/export policies
fn ipv6_policy_strategy() -> impl Strategy<Value = ImportExportPolicy6> {
    prop_oneof![
        Just(ImportExportPolicy6::NoFiltering),
        // Empty Allow set (tests serialization of empty BTreeSet)
        Just(ImportExportPolicy6::Allow(std::collections::BTreeSet::new())),
        // Allow with one IPv6 prefix
        v1_prefix6_strategy().prop_map(|prefix| {
            let mut set = std::collections::BTreeSet::new();
            set.insert(prefix);
            ImportExportPolicy6::Allow(set)
        }),
        // Allow with multiple IPv6 prefixes
        prop::collection::vec(v1_prefix6_strategy(), 1..5).prop_map(
            |prefixes| {
                let set: std::collections::BTreeSet<_> =
                    prefixes.into_iter().collect();
                ImportExportPolicy6::Allow(set)
            }
        ),
    ]
}

// Strategy for generating valid BgpNeighborInfo
// Focuses on testing critical fields: nexthop4, nexthop6, and policy variants.
// Uses sensible defaults for non-critical fields (primitives already well-tested by serde).
fn bgp_neighbor_info_strategy() -> impl Strategy<Value = BgpNeighborInfo> {
    (
        any::<u32>(),            // asn (random)
        any::<String>(), // name (random - tests any JSON-serializable string)
        socket_addr_strategy(), // host (random)
        any::<Option<IpAddr>>(), // nexthop4 (random - critical field)
        any::<Option<IpAddr>>(), // nexthop6 (random - critical field)
        ipv4_policy_strategy(), // allow_import4 (NoFiltering/Allow variants)
        ipv4_policy_strategy(), // allow_export4 (NoFiltering/Allow variants)
        ipv6_policy_strategy(), // allow_import6 (NoFiltering/Allow variants)
        ipv6_policy_strategy(), // allow_export6 (NoFiltering/Allow variants)
    )
        .prop_map(
            |(
                asn,
                name,
                host,
                nexthop4,
                nexthop6,
                allow_import4,
                allow_export4,
                allow_import6,
                allow_export6,
            )| {
                BgpNeighborInfo {
                    asn,
                    name,
                    host,
                    group: "test".into(),
                    parameters: BgpNeighborParameters {
                        hold_time: 90,
                        idle_hold_time: 60,
                        delay_open: 0,
                        connect_retry: 30,
                        keepalive: 30,
                        resolution: 1000,
                        passive: false,
                        remote_asn: Some(65001),
                        min_ttl: Some(1),
                        md5_auth_key: Some("password".to_string()),
                        multi_exit_discriminator: Some(100),
                        communities: vec![],
                        local_pref: Some(100),
                        enforce_first_as: false,
                        ipv4_enabled: true,
                        ipv6_enabled: true,
                        allow_import4,
                        allow_export4,
                        allow_import6,
                        allow_export6,
                        nexthop4,
                        nexthop6,
                        vlan_id: Some(1),
                        src_addr: None,
                        src_port: None,
                    },
                }
            },
        )
}

proptest! {
    /// Property: normalized IPv4 prefix has network address (no host bits)
    #[test]
    fn prop_ipv4_normalized_is_network_address(prefix in ipv4_prefix_strategy()) {
        prop_assert!(
            prefix.is_network_address(),
            "Normalized IPv4 prefix {prefix} should be a network address"
        );
    }

    /// Property: normalized IPv6 prefix has network address (no host bits)
    #[test]
    fn prop_ipv6_normalized_is_network_address(prefix in ipv6_prefix_strategy()) {
        prop_assert!(
            prefix.is_network_address(),
            "Normalized IPv6 prefix {prefix} should be a network address"
        );
    }

    /// Property: IPv4 prefix is always a subnet of itself
    #[test]
    fn prop_ipv4_subnet_of_self(prefix in ipv4_prefix_strategy()) {
        prop_assert!(
            prefix.is_subnet_of(&prefix),
            "IPv4 prefix {prefix} should be a subnet of itself"
        );
    }

    /// Property: IPv6 prefix is always a subnet of itself
    #[test]
    fn prop_ipv6_subnet_of_self(prefix in ipv6_prefix_strategy()) {
        prop_assert!(
            prefix.is_subnet_of(&prefix),
            "IPv6 prefix {prefix} should be a subnet of itself"
        );
    }

    /// Property: IPv4 default route (0.0.0.0/0) contains all IPv4 prefixes
    #[test]
    fn prop_ipv4_default_contains_all(prefix in ipv4_prefix_strategy()) {
        let default = Ipv4Net::new_unchecked(Ipv4Addr::new(0, 0, 0, 0), 0);
        prop_assert!(
            prefix.is_subnet_of(&default),
            "IPv4 prefix {prefix} should be a subnet of default route"
        );
    }

    /// Property: IPv6 default route (::/0) contains all IPv6 prefixes
    #[test]
    fn prop_ipv6_default_contains_all(prefix in ipv6_prefix_strategy()) {
        let default = Ipv6Net::new_unchecked(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0);
        prop_assert!(
            prefix.is_subnet_of(&default),
            "IPv6 prefix {prefix} should be a subnet of default route"
        );
    }

    /// Property: StaticRouteKey normalization is idempotent
    #[test]
    fn prop_static_route_key_normalization_idempotent(route in static_route_key_strategy()) {
        let once = StaticRouteKey {
            prefix: match route.prefix {
                IpNet::V4(n) => IpNet::V4(Ipv4Net::new_unchecked(n.prefix(), n.width())),
                IpNet::V6(n) => IpNet::V6(Ipv6Net::new_unchecked(n.prefix(), n.width())),
            },
            ..route
        };

        let twice = StaticRouteKey {
            prefix: match once.prefix {
                IpNet::V4(n) => IpNet::V4(Ipv4Net::new_unchecked(n.prefix(), n.width())),
                IpNet::V6(n) => IpNet::V6(Ipv6Net::new_unchecked(n.prefix(), n.width())),
            },
            ..once
        };

        prop_assert_eq!(
            once, twice,
            "Normalizing StaticRouteKey twice should be idempotent"
        );
    }

    /// Property: After normalization, prefix is a network address
    #[test]
    fn prop_static_route_key_normalized_is_network_address(route in static_route_key_strategy()) {
        let normalized = StaticRouteKey {
            prefix: match route.prefix {
                IpNet::V4(n) => IpNet::V4(Ipv4Net::new_unchecked(n.prefix(), n.width())),
                IpNet::V6(n) => IpNet::V6(Ipv6Net::new_unchecked(n.prefix(), n.width())),
            },
            ..route
        };

        prop_assert!(
            normalized.prefix.is_network_address(),
            "Normalized StaticRouteKey should have no host bits set"
        );
    }

    /// Property: Normalization preserves prefix length
    #[test]
    fn prop_static_route_key_normalization_preserves_length(route in static_route_key_strategy()) {
        let original_length = route.prefix.width();

        let normalized = StaticRouteKey {
            prefix: match route.prefix {
                IpNet::V4(n) => IpNet::V4(Ipv4Net::new_unchecked(n.prefix(), n.width())),
                IpNet::V6(n) => IpNet::V6(Ipv6Net::new_unchecked(n.prefix(), n.width())),
            },
            ..route
        };

        prop_assert_eq!(
            original_length, normalized.prefix.width(),
            "Normalization should preserve prefix length"
        );
    }

    /// Property: Normalization preserves nexthop, vlan_id, and rib_priority
    #[test]
    fn prop_static_route_key_normalization_preserves_fields(route in static_route_key_strategy()) {
        let normalized = StaticRouteKey {
            prefix: match route.prefix {
                IpNet::V4(n) => IpNet::V4(Ipv4Net::new_unchecked(n.prefix(), n.width())),
                IpNet::V6(n) => IpNet::V6(Ipv6Net::new_unchecked(n.prefix(), n.width())),
            },
            ..route
        };

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

    /// Property: Two routes with the same normalized prefix and same fields are equal
    #[test]
    fn prop_static_route_key_deduplication(
        addr1 in any::<u32>(),
        addr2 in any::<u32>(),
        length in 1u8..=31u8,
        nexthop in any::<u32>(),
        vlan_id in any::<Option<u16>>(),
        rib_priority in any::<u8>(),
    ) {
        let make_normalized = |addr_bits: u32| {
            let net = Ipv4Net::new_unchecked(Ipv4Addr::from(addr_bits), length);
            IpNet::V4(Ipv4Net::new_unchecked(net.prefix(), length))
        };

        let route1 = StaticRouteKey {
            prefix: make_normalized(addr1),
            nexthop: IpAddr::V4(Ipv4Addr::from(nexthop)),
            vlan_id,
            rib_priority,
        };

        let route2 = StaticRouteKey {
            prefix: make_normalized(addr2),
            nexthop: IpAddr::V4(Ipv4Addr::from(nexthop)),
            vlan_id,
            rib_priority,
        };

        // If the normalized prefixes are the same, the entire routes should be equal
        if route1.prefix == route2.prefix {
            prop_assert_eq!(
                route1, route2,
                "Routes with same normalized prefix and same nexthop/vlan/priority should be equal"
            );
        }
    }

    /// Property: StaticRouteKey normalization maintains Ord ordering consistency
    /// (normalized routes can be safely used in BTreeSet)
    #[test]
    fn prop_static_route_key_ord_consistency(route1 in static_route_key_strategy(), route2 in static_route_key_strategy()) {
        let normalize = |r: StaticRouteKey| StaticRouteKey {
            prefix: match r.prefix {
                IpNet::V4(n) => IpNet::V4(Ipv4Net::new_unchecked(n.prefix(), n.width())),
                IpNet::V6(n) => IpNet::V6(Ipv6Net::new_unchecked(n.prefix(), n.width())),
            },
            ..r
        };

        let norm1 = normalize(route1);
        let norm2 = normalize(route2);

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

    /// Property: BgpNeighborInfo survives JSON serialization/deserialization round-trip
    /// This ensures that the nexthop4 and nexthop6 fields (and all other fields) are
    /// correctly preserved when encoding to database and retrieving back.
    #[test]
    fn prop_bgp_neighbor_info_serialization_roundtrip(neighbor in bgp_neighbor_info_strategy()) {
        // Serialize to JSON (simulating database storage)
        let json = serde_json::to_string(&neighbor)
            .expect("Failed to serialize BgpNeighborInfo to JSON");

        // Deserialize from JSON (simulating database retrieval)
        let deserialized: BgpNeighborInfo = serde_json::from_str(&json)
            .expect("Failed to deserialize BgpNeighborInfo from JSON");

        // All fields should match after round-trip
        prop_assert_eq!(
            deserialized.asn, neighbor.asn,
            "ASN should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.name, neighbor.name,
            "Name should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.host, neighbor.host,
            "Host should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.parameters.nexthop4, neighbor.parameters.nexthop4,
            "IPv4 nexthop should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.parameters.nexthop6, neighbor.parameters.nexthop6,
            "IPv6 nexthop should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.parameters.ipv4_enabled, neighbor.parameters.ipv4_enabled,
            "IPv4 enabled flag should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.parameters.ipv6_enabled, neighbor.parameters.ipv6_enabled,
            "IPv6 enabled flag should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.parameters.multi_exit_discriminator, neighbor.parameters.multi_exit_discriminator,
            "MED should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.parameters.local_pref, neighbor.parameters.local_pref,
            "Local preference should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.parameters.remote_asn, neighbor.parameters.remote_asn,
            "Remote ASN should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.parameters.allow_import4, neighbor.parameters.allow_import4,
            "IPv4 import policy should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.parameters.allow_export4, neighbor.parameters.allow_export4,
            "IPv4 export policy should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.parameters.allow_import6, neighbor.parameters.allow_import6,
            "IPv6 import policy should survive serialization round-trip"
        );
        prop_assert_eq!(
            deserialized.parameters.allow_export6, neighbor.parameters.allow_export6,
            "IPv6 export policy should survive serialization round-trip"
        );
    }
}

// Generate IPv6 addresses that are not multicast or loopback.
//
// Returns raw Ipv6Addr, not UnicastAddrV6. Use this for tests that need
// a non-multicast address but don't require a routable unicast source
// (e.g., AF mismatch tests, RPF neighbor fields, multicast addr rejection).
//
// For multicast route key sources, use routable_ipv6_unicast_strategy()
// from mg_api_types::mrib.
fn ipv6_unicast_strategy() -> impl Strategy<Value = Ipv6Addr> {
    // Generate any address except ff00::/8 (multicast) and ::1 (loopback).
    // Multicast is only 1/256 of address space, so filter rejection is fine.
    any::<u128>().prop_filter_map("skip multicast/loopback", |bits| {
        let addr = Ipv6Addr::from(bits);
        if addr.is_multicast() || addr.is_loopback() {
            None
        } else {
            Some(addr)
        }
    })
}

proptest! {
    /// Property: Arbitrary `MulticastAddrV4` always validates
    #[test]
    fn prop_multicast_addr_v4_arbitrary_valid(addr in any::<MulticastAddrV4>()) {
        // Arbitrary impl only generates valid addresses
        prop_assert!(addr.ip().is_multicast());
    }

    /// Property: Arbitrary `MulticastAddrV6` always validates
    #[test]
    fn prop_multicast_addr_v6_arbitrary_valid(addr in any::<MulticastAddrV6>()) {
        // Arbitrary impl only generates valid addresses
        prop_assert!(addr.ip().is_multicast());
    }

    /// Property: IPv4 unicast addresses are rejected as multicast
    #[test]
    fn prop_multicast_addr_v4_rejects_unicast(addr in ipv4_unicast_strategy()) {
        let result = MulticastAddrV4::new(addr.ip());
        prop_assert!(
            result.is_err(),
            "unicast {addr} should be rejected as multicast"
        );
    }

    /// Property: IPv6 unicast addresses are rejected as multicast
    #[test]
    fn prop_multicast_addr_v6_rejects_unicast(addr in ipv6_unicast_strategy()) {
        let result = MulticastAddrV6::new(addr);
        prop_assert!(
            result.is_err(),
            "unicast {addr} should be rejected as multicast"
        );
    }

    /// Property: IPv4 link-local multicast (224.0.0.x) is rejected
    #[test]
    fn prop_multicast_addr_v4_rejects_link_local(last_octet in 0u8..=u8::MAX) {
        let mcast_base = IPV4_MULTICAST_RANGE.addr().octets()[0];
        let addr = Ipv4Addr::new(mcast_base, 0, 0, last_octet);
        let result = MulticastAddrV4::new(addr);
        prop_assert!(
            result.is_err(),
            "link-local {addr} should be rejected"
        );
    }

    /// Property: IPv6 link-local multicast (ff02::/16) is rejected
    #[test]
    fn prop_multicast_addr_v6_rejects_link_local(segs in any::<[u16; 7]>()) {
        let prefix = IPV6_LINK_LOCAL_MULTICAST_SUBNET.addr().segments()[0];
        let link_local = Ipv6Addr::new(
            prefix, segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6],
        );
        let result = MulticastAddrV6::new(link_local);
        prop_assert!(
            result.is_err(),
            "link-local {link_local} should be rejected"
        );
    }

    /// Property: IPv6 interface-local multicast (ff01::/16) is rejected
    #[test]
    fn prop_multicast_addr_v6_rejects_interface_local(segs in any::<[u16; 7]>()) {
        let prefix = IPV6_INTERFACE_LOCAL_MULTICAST_SUBNET.addr().segments()[0];
        let if_local = Ipv6Addr::new(
            prefix, segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6],
        );
        let result = MulticastAddrV6::new(if_local);
        prop_assert!(
            result.is_err(),
            "interface-local {if_local} should be rejected"
        );
    }

    /// Property: `MulticastAddrV4` roundtrip through ip() preserves address
    #[test]
    fn prop_multicast_addr_ip_roundtrip_v4(mcast in any::<MulticastAddrV4>()) {
        let ip = mcast.ip();
        let roundtrip = MulticastAddrV4::new(ip).expect("valid");
        prop_assert_eq!(mcast, roundtrip);
    }

    /// Property: `MulticastAddrV6` roundtrip through ip() preserves address
    #[test]
    fn prop_multicast_addr_ip_roundtrip_v6(mcast in any::<MulticastAddrV6>()) {
        let ip = mcast.ip();
        let roundtrip = MulticastAddrV6::new(ip).expect("valid");
        prop_assert_eq!(mcast, roundtrip);
    }

    /// Property: Arbitrary `MulticastRouteKey` always validates
    #[test]
    fn prop_route_key_arbitrary_valid(key in any::<MulticastRouteKey>()) {
        prop_assert!(
            key.validate().is_ok(),
            "arbitrary key should validate: {key:?}"
        );
    }

    /// Property: (*,G) with ASM group validates (source optional for ASM)
    #[test]
    fn prop_route_key_asm_star_g_valid_v4(group in ipv4_asm_group_strategy()) {
        let key = MulticastRouteKey::any_source(group.into());
        prop_assert!(
            key.validate().is_ok(),
            "(*,G) with ASM {group} should be valid");
    }

    /// Property: (*,G) with ASM group validates (source optional for ASM)
    #[test]
    fn prop_route_key_asm_star_g_valid_v6(group in ipv6_asm_group_strategy()) {
        let key = MulticastRouteKey::any_source(group.into());
        prop_assert!(
            key.validate().is_ok(),
            "(*,G) with ASM {group} should be valid"
        );
    }

    /// Property: (S,G) with unicast source validates (covers ASM and SSM)
    #[test]
    fn prop_route_key_sg_valid_v4(
        src in ipv4_unicast_strategy(),
        group in any::<MulticastAddrV4>(),
    ) {
        let key = MulticastRouteKey::source_specific_v4(src, group);
        prop_assert!(
            key.validate().is_ok(),
            "(S,G) with unicast source {src} should be valid"
        );
    }

    /// Property: (S,G) with unicast source validates (covers ASM and SSM)
    #[test]
    fn prop_route_key_sg_valid_v6(
        src in routable_ipv6_unicast_strategy(),
        group in any::<MulticastAddrV6>(),
    ) {
        let key = MulticastRouteKey::source_specific_v6(src, group);
        prop_assert!(
            key.validate().is_ok(),
            "(S,G) with unicast source {src} should be valid"
        );
    }

    /// Property: SSM without source fails validation (IPv4)
    #[test]
    fn prop_route_key_ssm_requires_source_v4(group in ipv4_ssm_group_strategy()) {
        let key = MulticastRouteKey::any_source(group.into());
        prop_assert!(
            key.validate().is_err(),
            "SSM (*,G) with {group} should require source"
        );
    }

    /// Property: SSM without source fails validation (IPv6)
    #[test]
    fn prop_route_key_ssm_requires_source_v6(group in ipv6_ssm_group_strategy()) {
        let key = MulticastRouteKey::any_source(group.into());
        prop_assert!(
            key.validate().is_err(),
            "SSM (*,G) with {group} should require source"
        );
    }

    /// Property: SSM with source passes validation (IPv4)
    #[test]
    fn prop_route_key_ssm_with_source_valid_v4(
        src in ipv4_unicast_strategy(),
        group in ipv4_ssm_group_strategy(),
    ) {
        let key = MulticastRouteKey::source_specific_v4(src, group);
        prop_assert!(
            key.validate().is_ok(),
            "SSM (S,G) with {src},{group} should be valid"
        );
    }

    /// Property: SSM with source passes validation (IPv6)
    #[test]
    fn prop_route_key_ssm_with_source_valid_v6(
        src in routable_ipv6_unicast_strategy(),
        group in ipv6_ssm_group_strategy(),
    ) {
        let key = MulticastRouteKey::source_specific_v6(src, group);
        prop_assert!(
            key.validate().is_ok(),
            "SSM (S,G) with {src},{group} should be valid"
        );
    }

    /// Property: VNI in valid range passes validation
    #[test]
    fn prop_route_key_valid_vni(
        src in ipv4_unicast_strategy(),
        group in any::<MulticastAddrV4>(),
        vni in valid_vni_strategy(),
    ) {
        // Use (S,G) so both ASM and SSM groups work
        let key = MulticastRouteKey::new(
            Some(IpAddr::V4(src.ip())),
            group.into(),
            vni,
        )
        .expect("valid key construction");
        let result = key.validate();
        prop_assert!(
            result.is_ok(),
            "VNI {vni:?} should be valid: {result:?}"
        );
    }

    /// Property: a VNI outside the 24-bit range is rejected at construction.
    #[test]
    fn prop_vni_rejects_out_of_range(vni in invalid_vni_strategy()) {
        prop_assert!(
            Vni::new(vni).is_err(),
            "VNI {vni} above the 24-bit max should be rejected"
        );
    }

    /// Property: VNI in valid range passes validation (IPv6)
    #[test]
    fn prop_route_key_valid_vni_v6(
        src in routable_ipv6_unicast_strategy(),
        group in any::<MulticastAddrV6>(),
        vni in valid_vni_strategy(),
    ) {
        let key = MulticastRouteKey::new(
            Some(IpAddr::V6(src.ip())),
            group.into(),
            vni,
        )
        .expect("valid key construction");
        let result = key.validate();
        prop_assert!(
            result.is_ok(),
            "VNI {vni:?} should be valid for v6: {result:?}"
        );
    }

    /// Property: Class E reserved (240/4) addresses rejected as unicast
    /// source. Per RFC 1112 Section 4, this range is reserved.
    #[test]
    fn prop_unicast_addr_v4_rejects_class_e(
        a in 240u8..=254,
        b in any::<u8>(),
        c in any::<u8>(),
        d in any::<u8>(),
    ) {
        let addr = Ipv4Addr::new(a, b, c, d);
        prop_assert!(
            UnicastAddrV4::new(addr).is_err(),
            "Class E address {addr} should be rejected"
        );
    }


    /// Property: Route with admin-local underlay group passes validation
    #[test]
    fn prop_route_admin_local_underlay_valid(
        group in ipv4_asm_group_strategy(),
        underlay in admin_local_multicast_strategy(),
    ) {
        let key = MulticastRouteKey::any_source(group.into());
        let route = MulticastRoute::new(
            key,
            underlay,
            MulticastSourceProtocol::Static,
        );
        prop_assert!(
            route.validate().is_ok(),
            "route with admin-local underlay should be valid"
        );
    }

    /// Property: Non-admin-local address is rejected by UnderlayMulticastIpv6
    #[test]
    fn prop_non_admin_local_underlay_rejected(
        underlay in non_admin_local_multicast_strategy(),
    ) {
        prop_assert!(
            UnderlayMulticastIpv6::new(underlay.ip()).is_err(),
            "non-admin-local address {underlay} should be rejected"
        );
    }



}
