// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Property-based tests for Prefix types using proptest
//!
//! These tests verify key invariants of the Prefix types to ensure
//! correctness and consistency of prefix operations (excluding wire format
//! tests, which are in bgp/src/proptest.rs since they test BgpWireFormat).

use crate::types::StaticRouteKey;
use mg_api_types::bgp::config::{
    Ipv4UnicastConfig, Ipv6UnicastConfig, Neighbor, NeighborConfig,
};
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

// Strategy for generating valid stored `Neighbor`s.
// Focuses on testing critical fields: nexthop4, nexthop6, and policy variants.
// Uses sensible defaults for non-critical fields (primitives already well-tested by serde).
fn bgp_neighbor_info_strategy() -> impl Strategy<Value = Neighbor> {
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
                Neighbor {
                    asn,
                    group: "test".into(),
                    config: NeighborConfig {
                        name,
                        peer: mg_api_types::bgp::peer::PeerId::Ip(host.ip()),
                        port: None,
                        act_as_a_default_ipv6_router: 0,
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
                        ipv4_unicast: Some(Ipv4UnicastConfig {
                            nexthop: nexthop4,
                            import_policy: allow_import4.into(),
                            export_policy: allow_export4.into(),
                        }),
                        ipv6_unicast: Some(Ipv6UnicastConfig {
                            nexthop: nexthop6,
                            import_policy: allow_import6.into(),
                            export_policy: allow_export6.into(),
                        }),
                        deterministic_collision_resolution: false,
                        idle_hold_jitter: None,
                        connect_retry_jitter: None,
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

    /// Property: a stored `Neighbor` survives JSON serialization/deserialization
    /// round-trip. Now that the dedicated storage twin is gone and the read type
    /// is persisted directly, every config field (including the previously
    /// non-persisted jitter / deterministic-collision fields) round-trips.
    #[test]
    fn prop_bgp_neighbor_info_serialization_roundtrip(neighbor in bgp_neighbor_info_strategy()) {
        // Serialize to JSON (simulating database storage)
        let json = serde_json::to_string(&neighbor)
            .expect("Failed to serialize Neighbor to JSON");

        // Deserialize from JSON (simulating database retrieval)
        let deserialized: Neighbor = serde_json::from_str(&json)
            .expect("Failed to deserialize Neighbor from JSON");

        // The whole value must match after round-trip.
        prop_assert_eq!(
            deserialized, neighbor,
            "Neighbor should survive serialization round-trip"
        );
    }
}
