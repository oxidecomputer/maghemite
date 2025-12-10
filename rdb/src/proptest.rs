// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Property-based tests for Prefix types using proptest
//!
//! These tests verify key invariants of the Prefix types to ensure
//! correctness and consistency of prefix operations (excluding wire format
//! tests, which are in bgp/src/proptest.rs since they test BgpWireFormat).

use crate::types::{
    DEFAULT_MULTICAST_VNI, MulticastAddr, MulticastAddrV4, MulticastAddrV6,
    MulticastRoute, MulticastRouteKey, MulticastRouteKeyV4,
    MulticastRouteKeyV6, MulticastRouteSource, Prefix, Prefix4, Prefix6,
    StaticRouteKey,
};
use omicron_common::address::{
    IPV4_SSM_SUBNET, IPV6_ADMIN_SCOPED_MULTICAST_PREFIX, IPV6_SSM_SUBNET,
};
use omicron_common::api::external::Vni;
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

// ============================================================================
// Multicast address and route-key property tests and setup
// ============================================================================

// Strategy for generating IPv4 unicast addresses (non-multicast)
fn ipv4_unicast_strategy() -> impl Strategy<Value = Ipv4Addr> {
    any::<u32>().prop_filter_map("must be unicast", |bits| {
        let addr = Ipv4Addr::from(bits);
        if !addr.is_multicast() && !addr.is_broadcast() && !addr.is_loopback() {
            Some(addr)
        } else {
            None
        }
    })
}

// Strategy for generating IPv6 unicast addresses (non-multicast)
fn ipv6_unicast_strategy() -> impl Strategy<Value = Ipv6Addr> {
    any::<u128>().prop_filter_map("must be unicast", |bits| {
        let addr = Ipv6Addr::from(bits);
        if !addr.is_multicast() && !addr.is_loopback() {
            Some(addr)
        } else {
            None
        }
    })
}

// Strategy for generating IPv4 SSM addresses (232.0.0.0/8)
fn ipv4_ssm_strategy() -> impl Strategy<Value = Ipv4Addr> {
    (0u8..=255, 0u8..=255, 0u8..=255)
        .prop_map(|(b, c, d)| Ipv4Addr::new(232, b, c, d))
}

// Strategy for generating IPv6 SSM addresses (ff3x::/32 with various scopes)
fn ipv6_ssm_strategy() -> impl Strategy<Value = Ipv6Addr> {
    // ff30::/12 covers all SSM scopes (ff30::, ff31::, ..., ff3f::)
    (0x30u8..=0x3f, any::<[u16; 7]>()).prop_map(|(scope_nibble, segs)| {
        let first_segment = 0xff00 | (scope_nibble as u16);
        Ipv6Addr::new(
            first_segment,
            segs[0],
            segs[1],
            segs[2],
            segs[3],
            segs[4],
            segs[5],
            segs[6],
        )
    })
}

// Strategy for generating valid VNIs (0 to Vni::MAX_VNI)
fn valid_vni_strategy() -> impl Strategy<Value = u32> {
    0u32..=Vni::MAX_VNI
}

// Strategy for generating invalid VNIs (> Vni::MAX_VNI)
fn invalid_vni_strategy() -> impl Strategy<Value = u32> {
    (Vni::MAX_VNI + 1)..=u32::MAX
}

// Strategy for admin-local scoped IPv6 multicast (ff04::/16)
fn admin_local_multicast_strategy() -> impl Strategy<Value = Ipv6Addr> {
    any::<u128>().prop_map(|bits| {
        let addr = Ipv6Addr::from(bits);
        let segments = addr.segments();
        Ipv6Addr::new(
            IPV6_ADMIN_SCOPED_MULTICAST_PREFIX,
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        )
    })
}

// Strategy for routable IPv6 unicast (not link-local, loopback, unspecified)
fn routable_ipv6_unicast_strategy() -> impl Strategy<Value = Ipv6Addr> {
    any::<u128>().prop_filter_map("must be routable unicast", |bits| {
        let addr = Ipv6Addr::from(bits);
        if !addr.is_multicast()
            && !addr.is_loopback()
            && !addr.is_unspecified()
            && !addr.is_unicast_link_local()
        {
            Some(addr)
        } else {
            None
        }
    })
}

// ============================================================================
// Arbitrary implementations for multicast types
// ============================================================================
//
// These allow using `any::<MulticastAddrV4>()` etc. in property tests,
// generating only valid instances of each type.

/// Strategy for generating valid unicast IPv4 sources.
fn v4_unicast_source_strategy() -> impl Strategy<Value = Ipv4Addr> {
    any::<u32>().prop_filter_map("must be unicast", |bits| {
        let addr = Ipv4Addr::from(bits);
        if addr.is_multicast() || addr.is_broadcast() || addr.is_loopback() {
            None
        } else {
            Some(addr)
        }
    })
}

/// Strategy for generating valid unicast IPv6 sources.
fn v6_unicast_source_strategy() -> impl Strategy<Value = Ipv6Addr> {
    any::<u128>().prop_filter_map("must be unicast", |bits| {
        let addr = Ipv6Addr::from(bits);
        if addr.is_multicast() || addr.is_loopback() {
            None
        } else {
            Some(addr)
        }
    })
}

impl Arbitrary for MulticastAddrV4 {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        // Generate directly in valid multicast ranges for efficiency
        // Valid: 224.0.1.0 - 239.255.255.255 (excluding 224.0.0.x link-local)
        prop_oneof![
            // 224.0.1.0 - 224.255.255.255 (skip 224.0.0.x link-local)
            (0u8..=255, 1u8..=255, any::<u8>()).prop_filter_map(
                "224.0.1+ range",
                |(b, c, d)| {
                    // 224.0.1+ is valid (224.0.0.x is link-local)
                    if b == 0 && c == 0 {
                        return None;
                    }
                    MulticastAddrV4::new(Ipv4Addr::new(224, b, c, d)).ok()
                }
            ),
            // 225.x.x.x - 231.x.x.x (globally routable)
            (225u8..=231, any::<u8>(), any::<u8>(), any::<u8>()).prop_map(
                |(a, b, c, d)| {
                    MulticastAddrV4::new(Ipv4Addr::new(a, b, c, d))
                        .expect("225-231 is valid multicast")
                }
            ),
            // 232.x.x.x (SSM range)
            (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| {
                MulticastAddrV4::new(Ipv4Addr::new(232, b, c, d))
                    .expect("232 is valid SSM")
            }),
            // 233.x.x.x - 238.x.x.x (GLOP, admin-scoped, etc.)
            (233u8..=238, any::<u8>(), any::<u8>(), any::<u8>()).prop_map(
                |(a, b, c, d)| {
                    MulticastAddrV4::new(Ipv4Addr::new(a, b, c, d))
                        .expect("233-238 is valid multicast")
                }
            ),
            // 239.x.x.x (admin-scoped)
            (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| {
                MulticastAddrV4::new(Ipv4Addr::new(239, b, c, d))
                    .expect("239 is valid admin-scoped")
            }),
        ]
        .boxed()
    }
}

impl Arbitrary for MulticastAddrV6 {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        // Generate with all valid flag/scope combinations
        // Format: ff<flags><scope>::
        // Valid scopes: 3-f (excluding 0=reserved, 1=if-local, 2=link-local)
        // Flags: 0-f (all combinations valid)
        (0x0u8..=0xf, 0x3u8..=0xf, any::<[u16; 7]>())
            .prop_map(|(flags, scope, segs)| {
                let first_segment =
                    0xff00 | ((flags as u16) << 4) | (scope as u16);
                let addr = Ipv6Addr::new(
                    first_segment,
                    segs[0],
                    segs[1],
                    segs[2],
                    segs[3],
                    segs[4],
                    segs[5],
                    segs[6],
                );
                MulticastAddrV6::new(addr)
                    .expect("scope 3-f with any flags is valid")
            })
            .boxed()
    }
}

impl Arbitrary for MulticastAddr {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<MulticastAddrV4>().prop_map(crate::types::MulticastAddr::V4),
            any::<MulticastAddrV6>().prop_map(crate::types::MulticastAddr::V6),
        ]
        .boxed()
    }
}

impl Arbitrary for MulticastRouteKey {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        // Split into distinct cases to avoid complex filtering:
        // 1. ASM (*,G) - no source required
        // 2. ASM (S,G) - optional source
        // 3. SSM (S,G) - source required
        let vni_strategy = 0u32..=Vni::MAX_VNI;

        prop_oneof![
            // V4 ASM (*,G): any non-SSM group, no source
            (any::<MulticastAddrV4>(), vni_strategy.clone()).prop_filter_map(
                "ASM v4 (*,G)",
                |(grp, vni)| {
                    if IPV4_SSM_SUBNET.contains(grp.ip()) {
                        return None;
                    }
                    Some(MulticastRouteKey::V4(MulticastRouteKeyV4 {
                        source: None,
                        group: grp,
                        vni,
                    }))
                }
            ),
            // V4 ASM (S,G): any non-SSM group with unicast source
            (
                v4_unicast_source_strategy(),
                any::<MulticastAddrV4>(),
                vni_strategy.clone()
            )
                .prop_filter_map(
                    "ASM v4 (S,G)",
                    |(src, grp, vni)| {
                        if IPV4_SSM_SUBNET.contains(grp.ip()) {
                            return None;
                        }
                        Some(MulticastRouteKey::V4(MulticastRouteKeyV4 {
                            source: Some(src),
                            group: grp,
                            vni,
                        }))
                    }
                ),
            // V4 SSM (S,G): SSM group requires source
            (
                v4_unicast_source_strategy(),
                any::<MulticastAddrV4>(),
                vni_strategy.clone()
            )
                .prop_filter_map(
                    "SSM v4 (S,G)",
                    |(src, grp, vni)| {
                        if !IPV4_SSM_SUBNET.contains(grp.ip()) {
                            return None;
                        }
                        Some(MulticastRouteKey::V4(MulticastRouteKeyV4 {
                            source: Some(src),
                            group: grp,
                            vni,
                        }))
                    }
                ),
            // V6 ASM (*,G): any non-SSM group, no source
            (any::<MulticastAddrV6>(), vni_strategy.clone()).prop_filter_map(
                "ASM v6 (*,G)",
                |(grp, vni)| {
                    if IPV6_SSM_SUBNET.contains(grp.ip()) {
                        return None;
                    }
                    Some(MulticastRouteKey::V6(MulticastRouteKeyV6 {
                        source: None,
                        group: grp,
                        vni,
                    }))
                }
            ),
            // V6 ASM (S,G): any non-SSM group with unicast source
            (
                v6_unicast_source_strategy(),
                any::<MulticastAddrV6>(),
                vni_strategy.clone()
            )
                .prop_filter_map(
                    "ASM v6 (S,G)",
                    |(src, grp, vni)| {
                        if IPV6_SSM_SUBNET.contains(grp.ip()) {
                            return None;
                        }
                        Some(MulticastRouteKey::V6(MulticastRouteKeyV6 {
                            source: Some(src),
                            group: grp,
                            vni,
                        }))
                    }
                ),
            // V6 SSM (S,G): SSM group requires source
            (
                v6_unicast_source_strategy(),
                any::<MulticastAddrV6>(),
                vni_strategy
            )
                .prop_filter_map(
                    "SSM v6 (S,G)",
                    |(src, grp, vni)| {
                        if !IPV6_SSM_SUBNET.contains(grp.ip()) {
                            return None;
                        }
                        Some(MulticastRouteKey::V6(MulticastRouteKeyV6 {
                            source: Some(src),
                            group: grp,
                            vni,
                        }))
                    }
                ),
        ]
        .boxed()
    }
}

proptest! {
    /// Property: Arbitrary `MulticastAddrV4` always validates
    #[test]
    fn prop_multicast_addr_v4_arbitrary_valid(addr in any::<MulticastAddrV4>()) {
        // Arbitrary impl only generates valid addresses
        prop_assert_eq!(addr.ip().is_multicast(), true);
    }

    /// Property: Arbitrary `MulticastAddrV6` always validates
    #[test]
    fn prop_multicast_addr_v6_arbitrary_valid(addr in any::<MulticastAddrV6>()) {
        // Arbitrary impl only generates valid addresses
        prop_assert_eq!(addr.ip().is_multicast(), true);
    }

    /// Property: IPv4 unicast addresses are rejected as multicast
    #[test]
    fn prop_multicast_addr_v4_rejects_unicast(addr in ipv4_unicast_strategy()) {
        let result = MulticastAddrV4::new(addr);
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
    fn prop_multicast_addr_v4_rejects_link_local(last_octet in 0u8..=255) {
        let addr = Ipv4Addr::new(224, 0, 0, last_octet);
        let result = MulticastAddrV4::new(addr);
        prop_assert!(
            result.is_err(),
            "link-local {addr} should be rejected"
        );
    }

    /// Property: IPv6 link-local multicast (ff02::/16) is rejected
    #[test]
    fn prop_multicast_addr_v6_rejects_link_local(segs in any::<[u16; 7]>()) {
        let link_local = Ipv6Addr::new(
            0xff02, segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6],
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
        let if_local = Ipv6Addr::new(
            0xff01, segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6],
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
    fn prop_route_key_asm_star_g_valid_v4(group in any::<MulticastAddrV4>()) {
        prop_assume!(!IPV4_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::any_source(group.into());
        prop_assert!(
            key.validate().is_ok(),
            "(*,G) with ASM {group} should be valid");
    }

    /// Property: (*,G) with ASM group validates (source optional for ASM)
    #[test]
    fn prop_route_key_asm_star_g_valid_v6(group in any::<MulticastAddrV6>()) {
        prop_assume!(!IPV6_SSM_SUBNET.contains(group.ip()));
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
        src in ipv6_unicast_strategy(),
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
    fn prop_route_key_ssm_requires_source_v4(addr in ipv4_ssm_strategy()) {
        let group = MulticastAddrV4::new(addr).expect("valid ssm");
        let key = MulticastRouteKey::any_source(group.into());
        prop_assert!(
            key.validate().is_err(),
            "SSM (*,G) with {addr} should require source"
        );
    }

    /// Property: SSM without source fails validation (IPv6)
    #[test]
    fn prop_route_key_ssm_requires_source_v6(addr in ipv6_ssm_strategy()) {
        // Filter to ensure we have a valid SSM address
        prop_assume!(IPV6_SSM_SUBNET.contains(addr));
        if let Ok(group) = MulticastAddrV6::new(addr) {
            let key = MulticastRouteKey::any_source(group.into());
            prop_assert!(
                key.validate().is_err(),
                "SSM (*,G) with {addr} should require source"
            );
        }
    }

    /// Property: SSM with source passes validation (IPv4)
    #[test]
    fn prop_route_key_ssm_with_source_valid_v4(
        src in ipv4_unicast_strategy(),
        addr in ipv4_ssm_strategy(),
    ) {
        let group = MulticastAddrV4::new(addr).expect("valid ssm");
        let key = MulticastRouteKey::source_specific_v4(src, group);
        prop_assert!(
            key.validate().is_ok(),
            "SSM (S,G) with {src},{addr} should be valid"
        );
    }

    /// Property: SSM with source passes validation (IPv6)
    #[test]
    fn prop_route_key_ssm_with_source_valid_v6(
        src in ipv6_unicast_strategy(),
        addr in ipv6_ssm_strategy(),
    ) {
        prop_assume!(IPV6_SSM_SUBNET.contains(addr));
        if let Ok(group) = MulticastAddrV6::new(addr) {
            let key = MulticastRouteKey::source_specific_v6(src, group);
            prop_assert!(
                key.validate().is_ok(),
                "SSM (S,G) with {src},{addr} should be valid"
            );
        }
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
            Some(IpAddr::V4(src)),
            group.into(),
            vni,
        )
        .expect("valid key construction");
        let result = key.validate();
        prop_assert!(
            result.is_ok(),
            "VNI {vni} should be valid: {result:?}"
        );
    }

    /// Property: VNI exceeding 24 bits fails validation
    #[test]
    fn prop_route_key_invalid_vni(
        src in ipv4_unicast_strategy(),
        group in any::<MulticastAddrV4>(),
        vni in invalid_vni_strategy(),
    ) {
        // Use (S,G) so both ASM and SSM groups work
        let key = MulticastRouteKey::new(
            Some(IpAddr::V4(src)),
            group.into(),
            vni,
        )
        .expect("valid key construction");
        prop_assert!(
            key.validate().is_err(),
            "VNI {vni} should be invalid (> 2^24-1)"
        );
    }

    /// Property: AF mismatch (v4 source, v6 group) rejected at construction
    #[test]
    fn prop_route_key_af_mismatch_v4_v6(
        src in ipv4_unicast_strategy(),
        group in any::<MulticastAddrV6>(),
    ) {
        let result = MulticastRouteKey::new(
            Some(IpAddr::V4(src)),
            group.into(),
            DEFAULT_MULTICAST_VNI,
        );
        prop_assert!(
            result.is_err(),
            "v4 source with v6 group should be rejected"
        );
    }

    /// Property: AF mismatch (v6 source, v4 group) rejected at construction
    #[test]
    fn prop_route_key_af_mismatch_v6_v4(
        src in ipv6_unicast_strategy(),
        group in any::<MulticastAddrV4>(),
    ) {
        let result = MulticastRouteKey::new(
            Some(IpAddr::V6(src)),
            group.into(),
            DEFAULT_MULTICAST_VNI,
        );
        prop_assert!(
            result.is_err(),
            "v6 source with v4 group should be rejected"
        );
    }

    /// Property: Multicast address as source rejected
    #[test]
    fn prop_route_key_multicast_source_rejected_v4(
        src in any::<MulticastAddrV4>(),
        group in any::<MulticastAddrV4>(),
    ) {
        prop_assume!(!IPV4_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::source_specific_v4(src.ip(), group);
        prop_assert!(
            key.validate().is_err(),
            "multicast source {src} should be rejected"
        );
    }

    /// Property: Multicast address as source rejected
    #[test]
    fn prop_route_key_multicast_source_rejected_v6(
        src in any::<MulticastAddrV6>(),
        group in any::<MulticastAddrV6>(),
    ) {
        prop_assume!(!IPV6_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::source_specific_v6(src.ip(), group);
        prop_assert!(
            key.validate().is_err(),
            "multicast source {src} should be rejected"
        );
    }

    /// Property: Route with admin-local underlay group passes validation
    #[test]
    fn prop_route_admin_local_underlay_valid(
        group in any::<MulticastAddrV4>(),
        underlay in admin_local_multicast_strategy(),
    ) {
        prop_assume!(!IPV4_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::any_source(group.into());
        let route = MulticastRoute::new(
            key,
            underlay,
            MulticastRouteSource::Static,
        );
        prop_assert!(
            route.validate().is_ok(),
            "route with admin-local underlay should be valid"
        );
    }

    /// Property: Route with non-admin-local underlay fails validation
    #[test]
    fn prop_route_non_admin_local_underlay_invalid(
        group in any::<MulticastAddrV4>(),
        underlay in any::<MulticastAddrV6>(),
    ) {
        prop_assume!(!IPV4_SSM_SUBNET.contains(group.ip()));
        // Only test if underlay is not already admin-local
        prop_assume!(underlay.ip().segments()[0] != IPV6_ADMIN_SCOPED_MULTICAST_PREFIX);
        let key = MulticastRouteKey::any_source(group.into());
        let route = MulticastRoute::new(
            key,
            underlay.ip(),
            MulticastRouteSource::Static,
        );
        prop_assert!(
            route.validate().is_err(),
            "route with non-admin-local underlay {underlay} should fail"
        );
    }

    /// Property: Unicast RPF neighbor passes validation (v4 group, v4 rpf)
    #[test]
    fn prop_route_unicast_rpf_valid_v4(
        group in any::<MulticastAddrV4>(),
        rpf in ipv4_unicast_strategy(),
        underlay in admin_local_multicast_strategy(),
    ) {
        prop_assume!(!IPV4_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::any_source(group.into());
        let mut route = MulticastRoute::new(
            key,
            underlay,
            MulticastRouteSource::Static,
        );
        route.rpf_neighbor = Some(IpAddr::V4(rpf));
        prop_assert!(
            route.validate().is_ok(),
            "unicast v4 RPF {rpf} should be valid"
        );
    }

    /// Property: Unicast RPF neighbor passes validation (v6 group, v6 rpf)
    #[test]
    fn prop_route_unicast_rpf_valid_v6(
        group in any::<MulticastAddrV6>(),
        rpf in ipv6_unicast_strategy(),
        underlay in admin_local_multicast_strategy(),
    ) {
        prop_assume!(!IPV6_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::any_source(group.into());
        let mut route = MulticastRoute::new(
            key,
            underlay,
            MulticastRouteSource::Static,
        );
        route.rpf_neighbor = Some(IpAddr::V6(rpf));
        prop_assert!(
            route.validate().is_ok(),
            "unicast v6 RPF {rpf} should be valid"
        );
    }

    /// Property: Multicast RPF neighbor fails validation (IPv4)
    #[test]
    fn prop_route_multicast_rpf_invalid_v4(
        group in any::<MulticastAddrV4>(),
        rpf in any::<MulticastAddrV4>(),
        underlay in admin_local_multicast_strategy(),
    ) {
        prop_assume!(!IPV4_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::any_source(group.into());
        let mut route = MulticastRoute::new(
            key,
            underlay,
            MulticastRouteSource::Static,
        );
        route.rpf_neighbor = Some(IpAddr::V4(rpf.ip()));
        prop_assert!(
            route.validate().is_err(),
            "multicast RPF {rpf} should be rejected"
        );
    }

    /// Property: Multicast RPF neighbor fails validation (IPv6)
    #[test]
    fn prop_route_multicast_rpf_invalid_v6(
        group in any::<MulticastAddrV6>(),
        rpf in any::<MulticastAddrV6>(),
        underlay in admin_local_multicast_strategy(),
    ) {
        prop_assume!(!IPV6_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::any_source(group.into());
        let mut route = MulticastRoute::new(
            key,
            underlay,
            MulticastRouteSource::Static,
        );
        route.rpf_neighbor = Some(IpAddr::V6(rpf.ip()));
        prop_assert!(
            route.validate().is_err(),
            "multicast RPF {rpf} should be rejected"
        );
    }

    /// Property: RPF AF mismatch fails validation (v4 rpf, v6 group)
    #[test]
    fn prop_route_rpf_af_mismatch_v4_v6(
        group in any::<MulticastAddrV6>(),
        rpf in ipv4_unicast_strategy(),
        underlay in admin_local_multicast_strategy(),
    ) {
        prop_assume!(!IPV6_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::any_source(group.into());
        let mut route = MulticastRoute::new(
            key,
            underlay,
            MulticastRouteSource::Static,
        );
        route.rpf_neighbor = Some(IpAddr::V4(rpf));
        prop_assert!(
            route.validate().is_err(),
            "v4 RPF with v6 group should be rejected"
        );
    }

    /// Property: RPF AF mismatch fails validation (v6 rpf, v4 group)
    #[test]
    fn prop_route_rpf_af_mismatch_v6_v4(
        group in any::<MulticastAddrV4>(),
        rpf in ipv6_unicast_strategy(),
        underlay in admin_local_multicast_strategy(),
    ) {
        prop_assume!(!IPV4_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::any_source(group.into());
        let mut route = MulticastRoute::new(
            key,
            underlay,
            MulticastRouteSource::Static,
        );
        route.rpf_neighbor = Some(IpAddr::V6(rpf));
        prop_assert!(
            route.validate().is_err(),
            "v6 RPF with v4 group should be rejected"
        );
    }

    /// Property: Routable unicast underlay nexthops pass validation
    #[test]
    fn prop_route_routable_nexthop_valid(
        group in any::<MulticastAddrV4>(),
        nexthop in routable_ipv6_unicast_strategy(),
        underlay in admin_local_multicast_strategy(),
    ) {
        prop_assume!(!IPV4_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::any_source(group.into());
        let mut route = MulticastRoute::new(
            key,
            underlay,
            MulticastRouteSource::Static,
        );
        route.underlay_nexthops.insert(nexthop);
        prop_assert!(
            route.validate().is_ok(),
            "routable nexthop {nexthop} should be valid"
        );
    }

    /// Property: Multicast underlay nexthop fails validation
    #[test]
    fn prop_route_multicast_nexthop_invalid(
        group in any::<MulticastAddrV4>(),
        nexthop in any::<MulticastAddrV6>(),
        underlay in admin_local_multicast_strategy(),
    ) {
        prop_assume!(!IPV4_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::any_source(group.into());
        let mut route = MulticastRoute::new(
            key,
            underlay,
            MulticastRouteSource::Static,
        );
        route.underlay_nexthops.insert(nexthop.ip());
        prop_assert!(
            route.validate().is_err(),
            "multicast nexthop {nexthop} should be rejected"
        );
    }

    /// Property: Link-local underlay nexthop fails validation
    #[test]
    fn prop_route_link_local_nexthop_invalid(
        group in any::<MulticastAddrV4>(),
        segs in any::<[u16; 7]>(),
        underlay in admin_local_multicast_strategy(),
    ) {
        prop_assume!(!IPV4_SSM_SUBNET.contains(group.ip()));
        // Create a link-local address (fe80::/10)
        let link_local = Ipv6Addr::new(
            0xfe80,
            segs[0] & 0x03ff, // Keep only bottom 10 bits for /10
            segs[1], segs[2], segs[3], segs[4], segs[5], segs[6],
        );
        let key = MulticastRouteKey::any_source(group.into());
        let mut route = MulticastRoute::new(
            key,
            underlay,
            MulticastRouteSource::Static,
        );
        route.underlay_nexthops.insert(link_local);
        prop_assert!(
            route.validate().is_err(),
            "link-local nexthop {link_local} should be rejected"
        );
    }

    /// Property: Loopback underlay nexthop fails validation
    #[test]
    fn prop_route_loopback_nexthop_invalid(
        group in any::<MulticastAddrV4>(),
        underlay in admin_local_multicast_strategy(),
    ) {
        prop_assume!(!IPV4_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::any_source(group.into());
        let mut route = MulticastRoute::new(
            key,
            underlay,
            MulticastRouteSource::Static,
        );
        route.underlay_nexthops.insert(Ipv6Addr::LOCALHOST);
        prop_assert!(
            route.validate().is_err(),
            "loopback nexthop should be rejected"
        );
    }

    /// Property: Unspecified underlay nexthop fails validation
    #[test]
    fn prop_route_unspecified_nexthop_invalid(
        group in any::<MulticastAddrV4>(),
        underlay in admin_local_multicast_strategy(),
    ) {
        prop_assume!(!IPV4_SSM_SUBNET.contains(group.ip()));
        let key = MulticastRouteKey::any_source(group.into());
        let mut route = MulticastRoute::new(
            key,
            underlay,
            MulticastRouteSource::Static,
        );
        route.underlay_nexthops.insert(Ipv6Addr::UNSPECIFIED);
        prop_assert!(
            route.validate().is_err(),
            "unspecified nexthop should be rejected"
        );
    }
}
