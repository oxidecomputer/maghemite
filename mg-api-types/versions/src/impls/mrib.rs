// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Proptest `Arbitrary` impls and strategy helpers for the latest MRIB types.

use std::net::{Ipv4Addr, Ipv6Addr};

use client_common::address::{
    IPV4_MULTICAST_RANGE, IPV4_SSM_SUBNET, IPV6_ADMIN_SCOPED_MULTICAST_PREFIX,
    IPV6_MULTICAST_PREFIX, IPV6_SSM_SUBNET,
};
use proptest::prelude::*;
use proptest::strategy::Just;

use crate::latest::mrib::{
    MAX_VNI, MulticastAddr, MulticastAddrV4, MulticastAddrV6,
    MulticastRouteKey, MulticastRouteKeyV4, MulticastRouteKeyV6,
    UnderlayMulticastIpv6, UnicastAddrV4, UnicastAddrV6, Vni,
};

/// Minimum valid IPv6 multicast scope for proptest strategies.
///
/// Scopes 0 (reserved), 1 (interface-local), and 2 (link-local) are
/// rejected by `MulticastAddrV6::new`, so generated addresses start
/// at scope 3 (realm-local).
const MIN_MULTICAST_SCOPE: u8 = 0x3;

/// Maximum valid IPv6 multicast scope for proptest strategies.
///
/// Scope F is reserved (RFC 7346) and rejected by `MulticastAddrV6::new`,
/// so generated addresses stop at scope E (global).
const MAX_MULTICAST_SCOPE: u8 = 0xe;

/// Maximum IPv6 multicast flags value (4 bits).
const MAX_MULTICAST_FLAGS: u8 = 0xf;

/// SSM flags nibble (RFC 4607). SSM addresses have flags = 3.
const SSM_FLAGS: u8 = 0x3;

/// Generate IPv4 unicast addresses suitable as a multicast source.
///
/// Avoids 0/8, 127/8, and the multicast/reserved ranges (224/3 onward).
pub fn ipv4_unicast_strategy() -> impl Strategy<Value = UnicastAddrV4> {
    prop_oneof![
        // 1.x.x.x - 126.x.x.x (skip 0.x.x.x and 127.x.x.x loopback)
        (1u8..=126, any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d)),
        // 128.x.x.x - 223.x.x.x (before multicast range)
        (128u8..=223, any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d)),
    ]
    .prop_filter_map("must be valid unicast", |addr| {
        UnicastAddrV4::new(addr).ok()
    })
}

/// Generate valid [`Vni`] values in `[0, MAX_VNI]`.
pub fn valid_vni_strategy() -> impl Strategy<Value = Vni> {
    (0u32..=MAX_VNI).prop_map(|v| Vni::new(v).expect("VNI is in range"))
}

/// Generate raw u32 values that exceed [`MAX_VNI`], rejected by [`Vni::new`].
pub fn invalid_vni_strategy() -> impl Strategy<Value = u32> {
    (MAX_VNI + 1)..=u32::MAX
}

/// Generate validated underlay multicast addresses within `ff04::/64`.
pub fn admin_local_multicast_strategy()
-> impl Strategy<Value = UnderlayMulticastIpv6> {
    any::<u64>().prop_map(|bits| {
        let addr = Ipv6Addr::new(
            IPV6_ADMIN_SCOPED_MULTICAST_PREFIX,
            0,
            0,
            0,
            (bits >> 48) as u16,
            (bits >> 32) as u16,
            (bits >> 16) as u16,
            bits as u16,
        );
        UnderlayMulticastIpv6::new(addr).expect("valid underlay address")
    })
}

/// Generate IPv6 multicast addresses outside the admin-local scope.
///
/// Scope is restricted to values >= 3 (link-local/interface-local
/// rejected by `MulticastAddrV6::new`) and != admin-local.
pub fn non_admin_local_multicast_strategy()
-> impl Strategy<Value = MulticastAddrV6> {
    // Extract admin-local scope from the constant (0xff04 -> 4)
    let admin_local_scope = (IPV6_ADMIN_SCOPED_MULTICAST_PREFIX & 0xf) as u8;
    // Scope must be valid (3+) and not admin-local
    let scope = prop_oneof![
        Just(MIN_MULTICAST_SCOPE),
        (admin_local_scope + 1)..=MAX_MULTICAST_SCOPE
    ];
    (any::<u8>(), scope, any::<[u16; 7]>()).prop_map(|(flags, scope, segs)| {
        let first = IPV6_MULTICAST_PREFIX
            | ((flags as u16 & MAX_MULTICAST_FLAGS as u16) << 4)
            | (scope as u16);
        MulticastAddrV6::new(Ipv6Addr::new(
            first, segs[0], segs[1], segs[2], segs[3], segs[4], segs[5],
            segs[6],
        ))
        .expect("non-admin-local multicast is valid")
    })
}

/// Generate routable IPv6 unicast addresses (excludes link-local,
/// loopback, unspecified, and multicast).
pub fn routable_ipv6_unicast_strategy() -> impl Strategy<Value = UnicastAddrV6>
{
    any::<u128>().prop_filter_map("must be valid unicast", |bits| {
        UnicastAddrV6::new(Ipv6Addr::from(bits)).ok()
    })
}

/// Generate ASM (non-SSM) IPv4 multicast addresses.
pub fn ipv4_asm_group_strategy() -> impl Strategy<Value = MulticastAddrV4> {
    // Derive range boundaries from constants
    let mcast_base = IPV4_MULTICAST_RANGE.addr().octets()[0];
    let mcast_end = mcast_base + 15; // /4 prefix = 16 values
    let ssm_first = IPV4_SSM_SUBNET.addr().octets()[0];

    // ASM ranges: mcast_base.0.1+ through (ssm_first-1), plus (ssm_first+1)-mcast_end
    prop_oneof![
        // mcast_base.0.1.0 - mcast_base.0.255.255 (skip link-local)
        (1u8..=u8::MAX, any::<u8>()).prop_map(move |(c, d)| {
            MulticastAddrV4::new(Ipv4Addr::new(mcast_base, 0, c, d))
                .expect("mcast_base.0.1+ is valid")
        }),
        // mcast_base.1.0.0 - mcast_base.255.255.255
        (1u8..=u8::MAX, any::<u8>(), any::<u8>()).prop_map(move |(b, c, d)| {
            MulticastAddrV4::new(Ipv4Addr::new(mcast_base, b, c, d))
                .expect("mcast_base.1+ is valid")
        }),
        // (mcast_base+1).x.x.x - (ssm_first-1).x.x.x
        (
            (mcast_base + 1)..=ssm_first - 1,
            any::<u8>(),
            any::<u8>(),
            any::<u8>()
        )
            .prop_map(|(a, b, c, d)| {
                MulticastAddrV4::new(Ipv4Addr::new(a, b, c, d))
                    .expect("pre-SSM ASM is valid")
            }),
        // (ssm_first+1).x.x.x - mcast_end.x.x.x (skip SSM)
        (
            (ssm_first + 1)..=mcast_end,
            any::<u8>(),
            any::<u8>(),
            any::<u8>()
        )
            .prop_map(|(a, b, c, d)| {
                MulticastAddrV4::new(Ipv4Addr::new(a, b, c, d))
                    .expect("post-SSM ASM is valid")
            }),
    ]
}

/// Generate SSM IPv4 multicast addresses (232.x.x.x).
pub fn ipv4_ssm_group_strategy() -> impl Strategy<Value = MulticastAddrV4> {
    let ssm_first_octet = IPV4_SSM_SUBNET.addr().octets()[0];
    (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(move |(b, c, d)| {
        MulticastAddrV4::new(Ipv4Addr::new(ssm_first_octet, b, c, d))
            .expect("SSM range is valid multicast")
    })
}

/// Generate ASM (non-SSM) IPv6 multicast addresses.
pub fn ipv6_asm_group_strategy() -> impl Strategy<Value = MulticastAddrV6> {
    // ASM: ff<flags><scope>:: where flags != SSM_FLAGS, scope in 3-f
    let flags = prop_oneof![
        Just(0x0u8),
        Just(0x1u8),
        Just(0x2u8),
        ((SSM_FLAGS + 1)..=MAX_MULTICAST_FLAGS),
    ];
    (
        flags,
        MIN_MULTICAST_SCOPE..=MAX_MULTICAST_SCOPE,
        any::<[u16; 7]>(),
    )
        .prop_map(|(f, s, segs)| {
            let first = IPV6_MULTICAST_PREFIX | ((f as u16) << 4) | (s as u16);
            MulticastAddrV6::new(Ipv6Addr::new(
                first, segs[0], segs[1], segs[2], segs[3], segs[4], segs[5],
                segs[6],
            ))
            .expect("ASM is valid")
        })
}

/// Generate SSM IPv6 multicast addresses (FF3x::/32).
pub fn ipv6_ssm_group_strategy() -> impl Strategy<Value = MulticastAddrV6> {
    // SSM: ff3<scope>:: where scope in 3-e (realm-local through global). The
    // second segment stays zero per the RFC 4607 FF3x::/32 allocation,
    // matching the SSM classification in `MulticastRouteKey::validate`.
    let ssm_base = IPV6_SSM_SUBNET.addr().segments()[0];
    (MIN_MULTICAST_SCOPE..=MAX_MULTICAST_SCOPE, any::<[u16; 6]>()).prop_map(
        move |(scope, segs)| {
            let first = ssm_base | (scope as u16);
            MulticastAddrV6::new(Ipv6Addr::new(
                first, 0, segs[0], segs[1], segs[2], segs[3], segs[4], segs[5],
            ))
            .expect("SSM is valid")
        },
    )
}

impl Arbitrary for MulticastAddrV4 {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        // Derive range boundaries from constants
        let mcast_base = IPV4_MULTICAST_RANGE.addr().octets()[0];
        let mcast_end = mcast_base + 15; // /4 prefix = 16 values
        let ssm_first = IPV4_SSM_SUBNET.addr().octets()[0];

        // Generate directly in valid multicast ranges for efficiency
        // Valid: 224.0.1.0 - 239.255.255.255 (excluding 224.0.0.x link-local)
        prop_oneof![
            // mcast_base.0.1.0 - mcast_base.0.255.255 (skip link-local)
            (1u8..=u8::MAX, any::<u8>()).prop_map(move |(c, d)| {
                MulticastAddrV4::new(Ipv4Addr::new(mcast_base, 0, c, d))
                    .expect("mcast_base.0.1+ is valid multicast")
            }),
            // mcast_base.1.0.0 - mcast_base.255.255.255
            (1u8..=u8::MAX, any::<u8>(), any::<u8>()).prop_map(
                move |(b, c, d)| {
                    MulticastAddrV4::new(Ipv4Addr::new(mcast_base, b, c, d))
                        .expect("mcast_base.1+ is valid multicast")
                }
            ),
            // (mcast_base+1).x.x.x - (ssm_first-1).x.x.x (globally routable)
            (
                (mcast_base + 1)..=ssm_first - 1,
                any::<u8>(),
                any::<u8>(),
                any::<u8>()
            )
                .prop_map(|(a, b, c, d)| {
                    MulticastAddrV4::new(Ipv4Addr::new(a, b, c, d))
                        .expect("pre-SSM range is valid multicast")
                }),
            // ssm_first.x.x.x (SSM range)
            (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(
                move |(b, c, d)| {
                    MulticastAddrV4::new(Ipv4Addr::new(ssm_first, b, c, d))
                        .expect("SSM is valid")
                }
            ),
            // (ssm_first+1).x.x.x - (mcast_end-1).x.x.x (GLOP, etc.)
            (
                (ssm_first + 1)..=mcast_end - 1,
                any::<u8>(),
                any::<u8>(),
                any::<u8>()
            )
                .prop_map(|(a, b, c, d)| {
                    MulticastAddrV4::new(Ipv4Addr::new(a, b, c, d))
                        .expect("post-SSM range is valid multicast")
                }),
            // mcast_end.x.x.x (admin-scoped)
            (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(
                move |(b, c, d)| {
                    MulticastAddrV4::new(Ipv4Addr::new(mcast_end, b, c, d))
                        .expect("admin-scoped is valid")
                }
            ),
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
        // Valid scopes: 3-e (excluding 0/f=reserved, 1=if-local, 2=link-local)
        // Flags: 0-f (all combinations valid)
        (
            0x0u8..=MAX_MULTICAST_FLAGS,
            MIN_MULTICAST_SCOPE..=MAX_MULTICAST_SCOPE,
            any::<[u16; 7]>(),
        )
            .prop_map(|(flags, scope, segs)| {
                let first_segment = IPV6_MULTICAST_PREFIX
                    | ((flags as u16) << 4)
                    | (scope as u16);
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
                    .expect("scope 3-e with any flags is valid")
            })
            .boxed()
    }
}

impl Arbitrary for MulticastAddr {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<MulticastAddrV4>().prop_map(MulticastAddr::V4),
            any::<MulticastAddrV6>().prop_map(MulticastAddr::V6),
        ]
        .boxed()
    }
}

impl Arbitrary for MulticastRouteKey {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        // Generate directly without filtering for efficiency with high case counts
        let vni = (0u32..=MAX_VNI)
            .prop_map(|v| Vni::new(v).expect("VNI is in range"));

        prop_oneof![
            // V4 ASM (*,G)
            (ipv4_asm_group_strategy(), vni.clone()).prop_map(|(grp, vni)| {
                MulticastRouteKey::V4(MulticastRouteKeyV4 {
                    source: None,
                    group: grp,
                    vni,
                })
            }),
            // V4 ASM (S,G)
            (
                ipv4_unicast_strategy(),
                ipv4_asm_group_strategy(),
                vni.clone()
            )
                .prop_map(|(src, grp, vni)| {
                    MulticastRouteKey::V4(MulticastRouteKeyV4 {
                        source: Some(src),
                        group: grp,
                        vni,
                    })
                }),
            // V4 SSM (S,G) - SSM requires source
            (
                ipv4_unicast_strategy(),
                ipv4_ssm_group_strategy(),
                vni.clone()
            )
                .prop_map(|(src, grp, vni)| {
                    MulticastRouteKey::V4(MulticastRouteKeyV4 {
                        source: Some(src),
                        group: grp,
                        vni,
                    })
                }),
            // V6 ASM (*,G)
            (ipv6_asm_group_strategy(), vni.clone()).prop_map(|(grp, vni)| {
                MulticastRouteKey::V6(MulticastRouteKeyV6 {
                    source: None,
                    group: grp,
                    vni,
                })
            }),
            // V6 ASM (S,G)
            (
                routable_ipv6_unicast_strategy(),
                ipv6_asm_group_strategy(),
                vni.clone()
            )
                .prop_map(|(src, grp, vni)| {
                    MulticastRouteKey::V6(MulticastRouteKeyV6 {
                        source: Some(src),
                        group: grp,
                        vni,
                    })
                }),
            // V6 SSM (S,G) - SSM requires source
            (
                routable_ipv6_unicast_strategy(),
                ipv6_ssm_group_strategy(),
                vni
            )
                .prop_map(|(src, grp, vni)| {
                    MulticastRouteKey::V6(MulticastRouteKeyV6 {
                        source: Some(src),
                        group: grp,
                        vni,
                    })
                }),
        ]
        .boxed()
    }
}
