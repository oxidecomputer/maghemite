// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Property-based tests for MRIB types.
//!
//! Properties stated with `iff` hold bidirectionally: the implementation
//! accepts an input if and only if the spec does.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use client_common::multicast::address::{
    IPV4_MULTICAST_RANGE, IPV4_SSM_SUBNET, IPV6_ADMIN_SCOPED_MULTICAST_PREFIX,
    IPV6_MULTICAST_PREFIX, IPV6_SSM_SUBNETS, is_ssm_address,
};
use client_common::multicast::{OverlayMulticast, UnderlayMulticastError};
use proptest::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use test_strategy::{Arbitrary, proptest};

use crate::latest::mrib::{
    EmbeddedIpv4, InvalidEmbeddedRp, InvalidMulticastSource, MulticastAddr,
    MulticastAddrV4, MulticastAddrV6, MulticastGroupError, MulticastRoute,
    MulticastRouteError, MulticastRouteKey, MulticastSourceError,
    MulticastSourceProtocol, UnderlayMulticastIpv6, UnicastAddrV4,
    UnicastAddrV6, Vni, VniError,
};

/// Usable IPv6 multicast scopes, containing every scope
/// `MulticastAddrV6::new` accepts (3 through f).
const USABLE_MULTICAST_SCOPES: [u8; 13] = [
    0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
];

/// SSM flags nibble (R=0, P=T=1) for `ff3x` addresses (RFC 7371 §4.1.2).
const SSM_FLAGS: u8 = 0x3;

/// Generate a usable IPv6 multicast scope nibble.
fn usable_scope_strategy() -> impl Strategy<Value = u8> {
    proptest::sample::select(&USABLE_MULTICAST_SCOPES[..])
}

/// Generate IPv4 unicast addresses that work as a multicast source.
///
/// This avoids 0/8, 127/8, 169.254/16, and the multicast/reserved ranges
/// (224/3 onward).
fn ipv4_unicast_strategy() -> impl Strategy<Value = UnicastAddrV4> {
    prop_oneof![
        0x0100_0000u32..=0x7eff_ffff,
        0x8000_0000u32..=0xa9fd_ffff,
        0xa9ff_0000u32..=0xdfff_ffff,
    ]
    .prop_map(|bits| {
        UnicastAddrV4::new(Ipv4Addr::from(bits))
            .expect("generated IPv4 source is valid")
    })
}

/// Generate valid `Vni` values in `[0, Vni::MAX_VNI]`.
fn valid_vni_strategy() -> impl Strategy<Value = Vni> {
    (0u32..=Vni::MAX_VNI)
        .prop_map(|value| Vni::new(value).expect("VNI is in range"))
}

/// Generate raw `u32` values that exceed `Vni::MAX_VNI`, which are rejected by
/// `Vni::new`.
fn out_of_range_vni_strategy() -> impl Strategy<Value = u32> {
    (Vni::MAX_VNI + 1)..=u32::MAX
}

/// Generate validated underlay multicast addresses within our internal
/// underlay `ff04::/64` block.
fn admin_local_multicast_strategy()
-> impl Strategy<Value = UnderlayMulticastIpv6> {
    any::<u64>().prop_map(|bits| {
        let addr = Ipv6Addr::from(
            (u128::from(IPV6_ADMIN_SCOPED_MULTICAST_PREFIX) << 112)
                | u128::from(bits),
        );
        UnderlayMulticastIpv6::new(addr).expect("valid underlay address")
    })
}

/// Generate IPv6 multicast addresses outside the admin-local scope.
fn non_admin_local_multicast_strategy() -> impl Strategy<Value = MulticastAddrV6>
{
    // Extract admin-local scope from the constant (0xff04 -> 4). Select
    // from the reduced set rather than filtering: a `prop_filter` rejects one
    // generated value in 13, which exhausts proptest's local-reject budget
    // (`max_local_rejects` ~ 65,536 by default) under high `PROPTEST_CASES`
    // runs.
    let admin_local_scope = (IPV6_ADMIN_SCOPED_MULTICAST_PREFIX & 0xf) as u8;
    let scopes: Vec<u8> = USABLE_MULTICAST_SCOPES
        .iter()
        .copied()
        .filter(|scope| *scope != admin_local_scope)
        .collect();
    let scope = proptest::sample::select(scopes);

    let flags = proptest::sample::select(&[0x0u8, 0x1, 0x3, 0x8, 0x9][..]);
    (flags, scope, any::<[u16; 7]>()).prop_map(|(flags, scope, segs)| {
        // Flags 3 with a zero prefix length would be SSM and subject to
        // the null group-ID rule. Force a nonzero prefix length. The
        // address is then an RFC 3306 unicast-prefix-based ASM address.
        //
        // Flags 0 with all of its remaining segments being zero would be the
        // reserved base address `ff0x::`. The second conditional branch sets
        // a nonzero segment for this case.
        let seg1 = if flags == SSM_FLAGS && segs[0] & 0xff == 0 {
            segs[0] | 0x20
        } else if flags == 0 && segs.iter().all(|seg| *seg == 0) {
            1
        } else {
            segs[0]
        };

        let first =
            IPV6_MULTICAST_PREFIX | ((flags as u16) << 4) | (scope as u16);
        MulticastAddrV6::new(Ipv6Addr::new(
            first, seg1, segs[1], segs[2], segs[3], segs[4], segs[5], segs[6],
        ))
        .expect("non-admin-local multicast is valid")
    })
}

/// Generate IPv6 unicast addresses that `UnicastAddrV6::new` accepts.
fn routable_ipv6_unicast_strategy() -> impl Strategy<Value = UnicastAddrV6> {
    prop_oneof![
        (1u128 << 32)..(0xffffu128 << 32),
        (1u128 << 48)..(0xfe80u128 << 112),
        (0xfec0u128 << 112)..(0xff00u128 << 112),
    ]
    .prop_map(|bits| {
        UnicastAddrV6::new(Ipv6Addr::from(bits))
            .expect("generated IPv6 source is valid")
    })
}

/// Generate ASM (non-SSM) IPv4 multicast addresses.
fn ipv4_asm_group_strategy() -> impl Strategy<Value = MulticastAddrV4> {
    let mcast_base = IPV4_MULTICAST_RANGE.addr().octets()[0];
    let mcast_end = mcast_base + 15; // /4 prefix = 16 values
    let ssm_first = IPV4_SSM_SUBNET.addr().octets()[0];

    // ASM ranges: mcast_base.0.1.0 - (ssm_first-1).255.255.255, plus
    // (ssm_first+1).0.0.0 - mcast_end.255.255.255.
    prop_oneof![
        // mcast_base.0.1.0 - mcast_base.0.255.255 (skip the local network
        // control block)
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

/// Generate SSM IPv4 multicast addresses (232.x.x.x), skipping the first
/// /24, which holds the SSM null address and the addresses reserved for IANA
/// allocation (RFC 4607 §4.3).
fn ipv4_ssm_group_strategy() -> impl Strategy<Value = MulticastAddrV4> {
    let ssm_first_octet = IPV4_SSM_SUBNET.addr().octets()[0];
    prop_oneof![
        // 232.1.0.0 - 232.255.255.255
        (1u8..=u8::MAX, any::<u8>(), any::<u8>()).prop_map(move |(b, c, d)| {
            MulticastAddrV4::new(Ipv4Addr::new(ssm_first_octet, b, c, d))
                .expect("SSM range is valid multicast")
        }),
        // 232.0.1.0 - 232.0.255.255
        (1u8..=u8::MAX, any::<u8>()).prop_map(move |(c, d)| {
            MulticastAddrV4::new(Ipv4Addr::new(ssm_first_octet, 0, c, d))
                .expect("SSM range is valid multicast")
        }),
    ]
}

/// Generate ASM (non-SSM) IPv6 multicast addresses.
fn ipv6_asm_group_strategy() -> impl Strategy<Value = MulticastAddrV6> {
    let non_ssm_flags = proptest::sample::select(&[0x0u8, 0x1, 0x8, 0x9][..]);
    prop_oneof![
        // `ff<flags><scope>::` where flags != `SSM_FLAGS`
        (non_ssm_flags, usable_scope_strategy(), any::<[u16; 7]>()).prop_map(
            |(flags, scope, segs)| {
                let first = IPV6_MULTICAST_PREFIX
                    | ((flags as u16) << 4)
                    | (scope as u16);
                // An admin-local address with zero bits between `ff04` and
                // the /64 boundary would fall in the reserved underlay
                // subnet (`ff04::/64`), which `MulticastAddrV6::new`
                // rejects.
                //
                // Flags 0 with all of its remaining segments being zero
                // would be the reserved base address `ff0x::`. In either case,
                // the conditional sets the second segment to 1.
                let seg1 = if (first == IPV6_ADMIN_SCOPED_MULTICAST_PREFIX
                    && segs[0] == 0
                    && segs[1] == 0
                    && segs[2] == 0)
                    || (flags == 0 && segs.iter().all(|seg| *seg == 0))
                {
                    1
                } else {
                    segs[0]
                };
                MulticastAddrV6::new(Ipv6Addr::new(
                    first, seg1, segs[1], segs[2], segs[3], segs[4], segs[5],
                    segs[6],
                ))
                .expect("ASM is valid")
            }
        ),
        // Use flags 3 with a nonzero prefix length to stay as ASM.
        (
            usable_scope_strategy(),
            (any::<u8>(), 1u8..=u8::MAX),
            any::<[u16; 6]>()
        )
            .prop_map(|(scope, (seg1_high, plen), segs)| {
                let first = IPV6_MULTICAST_PREFIX
                    | ((SSM_FLAGS as u16) << 4)
                    | (scope as u16);
                let seg1 = ((seg1_high as u16) << 8) | (plen as u16);
                MulticastAddrV6::new(Ipv6Addr::new(
                    first, seg1, segs[0], segs[1], segs[2], segs[3], segs[4],
                    segs[5],
                ))
                .expect("RFC 3306 ASM is valid")
            }),
    ]
}

/// Generate SSM IPv6 multicast addresses (`ff3x::/32`).
///
/// Addresses stay within the dynamic range: the prefix bits between the /32
/// boundary and the 32-bit group ID are zero, and the group ID is at least
/// `0x80000000` (RFC 3307 §4.3). This also avoids the null address
/// `ff3x::4000:0` that `MulticastAddrV6::new` rejects (RFC 4607 §4.3).
fn ipv6_ssm_group_strategy() -> impl Strategy<Value = MulticastAddrV6> {
    let ssm_base = IPV6_SSM_SUBNETS[0].addr().segments()[0];
    (usable_scope_strategy(), 0x8000u16..=u16::MAX, any::<u16>()).prop_map(
        move |(scope, id_hi, id_lo)| {
            let first = ssm_base | (scope as u16);
            MulticastAddrV6::new(Ipv6Addr::new(
                first, 0, 0, 0, 0, 0, id_hi, id_lo,
            ))
            .expect("allocatable SSM is valid")
        },
    )
}

/// Generate valid IPv4 multicast groups (ASM or SSM).
fn multicast_addr_v4_strategy() -> impl Strategy<Value = MulticastAddrV4> {
    prop_oneof![ipv4_asm_group_strategy(), ipv4_ssm_group_strategy()]
}

/// Generate valid IPv6 multicast groups (ASM or SSM).
fn multicast_addr_v6_strategy() -> impl Strategy<Value = MulticastAddrV6> {
    prop_oneof![ipv6_asm_group_strategy(), ipv6_ssm_group_strategy()]
}

/// Generate valid route keys of each IP address family: ASM (*,G), ASM
/// (S,G), and SSM (S,G).
fn multicast_route_key_strategy() -> impl Strategy<Value = MulticastRouteKey> {
    let parts = prop_oneof![
        2 => (
            proptest::option::of(ipv4_unicast_strategy()),
            ipv4_asm_group_strategy(),
        )
            .prop_map(|(src, grp)| {
                (src.map(IpAddr::from), MulticastAddr::from(grp))
            }),
        1 => (ipv4_unicast_strategy(), ipv4_ssm_group_strategy())
            .prop_map(|(src, grp)| {
                (Some(IpAddr::from(src)), MulticastAddr::from(grp))
            }),
        2 => (
            proptest::option::of(routable_ipv6_unicast_strategy()),
            ipv6_asm_group_strategy(),
        )
            .prop_map(|(src, grp)| {
                (src.map(IpAddr::from), MulticastAddr::from(grp))
            }),
        1 => (routable_ipv6_unicast_strategy(), ipv6_ssm_group_strategy())
            .prop_map(|(src, grp)| {
                (Some(IpAddr::from(src)), MulticastAddr::from(grp))
            }),
    ];
    (parts, valid_vni_strategy()).prop_map(|((source, group), vni)| {
        MulticastRouteKey::new(source, group, vni)
            .expect("generated route key parts are valid")
    })
}

/// Property: `MulticastRouteKey::new` rebuilds a key from its accessors, and
/// the key sustains across a JSON round trip
#[proptest]
fn prop_route_key_parts_roundtrip(
    #[strategy(multicast_route_key_strategy())] key: MulticastRouteKey,
) {
    prop_assert_eq!(
        MulticastRouteKey::new(key.source(), key.group(), key.vni()),
        Ok(key)
    );
    prop_assert_eq!(json_roundtrip(&key)?, key);
}

/// Property: `source_specific_v4` agrees with `new` (covers ASM and SSM)
#[proptest]
fn prop_route_key_sg_valid_v4(
    #[strategy(ipv4_unicast_strategy())] src: UnicastAddrV4,
    #[strategy(multicast_addr_v4_strategy())] group: MulticastAddrV4,
) {
    prop_assert_eq!(
        MulticastRouteKey::new(
            Some(IpAddr::from(src)),
            group.into(),
            Vni::DEFAULT_MULTICAST,
        ),
        Ok(MulticastRouteKey::source_specific_v4(src, group))
    );
}

/// Property: `source_specific_v6` agrees with `new` (covers ASM and SSM)
#[proptest]
fn prop_route_key_sg_valid_v6(
    #[strategy(routable_ipv6_unicast_strategy())] src: UnicastAddrV6,
    #[strategy(multicast_addr_v6_strategy())] group: MulticastAddrV6,
) {
    prop_assert_eq!(
        MulticastRouteKey::new(
            Some(IpAddr::from(src)),
            group.into(),
            Vni::DEFAULT_MULTICAST,
        ),
        Ok(MulticastRouteKey::source_specific_v6(src, group))
    );
}

/// Property: a VNI outside the 24-bit range is rejected at construction
#[proptest]
fn prop_vni_rejects_out_of_range(
    #[strategy(out_of_range_vni_strategy())] vni: u32,
) {
    prop_assert_eq!(Vni::new(vni), Err(VniError::OutOfRange { value: vni }));
}

/// Property: a route with an admin-local underlay group sustains across a
/// JSON round trip
#[proptest]
fn prop_route_serde_roundtrip(
    #[strategy(multicast_route_key_strategy())] key: MulticastRouteKey,
    #[strategy(admin_local_multicast_strategy())]
    underlay: UnderlayMulticastIpv6,
) {
    let route =
        MulticastRoute::new(key, underlay, MulticastSourceProtocol::Static);
    prop_assert_eq!(json_roundtrip(&route)?, route);
}

/// Property: a non-admin-local address is rejected by `UnderlayMulticastIpv6`
#[proptest]
fn prop_non_admin_local_underlay_rejected(
    #[strategy(non_admin_local_multicast_strategy())] underlay: MulticastAddrV6,
) {
    let addr = underlay.ip();
    prop_assert_eq!(
        UnderlayMulticastIpv6::new(addr),
        Err(UnderlayMulticastError::NotInSubnet { addr })
    );
}

/// Spec for SSM classification per RFC 4607 §1 and RFC 7371 §4.1.2.
fn spec_is_ssm(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.octets()[0] == 232,
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let flags = (bits >> 116) & 0xf;
            let plen = (bits >> 96) & 0xff;
            bits >> 120 == 0xff && flags & 0x7 == 0x3 && plen == 0
        }
    }
}

/// Spec for an IPv4 group per RFC 1112 §4 and RFC 4607 §4.3.
fn spec_group_v4(addr: Ipv4Addr) -> Result<(), MulticastGroupError> {
    let ip = IpAddr::V4(addr);
    if addr.octets()[0] & 0xf0 != 0xe0 {
        return Err(MulticastGroupError::NotMulticast(ip));
    }
    if addr.octets() == [224, 0, 0, 0] {
        return Err(MulticastGroupError::ReservedBaseAddress(ip));
    }
    if addr.octets() == [232, 0, 0, 0] {
        return Err(MulticastGroupError::ReservedSsmNull(ip));
    }
    Ok(())
}

/// Spec for the RP address embedded in a group per RFC 3956 §3 and §4.
fn spec_embedded_rp(addr: Ipv6Addr, plen: u32, riid: u16) -> Ipv6Addr {
    let prefix = (u128::from(addr) >> 32) as u64;
    let mask = if plen == 0 {
        0
    } else {
        u64::MAX << (64 - plen)
    };
    Ipv6Addr::from((u128::from(prefix & mask) << 64) | u128::from(riid))
}

/// Spec for a usable RP address per RFC 3956 §4 and §10.
fn spec_rp_usable(rp: Ipv6Addr) -> bool {
    rp.segments()[0] != 0 && !rp.is_unicast_link_local() && !rp.is_multicast()
}

/// Spec for an IPv6 group per RFC 4291 §2.7, RFC 3306 §4, RFC 3956 §3,
/// RFC 4607 §4.3, and RFC 7371 §4, plus the Oxide `ff04::/64` internal
/// underlay reservation.
fn spec_group_v6(addr: Ipv6Addr) -> Result<(), MulticastGroupError> {
    let ip = IpAddr::V6(addr);
    let bits = u128::from(addr);
    if bits >> 120 != 0xff {
        return Err(MulticastGroupError::NotMulticast(ip));
    }
    match (bits >> 112) & 0xf {
        0 => return Err(MulticastGroupError::ReservedIpv6Scope(ip)),
        1 | 2 => return Err(MulticastGroupError::LocalIpv6Scope(ip)),
        _ => {}
    }
    if bits >> 64 == 0xff04_0000_0000_0000 {
        return Err(MulticastGroupError::ReservedUnderlaySubnet(ip));
    }
    let flags = (bits >> 116) & 0xf;
    if flags == 0 && bits & ((1u128 << 112) - 1) == 0 {
        return Err(MulticastGroupError::ReservedBaseAddress(ip));
    }
    let r_flag = flags & 0x4 != 0;
    let p_flag = flags & 0x2 != 0;
    let t_flag = flags & 0x1 != 0;
    let plen = ((bits >> 96) & 0xff) as u32;
    let riid = ((bits >> 104) & 0xf) as u16;
    let rp_err = |reason| {
        Err(MulticastGroupError::MalformedEmbeddedRp { addr: ip, reason })
    };

    if r_flag {
        if !p_flag {
            return rp_err(InvalidEmbeddedRp::RequiresPrefixBased);
        }
        if !t_flag {
            return rp_err(InvalidEmbeddedRp::RequiresTransient);
        }
        if !(1..=64).contains(&plen) {
            return rp_err(InvalidEmbeddedRp::PrefixLengthOutOfRange(
                plen as u8,
            ));
        }
        if riid == 0 {
            return rp_err(InvalidEmbeddedRp::ZeroInterfaceId);
        }
        let rp = spec_embedded_rp(addr, plen, riid);
        if !spec_rp_usable(rp) {
            return rp_err(InvalidEmbeddedRp::UnusableAddress(rp));
        }
    } else if p_flag && !t_flag {
        return Err(MulticastGroupError::MalformedPrefixBased { addr: ip });
    }

    let network_prefix = (bits >> 32) as u64;
    let group_id = bits as u32;
    if spec_is_ssm(ip) && network_prefix == 0 && group_id == 0x4000_0000 {
        return Err(MulticastGroupError::InvalidIpv6Ssm(ip));
    }
    Ok(())
}

/// Spec for the Oxide underlay multicast subnet `ff04::/64`.
fn spec_underlay(addr: Ipv6Addr) -> bool {
    u128::from(addr) >> 64 == 0xff04_0000_0000_0000
}

/// Spec for an IPv4 (S,G) source per RFC 919 §7, RFC 1122 §3.2.1.3,
/// RFC 3927, and RFC 6890.
fn spec_source_v4(addr: Ipv4Addr) -> Result<(), MulticastSourceError> {
    let octets = addr.octets();
    if octets[0] & 0xf0 == 0xe0 {
        return Err(MulticastSourceError::NotUnicast(IpAddr::V4(addr)));
    }
    let reason = match octets {
        [0, 0, 0, 0] => InvalidMulticastSource::Unspecified,
        [127, ..] => InvalidMulticastSource::Loopback,
        [255, 255, 255, 255] => InvalidMulticastSource::Broadcast,
        [169, 254, ..] => InvalidMulticastSource::LinkLocal,
        [0, ..] => InvalidMulticastSource::ThisNetwork,
        [240..=255, ..] => InvalidMulticastSource::Reserved,
        _ => return Ok(()),
    };
    Err(MulticastSourceError::InvalidIpv4 { addr, reason })
}

/// Spec for an IPv6 (S,G) source per RFC 4291 §2.5.
fn spec_source_v6(addr: Ipv6Addr) -> Result<(), MulticastSourceError> {
    if u128::from(addr) >> 120 == 0xff {
        return Err(MulticastSourceError::NotUnicast(IpAddr::V6(addr)));
    }
    let embedded =
        |form| Err(MulticastSourceError::Ipv4Embedded { addr, form });
    let reason = match addr.segments() {
        [0, 0, 0, 0, 0, 0, 0, 0] => InvalidMulticastSource::Unspecified,
        [0, 0, 0, 0, 0, 0, 0, 1] => InvalidMulticastSource::Loopback,
        [0xfe80..=0xfebf, ..] => InvalidMulticastSource::LinkLocal,
        [0, 0, 0, 0, 0, 0xffff, ..] => return embedded(EmbeddedIpv4::Mapped),
        [0, 0, 0, 0, 0, 0, ..] => return embedded(EmbeddedIpv4::Compatible),
        _ => return Ok(()),
    };
    Err(MulticastSourceError::InvalidIpv6 { addr, reason })
}

fn outcome<T, E>(res: &Result<T, E>) -> Result<(), &E> {
    res.as_ref().map(drop)
}

/// Serialize to JSON and deserialize back.
fn json_roundtrip<T: Serialize + DeserializeOwned>(
    value: &T,
) -> Result<T, serde_json::Error> {
    serde_json::from_str(&serde_json::to_string(value)?)
}

/// Whether `T` deserializes from the JSON encoding of `candidate`.
fn json_accepts<T: DeserializeOwned>(candidate: &impl Serialize) -> bool {
    serde_json::to_string(candidate)
        .and_then(|json| serde_json::from_str::<T>(&json))
        .is_ok()
}

/// Generate candidate IPv4 bits biased toward 224/4, 224.0.0.0, 232.0.0.0,
/// and the class E block above 224/4.
fn group_v4_candidate_strategy() -> impl Strategy<Value = u32> {
    prop_oneof![
        any::<u32>(),
        // 224.0.0.0/4, multicast
        0xe000_0000u32..=0xefff_ffff,
        // 224.0.0.0, reserved base address
        Just(0xe000_0000u32),
        // 232.0.0.0, SSM null address
        Just(0xe800_0000u32),
        // 224.0.0.0/24, local network control block
        0xe000_0000u32..=0xe000_00ff,
        // 232.0.0.0/24, SSM block reserved for IANA allocation
        0xe800_0000u32..=0xe800_00ff,
        // 240.0.0.0/4, class E
        0xf000_0000u32..=u32::MAX,
    ]
}

/// Generate an IPv6 group from independently chosen flags, scope, `rsvd`,
/// RIID, prefix length, network prefix, and group ID fields.
#[derive(Debug, Arbitrary)]
struct GroupV6Case {
    #[strategy(0u16..=0xf)]
    flags: u16,
    #[strategy(0u16..=0xf)]
    scope: u16,
    #[strategy(0u16..=0xf)]
    rsvd: u16,
    #[strategy(0u16..=0xf)]
    riid: u16,
    #[strategy(prop_oneof![Just(0u16), 1u16..=64, 65u16..=255])]
    plen: u16,
    #[strategy(prop_oneof![Just([0u16; 4]), any::<[u16; 4]>()])]
    prefix: [u16; 4],
    #[strategy(prop_oneof![Just(0x4000_0000u32), Just(0u32), any::<u32>()])]
    group_id: u32,
}

impl GroupV6Case {
    fn addr(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            0xff00 | (self.flags << 4) | self.scope,
            (self.rsvd << 12) | (self.riid << 8) | self.plen,
            self.prefix[0],
            self.prefix[1],
            self.prefix[2],
            self.prefix[3],
            (self.group_id >> 16) as u16,
            self.group_id as u16,
        )
    }
}

/// Generate an embedded-RP group (i.e., R, P, and T flags set) whose derived RP
/// address is biased toward the `::/16`, link-local, and multicast boundaries
/// of `spec_rp_usable`, with the RP interface ID biased toward zero.
#[derive(Debug, Arbitrary)]
struct EmbeddedRpCase {
    #[strategy(proptest::sample::select(&[0x7u16, 0xf][..]))]
    flags: u16,
    #[strategy(usable_scope_strategy())]
    scope: u8,
    #[strategy(0u16..=0xf)]
    rsvd: u16,
    #[strategy(prop_oneof![Just(0u16), 1u16..=0xf])]
    riid: u16,
    #[strategy(1u16..=64)]
    plen: u16,
    #[strategy(prop_oneof![
        Just(0u16),
        0xfe00u16..=0xfe7f,
        0xfe80u16..=0xfebf,
        0xfec0u16..=0xfeff,
        0xff00u16..=0xffff,
        any::<u16>(),
    ])]
    prefix_first: u16,
    prefix_rest: [u16; 3],
    group_id: u32,
}

impl EmbeddedRpCase {
    fn addr(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            0xff00 | (self.flags << 4) | u16::from(self.scope),
            (self.rsvd << 12) | (self.riid << 8) | self.plen,
            self.prefix_first,
            self.prefix_rest[0],
            self.prefix_rest[1],
            self.prefix_rest[2],
            (self.group_id >> 16) as u16,
            self.group_id as u16,
        )
    }
}

/// Generate candidate IPv6 addresses biased toward the group rules:
/// independent fields, embedded RP, `ff04::/64` (including `ff04::`, which
/// is also a base address), the `ff0x::` base addresses, and the SSM null
/// addresses `ff3x::4000:0` and `ffbx::4000:0`.
fn group_v6_candidate_strategy() -> impl Strategy<Value = Ipv6Addr> {
    prop_oneof![
        6 => any::<GroupV6Case>().prop_map(|case| case.addr()),
        2 => any::<EmbeddedRpCase>().prop_map(|case| case.addr()),
        1 => any::<u64>().prop_map(|low| {
            Ipv6Addr::from((0xff04u128 << 112) | u128::from(low))
        }),
        1 => Just(Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 0)),
        1 => (0u16..=0xf).prop_map(|scope| {
            Ipv6Addr::new(0xff00 | scope, 0, 0, 0, 0, 0, 0, 0)
        }),
        1 => (proptest::sample::select(&[0x3u16, 0xb][..]), 0u16..=0xf)
            .prop_map(|(flags, scope)| {
                Ipv6Addr::new(
                    0xff00 | (flags << 4) | scope,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0x4000,
                    0,
                )
            }),
        1 => any::<u128>().prop_map(Ipv6Addr::from),
    ]
}

/// Generate candidate IPv4 bits biased toward the source rule blocks.
fn source_v4_candidate_strategy() -> impl Strategy<Value = u32> {
    prop_oneof![
        any::<u32>(),
        // 0.0.0.0/8 -> this host on this network
        0u32..=0x00ff_ffff,
        // 0.0.0.0, unspecified
        Just(0u32),
        // 127.0.0.0/8, loopback
        0x7f00_0000u32..=0x7fff_ffff,
        // 169.254.0.0/16, link-local
        0xa9fe_0000u32..=0xa9fe_ffff,
        // 240.0.0.0/4, class E
        0xf000_0000u32..=u32::MAX,
        // 255.255.255.255, limited broadcast
        Just(u32::MAX),
        // 224.0.0.0/4, multicast
        0xe000_0000u32..=0xefff_ffff,
        // 10.0.0.0/8, private (RFC 1918) and accepted
        0x0a00_0000u32..=0x0aff_ffff,
    ]
}

/// Generate candidate IPv6 addresses biased toward the source rule blocks.
fn source_v6_candidate_strategy() -> impl Strategy<Value = Ipv6Addr> {
    prop_oneof![
        any::<u128>(),
        // `::`, unspecified
        Just(0u128),
        // `::1`, loopback
        Just(1u128),
        // `fe80::/10`, link-local
        any::<u128>().prop_map(|bits| (0xfe80u128 << 112) | (bits >> 10)),
        // `::ffff:0:0/96`, IPv4-mapped
        any::<u32>().prop_map(|ipv4| (0xffffu128 << 32) | u128::from(ipv4)),
        // `::/96`, IPv4-compatible
        any::<u32>().prop_map(u128::from),
        // `ff00::/8`, multicast
        any::<u128>().prop_map(|bits| (0xffu128 << 120) | (bits >> 8)),
        // `fc00::/7`, unique local (RFC 4193) and accepted
        any::<u128>().prop_map(|bits| (0xfcu128 << 120) | (bits >> 7)),
        // `64:ff9b::/96`, NAT64 well-known prefix (RFC 6052) and accepted
        any::<u32>().prop_map(|ipv4| (0x64_ff9bu128 << 96) | u128::from(ipv4)),
    ]
    .prop_map(Ipv6Addr::from)
}

/// Generate addresses biased toward the SSM ranges and their flag and
/// prefix-length neighbors.
fn ssm_candidate_strategy() -> impl Strategy<Value = IpAddr> {
    let flags = prop_oneof![Just(0x3u16), Just(0xbu16), 0u16..=0xf];
    let plen = prop_oneof![Just(0u16), 0u16..=0xff];
    prop_oneof![
        any::<u32>().prop_map(|bits| IpAddr::V4(Ipv4Addr::from(bits))),
        (0u32..=0x00ff_ffff)
            .prop_map(|low| IpAddr::V4(Ipv4Addr::from(0xe800_0000 | low))),
        (flags, 0u16..=0xf, any::<u8>(), plen, any::<[u16; 6]>()).prop_map(
            |(flags, scope, seg1_high, plen, segs)| {
                IpAddr::V6(Ipv6Addr::new(
                    0xff00 | (flags << 4) | scope,
                    (u16::from(seg1_high) << 8) | plen,
                    segs[0],
                    segs[1],
                    segs[2],
                    segs[3],
                    segs[4],
                    segs[5],
                ))
            }
        ),
        any::<u128>().prop_map(|bits| IpAddr::V6(Ipv6Addr::from(bits))),
    ]
}

/// Generate candidate VNI values on both sides of the 24-bit bound.
fn vni_candidate_strategy() -> impl Strategy<Value = u32> {
    prop_oneof![
        0u32..=Vni::MAX_VNI,
        (Vni::MAX_VNI + 1)..=u32::MAX,
        Just(Vni::MAX_VNI),
        Just(Vni::MAX_VNI + 1),
    ]
}

/// Generate candidate IPv6 addresses inside, near, and outside `ff04::/64`.
fn underlay_candidate_strategy() -> impl Strategy<Value = Ipv6Addr> {
    prop_oneof![
        any::<u64>().prop_map(|low| (0xff04u128 << 112) | u128::from(low)),
        (1u64..(1 << 48), any::<u64>()).prop_map(|(mid, low)| {
            (0xff04u128 << 112) | (u128::from(mid) << 64) | u128::from(low)
        }),
        (any::<u16>(), any::<u64>()).prop_map(|(first, low)| {
            (u128::from(first) << 112) | u128::from(low)
        }),
        any::<u128>(),
    ]
    .prop_map(Ipv6Addr::from)
}

/// Generate IPv6 SSM groups in `ff3x` and `ffbx`, including nonzero `ff2`
/// and `rsvd` nibbles.
fn ipv6_ssm_wide_group_strategy() -> impl Strategy<Value = MulticastAddrV6> {
    (
        proptest::sample::select(&[0x3u16, 0xb][..]),
        usable_scope_strategy(),
        any::<u8>(),
        any::<[u16; 6]>(),
    )
        .prop_map(|(flags, scope, seg1_high, mut segs)| {
            // A zero network prefix with group ID `4000:0` is the SSM null
            // address (RFC 4607 §4.3), which `MulticastAddrV6::new` rejects.
            //
            // We remap it here because `group_v6_candidate_strategy` still
            // generates it for the rejection properties.
            if segs == [0, 0, 0, 0, 0x4000, 0] {
                segs[5] = 1;
            }
            MulticastAddrV6::new(Ipv6Addr::new(
                0xff00 | (flags << 4) | u16::from(scope),
                u16::from(seg1_high) << 8,
                segs[0],
                segs[1],
                segs[2],
                segs[3],
                segs[4],
                segs[5],
            ))
            .expect("wide SSM is valid")
        })
}

/// Generate candidate route key sources of either IP address family,
/// including invalid sources.
fn route_key_source_candidate_strategy() -> impl Strategy<Value = IpAddr> {
    let invalid_v4 = prop_oneof![
        // 127.0.0.0/8, loopback
        0x7f00_0000u32..=0x7fff_ffff,
        // 169.254.0.0/16, link-local
        0xa9fe_0000u32..=0xa9fe_ffff,
        // 224.0.0.0/4, multicast
        0xe000_0000u32..=0xefff_ffff,
        // 240.0.0.0/4, class E
        0xf000_0000u32..=u32::MAX,
    ]
    .prop_map(Ipv4Addr::from);

    let invalid_v6 = prop_oneof![
        // `::1`, loopback
        Just(1u128),
        // `fe80::/10`, link-local
        any::<u128>().prop_map(|bits| (0xfe80u128 << 112) | (bits >> 10)),
        // `ff00::/8`, multicast
        any::<u128>().prop_map(|bits| (0xffu128 << 120) | (bits >> 8)),
        // `::ffff:0:0/96`, IPv4-mapped
        any::<u32>().prop_map(|ipv4| (0xffffu128 << 32) | u128::from(ipv4)),
    ]
    .prop_map(Ipv6Addr::from);

    prop_oneof![
        3 => ipv4_unicast_strategy().prop_map_into::<IpAddr>(),
        1 => invalid_v4.prop_map_into::<IpAddr>(),
        3 => routable_ipv6_unicast_strategy().prop_map_into::<IpAddr>(),
        1 => invalid_v6.prop_map_into::<IpAddr>(),
    ]
}

/// Generate valid groups of either IP address family (ASM or SSM), including
/// `ffbx` and nonzero-`rsvd` SSM groups.
fn route_key_group_candidate_strategy() -> impl Strategy<Value = MulticastAddr>
{
    prop_oneof![
        2 => multicast_addr_v4_strategy().prop_map_into::<MulticastAddr>(),
        2 => multicast_addr_v6_strategy().prop_map_into::<MulticastAddr>(),
        1 => ipv6_ssm_wide_group_strategy().prop_map_into::<MulticastAddr>(),
    ]
}

/// Spec for route key construction.
///
/// A missing source is rejected for SSM groups (RFC 4607 §2), whereas a
/// present source is checked against the source rules and then against the
/// group's IP address family.
fn spec_route_key(
    source: Option<IpAddr>,
    group: MulticastAddr,
) -> Result<(), MulticastRouteError> {
    let Some(src) = source else {
        if spec_is_ssm(group.ip()) {
            return Err(MulticastRouteError::SsmRequiresSource {
                group: group.ip(),
            });
        }
        return Ok(());
    };
    match src {
        IpAddr::V4(s) => spec_source_v4(s)?,
        IpAddr::V6(s) => spec_source_v6(s)?,
    }
    if src.is_ipv4() != group.ip().is_ipv4() {
        return Err(MulticastRouteError::SourceFamilyMismatch {
            source_ip: src,
            group: group.ip(),
        });
    }
    Ok(())
}

/// Property: `Vni` deserialization accepts an input iff `new` accepts it
#[proptest]
fn prop_serde_agrees_vni(#[strategy(vni_candidate_strategy())] candidate: u32) {
    prop_assert_eq!(
        json_accepts::<Vni>(&candidate),
        Vni::new(candidate).is_ok()
    );
}

/// Property: `UnderlayMulticastIpv6::new` and deserialization accept an input
/// iff `spec_underlay` accepts it
#[proptest]
fn prop_underlay_matches_spec(
    #[strategy(underlay_candidate_strategy())] addr: Ipv6Addr,
) {
    let want = spec_underlay(addr);
    prop_assert_eq!(
        UnderlayMulticastIpv6::new(addr).is_ok(),
        want,
        "{}: construction disagrees with spec",
        addr
    );
    prop_assert_eq!(
        json_accepts::<UnderlayMulticastIpv6>(&addr),
        want,
        "{}: deserialization disagrees with spec",
        addr
    );
}

/// Property: `MulticastAddrV4::new` and `spec_group_v4` provide the same
/// outcome, including the error variant, and deserialization and
/// `OverlayMulticast::new` accept an input iff the spec does
#[proptest]
fn prop_group_v4_matches_spec(
    #[strategy(group_v4_candidate_strategy())]
    #[map(Ipv4Addr::from)]
    addr: Ipv4Addr,
) {
    let got = MulticastAddrV4::new(addr);
    let want = spec_group_v4(addr);
    prop_assert_eq!(outcome(&got), outcome(&want), "{}", addr);
    prop_assert_eq!(
        json_accepts::<MulticastAddrV4>(&addr),
        want.is_ok(),
        "{}: deserialization disagrees with spec",
        addr
    );
    prop_assert_eq!(
        OverlayMulticast::new(IpAddr::V4(addr)).is_ok(),
        want.is_ok(),
        "{}: overlay construction disagrees with spec",
        addr
    );
}

/// Property: `MulticastAddrV6::new` and `spec_group_v6` provide the same
/// outcome, including the error variant, and deserialization and
/// `OverlayMulticast::new` accept an input iff the spec does
#[proptest]
fn prop_group_v6_matches_spec(
    #[strategy(group_v6_candidate_strategy())] addr: Ipv6Addr,
) {
    let got = MulticastAddrV6::new(addr);
    let want = spec_group_v6(addr);
    prop_assert_eq!(outcome(&got), outcome(&want), "{}", addr);
    prop_assert_eq!(
        json_accepts::<MulticastAddrV6>(&addr),
        want.is_ok(),
        "{}: deserialization disagrees with spec",
        addr
    );
    prop_assert_eq!(
        OverlayMulticast::new(IpAddr::V6(addr)).is_ok(),
        want.is_ok(),
        "{}: overlay construction disagrees with spec",
        addr
    );
}

/// Property: `UnicastAddrV4::new` and `spec_source_v4` provide the same
/// outcome, including the error variant and its variant-order precedence,
/// and deserialization accepts an input iff the spec does
#[proptest]
fn prop_source_v4_matches_spec(
    #[strategy(source_v4_candidate_strategy())]
    #[map(Ipv4Addr::from)]
    addr: Ipv4Addr,
) {
    let got = UnicastAddrV4::new(addr);
    let want = spec_source_v4(addr);
    prop_assert_eq!(outcome(&got), outcome(&want), "{}", addr);
    prop_assert_eq!(
        json_accepts::<UnicastAddrV4>(&addr),
        want.is_ok(),
        "{}: deserialization disagrees with spec",
        addr
    );
}

/// Property: `UnicastAddrV6::new` and `spec_source_v6` provide the same
/// outcome, including the error variant and its variant-order precedence,
/// and deserialization accepts an input iff the spec does
#[proptest]
fn prop_source_v6_matches_spec(
    #[strategy(source_v6_candidate_strategy())] addr: Ipv6Addr,
) {
    let got = UnicastAddrV6::new(addr);
    let want = spec_source_v6(addr);
    prop_assert_eq!(outcome(&got), outcome(&want), "{}", addr);
    prop_assert_eq!(
        json_accepts::<UnicastAddrV6>(&addr),
        want.is_ok(),
        "{}: deserialization disagrees with spec",
        addr
    );
}

/// Property: `is_ssm_address` matches `spec_is_ssm`
#[proptest]
fn prop_is_ssm_matches_spec(
    #[strategy(ssm_candidate_strategy())] addr: IpAddr,
) {
    prop_assert_eq!(is_ssm_address(addr), spec_is_ssm(addr), "{}", addr);
}

/// Property: `MulticastRouteKey::new` and deserialization provide the same
/// outcome as `spec_route_key`
#[proptest]
fn prop_key_construction_matches_spec(
    #[strategy(proptest::option::of(route_key_source_candidate_strategy()))]
    source: Option<IpAddr>,
    #[strategy(route_key_group_candidate_strategy())] group: MulticastAddr,
    #[strategy(valid_vni_strategy())] vni: Vni,
) {
    let ip = group.ip();
    let want = spec_route_key(source, group);
    let got = MulticastRouteKey::new(source, group, vni);
    prop_assert_eq!(outcome(&got), outcome(&want), "({:?},{})", source, group);

    let fields =
        serde_json::json!({ "source": source, "group": ip, "vni": vni });
    let json = match group {
        MulticastAddr::V4(_) => serde_json::json!({ "V4": fields }),
        MulticastAddr::V6(_) => serde_json::json!({ "V6": fields }),
    };
    let decoded = serde_json::from_value::<MulticastRouteKey>(json.clone());
    prop_assert_eq!(decoded.ok(), got.ok(), "{}", json);
}
