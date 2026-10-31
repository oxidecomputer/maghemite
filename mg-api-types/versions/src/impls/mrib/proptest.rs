// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Property-based tests for MRIB types.
//!
//! Dendrite tests the address-validation rules. These properties cover
//! Maghemite's wrappers and route keys, including their JSON representation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dpd_types_versions::testing;
use dpd_types_versions::v14::mcast::{
    is_ssm_address, validate_external_multicast_ipv4,
    validate_external_multicast_ipv6,
};
use proptest::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use test_strategy::{Arbitrary, proptest};

use crate::latest::mrib::{
    MulticastAddr, MulticastAddrV4, MulticastAddrV6, MulticastRoute,
    MulticastRouteError, MulticastRouteKey, MulticastSourceProtocol,
    UnderlayMulticastIpv6, UnicastAddrV4, UnicastAddrV6, Vni,
};

/// Property: `MulticastRouteKey::new` rebuilds a key from its accessors, and
/// the key sustains across a JSON round trip
#[proptest]
fn prop_route_key_parts_roundtrip(key: MulticastRouteKey) {
    prop_assert_eq!(
        MulticastRouteKey::new(key.source(), key.group(), key.vni()),
        Ok(key)
    );
    prop_assert_eq!(json_roundtrip(&key)?, key);
}

/// Property: `source_specific_v4` agrees with `new` (covers ASM and SSM)
#[proptest]
fn prop_route_key_sg_valid_v4(
    src: UnicastAddrV4,
    group: MulticastAddrV4,
    vni: Vni,
) {
    prop_assert_eq!(
        MulticastRouteKey::new(Some(IpAddr::from(src)), group.into(), vni),
        Ok(MulticastRouteKey::source_specific_v4(src, group, vni))
    );
}

/// Property: `source_specific_v6` agrees with `new` (covers ASM and SSM)
#[proptest]
fn prop_route_key_sg_valid_v6(
    src: UnicastAddrV6,
    group: MulticastAddrV6,
    vni: Vni,
) {
    prop_assert_eq!(
        MulticastRouteKey::new(Some(IpAddr::from(src)), group.into(), vni),
        Ok(MulticastRouteKey::source_specific_v6(src, group, vni))
    );
}

/// Property: a route with an admin-local underlay group sustains across a
/// JSON round trip
#[proptest]
fn prop_route_serde_roundtrip(
    key: MulticastRouteKey,
    underlay: UnderlayMulticastIpv6,
) {
    let route =
        MulticastRoute::new(key, underlay, MulticastSourceProtocol::Static);
    prop_assert_eq!(json_roundtrip(&route)?, route);
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

/// Generate candidate IPv4 bits biased toward 224/4, 224.0.0.0, and
/// 232.0.0.0.
fn group_v4_candidate_strategy() -> impl Strategy<Value = u32> {
    prop_oneof![
        any::<u32>(),
        0xe000_0000u32..=0xefff_ffff,
        Just(0xe000_0000u32),
        Just(0xe800_0000u32),
    ]
}

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

/// Keep R, P, and T set to exercise the embedded-RP field checks.
#[derive(Debug, Arbitrary)]
struct EmbeddedRpCase {
    #[strategy(proptest::sample::select(&[0x7u16, 0xf][..]))]
    flags: u16,
    #[strategy(testing::usable_scope_strategy())]
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

/// Generate candidate IPv6 addresses biased toward `ff00::/8`.
///
/// Uniform multicast sampling seldom hits `ff04::/64` or specifically reserved
/// addresses. The targeted cases exercise these paths through Maghemite's
/// constructors and deserializers.
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

/// Generate IPv6 SSM groups in `ff3x` and `ffbx`, including nonzero `ff2`
/// and `rsvd` nibbles.
fn ipv6_ssm_wide_group_strategy() -> impl Strategy<Value = MulticastAddrV6> {
    (
        proptest::sample::select(&[0x3u16, 0xb][..]),
        testing::usable_scope_strategy(),
        any::<u8>(),
        any::<[u16; 6]>(),
    )
        .prop_map(|(flags, scope, seg1_high, mut segs)| {
            // A zero network prefix with group ID `4000:0` is the SSM null
            // address (RFC 4607 §4.3), which `MulticastAddrV6::new` rejects.
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
        3 => any::<UnicastAddrV4>().prop_map_into::<IpAddr>(),
        1 => invalid_v4.prop_map_into::<IpAddr>(),
        3 => any::<UnicastAddrV6>().prop_map_into::<IpAddr>(),
        1 => invalid_v6.prop_map_into::<IpAddr>(),
    ]
}

/// Generate valid groups of either IP address family (ASM or SSM), including
/// `ffbx` and nonzero-`rsvd` SSM groups.
fn route_key_group_candidate_strategy() -> impl Strategy<Value = MulticastAddr>
{
    prop_oneof![
        2 => any::<MulticastAddrV4>().prop_map_into::<MulticastAddr>(),
        2 => any::<MulticastAddrV6>().prop_map_into::<MulticastAddr>(),
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
        if is_ssm_address(group.ip()) {
            return Err(MulticastRouteError::SsmRequiresSource {
                group: group.ip(),
            });
        }
        return Ok(());
    };
    match src {
        IpAddr::V4(s) => drop(UnicastAddrV4::new(s)?),
        IpAddr::V6(s) => drop(UnicastAddrV6::new(s)?),
    }
    if src.is_ipv4() != group.ip().is_ipv4() {
        return Err(MulticastRouteError::SourceFamilyMismatch {
            source_ip: src,
            group: group.ip(),
        });
    }
    Ok(())
}

/// Property: `MulticastAddrV4::new` and deserialization agree with
/// `validate_external_multicast_ipv4`, including the error variant
#[proptest]
fn prop_group_v4_matches_validator(
    #[strategy(group_v4_candidate_strategy())]
    #[map(Ipv4Addr::from)]
    addr: Ipv4Addr,
) {
    let got = MulticastAddrV4::new(addr);
    let want = validate_external_multicast_ipv4(addr);
    prop_assert_eq!(outcome(&got), want.as_ref().map(drop), "{}", addr);
    let decoded =
        serde_json::from_value::<MulticastAddrV4>(serde_json::to_value(addr)?);
    prop_assert_eq!(decoded.ok(), got.as_ref().ok().copied());
    let ip = IpAddr::V4(addr);
    prop_assert_eq!(
        MulticastAddr::try_from(ip),
        got.clone().map(MulticastAddr::V4)
    );
    prop_assert_eq!(json_accepts::<MulticastAddr>(&ip), want.is_ok());
    if let Ok(group) = got {
        prop_assert_eq!(
            serde_json::to_value(group)?,
            serde_json::to_value(addr)?
        );
        let group = MulticastAddr::from(group);
        prop_assert_eq!(
            serde_json::to_value(group)?,
            serde_json::to_value(ip)?
        );
        prop_assert_eq!(json_roundtrip(&group)?, group);
    }
}

/// Property: `MulticastAddrV6::new` and deserialization agree with
/// `validate_external_multicast_ipv6`, including the error variant
#[proptest]
fn prop_group_v6_matches_validator(
    #[strategy(group_v6_candidate_strategy())] addr: Ipv6Addr,
) {
    let got = MulticastAddrV6::new(addr);
    let want = validate_external_multicast_ipv6(addr);
    prop_assert_eq!(outcome(&got), want.as_ref().map(drop), "{}", addr);
    let decoded =
        serde_json::from_value::<MulticastAddrV6>(serde_json::to_value(addr)?);
    prop_assert_eq!(decoded.ok(), got.as_ref().ok().copied());
    let ip = IpAddr::V6(addr);
    prop_assert_eq!(
        MulticastAddr::try_from(ip),
        got.clone().map(MulticastAddr::V6)
    );
    prop_assert_eq!(json_accepts::<MulticastAddr>(&ip), want.is_ok());
    if let Ok(group) = got {
        prop_assert_eq!(
            serde_json::to_value(group)?,
            serde_json::to_value(addr)?
        );
        let group = MulticastAddr::from(group);
        prop_assert_eq!(
            serde_json::to_value(group)?,
            serde_json::to_value(ip)?
        );
        prop_assert_eq!(json_roundtrip(&group)?, group);
    }
}

/// Property: `MulticastRouteKey::new` and deserialization provide the same
/// outcome as `spec_route_key`
#[proptest]
fn prop_key_construction_matches_spec(
    #[strategy(proptest::option::of(route_key_source_candidate_strategy()))]
    source: Option<IpAddr>,
    #[strategy(route_key_group_candidate_strategy())] group: MulticastAddr,
    vni: Vni,
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
