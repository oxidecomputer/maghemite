// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::types::{Path, PathOrigin};
use itertools::Itertools;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

/// The bestpath algorithm chooses the best set of up to `max` paths for a
/// particular prefix from the RIB. Pre-BGP filtering:
///
/// - partition candidate paths into active and shutdown groups.
/// - if only shutdown routes exist, select from that group, otherwise
///   select from the active group.
/// - filter the selection group to the set of paths with the smallest
///   rib priority
/// - prefer static routes over BGP when RIB priority is equal
///
/// BGP-specific tie-breaking follows RFC 4271 Section 9.1.2.2
pub fn bestpaths(paths: &BTreeSet<Path>, max: usize) -> Option<BTreeSet<Path>> {
    // Short-circuit: if there's only 1 candidate, then it is the best
    if paths.len() == 1 {
        return Some(paths.clone());
    }

    // Partition the choice space on whether routes are shutdown or not. If we
    // only have shutdown routes then use those. Otherwise use active routes
    let (shutdown, active): (BTreeSet<&Path>, BTreeSet<&Path>) =
        paths.iter().partition(|x| x.shutdown);
    let candidates = if active.is_empty() { shutdown } else { active };

    // Filter down to paths with the best (lowest) RIB priority. This is a
    // coarse filter to roughly separate RIB paths by protocol (e.g. BGP vs Static),
    // similar to Administrative Distance on Cisco-like platforms.
    let candidates = candidates
        .into_iter()
        .min_set_by_key(|path| path.rib_priority);

    // In the case where paths come from multiple protocols but have the same
    // RIB priority, follow the principle of least surprise. e.g. If a user has
    // configured a static route with the same RIB priority as BGP is using,
    // prefer the Static route.
    // TODO: update this if new upper layer protocols are added
    let (b, s): (BTreeSet<&Path>, BTreeSet<&Path>) =
        candidates.into_iter().partition(|path| path.bgp.is_some());

    // Some paths are static, return up to `max` paths from static routes
    if !s.is_empty() {
        return Some(s.into_iter().take(max).cloned().collect());
    }

    // None of the remaining paths are static.
    // Begin comparison of BGP Path Attributes.
    Some(bgp_bestpaths(b, max))
}

/// The BGP-specific portion of the bestpath algorithm. This evaluates BGP path
/// attributes in order to determine up to `max` suitable paths.
pub fn bgp_bestpaths(
    candidates: BTreeSet<&Path>,
    max: usize,
) -> BTreeSet<Path> {
    // Per RFC 4271 Section 9.1.2.2:
    // """
    // The tie-breaking algorithm begins by considering all equally
    // preferable routes to the same destination, and then selects routes to
    // be removed from consideration.  The algorithm terminates as soon as
    // only one route remains in consideration.  The criteria MUST be
    // applied in the order specified.
    // """
    //
    // We should be returning at any point the `candidates` only contains
    // 1 path. "Multipath" is not a standardized BGP behavior, however Cisco
    // implements that decision after the IGP metric check and many other
    // routing stacks have followed their lead. Again, following the principle
    // of least surprise, our multipath decision is made at the same step.
    //
    // XXX: This also gives us the opportunity to add trace points, debugs,
    // or even a "bestpath reason" specific to each step that can provide
    // better insight into the bestpath calculation itself.

    // Filter down to paths that are not stale (Graceful Restart).
    let candidates =
        candidates
            .into_iter()
            .min_set_by_key(|path| match path.bgp {
                Some(ref bgp) => match bgp.stale {
                    Some(_) => 1,
                    None => 0,
                },
                None => 0,
            });
    if candidates.len() == 1 {
        return candidates.into_iter().cloned().collect();
    }

    // Filter down to paths with the highest local preference
    // RFC 4271 Section 9.1.2
    let candidates =
        candidates
            .into_iter()
            .max_set_by_key(|path| match path.bgp {
                Some(ref bgp) => bgp.local_pref.unwrap_or(0),
                None => 0,
            });
    if candidates.len() == 1 {
        return candidates.into_iter().cloned().collect();
    }

    // Filter down to paths with the shortest AS-Path length
    // RFC 4271 Section 9.1.2.2 (a)
    let candidates =
        candidates
            .into_iter()
            .min_set_by_key(|path| match path.bgp {
                Some(ref bgp) => bgp.as_path.len(),
                None => 0,
            });
    if candidates.len() == 1 {
        return candidates.into_iter().cloned().collect();
    }

    // Filter down to paths with the lowest Origin
    // RFC 4271 Section 9.1.2.2 (b)
    let candidates =
        candidates
            .into_iter()
            .min_set_by_key(|path| match path.bgp {
                Some(ref bgp) => bgp.origin,
                None => PathOrigin::Incomplete,
            });
    if candidates.len() == 1 {
        return candidates.into_iter().cloned().collect();
    }

    // Group candidates by AS for MED selection
    // RFC 4271 Section 9.1.2.2 (c)
    let mut as_groups: BTreeMap<u32, Vec<&Path>> = BTreeMap::new();
    for path in candidates {
        let origin_as = path.bgp.as_ref().map(|bgp| bgp.origin_as).unwrap_or(0);
        as_groups.entry(origin_as).or_default().push(path);
    }

    // Filter each AS group to paths with lowest MED
    let candidates: Vec<&Path> = as_groups
        .into_values()
        .flat_map(|paths| {
            paths.into_iter().min_set_by_key(|path| {
                path.bgp.as_ref().and_then(|bgp| bgp.med).unwrap_or(0)
            })
        })
        .collect();
    if candidates.len() == 1 {
        return candidates.into_iter().cloned().collect();
    }

    // Filter down to eBGP paths when possible (prefer eBGP over
    // iBGP) RFC 4271 Section 9.1.2.2 (d)
    let candidates =
        candidates
            .into_iter()
            .min_set_by_key(|path| match path.bgp {
                Some(ref bgp) => bgp.internal,
                None => false,
            });
    if candidates.len() == 1 {
        return candidates.into_iter().cloned().collect();
    }

    // TODO(OSPF/IS-IS): Filter down to paths with lowest IGP cost
    // RFC 4271 Section 9.1.2.2 (e)
    // Note: DDM is currently the only supported IGP and it doesn't
    //       interface with the external world, so this is N/A.

    // All paths still under consideration at this point have
    // identical values for the earlier checks. Multipath is now
    // allowed if `max` permits it.
    if max > 1 {
        return candidates.into_iter().take(max).cloned().collect();
    }

    // Prefer the path with the lowest Router-ID (BGP Identifier)
    // RFC 4271 Section 9.1.2.2 (f)
    let candidates =
        candidates
            .into_iter()
            .min_set_by_key(|path| match path.bgp {
                Some(ref bgp) => bgp.id,
                None => u32::MAX,
            });
    if candidates.len() == 1 {
        return candidates.into_iter().cloned().collect();
    }

    // Prefer the path from the peer with the lowest IP address
    // RFC 4271 Section 9.1.2.2 (g)
    let candidates =
        candidates
            .into_iter()
            .min_set_by_key(|path| match path.bgp {
                Some(ref bgp) => match bgp.peer_ip {
                    IpAddr::V4(a) => u128::from(a.to_bits()),
                    IpAddr::V6(a) => a.to_bits(),
                },
                None => u128::MAX,
            });
    if candidates.len() == 1 {
        return candidates.into_iter().cloned().collect();
    }

    // Should be unreachable with distinct peers, but ensure we
    // never return more than 1 path after the multipath check.
    candidates.into_iter().take(1).cloned().collect()
}

#[cfg(test)]
mod test {
    use super::bestpaths;
    use crate::{
        BgpPathProperties, DEFAULT_RIB_PRIORITY_BGP,
        DEFAULT_RIB_PRIORITY_STATIC, Path, PathOrigin, PeerId,
        types::test_helpers::path_sets_equal,
    };
    use std::{collections::BTreeSet, net::IpAddr, str::FromStr};

    // Bestpaths is purely a function of the path info itself, so we don't
    // need a Rib or Prefix, just a set of candidate paths and a set of
    // expected paths.
    #[test]
    fn test_bestpath() {
        let mut max: usize = 2;
        let remote_ip1 = IpAddr::from_str("203.0.113.1").unwrap();
        let remote_ip2 = IpAddr::from_str("203.0.113.2").unwrap();
        let remote_ip3 = IpAddr::from_str("203.0.113.3").unwrap();
        let remote_ip4 = IpAddr::from_str("203.0.113.4").unwrap();

        // Add one path and make sure we get it back
        let path1 = Path {
            nexthop: remote_ip1,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 470,
                peer: PeerId::Ip(remote_ip1),
                peer_ip: remote_ip1,
                internal: false,
                id: 47,
                med: Some(75),
                local_pref: Some(100),
                as_path: vec![470, 64501, 64502],
                stale: None,
            }),
            vlan_id: None,
        };

        let mut candidates = BTreeSet::<Path>::new();
        candidates.insert(path1.clone());

        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(&result, &BTreeSet::from([path1.clone()])));

        // Add path2:
        let mut path2 = Path {
            nexthop: remote_ip2,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 480,
                peer: PeerId::Ip(remote_ip2),
                peer_ip: remote_ip2,
                internal: false,
                id: 48,
                med: Some(75),
                local_pref: Some(100),
                as_path: vec![480, 64501, 64502],
                stale: None,
            }),
            vlan_id: None,
        };

        candidates.insert(path2.clone());
        let result = bestpaths(&candidates, max).unwrap();

        // we expect both paths to be selected because path1 and path2 have:
        // - matching local-pref
        // - matching as-path-len
        // - matching med
        assert_eq!(result.len(), 2);
        assert!(path_sets_equal(
            &result,
            &BTreeSet::from([path1.clone(), path2.clone()])
        ));

        // Add path3 from a different AS (490).
        // Note: Since path3 is from a different AS than path1 (470) and path2 (480),
        // MED comparison does NOT apply across ASes per RFC 4271. Each path is the
        // best (and only) path from its respective AS, so all three pass the MED
        // filter. The max=2 limit determines which paths are returned.
        let path3 = Path {
            nexthop: remote_ip3,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 490,
                peer: PeerId::Ip(remote_ip3),
                peer_ip: remote_ip3,
                internal: false,
                id: 49,
                med: Some(100),
                local_pref: Some(100),
                as_path: vec![490, 64501, 64502],
                stale: None,
            }),
            vlan_id: None,
        };
        let mut candidates = result.clone();
        candidates.insert(path3.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 2);
        // With 3 paths from different ASes and max=2, only 2 are returned.
        // BTreeMap iteration order (by AS number) determines which: AS 470 and 480.
        assert!(path_sets_equal(
            &result,
            &BTreeSet::from([path1.clone(), path2.clone()])
        ));

        // Increase max paths to 3 - now all paths from all ASes fit within max.
        // Note: candidates still contains all 3 paths; path3 was only excluded from
        // the previous result due to max=2, not removed from candidates.
        max = 3;

        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 3);
        assert!(path_sets_equal(
            &result,
            &BTreeSet::from([path1.clone(), path2.clone(), path3.clone()])
        ));

        // bump the local_pref on path2, this should make it the singular
        // best path regardless of max paths
        let mut candidates = result.clone();
        candidates.remove(&path2);
        path2.bgp.as_mut().unwrap().local_pref = Some(125);
        candidates.insert(path2.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(&result, &BTreeSet::from([path2.clone()])));

        // Add a fourth path (which is static) and make sure that:
        // - path 4 loses to BGP paths with higher RIB priority
        // - path 4 wins over BGP paths with lower RIB priority
        // - path 4 wins over BGP paths with equal RIB priority
        //   > static is preferred over bgp when RIB priority matches
        let mut path4 = Path {
            nexthop: remote_ip4,
            nexthop_interface: None,
            rib_priority: u8::MAX,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };
        let mut candidates = result.clone();
        candidates.insert(path4.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        // path4 (static) has worse rib priority, path2 should win because it
        // has the best (highest) local-pref among bgp paths (paths 1-3)
        assert!(path_sets_equal(&result, &BTreeSet::from([path2.clone()])));

        // Lower the RIB Priority (better)
        let mut candidates = result.clone();
        candidates.remove(&path4);
        path4.rib_priority = DEFAULT_RIB_PRIORITY_STATIC;
        candidates.insert(path4.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        // path4 (static) has the best (lower) rib priority
        assert!(path_sets_equal(&result, &BTreeSet::from([path4.clone()])));

        // Raise the RIB Priority equal to BGP (paths 1-3)
        let mut candidates = result.clone();
        candidates.remove(&path4);
        path4.rib_priority = DEFAULT_RIB_PRIORITY_BGP;
        candidates.insert(path4.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        // path4 (static) wins due to protocol preference
        // i.e. static > bgp when rib priority matches
        assert!(path_sets_equal(&result, &BTreeSet::from([path4.clone()])));
    }

    /// Test that active (non-shutdown) paths are preferred over shutdown paths.
    /// Even when max allows multiple paths, shutdown paths should not be
    /// included when active paths exist.
    #[test]
    fn test_bestpath_shutdown_preference() {
        let remote_ip1 = IpAddr::from_str("203.0.113.1").unwrap();
        let remote_ip2 = IpAddr::from_str("203.0.113.2").unwrap();

        // Create two equivalent BGP paths, but one is shutdown
        let active_path = Path {
            nexthop: remote_ip1,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 470,
                peer: PeerId::Ip(remote_ip1),
                peer_ip: remote_ip1,
                internal: false,
                id: 47,
                med: Some(75),
                local_pref: Some(100),
                as_path: vec![470, 64501, 64502],
                stale: None,
            }),
            vlan_id: None,
        };

        let shutdown_path = Path {
            nexthop: remote_ip2,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: true, // This path is shutdown
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 480,
                peer: PeerId::Ip(remote_ip2),
                peer_ip: remote_ip2,
                internal: false,
                id: 48,
                med: Some(75),
                local_pref: Some(100),
                as_path: vec![480, 64501, 64502],
                stale: None,
            }),
            vlan_id: None,
        };

        // Both paths are equivalent except for shutdown status.
        // With max=2, we could return both if they were truly equivalent,
        // but the active path should win and the shutdown path should be excluded.
        let mut candidates = BTreeSet::new();
        candidates.insert(active_path.clone());
        candidates.insert(shutdown_path.clone());

        let result = bestpaths(&candidates, 2).unwrap();

        // Only the active path should be returned, not the shutdown path
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(
            &result,
            &BTreeSet::from([active_path.clone()])
        ));

        // Verify that if ONLY shutdown paths exist, we still get a result
        let mut shutdown_only = BTreeSet::new();
        shutdown_only.insert(shutdown_path.clone());

        let result = bestpaths(&shutdown_only, 2).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(
            &result,
            &BTreeSet::from([shutdown_path.clone()])
        ));

        // Test with two shutdown paths - both should be returned when max=2
        let shutdown_path2 = Path {
            nexthop: remote_ip1,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: true,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 470,
                peer: PeerId::Ip(remote_ip1),
                peer_ip: remote_ip1,
                internal: false,
                id: 47,
                med: Some(75),
                local_pref: Some(100),
                as_path: vec![470, 64501, 64502],
                stale: None,
            }),
            vlan_id: None,
        };

        let mut two_shutdown = BTreeSet::new();
        two_shutdown.insert(shutdown_path.clone());
        two_shutdown.insert(shutdown_path2.clone());

        let result = bestpaths(&two_shutdown, 2).unwrap();
        // Both shutdown paths should be returned since no active paths exist
        assert_eq!(result.len(), 2);
        assert!(path_sets_equal(
            &result,
            &BTreeSet::from([shutdown_path.clone(), shutdown_path2.clone()])
        ));
    }

    /// Test that MED comparison happens per-AS as required by RFC 4271.
    ///
    /// MED (Multi-Exit Discriminator) is only meaningful when comparing paths
    /// from the SAME neighboring AS. Paths from different ASes should not have
    /// their MEDs compared against each other.
    #[test]
    fn test_bestpath_med_per_as_grouping() {
        // Create paths with nexthops that will be non-consecutive when sorted.
        // This tests that AS grouping works regardless of input order.
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();
        let ip3 = IpAddr::from_str("10.0.0.3").unwrap();
        let ip4 = IpAddr::from_str("10.0.0.4").unwrap();

        // AS 100: two paths with different MEDs
        // Path from ip1 has MED 50 (better)
        // Path from ip3 has MED 100 (worse)
        let as100_path_good = Path {
            nexthop: ip1,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 100,
                peer: PeerId::Ip(ip1),
                peer_ip: ip1,
                internal: false,
                id: 1,
                med: Some(50),
                local_pref: Some(100),
                as_path: vec![100],
                stale: None,
            }),
            vlan_id: None,
        };

        let as100_path_bad = Path {
            nexthop: ip3,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 100,
                peer: PeerId::Ip(ip3),
                peer_ip: ip3,
                internal: false,
                id: 1,
                med: Some(100), // Higher MED = worse
                local_pref: Some(100),
                as_path: vec![100],
                stale: None,
            }),
            vlan_id: None,
        };

        // AS 200: one path with high MED
        // This should NOT be excluded just because AS 100 has a lower MED
        let as200_path = Path {
            nexthop: ip2,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 200,
                peer: PeerId::Ip(ip2),
                peer_ip: ip2,
                internal: false,
                id: 2,
                med: Some(999), // Very high MED, but irrelevant - different AS
                local_pref: Some(100),
                as_path: vec![200],
                stale: None,
            }),
            vlan_id: None,
        };

        // AS 300: one path with low MED
        let as300_path = Path {
            nexthop: ip4,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 300,
                peer: PeerId::Ip(ip4),
                peer_ip: ip4,
                internal: false,
                id: 3,
                med: Some(10), // Low MED, but can't "steal" selection from other ASes
                local_pref: Some(100),
                as_path: vec![300],
                stale: None,
            }),
            vlan_id: None,
        };

        // Insert in an order where AS 100's paths are NOT consecutive
        // BTreeSet orders by Path::cmp which orders by nexthop first:
        // ip1 (AS 100 good), ip2 (AS 200), ip3 (AS 100 bad), ip4 (AS 300)
        let mut candidates = BTreeSet::new();
        candidates.insert(as100_path_good.clone());
        candidates.insert(as100_path_bad.clone());
        candidates.insert(as200_path.clone());
        candidates.insert(as300_path.clone());

        // With max=10, we should get:
        // - AS 100: as100_path_good (MED 50 beats MED 100)
        // - AS 200: as200_path (only path from this AS, MED irrelevant)
        // - AS 300: as300_path (only path from this AS, MED irrelevant)
        // Total: 3 paths
        let result = bestpaths(&candidates, 10).unwrap();

        assert_eq!(
            result.len(),
            3,
            "Expected 3 paths (best from each AS), got {}",
            result.len()
        );

        // Verify the correct paths were selected
        assert!(
            result.iter().any(|p| p.nexthop == ip1),
            "AS 100's better MED path (ip1) should be selected"
        );
        assert!(
            !result.iter().any(|p| p.nexthop == ip3),
            "AS 100's worse MED path (ip3) should NOT be selected"
        );
        assert!(
            result.iter().any(|p| p.nexthop == ip2),
            "AS 200's path should be selected (MED not compared cross-AS)"
        );
        assert!(
            result.iter().any(|p| p.nexthop == ip4),
            "AS 300's path should be selected"
        );
    }

    /// Test that multiple paths from the same AS with equal MED are all kept.
    #[test]
    fn test_bestpath_med_same_as_equal_med() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();
        let ip3 = IpAddr::from_str("10.0.0.3").unwrap();

        // Three paths from AS 100, all with same MED
        let path1 = Path {
            nexthop: ip1,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 100,
                peer: PeerId::Ip(ip1),
                peer_ip: ip1,
                internal: false,
                id: 1,
                med: Some(50),
                local_pref: Some(100),
                as_path: vec![100],
                stale: None,
            }),
            vlan_id: None,
        };

        let path2 = Path {
            nexthop: ip2,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 100,
                peer: PeerId::Ip(ip2),
                peer_ip: ip2,
                internal: false,
                id: 1,
                med: Some(50), // Same MED
                local_pref: Some(100),
                as_path: vec![100],
                stale: None,
            }),
            vlan_id: None,
        };

        let path3 = Path {
            nexthop: ip3,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 100,
                peer: PeerId::Ip(ip3),
                peer_ip: ip3,
                internal: false,
                id: 1,
                med: Some(50), // Same MED
                local_pref: Some(100),
                as_path: vec![100],
                stale: None,
            }),
            vlan_id: None,
        };

        let mut candidates = BTreeSet::new();
        candidates.insert(path1.clone());
        candidates.insert(path2.clone());
        candidates.insert(path3.clone());

        // All three have equal MED, so all should be selected (up to max)
        let result = bestpaths(&candidates, 10).unwrap();
        assert_eq!(result.len(), 3, "All paths with equal MED should be kept");

        // With max=2, only 2 should be returned
        let result = bestpaths(&candidates, 2).unwrap();
        assert_eq!(result.len(), 2, "max should limit results");
    }

    /// Helper: build a BGP path with sensible defaults. Only the
    /// fields under test need to be overridden after construction.
    fn bgp_path(ip: IpAddr) -> Path {
        Path {
            nexthop: ip,
            nexthop_interface: None,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin: PathOrigin::Igp,
                origin_as: 100,
                peer: PeerId::Ip(ip),
                peer_ip: ip,
                internal: false,
                id: 1,
                med: None,
                local_pref: Some(100),
                as_path: vec![100],
                stale: None,
            }),
            vlan_id: None,
        }
    }

    // ----------------------------------------------------------------
    // Origin preference (RFC 4271 Section 9.1.2.2 (b))
    // ----------------------------------------------------------------

    /// IGP origin is preferred over EGP and Incomplete.
    #[test]
    fn test_bestpath_origin_igp_preferred() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();
        let ip3 = IpAddr::from_str("10.0.0.3").unwrap();

        let mut igp = bgp_path(ip1);
        igp.bgp.as_mut().unwrap().origin = PathOrigin::Igp;

        let mut egp = bgp_path(ip2);
        egp.bgp.as_mut().unwrap().origin = PathOrigin::Egp;

        let mut incomplete = bgp_path(ip3);
        incomplete.bgp.as_mut().unwrap().origin = PathOrigin::Incomplete;

        let candidates =
            BTreeSet::from([igp.clone(), egp.clone(), incomplete.clone()]);
        let result = bestpaths(&candidates, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(&result, &BTreeSet::from([igp.clone()])));

        // EGP beats Incomplete when IGP is absent
        let candidates = BTreeSet::from([egp.clone(), incomplete]);
        let result = bestpaths(&candidates, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(&result, &BTreeSet::from([egp.clone()])));
    }

    /// When all paths share the same origin, they all survive
    /// the origin filter.
    #[test]
    fn test_bestpath_origin_equal_passes_all() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();

        let mut p1 = bgp_path(ip1);
        p1.bgp.as_mut().unwrap().origin = PathOrigin::Egp;
        let mut p2 = bgp_path(ip2);
        p2.bgp.as_mut().unwrap().origin = PathOrigin::Egp;

        let candidates = BTreeSet::from([p1.clone(), p2.clone()]);
        let result = bestpaths(&candidates, 10).unwrap();
        assert_eq!(result.len(), 2, "equal origin should not eliminate paths");
    }

    // ----------------------------------------------------------------
    // eBGP over iBGP preference (RFC 4271 Section 9.1.2.2 (d))
    // ----------------------------------------------------------------

    /// eBGP paths are preferred over iBGP paths.
    #[test]
    fn test_bestpath_ebgp_over_ibgp() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();

        let ebgp = bgp_path(ip1); // internal: false by default

        let mut ibgp = bgp_path(ip2);
        ibgp.bgp.as_mut().unwrap().internal = true;

        let candidates = BTreeSet::from([ebgp.clone(), ibgp]);
        let result = bestpaths(&candidates, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(&result, &BTreeSet::from([ebgp.clone()])));
    }

    /// When all paths are iBGP, they all survive the eBGP filter.
    #[test]
    fn test_bestpath_all_ibgp_passes_all() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();

        let mut p1 = bgp_path(ip1);
        p1.bgp.as_mut().unwrap().internal = true;
        let mut p2 = bgp_path(ip2);
        p2.bgp.as_mut().unwrap().internal = true;

        let candidates = BTreeSet::from([p1.clone(), p2.clone()]);
        let result = bestpaths(&candidates, 10).unwrap();
        assert_eq!(result.len(), 2, "all-iBGP should not eliminate paths");
    }

    /// When all paths are eBGP, they all survive the eBGP filter.
    #[test]
    fn test_bestpath_all_ebgp_passes_all() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();

        let p1 = bgp_path(ip1); // internal: false by default
        let p2 = bgp_path(ip2);

        let candidates = BTreeSet::from([p1.clone(), p2.clone()]);
        let result = bestpaths(&candidates, 10).unwrap();
        assert_eq!(result.len(), 2, "all-eBGP should not eliminate paths");
    }

    // ----------------------------------------------------------------
    // Multipath decision point (after step (d), before (f))
    // ----------------------------------------------------------------

    /// When max > 1 and multiple paths survive through eBGP/iBGP,
    /// all are returned (up to max) without router-id or peer-ip
    /// tie-breaking.
    #[test]
    fn test_bestpath_multipath_returns_multiple() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();
        let ip3 = IpAddr::from_str("10.0.0.3").unwrap();

        // Three equivalent eBGP paths with different router-ids
        let mut p1 = bgp_path(ip1);
        p1.bgp.as_mut().unwrap().id = 10;
        let mut p2 = bgp_path(ip2);
        p2.bgp.as_mut().unwrap().id = 20;
        let mut p3 = bgp_path(ip3);
        p3.bgp.as_mut().unwrap().id = 30;

        let candidates = BTreeSet::from([p1.clone(), p2.clone(), p3.clone()]);

        // max=3: all should be returned
        let result = bestpaths(&candidates, 3).unwrap();
        assert_eq!(result.len(), 3);

        // max=2: only 2 returned
        let result = bestpaths(&candidates, 2).unwrap();
        assert_eq!(result.len(), 2);
    }

    // ----------------------------------------------------------------
    // Router-ID tie-breaking (RFC 4271 Section 9.1.2.2 (f))
    // ----------------------------------------------------------------

    /// Lowest Router-ID wins when max=1, which also means multipath
    /// is disabled and the algorithm falls through to tie-breaking.
    #[test]
    fn test_bestpath_router_id_tiebreak() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();

        let mut low_id = bgp_path(ip1);
        low_id.bgp.as_mut().unwrap().id = 1;
        let mut high_id = bgp_path(ip2);
        high_id.bgp.as_mut().unwrap().id = 999;

        let candidates = BTreeSet::from([high_id.clone(), low_id.clone()]);
        let result = bestpaths(&candidates, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(&result, &BTreeSet::from([low_id])));
    }

    // ----------------------------------------------------------------
    // Peer IP tie-breaking (RFC 4271 Section 9.1.2.2 (g))
    // ----------------------------------------------------------------

    /// Lowest peer IPv4 address wins when router-ids are equal.
    #[test]
    fn test_bestpath_peer_ip_tiebreak_v4() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();

        let low_peer = bgp_path(ip1);
        let high_peer = bgp_path(ip2);

        let candidates = BTreeSet::from([high_peer.clone(), low_peer.clone()]);
        let result = bestpaths(&candidates, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(&result, &BTreeSet::from([low_peer])));
    }

    /// Lowest peer IPv6 address wins when router-ids are equal.
    #[test]
    fn test_bestpath_peer_ip_tiebreak_v6() {
        let ip1 = IpAddr::from_str("2001:db8::1").unwrap();
        let ip2 = IpAddr::from_str("2001:db8::2").unwrap();

        let low_peer = bgp_path(ip1);
        let high_peer = bgp_path(ip2);

        let candidates = BTreeSet::from([high_peer.clone(), low_peer.clone()]);
        let result = bestpaths(&candidates, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(&result, &BTreeSet::from([low_peer])));
    }

    /// When candidates have a mix of IPv4 and IPv6 peer IPs,
    /// the IPv4 peer wins because its u128 representation is
    /// smaller than any non-trivial IPv6 address.
    #[test]
    fn test_bestpath_peer_ip_tiebreak_v4_vs_v6() {
        let v4 = IpAddr::from_str("203.0.113.1").unwrap();
        let v6 = IpAddr::from_str("2001:db8::1").unwrap();

        let v4_path = bgp_path(v4);
        let v6_path = bgp_path(v6);

        let candidates = BTreeSet::from([v6_path.clone(), v4_path.clone()]);
        let result = bestpaths(&candidates, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(&result, &BTreeSet::from([v4_path])));
    }

    // ----------------------------------------------------------------
    // Stale path preference (Graceful Restart)
    // ----------------------------------------------------------------

    /// Non-stale paths are preferred over stale paths.
    #[test]
    fn test_bestpath_stale_preference() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();

        let fresh = bgp_path(ip1);

        let mut stale = bgp_path(ip2);
        stale.bgp.as_mut().unwrap().stale = Some(chrono::Utc::now());

        let candidates = BTreeSet::from([fresh.clone(), stale]);
        let result = bestpaths(&candidates, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(&result, &BTreeSet::from([fresh])));
    }

    // ----------------------------------------------------------------
    // Full pipeline: exercise multiple tie-breaking steps in one test
    // ----------------------------------------------------------------

    /// Walk the entire BGP bestpath pipeline from local_pref through
    /// peer-ip, confirming each step eliminates the right candidate.
    #[test]
    fn test_bestpath_full_pipeline() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();
        let ip3 = IpAddr::from_str("10.0.0.3").unwrap();
        let ip4 = IpAddr::from_str("10.0.0.4").unwrap();
        let ip5 = IpAddr::from_str("10.0.0.5").unwrap();
        let ip6 = IpAddr::from_str("10.0.0.6").unwrap();
        let ip7 = IpAddr::from_str("10.0.0.7").unwrap();

        // p1: eliminated by local_pref (lower than others)
        let mut p1 = bgp_path(ip1);
        p1.bgp.as_mut().unwrap().local_pref = Some(50);

        // p2: eliminated by AS path length (longer)
        let mut p2 = bgp_path(ip2);
        p2.bgp.as_mut().unwrap().as_path = vec![100, 200, 300];

        // p3: eliminated by origin (Incomplete vs Igp)
        let mut p3 = bgp_path(ip3);
        p3.bgp.as_mut().unwrap().origin = PathOrigin::Incomplete;

        // p4: eliminated by MED (higher than p5-p7)
        let mut p4 = bgp_path(ip4);
        p4.bgp.as_mut().unwrap().med = Some(999);

        // p5: eliminated by eBGP/iBGP (internal)
        let mut p5 = bgp_path(ip5);
        p5.bgp.as_mut().unwrap().internal = true;

        // p6: eliminated by router-id (higher than p7)
        let mut p6 = bgp_path(ip6);
        p6.bgp.as_mut().unwrap().id = 999;

        // p7: survives — best at every step
        let p7 = bgp_path(ip7);
        // id=1, peer_ip=10.0.0.7, internal=false, origin=Igp,
        // local_pref=100, as_path=[100], med=None

        let candidates = BTreeSet::from([p1, p2, p3, p4, p5, p6, p7.clone()]);
        let result = bestpaths(&candidates, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(&result, &BTreeSet::from([p7])));
    }

    /// Verify that the AS path length filter uses element count,
    /// not the raw AS numbers.
    #[test]
    fn test_bestpath_as_path_length_not_values() {
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();

        // Short path with large AS numbers
        let mut short = bgp_path(ip1);
        short.bgp.as_mut().unwrap().as_path = vec![65000];
        short.bgp.as_mut().unwrap().origin_as = 65000;

        // Long path with small AS numbers
        let mut long = bgp_path(ip2);
        long.bgp.as_mut().unwrap().as_path = vec![1, 2, 3];
        long.bgp.as_mut().unwrap().origin_as = 1;

        let candidates = BTreeSet::from([short.clone(), long]);
        let result = bestpaths(&candidates, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert!(path_sets_equal(&result, &BTreeSet::from([short])));
    }
}
