// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

use crate::types::{Path, PathKey};
use itertools::Itertools;

/// The bestpath algorithm chooses the best set of up to `max` paths for a
/// particular prefix from the RIB. The set of paths chosen will all have
/// equal RIB priority, MED, local_pref, AS path length and shutdown status.
/// The bestpath algorithm performs path filtering in the following ordered
/// sequence of operations.
///
/// - partition candidate paths into active and shutdown groups.
/// - if only shutdown routes exist, select from that group, otherwise
///   select from the active group.
/// - filter the selection group to the set of paths with the smallest
///   rib priority
/// - filter the selection group to the set of paths with the largest
///   local preference
/// - filter the selection group to the set of paths with the smallest
///   AS path length
/// - filter the selection group to the set of paths with the smallest
///   multi-exit discriminator (MED) on a per-AS basis.
///
/// Upon completion of these filtering operations, if the selection group
/// is larger than `max`, return the first `max` entries. If the
/// selection group is smaller than `max`, the entire group is returned.
pub fn bestpaths(
    paths: &HashMap<PathKey, Path>,
    max: usize,
) -> Option<HashMap<PathKey, Path>> {
    // Short-circuit: if there are no candidates, there is no best path
    if paths.is_empty() {
        return None;
    }

    // Short-circuit: if there's only 1 candidate, then it is the best
    if paths.len() == 1 {
        return Some(paths.clone());
    }

    // Extract references to path values from the HashMap
    let path_refs: Vec<&Path> = paths.values().collect();

    // Partition the choice space on whether routes are shutdown or not. If we
    // only have shutdown routes then use those. Otherwise use active routes
    let (active, shutdown): (Vec<&Path>, Vec<&Path>) =
        path_refs.into_iter().partition(|x| x.shutdown);
    let candidates = if active.is_empty() { shutdown } else { active };

    // Filter down to paths with the best (lowest) RIB priority. This is a
    // coarse filter to roughly separate RIB paths by protocol (e.g. BGP vs Static),
    // similar to Administrative Distance on Cisco-like platforms.
    let candidates: Vec<&Path> = candidates
        .into_iter()
        .min_set_by_key(|path| path.rib_priority)
        .into_iter()
        .collect();

    // In the case where paths come from multiple protocols but have the same
    // RIB priority, follow the principle of least surprise. e.g. If a user has
    // configured a static route with the same RIB priority as BGP is using,
    // prefer the Static route.
    // TODO: update this if new upper layer protocols are added
    let (b, s): (Vec<&Path>, Vec<&Path>) =
        candidates.into_iter().partition(|path| path.bgp.is_some());

    // Some paths are static, return up to `max` paths from static routes
    if !s.is_empty() {
        let mut result = HashMap::new();
        for path in s.into_iter().take(max) {
            result.insert(path.key(), path.clone());
        }
        return Some(result);
    }

    // None of the remaining paths are static.
    // Begin comparison of BGP Path Attributes.
    Some(bgp_bestpaths(b, max))
}

/// The BGP-specific portion of the bestpath algorithm. This evaluates BGP path
/// attributes in order to determine up to `max` suitable paths.
pub fn bgp_bestpaths(
    candidates: Vec<&Path>,
    max: usize,
) -> HashMap<PathKey, Path> {
    // Filter down to paths that are not stale (Graceful Restart).
    // The `min_set_by_key` method allows us to assign "not stale" paths to the
    // `0` set, and "stale" paths to the `1` set. The method will then return
    // the `0` set if any "not stale" paths exist.
    let candidates: Vec<&Path> = candidates
        .into_iter()
        .min_set_by_key(|path| match path.bgp {
            Some(ref bgp) => match bgp.stale {
                Some(_) => 1,
                None => 0,
            },
            None => 0,
        })
        .into_iter()
        .collect();

    // Filter down to paths with the highest local preference
    let candidates: Vec<&Path> = candidates
        .into_iter()
        .max_set_by_key(|path| match path.bgp {
            Some(ref bgp) => bgp.local_pref.unwrap_or(0),
            None => 0,
        })
        .into_iter()
        .collect();

    // Filter down to paths with the shortest AS-Path length
    let candidates: Vec<&Path> = candidates
        .into_iter()
        .min_set_by_key(|path| match path.bgp {
            Some(ref bgp) => bgp.as_path.len(),
            None => 0,
        })
        .into_iter()
        .collect();

    // Group candidates by AS for MED selection using HashMap
    let mut as_groups: HashMap<u32, Vec<&Path>> = HashMap::new();
    for path in candidates {
        let origin_as = match path.bgp {
            Some(ref bgp) => bgp.origin_as,
            None => 0,
        };
        as_groups.entry(origin_as).or_default().push(path);
    }

    // Filter AS groups to paths with lowest MED
    let mut candidates: Vec<&Path> = as_groups
        .into_iter()
        .flat_map(|(_asn, paths)| {
            paths
                .into_iter()
                .min_set_by_key(|path| match path.bgp {
                    Some(ref bgp) => bgp.med.unwrap_or(0),
                    None => 0,
                })
                .into_iter()
                .collect::<Vec<_>>()
        })
        .collect();

    // Return up to max elements, in deterministic order (sorted by nexthop for consistency)
    candidates.sort_by_key(|p| p.nexthop);
    candidates.truncate(max);
    candidates
        .into_iter()
        .cloned()
        .map(|p| (p.key(), p))
        .collect()
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::str::FromStr;

    use super::bestpaths;
    use crate::{
        BgpPathProperties, DEFAULT_RIB_PRIORITY_BGP,
        DEFAULT_RIB_PRIORITY_STATIC, Path, PathKey,
    };

    // Helper function to create a BGP path with common attributes
    fn make_bgp_path(
        nexthop: IpAddr,
        peer: IpAddr,
        origin_as: u32,
        local_pref: u32,
        med: u32,
        as_path: Vec<u32>,
    ) -> Path {
        Path {
            nexthop,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as,
                peer,
                id: origin_as,
                med: Some(med),
                local_pref: Some(local_pref),
                as_path,
                stale: None,
            }),
            vlan_id: None,
        }
    }

    // Helper function to create a static path
    fn make_static_path(
        nexthop: IpAddr,
        vlan_id: Option<u16>,
        priority: u8,
    ) -> Path {
        Path {
            nexthop,
            rib_priority: priority,
            shutdown: false,
            bgp: None,
            vlan_id,
        }
    }

    // Helper function to assert a path exists in the result
    fn assert_path_in_result(result: &HashMap<PathKey, Path>, expected: &Path) {
        assert!(
            result.values().any(|p| p == expected),
            "Expected path with nexthop {:?} not found in result",
            expected.nexthop
        );
    }

    // Bestpaths is purely a function of the path info itself, so we don't
    // need a Rib or Prefix, just a set of candidate paths and a set of
    // expected paths.
    #[test]
    fn test_bestpath() {
        let peer1 = IpAddr::from_str("203.0.113.1").unwrap();
        let peer2 = IpAddr::from_str("203.0.113.2").unwrap();
        let peer3 = IpAddr::from_str("203.0.113.3").unwrap();
        let peer4 = IpAddr::from_str("203.0.113.4").unwrap();
        let mut max = 2;

        // Add one path and make sure we get it back
        let path1 =
            make_bgp_path(peer1, peer1, 470, 100, 75, vec![470, 64501, 64502]);
        let mut candidates = HashMap::new();
        candidates.insert(path1.key(), path1.clone());

        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        assert_path_in_result(&result, &path1);

        // Add path2 with same local_pref, as_path, and med
        let path2 =
            make_bgp_path(peer2, peer2, 480, 100, 75, vec![480, 64501, 64502]);
        let mut candidates = HashMap::new();
        candidates.insert(path1.key(), path1.clone());
        candidates.insert(path2.key(), path2.clone());
        let result = bestpaths(&candidates, max).unwrap();

        // we expect both paths to be selected (ECMP)
        assert_eq!(result.len(), 2);
        assert_path_in_result(&result, &path1);
        assert_path_in_result(&result, &path2);

        // Add path3 with worse (higher) MED
        let path3 =
            make_bgp_path(peer3, peer3, 490, 100, 100, vec![490, 64501, 64502]);
        let mut candidates = HashMap::new();
        candidates.insert(path1.key(), path1.clone());
        candidates.insert(path2.key(), path2.clone());
        candidates.insert(path3.key(), path3.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 2);
        // paths 1 and 2 should be selected (lowest MED)
        assert_path_in_result(&result, &path1);
        assert_path_in_result(&result, &path2);

        // Improve path3's MED to match path1 and path2
        let mut path3 = path3;
        path3.bgp.as_mut().unwrap().med = Some(75);
        max = 3;
        let mut candidates = HashMap::new();
        candidates.insert(path1.key(), path1.clone());
        candidates.insert(path2.key(), path2.clone());
        candidates.insert(path3.key(), path3.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 3);
        assert_path_in_result(&result, &path1);
        assert_path_in_result(&result, &path2);
        assert_path_in_result(&result, &path3);

        // Boost path2's local_pref - it should become the only best path
        let mut path2 = path2;
        path2.bgp.as_mut().unwrap().local_pref = Some(125);
        let mut candidates = HashMap::new();
        candidates.insert(path1.key(), path1.clone());
        candidates.insert(path2.key(), path2.clone());
        candidates.insert(path3.key(), path3.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        assert_path_in_result(&result, &path2);

        // Test static route vs BGP with different RIB priorities
        // path4 with poor (high) priority should lose to BGP
        let path4_low_priority = make_static_path(peer4, None, u8::MAX);
        let mut candidates = HashMap::new();
        candidates.insert(path1.key(), path1.clone());
        candidates.insert(path2.key(), path2.clone());
        candidates.insert(path3.key(), path3.clone());
        candidates.insert(path4_low_priority.key(), path4_low_priority.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        // BGP path2 wins (priority 20 < 255)
        assert_path_in_result(&result, &path2);

        // Lower path4's priority to static default - now it should win
        let path4_static_priority =
            make_static_path(peer4, None, DEFAULT_RIB_PRIORITY_STATIC);
        let mut candidates = HashMap::new();
        candidates.insert(path1.key(), path1.clone());
        candidates.insert(path2.key(), path2.clone());
        candidates.insert(path3.key(), path3.clone());
        candidates
            .insert(path4_static_priority.key(), path4_static_priority.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        // Static path4 wins (priority 1 < 20)
        assert_path_in_result(&result, &path4_static_priority);

        // Set path4's priority equal to BGP - static should win due to protocol preference
        let path4_bgp_priority =
            make_static_path(peer4, None, DEFAULT_RIB_PRIORITY_BGP);
        let mut candidates = HashMap::new();
        candidates.insert(path1.key(), path1.clone());
        candidates.insert(path2.key(), path2.clone());
        candidates.insert(path3.key(), path3.clone());
        candidates.insert(path4_bgp_priority.key(), path4_bgp_priority.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        // Static path4 wins over BGP (same priority, but static preferred)
        assert_path_in_result(&result, &path4_bgp_priority);
    }

    #[test]
    fn test_pathkey_replacement_same_key() {
        // Test that when two paths have the same PathKey, the second insertion
        // replaces the first one in the HashMap.
        let max = 1;
        let nexthop = IpAddr::from_str("10.0.0.1").unwrap();

        // Create path1 with priority 1
        let path1 = make_static_path(nexthop, None, 1);
        let mut candidates = HashMap::new();
        candidates.insert(path1.key(), path1.clone());
        assert_eq!(candidates.len(), 1);

        // Create path2 with same nexthop and vlan_id but priority 10
        // This has the same PathKey as path1, so it should replace it
        let path2 = make_static_path(nexthop, None, 10);
        candidates.insert(path2.key(), path2.clone());
        assert_eq!(
            candidates.len(),
            1,
            "Expected replacement, but HashMap has 2 entries"
        );

        // Verify that path2 is the only one in the HashMap
        assert_eq!(candidates.get(&path2.key()), Some(&path2));
        assert_eq!(candidates.get(&path1.key()), Some(&path2));

        // Run bestpath and verify it uses path2's priority (10, which is worse than expected)
        let result = bestpaths(&candidates, max).unwrap();
        assert_path_in_result(&result, &path2);
    }

    #[test]
    fn test_bestpath_max_parameter_limits() {
        // Test that bestpaths respects the max parameter
        let mut max = 5;
        let nexthop1 = IpAddr::from_str("10.0.0.1").unwrap();
        let nexthop2 = IpAddr::from_str("10.0.0.2").unwrap();
        let peer1 = IpAddr::from_str("192.0.2.1").unwrap();
        let peer2 = IpAddr::from_str("192.0.2.2").unwrap();
        let peer3 = IpAddr::from_str("192.0.2.3").unwrap();
        let peer4 = IpAddr::from_str("192.0.2.4").unwrap();
        let peer5 = IpAddr::from_str("192.0.2.5").unwrap();

        // Test case 1: 2 candidates, max=5 should return 2
        let path1 = make_bgp_path(nexthop1, peer1, 100, 100, 75, vec![100]);
        let path2 = make_bgp_path(nexthop2, peer2, 100, 100, 75, vec![100]);
        let mut candidates = HashMap::new();
        candidates.insert(path1.key(), path1.clone());
        candidates.insert(path2.key(), path2.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(
            result.len(),
            2,
            "With 2 candidates and max=5, expected 2 results"
        );

        // Test case 2: 5 ECMP candidates, max=2 should return 2
        let path3 = make_bgp_path(
            IpAddr::from_str("10.0.0.3").unwrap(),
            peer3,
            100,
            100,
            75,
            vec![100],
        );
        let path4 = make_bgp_path(
            IpAddr::from_str("10.0.0.4").unwrap(),
            peer4,
            100,
            100,
            75,
            vec![100],
        );
        let path5 = make_bgp_path(
            IpAddr::from_str("10.0.0.5").unwrap(),
            peer5,
            100,
            100,
            75,
            vec![100],
        );
        max = 2;
        let mut candidates = HashMap::new();
        candidates.insert(path1.key(), path1);
        candidates.insert(path2.key(), path2);
        candidates.insert(path3.key(), path3);
        candidates.insert(path4.key(), path4);
        candidates.insert(path5.key(), path5);
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(
            result.len(),
            2,
            "With 5 candidates and max=2, expected 2 results"
        );

        // Test case 3: empty HashMap should return None
        max = 10;
        let empty: HashMap<PathKey, Path> = HashMap::new();
        let result = bestpaths(&empty, max);
        assert_eq!(result, None, "Empty candidates should return None");
    }

    #[test]
    fn test_bestpath_deterministic_ordering() {
        // Test that bestpath returns results in deterministic order (sorted by nexthop).
        // This is important for consistent behavior across runs.
        let max = 3;
        let nh3 = IpAddr::from_str("10.0.0.3").unwrap();
        let nh1 = IpAddr::from_str("10.0.0.1").unwrap();
        let nh2 = IpAddr::from_str("10.0.0.2").unwrap();
        let peer1 = IpAddr::from_str("192.0.2.1").unwrap();
        let peer2 = IpAddr::from_str("192.0.2.2").unwrap();
        let peer3 = IpAddr::from_str("192.0.2.3").unwrap();

        // Create 3 ECMP paths with identical attributes but different nexthops
        // They have the same local_pref, med, as_path, so they're all equally good
        let path3 = make_bgp_path(nh3, peer3, 100, 100, 75, vec![100]);
        let path1 = make_bgp_path(nh1, peer1, 100, 100, 75, vec![100]);
        let path2 = make_bgp_path(nh2, peer2, 100, 100, 75, vec![100]);

        // Add in reverse order (3, 2, 1) to ensure sorting doesn't just rely on insertion order
        let mut candidates = HashMap::new();
        candidates.insert(path3.key(), path3.clone());
        candidates.insert(path2.key(), path2.clone());
        candidates.insert(path1.key(), path1.clone());

        // Get results
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 3);

        // Convert to sorted vector to check order
        let mut result_vec: Vec<_> = result.values().collect();
        result_vec.sort_by_key(|p| p.nexthop);

        // Verify they're sorted by nexthop
        assert_eq!(result_vec[0].nexthop, nh1);
        assert_eq!(result_vec[1].nexthop, nh2);
        assert_eq!(result_vec[2].nexthop, nh3);

        // Run multiple times to ensure consistency (deterministic)
        for _ in 0..5 {
            let result = bestpaths(&candidates, max).unwrap();
            let mut result_vec: Vec<_> = result.values().collect();
            result_vec.sort_by_key(|p| p.nexthop);
            assert_eq!(result_vec[0].nexthop, nh1);
            assert_eq!(result_vec[1].nexthop, nh2);
            assert_eq!(result_vec[2].nexthop, nh3);
        }
    }
}
