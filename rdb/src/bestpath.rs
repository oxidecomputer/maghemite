// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use crate::types::Path;
use itertools::Itertools;

/// The bestpath algorithms chooses the best set of up to `max` paths for a
/// particular prefix from the RIB. The set of paths chosen will all have
/// equal RIB priority, MED, local_pref, AS path length and shutdown status.
/// The bestpath algorithm performs path filtering in the following ordered
/// sequece of operations.
///
/// - partition candidate paths into active and shutdown groups.
/// - if only shutdown routes exist, select from that group, otherwise
///   select from the active group.
/// - filter the selection group to the set of paths with the smallest
///   rib priority
/// - filter the selection group to the set of paths with the smallest
///   local preference
/// - filter the selection group to the set of paths with the smallest
///   AS path length
/// - filter the selection group to the set of paths with the smallest
///   multi-exit discriminator (MED) on a per-AS basis.
///
/// Upon completion of these filtering operations, if the selection group
/// is larger than `max`, return the first `max` entries. This is a set,
/// so "first" has no semantic meaning, consider it to be random. If the
/// selection group is smaller than `max`, the entire group is returned.
pub fn bestpaths(paths: &BTreeSet<Path>, max: usize) -> Option<BTreeSet<Path>> {
    // Partition the choice space on whether routes are shutdown or not. If we
    // only have shutdown routes then use those. Otherwise use active routes
    let (active, shutdown): (BTreeSet<&Path>, BTreeSet<&Path>) =
        paths.iter().partition(|x| x.shutdown);
    let candidates = if active.is_empty() { shutdown } else { active };

    // Filter down to paths with the best (lowest) RIB priority. This is a
    // coarse filter to roughly separate RIB paths by protocol (e.g. BGP vs Static),
    // similar to Administrative Distance on Cisco-like platforms.
    let candidates = candidates.into_iter().min_set_by_key(|x| x.rib_priority);

    // In the case where paths come from multiple protocols but have the same
    // RIB priority, follow the principle of least surprise. e.g. If a user has
    // configured a static route with the same RIB priority as BGP is using,
    // prefer the Static route.
    // TODO: update this if new upper layer protocols are added
    let (b, s): (BTreeSet<&Path>, BTreeSet<&Path>) =
        candidates.into_iter().partition(|x| x.bgp.is_some());

    if !s.is_empty() {
        // Some paths are static, return up to max paths from static routes
        return Some(s.into_iter().take(max).cloned().collect());
    }

    // Begin comparison of BGP Path Attributes

    // Filter down to paths that are not stale. The `min_set_by_key` method
    // allows us to assign "not stale" paths to the `0` set, and "stale" paths
    // to the `1` set. The method will then return the `0` set.
    let candidates = b.into_iter().min_set_by_key(|x| match x.bgp {
        Some(ref bgp) => match bgp.stale {
            Some(_) => 1,
            None => 0,
        },
        None => 0,
    });

    // Filter down to paths with the highest local preference
    let candidates = candidates.into_iter().max_set_by_key(|x| match x.bgp {
        Some(ref bgp) => bgp.local_pref.unwrap_or(0),
        None => 0,
    });

    // Filter down to paths with the shortest length
    let candidates = candidates.into_iter().min_set_by_key(|x| match x.bgp {
        Some(ref bgp) => bgp.as_path.len(),
        None => 0,
    });

    // Group candidates by AS for MED selection
    let as_groups = candidates.into_iter().chunk_by(|path| match path.bgp {
        Some(ref bgp) => bgp.origin_as,
        None => 0,
    });

    // Filter AS groups to paths with lowest MED
    let candidates = as_groups.into_iter().flat_map(|(_asn, paths)| {
        paths.min_set_by_key(|x| match x.bgp {
            Some(ref bgp) => bgp.med.unwrap_or(0),
            None => 0,
        })
    });

    // Return up to max elements
    Some(candidates.take(max).cloned().collect())
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;
    use std::net::IpAddr;
    use std::str::FromStr;

    use super::bestpaths;
    use crate::{
        BgpPathProperties, Path, DEFAULT_RIB_PRIORITY_BGP,
        DEFAULT_RIB_PRIORITY_STATIC,
    };

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
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 470,
                peer: remote_ip1,
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
        assert_eq!(result, BTreeSet::from([path1.clone()]));

        // Add path2:
        let mut path2 = Path {
            nexthop: remote_ip2,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 480,
                peer: remote_ip2,
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
        assert_eq!(result, BTreeSet::from([path1.clone(), path2.clone()]));

        // Add path3 with:
        // - matching local-pref
        // - matching as-path-len
        // - worse (higher) med
        let mut path3 = Path {
            nexthop: remote_ip3,
            rib_priority: DEFAULT_RIB_PRIORITY_BGP,
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 490,
                peer: remote_ip3,
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
        // paths 1 and 2 should always be selected since they have the lowest MED
        assert_eq!(result, BTreeSet::from([path1.clone(), path2.clone()]));

        // increase max paths to 3
        max = 3;

        // set the med to 75 (matching path1/path2) and re-run bestpath w/
        // max paths set to 3. path3 should now be part of the ecmp group returned.
        let mut candidates = result.clone();
        candidates.remove(&path3);
        path3.bgp.as_mut().unwrap().med = Some(75);
        candidates.insert(path3.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(
            result,
            BTreeSet::from([path1.clone(), path2.clone(), path3.clone()])
        );

        // bump the local_pref on path2, this should make it the singular
        // best path regardless of max paths
        let mut candidates = result.clone();
        candidates.remove(&path2);
        path2.bgp.as_mut().unwrap().local_pref = Some(125);
        candidates.insert(path2.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result, BTreeSet::from([path2.clone()]));

        // Add a fourth path (which is static) and make sure that:
        // - path 4 loses to BGP paths with higher RIB priority
        // - path 4 wins over BGP paths with lower RIB priority
        // - path 4 wins over BGP paths with equal RIB priority
        //   > static is preferred over bgp when RIB priority matches
        let mut path4 = Path {
            nexthop: remote_ip4,
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
        assert_eq!(result, BTreeSet::from([path2.clone()]));

        // Lower the RIB Priority (better)
        let mut candidates = result.clone();
        candidates.remove(&path4);
        path4.rib_priority = DEFAULT_RIB_PRIORITY_STATIC;
        candidates.insert(path4.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        // path4 (static) has the best (lower) rib priority
        assert_eq!(result, BTreeSet::from([path4.clone()]));

        // Raise the RIB Priority equal to BGP (paths 1-3)
        let mut candidates = result.clone();
        candidates.remove(&path4);
        path4.rib_priority = DEFAULT_RIB_PRIORITY_BGP;
        candidates.insert(path4.clone());
        let result = bestpaths(&candidates, max).unwrap();
        assert_eq!(result.len(), 1);
        // path4 (static) wins due to protocol preference
        // i.e. static > bgp when rib priority matches
        assert_eq!(result, BTreeSet::from([path4.clone()]));
    }
}
