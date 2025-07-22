// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use crate::{db::Rib, types::Path, Prefix};
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
/// is larger than `max`, return the first `max` entries. This is a set,
/// so "first" has no semantic meaning, consider it to be random. If the
/// selection group is smaller than `max`, the entire group is returned.
pub fn bestpaths(
    prefix: Prefix,
    rib: &Rib,
    max: usize,
) -> Option<BTreeSet<Path>> {
    let candidates = rib.get(&prefix)?;

    // Short-circuit: if there's only 1 candidate, then it is the best
    if candidates.len() == 1 {
        return Some(candidates.clone());
    }

    // Partition the choice space on whether routes are shutdown or not. If we
    // only have shutdown routes then use those. Otherwise use active routes
    let (active, shutdown): (BTreeSet<&Path>, BTreeSet<&Path>) =
        candidates.iter().partition(|path| path.shutdown);
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

    // Begin comparison of BGP Path Attributes

    // Filter down to paths that are not stale. The `min_set_by_key` method
    // allows us to assign "not stale" paths to the `0` set, and "stale" paths
    // to the `1` set. The method will then return the `0` set.
    let candidates = b.into_iter().min_set_by_key(|path| match path.bgp {
        Some(ref bgp) => match bgp.stale {
            Some(_) => 1,
            None => 0,
        },
        None => 0,
    });

    // Filter down to paths with the highest local preference
    let candidates =
        candidates
            .into_iter()
            .max_set_by_key(|path| match path.bgp {
                Some(ref bgp) => bgp.local_pref.unwrap_or(0),
                None => 0,
            });

    // Filter down to paths with the shortest AS-Path length
    let candidates =
        candidates
            .into_iter()
            .min_set_by_key(|path| match path.bgp {
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
        paths.min_set_by_key(|path| match path.bgp {
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
        db::Rib, BgpPathProperties, Path, Prefix, Prefix4,
        DEFAULT_RIB_PRIORITY_BGP, DEFAULT_RIB_PRIORITY_STATIC,
    };

    #[test]
    fn test_bestpath() {
        let mut rib = Rib::default();
        let target: Prefix4 = "198.51.100.0/24".parse().unwrap();
        let remote_ip1 = IpAddr::from_str("203.0.113.1").unwrap();
        let remote_ip2 = IpAddr::from_str("203.0.113.2").unwrap();
        let remote_ip3 = IpAddr::from_str("203.0.113.3").unwrap();
        let remote_ip4 = IpAddr::from_str("203.0.113.4").unwrap();

        // The best path for an empty RIB should be empty
        const MAX_ECMP_FANOUT: usize = 2;
        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT);
        assert!(result.is_none());

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
                as_path: vec![64500, 64501, 64502],
                stale: None,
            }),
            vlan_id: None,
        };
        rib.insert(target.into(), BTreeSet::from([path1.clone()]));

        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result, BTreeSet::from([path1.clone()]));

        // Add another path to the same prefix and make sure bestpath returns both
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
                as_path: vec![64500, 64501, 64502],
                stale: None,
            }),
            vlan_id: None,
        };
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path2.clone());
        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result, BTreeSet::from([path1.clone(), path2.clone()]));

        // Add a third path and make sure that
        //   - results are limited to 2 paths when max is 2
        //   - we get all three paths back wihen max is 3
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
                as_path: vec![64500, 64501, 64502],
                stale: None,
            }),
            vlan_id: None,
        };
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path3.clone());
        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT).unwrap();
        assert_eq!(result.len(), 2);
        // paths 1 and 2 should always be selected since they have the lowest MED
        assert_eq!(result, BTreeSet::from([path1.clone(), path2.clone()]));

        // set the med to 75 to get an ecmp group of size 3
        rib.get_mut(&Prefix::V4(target)).unwrap().remove(&path3);
        path3.bgp.as_mut().unwrap().med = Some(75);
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path3.clone());
        let result =
            bestpaths(target.into(), &rib, MAX_ECMP_FANOUT + 1).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(
            result,
            BTreeSet::from([path1.clone(), path2.clone(), path3.clone()])
        );

        // bump the local_pref on route 2, this should make it the singular
        // best path
        rib.get_mut(&Prefix::V4(target)).unwrap().remove(&path2);
        path2.bgp.as_mut().unwrap().local_pref = Some(125);
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path2.clone());
        let result =
            bestpaths(target.into(), &rib, MAX_ECMP_FANOUT + 1).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result, BTreeSet::from([path2.clone()]));

        // Add a fourth path (which is static) and make sure that:
        // - path 4 loses to BGP paths with higher RIB priority
        // - path 4 wins over BGP paths with lower RIB priority
        // - path 4 wins over BGP paths with equal RIB priority
        let mut path4 = Path {
            nexthop: remote_ip4,
            rib_priority: u8::MAX,
            shutdown: false,
            bgp: None,
            vlan_id: None,
        };
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path4.clone());
        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result, BTreeSet::from([path2.clone()]));

        // Lower the RIB Priority to beat BGP
        rib.get_mut(&Prefix::V4(target)).unwrap().remove(&path4);
        path4.rib_priority = DEFAULT_RIB_PRIORITY_STATIC;
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path4.clone());
        let result =
            bestpaths(target.into(), &rib, MAX_ECMP_FANOUT + 1).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result, BTreeSet::from([path4.clone()]));

        // Raise the RIB Priority to match BGP
        rib.get_mut(&Prefix::V4(target)).unwrap().remove(&path4);
        path4.rib_priority = DEFAULT_RIB_PRIORITY_BGP;
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path4.clone());
        let result =
            bestpaths(target.into(), &rib, MAX_ECMP_FANOUT + 1).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result, BTreeSet::from([path4.clone()]));
    }
}
