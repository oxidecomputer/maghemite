// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use crate::{db::Rib, types::Path, Prefix};
use itertools::Itertools;

/// The bestpath algorithms chooses the best set of up to `max` paths for a
/// particular prefix from the RIB. The set of paths chosen will all have
/// equal MED, local_pref, AS path length and shutdown status. The bestpath
/// algorithm performs path filtering in the following ordered sequece of
/// operations.
///
/// - partition candidate paths into active and shutdown groups.
/// - if only shutdown routes exist, select from that group, otherwise
///   select from the active group.
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
pub fn bestpaths(
    prefix: Prefix,
    rib: &Rib,
    max: usize,
) -> Option<BTreeSet<Path>> {
    let candidates = match rib.get(&prefix) {
        Some(cs) => cs,
        None => return None,
    };

    // Partition the choice space on whether routes are shutdown or not. If we
    // only have shutdown routes then use those. Otherwise use active routes
    let (active, shutdown): (BTreeSet<&Path>, BTreeSet<&Path>) =
        candidates.iter().partition(|x| x.shutdown);
    let candidates = if active.is_empty() { shutdown } else { active };

    // Filter down to paths that are not stale. The `min_set_by_key` method
    // allows us to assign "not stale" paths to the `0` set, and "stale" paths
    // to the `1` set. The method will then return the `0` set.
    let candidates = candidates.into_iter().min_set_by_key(|x| match x.bgp {
        Some(ref bgp) => match bgp.stale {
            Some(_) => 1,
            None => 0,
        },
        None => 0,
    });

    // Filter down to paths with the highest local preference
    let candidates = candidates
        .into_iter()
        .max_set_by_key(|x| x.local_pref.unwrap_or(0));

    // Filter down to paths with the shortest length
    let candidates = candidates.into_iter().min_set_by_key(|x| match x.bgp {
        Some(ref bgp) => bgp.as_path.len(),
        None => 0,
    });

    // Group candidates by AS for MED selection
    let as_groups = candidates.into_iter().group_by(|path| match path.bgp {
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

    use super::bestpaths;
    use crate::{db::Rib, BgpPathProperties, Path, Prefix, Prefix4};

    #[test]
    fn test_bestpath() {
        let mut rib = Rib::default();
        let target: Prefix4 = "198.51.100.0/24".parse().unwrap();

        // The best path for an empty RIB should be empty
        const MAX_ECMP_FANOUT: usize = 2;
        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT);
        assert!(result.is_none());

        // Add one path and make sure we get it back
        let path1 = Path {
            nexthop: "203.0.113.1".parse().unwrap(),
            local_pref: Some(100),
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 470,
                id: 47,
                med: Some(75),
                stale: None,
                as_path: vec![64500, 64501, 64502],
            }),
            vlan_id: None,
        };
        rib.insert(target.into(), BTreeSet::from([path1.clone()]));

        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result, BTreeSet::from([path1.clone()]));

        // Add another path to the same prefix and make sure bestpath returns both
        let mut path2 = Path {
            nexthop: "203.0.113.2".parse().unwrap(),
            local_pref: Some(100),
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 480,
                id: 48,
                med: Some(75),
                stale: None,
                as_path: vec![64500, 64501, 64502],
            }),
            vlan_id: None,
        };
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path2.clone());
        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result, BTreeSet::from([path1.clone(), path2.clone()]));

        // Add a thrid path and make sure that
        //   - results are limited to 2 paths when max is 2
        //   - we get all three paths back wihen max is 3
        let mut path3 = Path {
            nexthop: "203.0.113.3".parse().unwrap(),
            local_pref: Some(100),
            shutdown: false,
            bgp: Some(BgpPathProperties {
                origin_as: 490,
                id: 49,
                med: Some(100),
                stale: None,
                as_path: vec![64500, 64501, 64502],
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
        path2.local_pref = Some(125);
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path2.clone());
        let result =
            bestpaths(target.into(), &rib, MAX_ECMP_FANOUT + 1).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result, BTreeSet::from([path2.clone()]));
    }
}
