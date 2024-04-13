// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashSet;

use crate::{db::Rib, types::Path, Prefix};
use itertools::Itertools;

/// The bestpath algorithms chooses the best set of up to `max` paths for a
/// particular prefix from the RIB. The set of paths chosen will all have
/// equal MED, local_pref, AS path lenght and shutdown status. The bestpath
/// algorithm performs path filtering in the following ordered sequece of
/// operations.
///
/// - partition candidate paths into active and shutdown groups.
/// - if only shutdown routes exist, select from that group, otherwise
///   select from the active group.
/// - filter the selection group to the set of paths with the smallest
///   local preference
/// - filter the selection group to the set of paths with the smallest
///   AS path lenght
/// - filter the selection group to the set of paths with the smallest
///   multi-exit discriminator (MED).
///
/// Upon completion of these filtering operations, if the selection group
/// is larger than `max`, return the first `max` entries. This is a set,
/// so "first" has no semantic meaning, consider it to be random. If the
/// selection group is smaller than `max`, the entire group is returned.
pub fn bestpaths(prefix: Prefix, rib: &Rib, max: usize) -> HashSet<Path> {
    let candidates = match rib.get(&prefix) {
        Some(cs) => cs,
        None => return HashSet::new(),
    };

    // Partition the choice space on whether routes are shutdown or not. If we
    // only have shutdown routes then use those. Otherwise use active routes
    let (active, shutdown): (HashSet<&Path>, HashSet<&Path>) =
        candidates.iter().partition(|x| x.shutdown);
    let candidates = match (active.len(), shutdown.len()) {
        (0, _) => shutdown,
        (_, _) => active,
    };

    // Filter down to paths with the highest local preference
    let candidates = candidates
        .into_iter()
        .max_set_by_key(|x| x.local_pref.unwrap_or(0));

    // Filter down to paths with the shortest length
    let candidates = candidates.into_iter().min_set_by_key(|x| x.as_path.len());

    // Filter down to paths with the smallest MED
    let candidates = candidates
        .into_iter()
        .min_set_by_key(|x| x.med.unwrap_or(0));

    let candidates = if candidates.len() > max {
        candidates[..max].into()
    } else {
        candidates
    };

    candidates.into_iter().cloned().collect()
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use super::bestpaths;
    use crate::{db::Rib, Path, Prefix, Prefix4};

    #[test]
    fn test_bestpath() {
        let mut rib = Rib::default();
        let target: Prefix4 = "198.51.100.0/24".parse().unwrap();

        // The best path for an empty RIB should be empty
        const MAX_ECMP_FANOUT: usize = 2;
        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT);
        assert!(result.is_empty());

        // Add one path and make sure we get it back
        let path1 = Path {
            nexthop: "203.0.113.1".parse().unwrap(),
            bgp_id: 47,
            shutdown: false,
            med: Some(75),
            local_pref: Some(100),
            as_path: vec![64500, 64501, 64502],
        };
        rib.insert(target.into(), HashSet::from([path1.clone()]));

        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT);
        assert_eq!(result.len(), 1);
        assert_eq!(result, HashSet::from([path1.clone()]));

        // Add another path to the same prefix and make sure bestpath returns both
        let mut path2 = Path {
            nexthop: "203.0.113.2".parse().unwrap(),
            bgp_id: 48,
            shutdown: false,
            med: Some(75),
            local_pref: Some(100),
            as_path: vec![64500, 64501, 64502],
        };
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path2.clone());
        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT);
        assert_eq!(result.len(), 2);
        assert_eq!(result, HashSet::from([path1.clone(), path2.clone()]));

        // Add a thrid path and make sure that
        //   - results are limited to 2 paths when max is 2
        //   - we get all three paths back wihen max is 3
        let mut path3 = Path {
            nexthop: "203.0.113.3".parse().unwrap(),
            bgp_id: 49,
            shutdown: false,
            med: Some(100),
            local_pref: Some(100),
            as_path: vec![64500, 64501, 64502],
        };
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path3.clone());
        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT);
        assert_eq!(result.len(), 2);
        // paths 1 and 2 should always be selected since they have the lowest MED
        assert_eq!(result, HashSet::from([path1.clone(), path2.clone()]));

        // set the med to 75 to get an ecmp group of size 3
        rib.get_mut(&Prefix::V4(target)).unwrap().remove(&path3);
        path3.med = Some(75);
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path3.clone());
        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT + 1);
        assert_eq!(result.len(), 3);
        assert_eq!(
            result,
            HashSet::from([path1.clone(), path2.clone(), path3.clone()])
        );

        // drop the local_pref on route 2, this should make it the singular
        // best path
        rib.get_mut(&Prefix::V4(target)).unwrap().remove(&path2);
        path2.local_pref = Some(75);
        rib.get_mut(&Prefix::V4(target))
            .unwrap()
            .insert(path2.clone());
        let result = bestpaths(target.into(), &rib, MAX_ECMP_FANOUT + 1);
        assert_eq!(result.len(), 1);
        assert_eq!(result, HashSet::from([path2.clone()]));
    }
}
