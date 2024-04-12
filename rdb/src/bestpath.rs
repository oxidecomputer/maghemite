// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{db::Rib, types::Path, Prefix};
use itertools::Itertools;

pub fn bestpaths(prefix: Prefix, rib: &Rib, max: usize) -> Vec<Path> {
    let candidates = match rib.get(&prefix) {
        Some(cs) => cs,
        None => return Vec::new(),
    };

    // Partition the choice space on whether routes are shutdown or not. If we
    // only have shutdown routes then use those. Otherwise use active routes
    let (active, shutdown): (Vec<&Path>, Vec<&Path>) =
        candidates.iter().partition(|x| x.shutdown);
    let candidates = match (active.len(), shutdown.len()) {
        (0, _) => shutdown,
        (_, _) => active,
    };

    // Filter down to paths with the shortest local preference
    let candidates = candidates
        .into_iter()
        .min_set_by_key(|x| x.local_pref.unwrap_or(0));

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
