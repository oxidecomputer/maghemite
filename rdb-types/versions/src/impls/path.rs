// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::latest::path::{BgpPathProperties, Path};
use chrono::Utc;
use std::cmp::Ordering;

// Ord defines path *identity* for BTreeSet membership.
//
// A path's identity determines when insert() is a no-op and when
// replace() overwrites an existing entry. Attributes like shutdown,
// rib_priority, med, local_pref, etc. are NOT part of identity —
// they are carried on a path and can be updated via replace().
//
// Identity rules:
// - BGP path:    identified solely by PeerId
// - Static path: identified by (nexthop, nexthop_interface, vlan_id)
// - BGP and static paths are never the same path
//
// Note: this intentionally disagrees with derived Eq (which compares
// all fields). Eq gives structural equality; Ord gives set identity.
impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Path {
    fn cmp(&self, other: &Self) -> Ordering {
        match (&self.bgp, &other.bgp) {
            // BGP path identity is purely PeerId.
            (Some(a), Some(b)) => a.peer.cmp(&b.peer),

            // Static path identity is
            // (nexthop, nexthop_interface, vlan_id).
            (None, None) => self
                .nexthop
                .cmp(&other.nexthop)
                .then_with(|| {
                    self.nexthop_interface.cmp(&other.nexthop_interface)
                })
                .then_with(|| self.vlan_id.cmp(&other.vlan_id)),

            // BGP and static paths are never the same path.
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
        }
    }
}

impl BgpPathProperties {
    pub fn as_stale(&self) -> Self {
        let mut s = self.clone();
        s.stale = Some(Utc::now());
        s
    }
}
