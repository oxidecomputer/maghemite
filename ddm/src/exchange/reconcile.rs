// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Side-effect-free reconciliation management shared by exchange
//! runtime paths, taking state in as arguments and returning updates
//! without database or network effects.

use ddm_api_types::net::MulticastOrigin;
use ddm_protocol::v4::{
    MulticastPathHop, MulticastPathVector, MulticastUpdate,
};

/// Rewrite each withdrawal as a replacement announcement when another path to
/// the origin remains, and as a final withdrawal otherwise.
///
/// Downstream peers keep exactly one route per `(origin, nexthop)`, with this
/// router as the nexthop, regardless of how many paths line up behind it.
/// Blindly forwarding a withdrawal would drop the peer's only route through
/// this router even when the origin is still reachable in another way. For each
/// withdrawal, this checks the local origins first, then the best entry in
/// the imported set. A remaining path produces an announcement with a
/// refreshed path vector.
///
/// Only when nothing remains is the final withdrawal emitted with `local_hop`
/// appended.
///
/// The reachability snapshot always describes post-modification state. Peer
/// expiry and renumber capture it in `remove_nexthop_routes`, exchange
/// updates in `update_imported_mcast`, and the admin withdraws read it at
/// processing time via `multicast_reachability`, which is still
/// post-modification because the event is enqueued only after the
/// modification lands.
pub(crate) fn reconcile_multicast_withdrawals<'a>(
    withdrawals: impl IntoIterator<Item = &'a MulticastPathVector>,
    reachability: &crate::db::MulticastReachability,
    local_hop: &MulticastPathHop,
) -> MulticastUpdate {
    let mut update = MulticastUpdate::default();

    for withdrawal in withdrawals {
        let replacement = MulticastOrigin::try_from(&withdrawal.origin)
            .ok()
            .and_then(|origin| {
                if let Some(local_origin) =
                    reachability.originated().get(&origin)
                {
                    return Some(MulticastPathVector {
                        origin: local_origin.into(),
                        path: vec![local_hop.clone()],
                    });
                }

                reachability
                    .imported()
                    .iter()
                    .filter(|route| route.origin == origin)
                    // Route identity guarantees one entry per nexthop for this
                    // origin. Address order is only a stable tie-breaker (it
                    // does not assign semantics to multicast metric).
                    .min_by_key(|route| route.nexthop)
                    .map(|route| {
                        let mut path = route.path.clone();
                        path.push(local_hop.clone());
                        MulticastPathVector {
                            origin: (&route.origin).into(),
                            path,
                        }
                    })
            });

        match replacement {
            Some(replacement) => {
                update.announce.insert(replacement);
            }
            // A degraded snapshot cannot confirm the absence of a local
            // origin, so a final withdrawal here could tear down a route to
            // an origin that is still reachable. Dropping the withdrawal is
            // the safe direction. The worst case is a transient stale route
            // to an origin that really is gone, while a false withdrawal
            // could remove a peer's only path through this router. The
            // periodic exchange resync repairs the drift either way.
            None if reachability.origins_degraded() => {}
            None => {
                update
                    .withdraw
                    .insert(withdrawal.with_hop(local_hop.clone()));
            }
        }
    }

    update
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Db, MulticastReachability};
    use ddm_api_types::db::MulticastRoute;
    use slog::Logger;
    use std::collections::HashSet;
    use std::net::Ipv6Addr;
    use tempfile::TempDir;

    fn origin(metric: u64) -> MulticastOrigin {
        serde_json::from_value(serde_json::json!({
            "overlay_group": "233.252.0.1",
            "underlay_group": "ff04::1",
            "vni": 77,
            "metric": metric,
        }))
        .unwrap()
    }

    fn hop(router_id: &str, last: u16) -> MulticastPathHop {
        MulticastPathHop::new(
            router_id.to_string(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last),
        )
    }

    /// Build a `MulticastReachability` snapshot through `Db` persistence
    /// rather than constructing it by hand, so tests exercise the same
    /// snapshot path production uses. Any origins in `originated` are
    /// persisted before the imported set is applied, so the captured
    /// snapshot reflects both sources of reachability.
    fn snapshot(
        imported: HashSet<MulticastRoute>,
        originated: HashSet<MulticastOrigin>,
    ) -> (TempDir, MulticastReachability) {
        let dir = TempDir::new().unwrap();
        let log = Logger::root(slog::Discard, slog::o!());
        let db = Db::new(dir.path().to_str().unwrap(), log).unwrap();
        if !originated.is_empty() {
            db.originate_mcast(&originated).unwrap();
        }
        let (_delta, reachability) = db
            .update_imported_mcast_with_reachability(
                &imported,
                &HashSet::new(),
            );
        (dir, reachability)
    }

    #[test]
    fn remaining_import_replaces_withdrawal_and_refreshes_path() {
        let origin = origin(10);
        let withdrawn = MulticastPathVector {
            origin: (&origin).into(),
            path: vec![hop("withdrawn", 1)],
        };
        let remaining_hop = hop("remaining", 2);
        let imported = HashSet::from([MulticastRoute {
            origin: origin.clone(),
            nexthop: "fe80::2".parse().unwrap(),
            path: vec![remaining_hop.clone()],
        }]);
        let local_hop = hop("local", 3);
        let (_dir, remaining) = snapshot(imported, HashSet::new());

        let update = reconcile_multicast_withdrawals(
            [&withdrawn],
            &remaining,
            &local_hop,
        );

        assert!(update.withdraw.is_empty());
        let replacement = update.announce.iter().next().unwrap();
        assert_eq!(replacement.path, vec![remaining_hop, local_hop]);
    }

    #[test]
    fn remaining_local_origin_replaces_withdrawal() {
        let origin = origin(10);
        let withdrawn = MulticastPathVector {
            origin: (&origin).into(),
            path: vec![hop("withdrawn", 1)],
        };
        let local_hop = hop("local", 3);
        let (_dir, remaining) =
            snapshot(HashSet::new(), HashSet::from([origin]));

        let update = reconcile_multicast_withdrawals(
            [&withdrawn],
            &remaining,
            &local_hop,
        );

        assert!(update.withdraw.is_empty());
        let replacement = update.announce.iter().next().unwrap();
        assert_eq!(replacement.path, vec![local_hop]);
    }

    #[test]
    fn final_withdrawal_preserves_path_and_appends_local_hop() {
        let origin = origin(10);
        let withdrawn_hop = hop("withdrawn", 1);
        let withdrawn = MulticastPathVector {
            origin: (&origin).into(),
            path: vec![withdrawn_hop.clone()],
        };
        let local_hop = hop("local", 3);
        let (_dir, remaining) = snapshot(HashSet::new(), HashSet::new());

        let update = reconcile_multicast_withdrawals(
            [&withdrawn],
            &remaining,
            &local_hop,
        );

        assert!(update.announce.is_empty());
        let forwarded = update.withdraw.iter().next().unwrap();
        assert_eq!(forwarded.path, vec![withdrawn_hop, local_hop]);
    }

    /// The processing-time read path used by admin withdraw
    /// revalidation must observe both persisted origins and the current
    /// imported set.
    #[test]
    fn multicast_reachability_reads_current_imported_and_originated() {
        let dir = TempDir::new().unwrap();
        let log = Logger::root(slog::Discard, slog::o!());
        let db = Db::new(dir.path().to_str().unwrap(), log).unwrap();

        // Distinct overlay/underlay groups so identity-based equality on
        // `MulticastOrigin` keeps the persisted and imported origins apart.
        let local_origin: MulticastOrigin =
            serde_json::from_value(serde_json::json!({
                "overlay_group": "233.252.0.1",
                "underlay_group": "ff04::1",
                "vni": 77,
                "metric": 10,
            }))
            .unwrap();

        let imported_origin: MulticastOrigin =
            serde_json::from_value(serde_json::json!({
                "overlay_group": "233.252.0.2",
                "underlay_group": "ff04::2",
                "vni": 77,
                "metric": 20,
            }))
            .unwrap();

        let route = MulticastRoute {
            origin: imported_origin,
            nexthop: "fe80::2".parse().unwrap(),
            path: vec![hop("remote", 2)],
        };

        db.originate_mcast(&HashSet::from([local_origin.clone()]))
            .unwrap();
        db.update_imported_mcast(
            &HashSet::from([route.clone()]),
            &HashSet::new(),
        );

        let reachability = db.multicast_reachability();
        assert_eq!(reachability.imported(), &HashSet::from([route]));
        assert_eq!(reachability.originated(), &HashSet::from([local_origin]));
    }
}
