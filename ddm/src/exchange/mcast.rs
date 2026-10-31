// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multicast update reconciliation.
//!
//! An outgoing multicast update can wait in a peer state machine's event
//! queue while routes change elsewhere. Before sending it out, the state
//! machine takes a fresh path snapshot and reconciles the update against
//! it.
//!
//! An announcement whose origin has no remaining path is dropped, as the
//! peer would then route through this router to a group this router can no
//! longer reach.
//!
//! An announcement for a reachable origin is sent through the preferred path
//! from the snapshot and not on the path it arrived with. A peer keeps one
//! route per nexthop, and we want to avoid a worse path announced later
//! replacing a better one through this router.
//!
//! A withdrawal whose origin still has another path is sent as an
//! announcement instead. Forwarding the withdrawal would make the peer drop
//! its route through this router even though the group is still reachable.
//! The announcement carries the remaining path, so the peer keeps its route
//! and only the path changes.

use std::collections::HashSet;

use ddm_protocol::v4::{
    MulticastOrigin, MulticastPathHop, MulticastPathVector, MulticastUpdate,
};

/// Reconcile an outgoing multicast update against current reachability.
///
/// An origin is reachable when the path snapshot has a path for it,
/// which is either a local origin or an imported route whose path does not
/// pass through the target peer.
///
/// Announcements are dropped when the same update withdraws their origin or
/// when the origin is no longer reachable. A retained announcement is sent
/// through the preferred path, the same one a pull or a withdrawal
/// replacement would use.
///
/// Withdrawals for origins that are still reachable become announcements.
/// A downstream peer keeps one route per `(origin, nexthop)`. Forwarding a
/// withdrawal unconditionally would remove its route through us even when
/// another path remains.
///
/// The preferred path is a local origin first, then the imported route
/// selected by the snapshot.
///
/// Final withdrawals append `local_hop` to the supplied path.
pub(crate) fn reconcile_multicast_update(
    mut update: MulticastUpdate,
    paths: &crate::db::McastPathSnapshot,
    local_hop: &MulticastPathHop,
) -> MulticastUpdate {
    let preferred = |origin: &MulticastOrigin| {
        paths
            .originated()
            .and_then(|originated| originated.get(origin))
            .map(|local_origin| MulticastPathVector {
                origin: local_origin.clone(),
                path: vec![local_hop.clone()],
            })
            .or_else(|| {
                paths.imported(origin).map(|route| {
                    let mut path = route.path.clone();
                    path.push(local_hop.clone());
                    MulticastPathVector {
                        origin: route.origin.clone(),
                        path,
                    }
                })
            })
    };

    let withdrawing: HashSet<_> =
        update.withdraw.iter().map(|pv| pv.origin.clone()).collect();
    update.announce = std::mem::take(&mut update.announce)
        .into_iter()
        .filter(|pv| !withdrawing.contains(&pv.origin))
        .filter_map(|pv| preferred(&pv.origin))
        .collect();
    let withdrawals = std::mem::take(&mut update.withdraw);

    for mut withdrawal in withdrawals {
        match preferred(&withdrawal.origin) {
            Some(replacement) => {
                update.announce.insert(replacement);
            }
            // A failed origin read cannot confirm the final withdrawal.
            // We keep the route around until a complete resync, as a false
            // withdrawal can remove the peer's only path through this router.
            None if paths.originated().is_none() => {}
            None => {
                withdrawal.path.push(local_hop.clone());
                update.withdraw.insert(withdrawal);
            }
        }
    }

    update
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::Ipv6Addr;

    use camino_tempfile::Utf8TempDir;
    use ddm_api_types::db::MulticastRoute;
    use ddm_api_types::net::{
        MulticastOrigin, OverlayMulticast, UnderlayMulticastIpv6, Vni,
    };
    use ddm_protocol::RouterId;
    use slog::Logger;

    use super::*;
    use crate::db::mcast::tests::corrupt_mcast_origin_store;
    use crate::db::{Db, McastPathSnapshot, MulticastRibChange};

    const NO_PEER: RouterId = RouterId::new(String::new());

    fn origin(overlay: &str, underlay: &str, metric: u64) -> MulticastOrigin {
        MulticastOrigin::new(
            OverlayMulticast::new(overlay.parse().unwrap()).unwrap(),
            UnderlayMulticastIpv6::new(underlay.parse().unwrap()).unwrap(),
            Vni::new(77).unwrap(),
            None,
        )
        .unwrap()
        .with_metric(metric)
    }

    fn hop(router_id: &str, last: u16) -> MulticastPathHop {
        MulticastPathHop::new(
            router_id.into(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last),
        )
    }

    /// Build a `McastPathSnapshot` through `Db` persistence.
    fn snapshot(
        imported: HashSet<MulticastRoute>,
        originated: HashSet<MulticastOrigin>,
    ) -> McastPathSnapshot {
        let dir = Utf8TempDir::new().unwrap();
        let log = Logger::root(slog::Discard, slog::o!());
        let db = Db::new(dir.path().as_str(), log).unwrap();
        if !originated.is_empty() {
            db.originate_mcast(&originated).unwrap();
        }
        db.update_imported_mcast(MulticastRibChange::new(
            &imported,
            &HashSet::new(),
        ));

        let origins = imported
            .iter()
            .map(|route| &route.origin)
            .chain(&originated);
        db.snapshot_mcast_paths(origins, &NO_PEER)
    }

    #[test]
    fn remaining_import_replaces_withdrawal_and_refreshes_path() {
        let origin = origin("233.252.0.1", "ff04::1", 10);
        let withdrawn = MulticastPathVector {
            origin: origin.clone(),
            path: vec![hop("withdrawn", 1)],
        };
        let remaining_hop = hop("remaining", 2);
        let imported = HashSet::from([MulticastRoute {
            origin: origin.clone(),
            nexthop: "fe80::2".parse().unwrap(),
            path: vec![remaining_hop.clone()],
        }]);
        let local_hop = hop("local", 3);
        let remaining = snapshot(imported, HashSet::new());

        let update = reconcile_multicast_update(
            MulticastUpdate::withdraw(HashSet::from([withdrawn])),
            &remaining,
            &local_hop,
        );

        assert!(update.withdraw.is_empty());
        assert_eq!(
            update.announce,
            HashSet::from([MulticastPathVector {
                origin,
                path: vec![remaining_hop, local_hop],
            }]),
        );
    }

    #[test]
    fn remaining_local_origin_replaces_withdrawal() {
        let origin = origin("233.252.0.1", "ff04::1", 10);
        let withdrawn = MulticastPathVector {
            origin: origin.clone().with_metric(20),
            path: vec![hop("withdrawn", 1)],
        };
        let local_hop = hop("local", 3);
        let remaining =
            snapshot(HashSet::new(), HashSet::from([origin.clone()]));

        let update = reconcile_multicast_update(
            MulticastUpdate::withdraw(HashSet::from([withdrawn])),
            &remaining,
            &local_hop,
        );

        assert!(update.withdraw.is_empty());
        assert_eq!(
            update.announce,
            HashSet::from([MulticastPathVector {
                origin,
                path: vec![local_hop],
            }]),
        );
        let announced = update.announce.iter().next().unwrap();
        assert_eq!(announced.origin.metric(), 10);
    }

    /// A local origin takes precedence over an imported copy during
    /// replacement.
    #[test]
    fn local_origin_preferred_over_imported() {
        let local_origin = origin("233.252.0.1", "ff04::1", 10);
        let imported_origin = local_origin.clone().with_metric(20);
        let imported = HashSet::from([MulticastRoute {
            origin: imported_origin.clone(),
            nexthop: "fe80::2".parse().unwrap(),
            path: vec![hop("remote", 2)],
        }]);
        let withdrawn = MulticastPathVector {
            origin: imported_origin,
            path: vec![hop("withdrawn", 1)],
        };
        let local_hop = hop("local", 3);
        let remaining = snapshot(imported, HashSet::from([local_origin]));

        let update = reconcile_multicast_update(
            MulticastUpdate::withdraw(HashSet::from([withdrawn])),
            &remaining,
            &local_hop,
        );

        assert!(update.withdraw.is_empty());
        assert_eq!(update.announce.len(), 1);
        let announced = update.announce.iter().next().unwrap();
        assert_eq!(announced.path, vec![local_hop]);
        assert_eq!(announced.origin.metric(), 10);
    }

    /// Imported replacements use nexthop ordering to choose a path.
    #[test]
    fn lowest_nexthop_wins_among_imported_paths() {
        let origin = origin("233.252.0.1", "ff04::1", 10);
        let low_hop = hop("low", 1);
        let high_hop = hop("high", 2);
        let imported = HashSet::from([
            MulticastRoute {
                origin: origin.clone(),
                nexthop: "fe80::2".parse().unwrap(),
                path: vec![high_hop],
            },
            MulticastRoute {
                origin: origin.clone(),
                nexthop: "fe80::1".parse().unwrap(),
                path: vec![low_hop.clone()],
            },
        ]);
        let withdrawn = MulticastPathVector {
            origin,
            path: vec![hop("withdrawn", 4)],
        };
        let local_hop = hop("local", 3);
        let remaining = snapshot(imported, HashSet::new());

        let update = reconcile_multicast_update(
            MulticastUpdate::withdraw(HashSet::from([withdrawn])),
            &remaining,
            &local_hop,
        );

        assert!(update.withdraw.is_empty());
        assert_eq!(update.announce.len(), 1);
        let announced = update.announce.iter().next().unwrap();
        assert_eq!(announced.path, vec![low_hop, local_hop]);
    }

    #[test]
    fn announcements_use_the_preferred_path() {
        let by_metric = origin("233.252.0.1", "ff04::1", 10);
        let by_length = origin("233.252.0.2", "ff04::2", 10);
        let route =
            |origin: &MulticastOrigin, metric, last, path| MulticastRoute {
                origin: origin.clone().with_metric(metric),
                nexthop: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last),
                path,
            };

        // Only choosing by nexthop would select the route with metric 20.
        let preferred_metric =
            route(&by_metric, 10, 2, vec![hop("metric-10", 2), hop("a", 5)]);

        let a_worse_metric =
            route(&by_metric, 20, 1, vec![hop("metric-20", 1), hop("b", 6)]);

        let shorter = route(&by_length, 10, 3, vec![hop("short", 3)]);
        let longer = route(
            &by_length,
            10,
            4,
            vec![hop("long", 4), hop("c", 7), hop("d", 8)],
        );
        let local_hop = hop("local", 9);
        let paths = snapshot(
            HashSet::from([
                preferred_metric.clone(),
                a_worse_metric.clone(),
                shorter.clone(),
                longer.clone(),
            ]),
            HashSet::new(),
        );
        let pushed = |route: &MulticastRoute| {
            MulticastPathVector {
                origin: route.origin.clone(),
                path: route.path.clone(),
            }
            .with_hop(local_hop.clone())
        };

        let update = reconcile_multicast_update(
            MulticastUpdate::announce(HashSet::from([
                pushed(&a_worse_metric),
                pushed(&longer),
            ])),
            &paths,
            &local_hop,
        );

        assert!(update.withdraw.is_empty());
        assert_eq!(
            update.announce,
            HashSet::from([pushed(&preferred_metric), pushed(&shorter)]),
        );
        // We check the value separately because origin equality ignores metric.
        let announced: Vec<_> = update
            .announce
            .iter()
            .filter(|pv| pv.origin == by_metric)
            .map(|pv| pv.origin.metric())
            .collect();
        assert_eq!(announced, vec![10]);
    }

    #[test]
    fn final_withdrawal_preserves_path_and_appends_local_hop() {
        let origin = origin("233.252.0.1", "ff04::1", 10);
        let withdrawn_hop = hop("withdrawn", 1);
        let withdrawn = MulticastPathVector {
            origin: origin.clone(),
            path: vec![withdrawn_hop.clone()],
        };
        let local_hop = hop("local", 3);
        let remaining = snapshot(HashSet::new(), HashSet::new());

        let update = reconcile_multicast_update(
            MulticastUpdate::withdraw(HashSet::from([withdrawn])),
            &remaining,
            &local_hop,
        );

        assert!(update.announce.is_empty());
        assert_eq!(
            update.withdraw,
            HashSet::from([MulticastPathVector {
                origin,
                path: vec![withdrawn_hop, local_hop],
            }]),
        );
    }

    #[test]
    fn withdrawn_or_unreachable_announcements_are_dropped() {
        let reachable = origin("233.252.0.1", "ff04::1", 10);
        let withdrawn = origin("233.252.0.2", "ff04::2", 10);
        let unreachable = origin("233.252.0.3", "ff04::3", 10);
        let remaining_hop = hop("remaining", 2);
        let local_hop = hop("local", 3);
        let paths = snapshot(
            HashSet::from([MulticastRoute {
                origin: withdrawn.clone(),
                nexthop: "fe80::2".parse().unwrap(),
                path: vec![remaining_hop.clone()],
            }]),
            HashSet::from([reachable.clone()]),
        );
        let vector = |origin: &MulticastOrigin, path| MulticastPathVector {
            origin: origin.clone(),
            path,
        };

        let update = reconcile_multicast_update(
            MulticastUpdate {
                announce: HashSet::from([
                    vector(&reachable, vec![local_hop.clone()]),
                    vector(&withdrawn, vec![hop("stale", 4)]),
                    vector(&unreachable, vec![local_hop.clone()]),
                ]),
                withdraw: HashSet::from([vector(&withdrawn, Vec::new())]),
            },
            &paths,
            &local_hop,
        );

        assert_eq!(
            update.announce,
            HashSet::from([
                vector(&reachable, vec![local_hop.clone()]),
                vector(&withdrawn, vec![remaining_hop, local_hop]),
            ]),
        );
        assert!(update.withdraw.is_empty());
    }

    #[test]
    fn unknown_origins_suppress_final_withdrawals() {
        let dir = Utf8TempDir::new().unwrap();
        let log = Logger::root(slog::Discard, slog::o!());
        let db = Db::new(dir.path().as_str(), log).unwrap();

        let still_imported = origin("233.252.0.1", "ff04::1", 10);
        let local_origin = origin("233.252.0.2", "ff04::2", 10);
        let remaining_hop = hop("remaining", 2);
        db.update_imported_mcast(MulticastRibChange::new(
            &HashSet::from([MulticastRoute {
                origin: still_imported.clone(),
                nexthop: "fe80::2".parse().unwrap(),
                path: vec![remaining_hop.clone()],
            }]),
            &HashSet::new(),
        ));
        db.originate_mcast(&HashSet::from([local_origin.clone()]))
            .unwrap();
        corrupt_mcast_origin_store(&db, &local_origin);
        let paths =
            db.snapshot_mcast_paths([&still_imported, &local_origin], &NO_PEER);
        assert!(paths.originated().is_none());

        let local_hop = hop("local", 3);
        let withdrawals = HashSet::from([
            MulticastPathVector {
                origin: still_imported.clone(),
                path: vec![hop("withdrawn", 1)],
            },
            MulticastPathVector {
                origin: local_origin,
                path: vec![hop("withdrawn", 1)],
            },
        ]);
        let update = reconcile_multicast_update(
            MulticastUpdate::withdraw(withdrawals),
            &paths,
            &local_hop,
        );

        assert!(update.withdraw.is_empty());
        assert_eq!(
            update.announce,
            HashSet::from([MulticastPathVector {
                origin: still_imported,
                path: vec![remaining_hop, local_hop],
            }]),
        );
    }

    /// A replacement path never goes through the peer receiving it.
    #[test]
    fn replacement_excludes_the_target_peer() {
        let dir = Utf8TempDir::new().unwrap();
        let log = Logger::root(slog::Discard, slog::o!());
        let db = Db::new(dir.path().as_str(), log).unwrap();

        // Has a route via another peer, so its withdrawal is replaced.
        let alternate = origin("233.252.0.1", "ff04::1", 10);
        // Has only the target's route, so its withdrawal stays final.
        let target_only = origin("233.252.0.2", "ff04::2", 10);
        let target_hop = hop("target", 1);
        let other_hop = hop("other", 3);
        let local_hop = hop("local", 2);
        let withdrawn_hop = hop("withdrawn", 4);
        db.update_imported_mcast(MulticastRibChange::new(
            &HashSet::from([
                MulticastRoute {
                    origin: alternate.clone(),
                    nexthop: target_hop.underlay_addr,
                    path: vec![target_hop.clone()],
                },
                MulticastRoute {
                    origin: alternate.clone(),
                    nexthop: other_hop.underlay_addr,
                    path: vec![other_hop.clone()],
                },
                MulticastRoute {
                    origin: target_only.clone(),
                    nexthop: target_hop.underlay_addr,
                    path: vec![target_hop.clone()],
                },
            ]),
            &HashSet::new(),
        ));
        let paths = db.snapshot_mcast_paths(
            [&alternate, &target_only],
            &target_hop.router_id,
        );

        let update = reconcile_multicast_update(
            MulticastUpdate::withdraw(HashSet::from([
                MulticastPathVector {
                    origin: alternate.clone(),
                    path: vec![withdrawn_hop.clone()],
                },
                MulticastPathVector {
                    origin: target_only.clone(),
                    path: vec![withdrawn_hop.clone()],
                },
            ])),
            &paths,
            &local_hop,
        );

        assert_eq!(
            update.announce,
            HashSet::from([MulticastPathVector {
                origin: alternate,
                path: vec![other_hop, local_hop.clone()],
            }]),
        );
        assert_eq!(
            update.withdraw,
            HashSet::from([MulticastPathVector {
                origin: target_only,
                path: vec![withdrawn_hop, local_hop],
            }]),
        );
    }
}
