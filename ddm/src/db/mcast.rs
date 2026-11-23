// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Imported multicast routes, push sequence numbers, local origins,
//! and path snapshots used for update reconciliation.

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;

use ddm_api_types::db::MulticastRoute;
use ddm_api_types::net::MulticastOrigin;
use ddm_protocol::RouterId;
use mg_common::lock;
use omicron_common::api::external::Generation;

use super::{Db, DbData, RemovedNexthopRoutes};

fn next_seq(seq: Option<Generation>) -> Generation {
    seq.map_or(Generation::new(), |seq| seq.next())
}

impl Db {
    pub fn imported_mcast(&self) -> HashSet<MulticastRoute> {
        lock!(self.data).imported_mcast.routes().cloned().collect()
    }

    pub fn shortest_path_mcast(
        &self,
        peer_router_id: &RouterId,
    ) -> Vec<MulticastRoute> {
        lock!(self.data)
            .imported_mcast
            .shortest_path_routes(peer_router_id)
            .cloned()
            .collect()
    }

    /// Read the next multicast sequence as the start of an outgoing pull.
    pub fn next_mcast_seq(&self) -> Generation {
        next_seq(lock!(self.data).mcast_seq)
    }

    /// Apply multicast imports and removals under the DB lock.
    ///
    /// A pull can return a snapshot taken before a push that we've already
    /// applied. That snapshot can restore a withdrawn route or remove a route
    /// that the peer just announced.
    ///
    /// Any push with imports or removals in it advances the sequence for its
    /// nexthop. A removal still counts even if the route is already vapor. A
    /// pull is superseded iff a push from its nexthop was recorded at
    /// or after the pull had started. If not superseded, the pull's imports
    /// replace the nexthop's routes, with omitted routes being removed.
    ///
    /// An applied batch returns the routes it removed.
    pub fn update_imported_mcast(
        &self,
        update: MulticastRibChange<'_>,
    ) -> McastUpdateOutcome {
        let mut guard = lock!(self.data);
        let data = &mut *guard;

        if let McastUpdateSource::Pull {
            nexthop,
            started_at,
        } = update.source
            && data
                .mcast_push_seq
                .get(&nexthop)
                .is_some_and(|seq| *seq >= started_at)
        {
            return McastUpdateOutcome::Superseded;
        }

        // Path and metric live outside of route identity and may change on
        // re-import.
        for x in update.import {
            data.imported_mcast.insert(x);
        }

        let removed = match update.source {
            McastUpdateSource::Push { nexthop } => {
                // Advance the sequence for withdrawals of absent routes too.
                // A snapshot in flight may still include the route. An empty
                // batch (i.e., echoed withdrawals) changes nothing that a
                // pull could restore.
                if !update.import.is_empty() || !update.remove.is_empty() {
                    let seq = next_seq(data.mcast_seq);
                    data.mcast_seq = Some(seq);
                    data.mcast_push_seq.insert(nexthop, seq);
                }
                update
                    .remove
                    .iter()
                    .filter_map(|x| data.imported_mcast.remove(x))
                    .collect()
            }
            McastUpdateSource::Pull { nexthop, .. } => {
                let keep: HashSet<_> =
                    update.import.iter().map(|route| &route.origin).collect();
                data.imported_mcast.extract_nexthop_if(nexthop, |origin| {
                    !keep.contains(origin)
                })
            }
        };

        McastUpdateOutcome::Applied(removed)
    }

    /// Mark multicast origins to advertise to peers.
    pub fn originate_mcast(&self, origins: &HashSet<MulticastOrigin>) {
        let originated = &mut lock!(self.data).originated_mcast;
        for origin in origins {
            // Replace rather than insert here because re-origination can
            // update the metric.
            originated.replace(origin.clone());
        }
    }

    /// Read the locally originated multicast origins.
    pub fn originated_mcast(&self) -> HashSet<MulticastOrigin> {
        lock!(self.data).originated_mcast.clone()
    }

    /// Stop advertising multicast origins.
    pub fn withdraw_mcast(&self, origins: &HashSet<MulticastOrigin>) {
        let originated = &mut lock!(self.data).originated_mcast;
        for origin in origins {
            // Withdraw by identity, regardless of the supplied metric.
            originated.remove(origin);
        }
    }

    /// Snapshot multicast paths through local origins and imported routes.
    pub fn snapshot_mcast_paths<'a>(
        &self,
        origins: impl IntoIterator<Item = &'a MulticastOrigin>,
        peer_router_id: &RouterId,
    ) -> McastPathSnapshot {
        let origins: Vec<_> = origins.into_iter().collect();
        let data = lock!(self.data);
        let imported = origins
            .iter()
            .filter_map(|origin| {
                data.imported_mcast.shortest_path(origin, peer_router_id)
            })
            .map(|route| (route.origin.clone(), route.clone()))
            .collect();
        Self::path_snapshot(&data, &origins, imported)
    }

    /// Snapshot multicast paths through local origins only.
    pub fn snapshot_local_mcast_paths<'a>(
        &self,
        origins: impl IntoIterator<Item = &'a MulticastOrigin>,
    ) -> McastPathSnapshot {
        let origins: Vec<_> = origins.into_iter().collect();
        let data = lock!(self.data);
        Self::path_snapshot(&data, &origins, HashMap::new())
    }

    /// Remove multicast routes via `nexthop` on a downgrade below V4.
    ///
    /// Underlay and tunnel routes remain intact.
    pub fn remove_nexthop_mcast_routes(
        &self,
        nexthop: Ipv6Addr,
    ) -> RemovedNexthopRoutes {
        let mut data = lock!(self.data);
        let removed = data.imported_mcast.extract_nexthop(nexthop);
        data.mcast_push_seq.remove(&nexthop);

        RemovedNexthopRoutes {
            underlay: HashSet::new(),
            tunnel: HashSet::new(),
            multicast: removed,
        }
    }

    /// Read local origins to complete the snapshot of `imported`.
    fn path_snapshot(
        data: &DbData,
        origins: &[&MulticastOrigin],
        imported: HashMap<MulticastOrigin, MulticastRoute>,
    ) -> McastPathSnapshot {
        let originated = origins
            .iter()
            .filter_map(|origin| data.originated_mcast.get(*origin))
            .cloned()
            .collect();
        McastPathSnapshot {
            imported,
            originated,
        }
    }
}

/// A type wrapper over the set of imported multicast routes, keyed by origin
/// and then by nexthop.
///
/// A path snapshot for an update's origins is a lookup per origin. Each
/// origin's routes are sorted by nexthop, with the lowest-nexthop route
/// coming first. Per-peer work (e.g., pull replacement, expiry) visits each
/// origin once.
// Note: We use a sorted `Vec` here over a `BTreeMap` because an origin rarely
// has more than a few nexthops.
#[derive(Debug, Default, Clone)]
pub struct ImportedMcast(HashMap<MulticastOrigin, Vec<MulticastRoute>>);

fn find_nexthop(
    nexthops: &[MulticastRoute],
    nexthop: Ipv6Addr,
) -> Result<usize, usize> {
    nexthops.binary_search_by_key(&nexthop, |route| route.nexthop)
}

impl ImportedMcast {
    fn routes(&self) -> impl Iterator<Item = &MulticastRoute> {
        self.0.values().flatten()
    }

    fn shortest_path_routes<'a>(
        &'a self,
        peer_router_id: &'a RouterId,
    ) -> impl Iterator<Item = &'a MulticastRoute> {
        self.0.keys().filter_map(move |origin| {
            self.shortest_path(origin, peer_router_id)
        })
    }

    fn insert(&mut self, route: &MulticastRoute) {
        let nexthops = self.0.entry(route.origin.clone()).or_default();
        match find_nexthop(nexthops, route.nexthop) {
            Ok(idx) => {
                let existing = &mut nexthops[idx];
                if existing.path != route.path
                    || existing.origin.metric() != route.origin.metric()
                {
                    *existing = route.clone();
                }
            }
            Err(idx) => {
                // Grow one slot at a time.
                nexthops.reserve_exact(1);
                nexthops.insert(idx, route.clone());
            }
        }
    }

    fn remove(&mut self, route: &MulticastRoute) -> Option<MulticastRoute> {
        let nexthops = self.0.get_mut(&route.origin)?;
        let idx = find_nexthop(nexthops, route.nexthop).ok()?;
        let removed = nexthops.remove(idx);
        if nexthops.is_empty() {
            self.0.remove(&route.origin);
        }
        Some(removed)
    }

    pub(super) fn extract_nexthop(
        &mut self,
        nexthop: Ipv6Addr,
    ) -> HashSet<MulticastRoute> {
        self.extract_nexthop_if(nexthop, |_| true)
    }

    fn extract_nexthop_if(
        &mut self,
        nexthop: Ipv6Addr,
        mut should_extract: impl FnMut(&MulticastOrigin) -> bool,
    ) -> HashSet<MulticastRoute> {
        let mut extracted = HashSet::new();
        self.0.retain(|origin, nexthops| {
            if let Ok(idx) = find_nexthop(nexthops, nexthop)
                && should_extract(origin)
            {
                extracted.insert(nexthops.remove(idx));
            }
            !nexthops.is_empty()
        });
        extracted
    }

    /// Pick the route with the shortest path, breaking ties by the lowest
    /// origin metric (first) and then by the lowest nexthop address (e.g.,
    /// `fe80::1` < `fe80::2`).
    ///
    /// Routes whose path contains `peer_router_id` (the peer an update gets
    /// sent to) are omitted. That peer would discard such a path as a loop
    /// and drop its route through us.
    fn shortest_path(
        &self,
        origin: &MulticastOrigin,
        peer_router_id: &RouterId,
    ) -> Option<&MulticastRoute> {
        self.0
            .get(origin)?
            .iter()
            .filter(|route| {
                !route
                    .path
                    .iter()
                    .any(|hop| &hop.router_id == peer_router_id)
            })
            .min_by_key(|route| {
                (route.path.len(), route.origin.metric(), route.nexthop)
            })
    }
}

/// A batch of multicast imports and removals.
#[derive(Debug, Clone, Copy)]
pub struct MulticastRibChange<'a> {
    pub import: &'a HashSet<MulticastRoute>,
    pub remove: &'a HashSet<MulticastRoute>,
    pub source: McastUpdateSource,
}

/// From whence the [`MulticastRibChange`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McastUpdateSource {
    /// An incremental update pushed by the peer at `nexthop`.
    Push { nexthop: Ipv6Addr },
    /// A full snapshot pulled from the peer at `nexthop`.
    ///
    /// `started_at` is the sequence read before the request was sent.
    Pull {
        nexthop: Ipv6Addr,
        started_at: Generation,
    },
}

/// The result of applying a [`MulticastRibChange`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McastUpdateOutcome {
    /// Applied, with the routes it removed.
    Applied(HashSet<MulticastRoute>),
    /// A pull was discarded because a push from the same peer was applied
    /// after the pull started.
    Superseded,
}

impl<'a> MulticastRibChange<'a> {
    /// A push from `nexthop`.
    pub fn new(
        nexthop: Ipv6Addr,
        import: &'a HashSet<MulticastRoute>,
        remove: &'a HashSet<MulticastRoute>,
    ) -> Self {
        Self {
            import,
            remove,
            source: McastUpdateSource::Push { nexthop },
        }
    }
}

/// Imported routes and local origins used for multicast update
/// reconciliation.
#[derive(Debug, Clone)]
pub struct McastPathSnapshot {
    imported: HashMap<MulticastOrigin, MulticastRoute>,
    originated: HashSet<MulticastOrigin>,
}

impl McastPathSnapshot {
    pub fn imported(
        &self,
        origin: &MulticastOrigin,
    ) -> Option<&MulticastRoute> {
        self.imported.get(origin)
    }

    /// Local origins among the snapshot's requested origins.
    pub fn originated(&self) -> &HashSet<MulticastOrigin> {
        &self.originated
    }
}

#[cfg(test)]
mod tests {
    use ddm_api_types::db::TunnelRoute;
    use ddm_api_types::net::{
        OverlayMulticast, TunnelOrigin, UnderlayMulticastIpv6, Vni,
    };
    use ddm_protocol::v4::MulticastPathHop;
    use pretty_assertions::assert_eq;

    use super::*;

    const NO_PEER: RouterId = RouterId::new(String::new());

    fn mcast_origin(overlay: &str, underlay: &str) -> MulticastOrigin {
        MulticastOrigin::new(
            OverlayMulticast::new(overlay.parse().unwrap()).unwrap(),
            UnderlayMulticastIpv6::new(underlay.parse().unwrap()).unwrap(),
            Vni::new(77).unwrap(),
            None,
        )
        .unwrap()
    }

    fn route(origin: MulticastOrigin, nexthop: &str) -> MulticastRoute {
        MulticastRoute {
            origin,
            nexthop: nexthop.parse().unwrap(),
            path: vec![MulticastPathHop::new(
                "remote".into(),
                "fe80::2".parse().unwrap(),
            )],
        }
    }

    fn import(db: &Db, routes: &HashSet<MulticastRoute>) {
        for route in routes {
            db.update_imported_mcast(MulticastRibChange::new(
                route.nexthop,
                &HashSet::from([route.clone()]),
                &HashSet::new(),
            ));
        }
    }

    fn withdraw(db: &Db, route: &MulticastRoute) -> McastUpdateOutcome {
        db.update_imported_mcast(MulticastRibChange::new(
            route.nexthop,
            &HashSet::new(),
            &HashSet::from([route.clone()]),
        ))
    }

    /// A path snapshot includes local origins and current imports.
    #[test]
    fn snapshot_mcast_paths_reads_both_sources() {
        let db = Db::new();

        // Distinct overlay/underlay groups so identity-based equality on
        // `MulticastOrigin` keeps the local and imported origins apart.
        let local_origin =
            mcast_origin("233.252.0.1", "ff04::1").with_metric(10);
        let imported_origin =
            mcast_origin("233.252.0.2", "ff04::2").with_metric(20);
        let route = route(imported_origin, "fe80::2");

        db.originate_mcast(&HashSet::from([local_origin.clone()]));
        import(&db, &HashSet::from([route.clone()]));

        let paths =
            db.snapshot_mcast_paths([&local_origin, &route.origin], &NO_PEER);
        let imported = paths.imported(&route.origin).unwrap();
        assert_eq!(imported, &route);
        assert_eq!(imported.origin.metric(), 20);
        assert_eq!(imported.path, route.path);
        let originated = paths.originated();
        assert_eq!(originated.get(&local_origin).unwrap().metric(), 10);
        assert_eq!(originated, &HashSet::from([local_origin]));
    }

    /// Originated multicast origins are keyed on identity (`metric` can
    /// never split an entry).
    #[test]
    fn originated_mcast_keys_on_identity_not_metric() {
        let db = Db::new();

        // Re-originating with a changed metric overwrites the stored entry.
        db.originate_mcast(&HashSet::from([mcast_origin(
            "233.252.0.1",
            "ff04::1",
        )
        .with_metric(10)]));
        db.originate_mcast(&HashSet::from([mcast_origin(
            "233.252.0.1",
            "ff04::1",
        )
        .with_metric(20)]));

        let stored = db.originated_mcast();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored.iter().next().unwrap().metric(), 20);

        // A withdraw with the default metric still matches.
        db.withdraw_mcast(&HashSet::from([mcast_origin(
            "233.252.0.1",
            "ff04::1",
        )]));
        assert!(db.originated_mcast().is_empty());
    }

    /// Only the multicast routes via the given nexthop are removed.
    #[test]
    fn remove_nexthop_mcast_routes_is_scoped_to_the_peer() {
        let db = Db::new();

        // `a` and `a2` go via the removed nexthop. `b` is another peer's and
        // stays.
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let b = route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::b");
        let a2 = route(mcast_origin("233.252.0.3", "ff04::3"), "fe80::a");
        import(&db, &HashSet::from([a.clone(), b.clone(), a2.clone()]));

        // Underlay and tunnel routes via the same nexthop also stay.
        db.import(&HashSet::from([crate::db::Route {
            destination: "fd00::/64".parse().unwrap(),
            nexthop: "fe80::a".parse().unwrap(),
            ifname: "test0".into(),
            path: vec!["remote".into()],
        }]));

        let tunnel = TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "203.0.113.0/24".parse().unwrap(),
                boundary_addr: "fd00:1701::a".parse().unwrap(),
                vni: 47,
                metric: 0,
            },
            nexthop: "fe80::a".parse().unwrap(),
        };
        db.import_tunnel(&HashSet::from([tunnel]));

        let removed =
            db.remove_nexthop_mcast_routes("fe80::a".parse().unwrap());

        // A snapshot taken after removal no longer views the removed routes.
        let paths = db
            .snapshot_mcast_paths([&a.origin, &b.origin, &a2.origin], &NO_PEER);
        assert!(paths.imported(&a.origin).is_none());
        assert!(paths.imported(&a2.origin).is_none());
        assert_eq!(paths.imported(&b.origin), Some(&b));
        assert_eq!(removed.multicast, HashSet::from([a, a2]));
        assert!(removed.underlay.is_empty());
        assert!(removed.tunnel.is_empty());
        assert_eq!(db.imported_mcast(), HashSet::from([b.clone()]));
        assert_eq!(db.imported_count(), 1);
        assert_eq!(db.imported_tunnel(), HashSet::from([tunnel]));
    }

    #[test]
    fn remove_nexthop_routes_removes_every_family_for_a_peer() {
        let db = Db::new();

        let multicast_a =
            route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let multicast_b =
            route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::b");
        import(
            &db,
            &HashSet::from([multicast_a.clone(), multicast_b.clone()]),
        );

        let underlay = |nexthop: &str, dst: &str| crate::db::Route {
            destination: dst.parse().unwrap(),
            nexthop: nexthop.parse().unwrap(),
            ifname: "test0".into(),
            path: vec!["remote".into()],
        };
        let underlay_a = underlay("fe80::a", "fd00:a::/64");
        let underlay_b = underlay("fe80::b", "fd00:b::/64");
        db.import(&HashSet::from([underlay_a.clone(), underlay_b.clone()]));

        let tunnel = |nexthop: &str, boundary: &str| TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: "203.0.113.0/24".parse().unwrap(),
                boundary_addr: boundary.parse().unwrap(),
                vni: 47,
                metric: 0,
            },
            nexthop: nexthop.parse().unwrap(),
        };
        let tunnel_a = tunnel("fe80::a", "fd00:1701::a");
        let tunnel_b = tunnel("fe80::b", "fd00:1701::b");
        db.import_tunnel(&HashSet::from([tunnel_a, tunnel_b]));

        let removed = db.remove_nexthop_routes("fe80::a".parse().unwrap());

        assert_eq!(removed.underlay, HashSet::from([underlay_a]));
        assert_eq!(removed.tunnel, HashSet::from([tunnel_a]));
        let paths = db.snapshot_mcast_paths(
            [&multicast_a.origin, &multicast_b.origin],
            &NO_PEER,
        );
        assert!(paths.imported(&multicast_a.origin).is_none());
        assert_eq!(paths.imported(&multicast_b.origin), Some(&multicast_b));
        assert_eq!(removed.multicast, HashSet::from([multicast_a]));
        assert_eq!(db.imported(), HashSet::from([underlay_b]));
        assert_eq!(db.imported_tunnel(), HashSet::from([tunnel_b]));
    }

    #[test]
    fn pull_replaces_the_peers_routes_with_its_snapshot() {
        let db = Db::new();
        let kept = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let omitted = route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::a");
        let other_peer =
            route(mcast_origin("233.252.0.3", "ff04::3"), "fe80::b");
        import(
            &db,
            &HashSet::from([kept.clone(), omitted.clone(), other_peer.clone()]),
        );

        let started_at = db.next_mcast_seq();
        let added = route(mcast_origin("233.252.0.4", "ff04::4"), "fe80::a");
        let outcome = pull(
            &db,
            HashSet::from([kept.clone(), added.clone()]),
            kept.nexthop,
            started_at,
        );

        assert_eq!(
            outcome,
            McastUpdateOutcome::Applied(HashSet::from([omitted]))
        );
        assert_eq!(
            db.imported_mcast(),
            HashSet::from([kept, added, other_peer])
        );
    }

    #[test]
    fn empty_pull_snapshot_removes_all_of_the_peers_routes() {
        let db = Db::new();
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        import(&db, &HashSet::from([a.clone()]));

        let started_at = db.next_mcast_seq();
        let outcome = pull(&db, HashSet::new(), a.nexthop, started_at);

        assert_eq!(outcome, McastUpdateOutcome::Applied(HashSet::from([a])));
        assert!(db.imported_mcast().is_empty());
    }

    fn pull(
        db: &Db,
        routes: HashSet<MulticastRoute>,
        nexthop: Ipv6Addr,
        started_at: Generation,
    ) -> McastUpdateOutcome {
        db.update_imported_mcast(MulticastRibChange {
            import: &routes,
            remove: &HashSet::new(),
            source: McastUpdateSource::Pull {
                nexthop,
                started_at,
            },
        })
    }

    #[test]
    fn push_withdrawal_supersedes_pull() {
        let db = Db::new();
        let g = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");
        import(&db, &HashSet::from([g.clone()]));

        let started_at = db.next_mcast_seq();
        withdraw(&db, &g);

        let outcome =
            pull(&db, HashSet::from([g.clone()]), g.nexthop, started_at);
        assert_eq!(outcome, McastUpdateOutcome::Superseded);
        assert!(db.imported_mcast().is_empty());
    }

    #[test]
    fn push_withdrawal_of_absent_route_supersedes_pull() {
        let db = Db::new();
        let g = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");

        let started_at = db.next_mcast_seq();
        assert_eq!(
            withdraw(&db, &g),
            McastUpdateOutcome::Applied(HashSet::new())
        );

        let outcome =
            pull(&db, HashSet::from([g.clone()]), g.nexthop, started_at);
        assert_eq!(outcome, McastUpdateOutcome::Superseded);
        assert!(db.imported_mcast().is_empty());
    }

    #[test]
    fn empty_push_does_not_supersede_pull() {
        let db = Db::new();
        let g = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");

        let started_at = db.next_mcast_seq();
        db.update_imported_mcast(MulticastRibChange::new(
            g.nexthop,
            &HashSet::new(),
            &HashSet::new(),
        ));

        let outcome =
            pull(&db, HashSet::from([g.clone()]), g.nexthop, started_at);
        assert_eq!(outcome, McastUpdateOutcome::Applied(HashSet::new()));
        assert_eq!(db.imported_mcast(), HashSet::from([g]));
    }

    #[test]
    fn push_path_change_supersedes_pull() {
        let db = Db::new();
        let old = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");
        import(&db, &HashSet::from([old.clone()]));

        let started_at = db.next_mcast_seq();
        let new = MulticastRoute {
            path: vec![MulticastPathHop::new(
                "other".into(),
                "fe80::3".parse().unwrap(),
            )],
            ..old.clone()
        };
        import(&db, &HashSet::from([new.clone()]));

        let outcome =
            pull(&db, HashSet::from([old.clone()]), old.nexthop, started_at);
        assert_eq!(outcome, McastUpdateOutcome::Superseded);
        let imported = db.imported_mcast();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported.iter().next().unwrap().path, new.path);
    }

    #[test]
    fn nexthop_removal_resets_push_sequence() {
        let db = Db::new();
        let g = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");

        for remove in [
            |db: &Db, nexthop| {
                db.remove_nexthop_mcast_routes(nexthop);
            },
            |db: &Db, nexthop| {
                db.remove_nexthop_routes(nexthop);
            },
        ] {
            let started_at = db.next_mcast_seq();
            import(&db, &HashSet::from([g.clone()]));
            remove(&db, g.nexthop);

            let outcome =
                pull(&db, HashSet::from([g.clone()]), g.nexthop, started_at);
            assert_eq!(outcome, McastUpdateOutcome::Applied(HashSet::new()));
            assert_eq!(db.imported_mcast(), HashSet::from([g.clone()]));
        }
    }

    #[test]
    fn shortest_path_falls_back() {
        let db = Db::new();
        let origin = mcast_origin("233.252.0.1", "ff04::1");
        let other = mcast_origin("233.252.0.2", "ff04::2");
        let low = route(origin.clone(), "fe80::1");
        let high = route(origin.clone(), "fe80::2");
        let other_low = route(other.clone(), "fe80::1");
        import(&db, &HashSet::from([low.clone(), high.clone(), other_low]));

        let shortest = |db: &Db, origin: &MulticastOrigin| {
            db.snapshot_mcast_paths([origin], &NO_PEER)
                .imported(origin)
                .map(|route| (route.nexthop, route.path.clone()))
        };
        assert_eq!(
            shortest(&db, &origin),
            Some((low.nexthop, low.path.clone()))
        );

        withdraw(&db, &low);
        assert_eq!(
            shortest(&db, &origin),
            Some((high.nexthop, high.path.clone()))
        );

        let refreshed = MulticastRoute {
            path: vec![MulticastPathHop::new(
                "refreshed".into(),
                "fe80::3".parse().unwrap(),
            )],
            ..high.clone()
        };
        import(&db, &HashSet::from([refreshed.clone()]));
        assert_eq!(
            shortest(&db, &origin),
            Some((high.nexthop, refreshed.path.clone()))
        );

        import(&db, &HashSet::from([low.clone()]));
        let removed = db.remove_nexthop_mcast_routes(low.nexthop);
        assert_eq!(removed.multicast.len(), 2);
        assert_eq!(
            shortest(&db, &origin),
            Some((high.nexthop, refreshed.path))
        );
        assert_eq!(shortest(&db, &other), None);

        db.remove_nexthop_mcast_routes(high.nexthop);
        assert_eq!(shortest(&db, &origin), None);
        assert!(db.imported_mcast().is_empty());
    }

    #[test]
    fn shortest_path_skips_the_peer_and_prefers_shorter_paths() {
        let mut imported = ImportedMcast::default();
        let origin = mcast_origin("233.252.0.1", "ff04::1");
        let hop = |id: &str| {
            MulticastPathHop::new(id.into(), "fe80::9".parse().unwrap())
        };
        let via = |nexthop: &str, path: &[&str]| MulticastRoute {
            origin: origin.clone(),
            nexthop: nexthop.parse().unwrap(),
            path: path.iter().map(|id| hop(id)).collect(),
        };

        let peer_in_path = via("fe80::1", &["peer", "x"]);
        let long = via("fe80::2", &["a", "b", "c"]);
        let short = via("fe80::3", &["d", "e"]);
        imported.insert(&peer_in_path);
        imported.insert(&long);
        imported.insert(&short);

        let picked = imported.shortest_path(&origin, &"peer".into()).unwrap();
        assert_eq!(picked.nexthop, short.nexthop);

        let picked = imported.shortest_path(&origin, &"other".into()).unwrap();
        assert_eq!(picked.nexthop, peer_in_path.nexthop);
    }

    #[test]
    fn shortest_path_handles_length_ties_by_metric() {
        let mut imported = ImportedMcast::default();
        let origin = mcast_origin("233.252.0.1", "ff04::1");
        let hop = |id: &str| {
            MulticastPathHop::new(id.into(), "fe80::9".parse().unwrap())
        };
        let via = |nexthop: &str, metric: u64, path: &[&str]| MulticastRoute {
            origin: origin.clone().with_metric(metric),
            nexthop: nexthop.parse().unwrap(),
            path: path.iter().map(|id| hop(id)).collect(),
        };

        let low_nexthop = via("fe80::1", 20, &["a", "b"]);
        let low_metric = via("fe80::2", 10, &["c", "d"]);
        let shorter = via("fe80::3", 30, &["e"]);
        imported.insert(&low_nexthop);
        imported.insert(&low_metric);

        let picked = imported.shortest_path(&origin, &"peer".into()).unwrap();
        assert_eq!(picked.nexthop, low_metric.nexthop);

        imported.insert(&shorter);
        let picked = imported.shortest_path(&origin, &"peer".into()).unwrap();
        assert_eq!(picked.nexthop, shorter.nexthop);
    }

    #[test]
    fn imported_mcast_drops_emptied_origins() {
        let mut imported = ImportedMcast::default();
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");

        imported.insert(&a);
        assert_eq!(imported.remove(&a), Some(a.clone()));
        assert!(imported.0.is_empty());

        imported.insert(&a);
        assert_eq!(imported.extract_nexthop(a.nexthop), HashSet::from([a]));
        assert!(imported.0.is_empty());
    }
}
