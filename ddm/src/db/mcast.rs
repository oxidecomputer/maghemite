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

mod imported;

pub(in crate::db) use imported::ImportedMcast;
use imported::Inserted;

/// The effect of [`Db::splice_imported_mcast`] on the imported set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplicedMulticast {
    /// Imports that added an entry or changed an entry's path or metric.
    pub imported: HashSet<MulticastRoute>,
    /// Routes that were removed.
    pub removed: HashSet<MulticastRoute>,
}

fn next_seq(seq: Option<Generation>) -> Generation {
    seq.map_or(Generation::new(), |seq| seq.next())
}

impl Db {
    pub fn imported_mcast_links(&self) -> Vec<(MulticastRoute, String)> {
        lock!(self.data)
            .imported_mcast
            .links()
            .map(|(route, ifname)| (route.clone(), ifname.to_string()))
            .collect()
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
    /// An applied batch returns the imports it modified and the routes it
    /// removed.
    pub fn splice_imported_mcast(
        &self,
        update: MulticastRibChange<'_>,
    ) -> McastUpdateOutcome {
        let mut guard = lock!(self.data);
        let data = &mut *guard;

        if let McastUpdateSource::Pull {
            nexthop,
            ifname,
            started_at,
        } = update.source
            && data
                .mcast_push_seq
                .get(&(nexthop, ifname.to_string()))
                .is_some_and(|seq| *seq >= started_at)
        {
            return McastUpdateOutcome::Superseded;
        }

        let mut edit = data.imported_mcast.edit(&self.mcast_wake);
        let (McastUpdateSource::Push { ifname, .. }
        | McastUpdateSource::Pull { ifname, .. }) = update.source;

        // Path and metric live outside of route identity and may change on
        // re-import.
        let imported = update
            .import
            .iter()
            .filter(|x| edit.insert(x, ifname) != Inserted::Unchanged)
            .cloned()
            .collect();

        let removed = match update.source {
            McastUpdateSource::Push { nexthop, ifname } => {
                // Advance the sequence for withdrawals of absent routes too.
                // A snapshot in flight may still include the route. An empty
                // batch (i.e., echoed withdrawals) changes nothing that a
                // pull could restore.
                if !update.import.is_empty() || !update.remove.is_empty() {
                    let seq = next_seq(data.mcast_seq);
                    data.mcast_seq = Some(seq);
                    data.mcast_push_seq
                        .insert((nexthop, ifname.to_string()), seq);
                }
                update
                    .remove
                    .iter()
                    .filter_map(|x| edit.remove(x, ifname))
                    .collect()
            }
            McastUpdateSource::Pull {
                nexthop, ifname, ..
            } => {
                let keep: HashSet<_> =
                    update.import.iter().map(|route| &route.origin).collect();
                edit.extract_link_if(nexthop, ifname, |origin| {
                    !keep.contains(origin)
                })
            }
        };

        McastUpdateOutcome::Applied(SplicedMulticast { imported, removed })
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

    /// Remove multicast routes via `nexthop` on `ifname` on a downgrade below
    /// V4.
    ///
    /// Underlay and tunnel routes remain intact.
    pub fn remove_nexthop_mcast_routes(
        &self,
        nexthop: Ipv6Addr,
        ifname: &str,
    ) -> RemovedNexthopRoutes {
        let mut data = lock!(self.data);
        let removed = data
            .imported_mcast
            .edit(&self.mcast_wake)
            .extract_link(nexthop, ifname);
        data.mcast_push_seq.remove(&(nexthop, ifname.to_string()));

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

/// A batch of multicast imports and removals.
#[derive(Debug, Clone, Copy)]
pub struct MulticastRibChange<'a> {
    pub import: &'a HashSet<MulticastRoute>,
    pub remove: &'a HashSet<MulticastRoute>,
    pub source: McastUpdateSource<'a>,
}

/// From whence the [`MulticastRibChange`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McastUpdateSource<'a> {
    /// An incremental update pushed by the peer at `nexthop`.
    Push { nexthop: Ipv6Addr, ifname: &'a str },
    /// A full snapshot pulled from the peer at `nexthop`.
    ///
    /// `started_at` is the sequence read before the request was sent.
    Pull {
        nexthop: Ipv6Addr,
        ifname: &'a str,
        started_at: Generation,
    },
}

/// The result of applying a [`MulticastRibChange`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McastUpdateOutcome {
    /// Applied, with the imports it modified and the routes it removed.
    Applied(SplicedMulticast),
    /// A pull was discarded because a push on the same link (nexthop and
    /// interface) was applied after the pull started.
    Superseded,
}

impl<'a> MulticastRibChange<'a> {
    /// A push from `nexthop` on `ifname`.
    pub fn new(
        nexthop: Ipv6Addr,
        ifname: &'a str,
        import: &'a HashSet<MulticastRoute>,
        remove: &'a HashSet<MulticastRoute>,
    ) -> Self {
        Self {
            import,
            remove,
            source: McastUpdateSource::Push { nexthop, ifname },
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
    use tokio::sync::watch;

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
        import_on(db, "test0", routes);
    }

    fn import_on(db: &Db, ifname: &str, routes: &HashSet<MulticastRoute>) {
        for route in routes {
            db.splice_imported_mcast(MulticastRibChange::new(
                route.nexthop,
                ifname,
                &HashSet::from([route.clone()]),
                &HashSet::new(),
            ));
        }
    }

    fn withdraw(db: &Db, route: &MulticastRoute) -> McastUpdateOutcome {
        db.splice_imported_mcast(MulticastRibChange::new(
            route.nexthop,
            "test0",
            &HashSet::new(),
            &HashSet::from([route.clone()]),
        ))
    }

    fn pull(
        db: &Db,
        routes: HashSet<MulticastRoute>,
        nexthop: Ipv6Addr,
        ifname: &str,
        started_at: Generation,
    ) -> McastUpdateOutcome {
        db.splice_imported_mcast(MulticastRibChange {
            import: &routes,
            remove: &HashSet::new(),
            source: McastUpdateSource::Pull {
                nexthop,
                ifname,
                started_at,
            },
        })
    }

    fn applied(
        imported: HashSet<MulticastRoute>,
        removed: HashSet<MulticastRoute>,
    ) -> McastUpdateOutcome {
        McastUpdateOutcome::Applied(SplicedMulticast { imported, removed })
    }

    fn imported_routes(db: &Db) -> HashSet<MulticastRoute> {
        db.imported_mcast_links()
            .into_iter()
            .map(|(route, _)| route)
            .collect()
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
            db.remove_nexthop_mcast_routes("fe80::a".parse().unwrap(), "test0");

        // A snapshot taken after removal no longer views the removed routes.
        let paths = db
            .snapshot_mcast_paths([&a.origin, &b.origin, &a2.origin], &NO_PEER);
        assert!(paths.imported(&a.origin).is_none());
        assert!(paths.imported(&a2.origin).is_none());
        assert_eq!(paths.imported(&b.origin), Some(&b));
        assert_eq!(removed.multicast, HashSet::from([a, a2]));
        assert!(removed.underlay.is_empty());
        assert!(removed.tunnel.is_empty());
        assert_eq!(db.imported_mcast_links(), vec![(b, "test0".to_string())]);
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

        let removed =
            db.remove_nexthop_routes("fe80::a".parse().unwrap(), "test0");

        assert_eq!(removed.underlay, HashSet::from([underlay_a]));
        assert_eq!(removed.tunnel, HashSet::from([tunnel_a]));
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
            "test0",
            started_at,
        );

        assert_eq!(
            outcome,
            applied(HashSet::from([added.clone()]), HashSet::from([omitted]))
        );
        assert_eq!(
            imported_routes(&db),
            HashSet::from([kept, added, other_peer])
        );
    }

    #[test]
    fn empty_pull_snapshot_removes_all_of_the_peers_routes() {
        let db = Db::new();
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        import(&db, &HashSet::from([a.clone()]));

        let started_at = db.next_mcast_seq();
        let outcome = pull(&db, HashSet::new(), a.nexthop, "test0", started_at);

        assert_eq!(outcome, applied(HashSet::new(), HashSet::from([a])));
        assert!(db.imported_mcast_links().is_empty());
    }

    #[test]
    fn push_withdrawal_supersedes_pull() {
        let db = Db::new();
        let g = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");
        import(&db, &HashSet::from([g.clone()]));

        let started_at = db.next_mcast_seq();
        withdraw(&db, &g);

        let outcome = pull(
            &db,
            HashSet::from([g.clone()]),
            g.nexthop,
            "test0",
            started_at,
        );
        assert_eq!(outcome, McastUpdateOutcome::Superseded);
        assert!(db.imported_mcast_links().is_empty());
    }

    #[test]
    fn push_withdrawal_of_absent_route_supersedes_pull() {
        let db = Db::new();
        let g = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");

        let started_at = db.next_mcast_seq();
        assert_eq!(withdraw(&db, &g), applied(HashSet::new(), HashSet::new()));

        let outcome = pull(
            &db,
            HashSet::from([g.clone()]),
            g.nexthop,
            "test0",
            started_at,
        );
        assert_eq!(outcome, McastUpdateOutcome::Superseded);
        assert!(db.imported_mcast_links().is_empty());
    }

    #[test]
    fn empty_push_does_not_supersede_pull() {
        let db = Db::new();
        let g = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");

        let started_at = db.next_mcast_seq();
        db.splice_imported_mcast(MulticastRibChange::new(
            g.nexthop,
            "test0",
            &HashSet::new(),
            &HashSet::new(),
        ));

        let outcome = pull(
            &db,
            HashSet::from([g.clone()]),
            g.nexthop,
            "test0",
            started_at,
        );
        assert_eq!(
            outcome,
            applied(HashSet::from([g.clone()]), HashSet::new())
        );
        assert_eq!(imported_routes(&db), HashSet::from([g]));
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

        let outcome = pull(
            &db,
            HashSet::from([old.clone()]),
            old.nexthop,
            "test0",
            started_at,
        );
        assert_eq!(outcome, McastUpdateOutcome::Superseded);
        let imported = imported_routes(&db);
        assert_eq!(imported.len(), 1);
        assert_eq!(imported.iter().next().unwrap().path, new.path);
    }

    #[test]
    fn push_on_other_interface_does_not_supersede_pull() {
        let db = Db::new();
        let g = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");

        let started_at = db.next_mcast_seq();
        import_on(&db, "test1", &HashSet::from([g.clone()]));

        let outcome = pull(
            &db,
            HashSet::from([g.clone()]),
            g.nexthop,
            "test0",
            started_at,
        );
        assert_eq!(
            outcome,
            applied(HashSet::from([g.clone()]), HashSet::new())
        );
        assert_eq!(
            db.imported_mcast_links()
                .into_iter()
                .collect::<HashSet<_>>(),
            HashSet::from([
                (g.clone(), "test0".to_string()),
                (g, "test1".to_string()),
            ]),
        );
    }

    #[test]
    fn pull_leaves_other_interface_routes_alone() {
        let db = Db::new();
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");
        let b = route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::1");
        import_on(&db, "test0", &HashSet::from([a.clone()]));
        import_on(&db, "test1", &HashSet::from([b.clone()]));

        let started_at = db.next_mcast_seq();
        let outcome = pull(&db, HashSet::new(), a.nexthop, "test0", started_at);

        assert_eq!(outcome, applied(HashSet::new(), HashSet::from([a])));
        assert_eq!(db.imported_mcast_links(), vec![(b, "test1".to_string())]);
    }

    #[test]
    fn nexthop_removal_resets_push_sequence() {
        let db = Db::new();
        let g = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");

        for remove in [
            |db: &Db, nexthop, ifname: &str| {
                db.remove_nexthop_mcast_routes(nexthop, ifname);
            },
            |db: &Db, nexthop, ifname: &str| {
                db.remove_nexthop_routes(nexthop, ifname);
            },
        ] {
            let started_at = db.next_mcast_seq();
            import(&db, &HashSet::from([g.clone()]));
            remove(&db, g.nexthop, "test0");

            let outcome = pull(
                &db,
                HashSet::from([g.clone()]),
                g.nexthop,
                "test0",
                started_at,
            );
            assert_eq!(
                outcome,
                applied(HashSet::from([g.clone()]), HashSet::new())
            );
            assert_eq!(imported_routes(&db), HashSet::from([g.clone()]));
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
        let removed = db.remove_nexthop_mcast_routes(low.nexthop, "test0");
        assert_eq!(removed.multicast.len(), 2);
        assert_eq!(
            shortest(&db, &origin),
            Some((high.nexthop, refreshed.path))
        );
        assert_eq!(shortest(&db, &other), None);

        db.remove_nexthop_mcast_routes(high.nexthop, "test0");
        assert_eq!(shortest(&db, &origin), None);
        assert!(db.imported_mcast_links().is_empty());
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
        let wake = watch::Sender::new(0);
        let mut edit = imported.edit(&wake);
        edit.insert(&peer_in_path, "test0");
        edit.insert(&long, "test0");
        edit.insert(&short, "test0");
        drop(edit);

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
        let wake = watch::Sender::new(0);
        let mut edit = imported.edit(&wake);
        edit.insert(&low_nexthop, "test0");
        edit.insert(&low_metric, "test0");
        drop(edit);

        let picked = imported.shortest_path(&origin, &"peer".into()).unwrap();
        assert_eq!(picked.nexthop, low_metric.nexthop);

        imported.edit(&wake).insert(&shorter, "test0");
        let picked = imported.shortest_path(&origin, &"peer".into()).unwrap();
        assert_eq!(picked.nexthop, shorter.nexthop);
    }

    #[test]
    fn imported_mcast_drops_emptied_origins() {
        let mut imported = ImportedMcast::default();
        let wake = watch::Sender::new(0);
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");

        let mut edit = imported.edit(&wake);
        edit.insert(&a, "test0");
        assert_eq!(edit.remove(&a, "test0"), Some(a.clone()));
        drop(edit);
        assert!(imported.links().next().is_none());
    }

    #[test]
    fn imports_are_keyed_per_link() {
        let mut imported = ImportedMcast::default();
        let wake = watch::Sender::new(0);
        let ifnames = |imported: &ImportedMcast| -> Vec<String> {
            imported
                .links()
                .map(|(_, ifname)| ifname.to_string())
                .collect()
        };
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");

        let mut edit = imported.edit(&wake);
        assert_eq!(edit.insert(&a, "tfportrear0_0"), Inserted::New);
        assert_eq!(edit.insert(&a, "tfportrear1_0"), Inserted::New);
        drop(edit);
        assert_eq!(*wake.borrow(), 1);

        assert_eq!(
            imported.edit(&wake).insert(&a, "tfportrear0_0"),
            Inserted::Unchanged
        );
        assert_eq!(*wake.borrow(), 1);
        assert_eq!(imported.links().count(), 2);

        assert_eq!(
            imported.edit(&wake).remove(&a, "tfportrear0_0"),
            Some(a.clone())
        );
        assert_eq!(ifnames(&imported), vec!["tfportrear1_0"]);

        let mut edit = imported.edit(&wake);
        edit.insert(&a, "tfportrear0_0");
        assert_eq!(
            edit.extract_link(a.nexthop, "tfportrear0_0"),
            HashSet::from([a.clone()]),
        );
        drop(edit);
        assert_eq!(ifnames(&imported), vec!["tfportrear1_0"]);
        assert_eq!(
            imported
                .edit(&wake)
                .extract_link(a.nexthop, "tfportrear1_0"),
            HashSet::from([a]),
        );
        assert!(imported.links().next().is_none());
        assert_eq!(*wake.borrow(), 4);
    }

    #[test]
    fn splice_reports_only_changed_imports() {
        let db = Db::new();
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let nexthop = a.nexthop;
        let splice = |routes: &HashSet<MulticastRoute>| match db
            .splice_imported_mcast(MulticastRibChange::new(
                nexthop,
                "test0",
                routes,
                &HashSet::new(),
            )) {
            McastUpdateOutcome::Applied(spliced) => spliced.imported,
            McastUpdateOutcome::Superseded => {
                panic!("a push is never superseded")
            }
        };

        let routes = HashSet::from([a.clone()]);
        assert_eq!(splice(&routes), routes);
        assert!(splice(&routes).is_empty());

        let mut wake = db.subscribe_mcast_sweep();
        wake.borrow_and_update();

        let remetric = MulticastRoute {
            origin: a.origin.clone().with_metric(5),
            ..a
        };
        let changed = splice(&HashSet::from([remetric.clone()]));
        assert_eq!(
            changed
                .iter()
                .map(|r| r.origin.metric())
                .collect::<Vec<_>>(),
            vec![5],
        );
        assert!(splice(&HashSet::from([remetric])).is_empty());
        assert!(!wake.has_changed().unwrap());
    }

    fn check_multicast_removal_by_interface(
        remove_routes: impl Fn(&Db, Ipv6Addr, &str) -> RemovedNexthopRoutes,
    ) {
        let db = Db::new();
        let shared = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");
        let unique = route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::1");
        let other = route(mcast_origin("233.252.0.3", "ff04::3"), "fe80::2");
        import_on(
            &db,
            "tfportrear0_0",
            &HashSet::from([shared.clone(), unique.clone(), other.clone()]),
        );
        import_on(&db, "tfportrear1_0", &HashSet::from([shared.clone()]));

        let mut rx = db.subscribe_mcast_sweep();
        let generation = *rx.borrow_and_update();
        let removed = remove_routes(&db, shared.nexthop, "tfportrear2_0");
        assert!(removed.multicast.is_empty());
        assert_eq!(db.imported_mcast_links().len(), 4);
        assert_eq!(*rx.borrow_and_update(), generation);

        let removed = remove_routes(&db, shared.nexthop, "tfportrear0_0");
        assert_eq!(
            removed.multicast,
            HashSet::from([shared.clone(), unique.clone()]),
        );
        assert_eq!(
            db.imported_mcast_links()
                .into_iter()
                .collect::<HashSet<_>>(),
            HashSet::from([
                (shared.clone(), "tfportrear1_0".to_string()),
                (other.clone(), "tfportrear0_0".to_string()),
            ]),
        );
        let paths =
            db.snapshot_mcast_paths([&shared.origin, &unique.origin], &NO_PEER);
        assert_eq!(paths.imported(&shared.origin), Some(&shared));
        assert!(paths.imported(&unique.origin).is_none());
        assert_eq!(*rx.borrow_and_update(), generation + 1);

        let removed = remove_routes(&db, shared.nexthop, "tfportrear0_0");
        assert!(removed.multicast.is_empty());
        assert_eq!(*rx.borrow_and_update(), generation + 1);

        let removed = remove_routes(&db, shared.nexthop, "tfportrear1_0");
        assert_eq!(removed.multicast, HashSet::from([shared.clone()]));
        assert_eq!(
            db.imported_mcast_links(),
            vec![(other, "tfportrear0_0".to_string())],
        );
        assert!(
            db.snapshot_mcast_paths([&shared.origin], &NO_PEER)
                .imported(&shared.origin)
                .is_none(),
        );
        assert_eq!(*rx.borrow_and_update(), generation + 2);
    }

    #[test]
    fn expiry_preserves_multicast_on_other_interfaces() {
        check_multicast_removal_by_interface(Db::remove_nexthop_routes);
    }

    #[test]
    fn downgrade_preserves_multicast_on_other_interfaces() {
        check_multicast_removal_by_interface(Db::remove_nexthop_mcast_routes);
    }

    #[test]
    fn membership_changes_wake_subscribers() {
        let db = Db::new();
        let mut rx = db.subscribe_mcast_sweep();
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let b = route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::a");

        import(&db, &HashSet::from([a.clone()]));
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();

        import(&db, &HashSet::from([b.clone()]));
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();

        withdraw(&db, &b);
        assert!(rx.has_changed().unwrap());
    }

    #[test]
    fn non_membership_changes_do_not_wake_subscribers() {
        let db = Db::new();
        let mut rx = db.subscribe_mcast_sweep();
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let absent = route(mcast_origin("233.252.0.9", "ff04::9"), "fe80::b");

        import(&db, &HashSet::from([a.clone()]));
        rx.borrow_and_update();

        import(&db, &HashSet::from([a.clone()]));
        let mut rerouted = a.clone();
        rerouted.path.push(MulticastPathHop::new(
            "other".into(),
            "fe80::3".parse().unwrap(),
        ));
        import(&db, &HashSet::from([rerouted]));

        db.splice_imported_mcast(MulticastRibChange::new(
            a.nexthop,
            "test0",
            &HashSet::new(),
            &HashSet::new(),
        ));
        withdraw(&db, &absent);
        let started_at = db.next_mcast_seq();
        let outcome = pull(
            &db,
            HashSet::from([a.clone()]),
            a.nexthop,
            "test0",
            started_at,
        );
        assert_eq!(outcome, applied(HashSet::from([a]), HashSet::new()));
        db.remove_nexthop_mcast_routes(absent.nexthop, "test0");
        db.remove_nexthop_routes(absent.nexthop, "test0");

        assert!(!rx.has_changed().unwrap());
    }
}
