// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Imported multicast routes and sequence numbers, persisted local origins,
//! and path snapshots used for update reconciliation.

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;

use ddm_api_types::db::MulticastRoute;
use ddm_api_types::net::MulticastOrigin;
use ddm_protocol::RouterId;
use mg_common::lock;
use slog::error;

use super::{Db, Error, RemovedNexthopRoutes};

mod imported;

pub(in crate::db) use imported::ImportedMcast;
use imported::Inserted;

/// The effect of [`Db::splice_imported_mcast`] on the imported set.
pub struct SplicedMulticast {
    /// Imports that added an entry or changed an entry's path or metric.
    pub imported: HashSet<MulticastRoute>,
    /// Routes that were removed.
    pub removed: HashSet<MulticastRoute>,
}

/// Persistent tree for locally originated multicast groups.
const MCAST_ORIGINATE: &str = "mcast_originate";

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

    /// Pull sequence number used to identify earlier imports.
    pub fn next_mcast_seq(&self) -> u64 {
        lock!(self.data).mcast_seq + 1
    }

    /// Apply multicast imports and removals under a held data lock, returning
    /// the imports that affected the RIB and the routes that were actually
    /// removed.
    pub fn splice_imported_mcast(
        &self,
        update: MulticastRibChange<'_>,
    ) -> SplicedMulticast {
        let mut guard = lock!(self.data);
        let data = &mut *guard;
        let mut edit = data.imported_mcast.edit(&self.mcast_wake);

        // Path and metric live outside of route identity and may change on
        // re-import.
        let imported = update
            .import
            .iter()
            .filter(|x| {
                data.mcast_seq += 1;
                edit.insert(x, update.ifname, data.mcast_seq)
                    != Inserted::Unchanged
            })
            .cloned()
            .collect();

        let removed = update
            .remove
            .iter()
            .filter_map(|x| {
                edit.remove(x, update.ifname, update.imported_before)
            })
            .collect();

        SplicedMulticast { imported, removed }
    }

    /// Persist multicast origins to advertise to peers.
    pub fn originate_mcast(
        &self,
        origins: &HashSet<MulticastOrigin>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(MCAST_ORIGINATE)?;
        for origin in origins {
            // Keep metric in the value; re-origination can update it.
            tree.insert(
                mcast_origin_key(origin)?.as_str(),
                serde_json::to_string(origin)?.as_str(),
            )?;
        }
        tree.flush()?;
        Ok(())
    }

    /// Read the locally originated multicast origins.
    ///
    /// Bypassing an unreadable entry could cause a false withdrawal during
    /// reconciliation, so we fail the entire read to avoid this situation.
    ///
    /// # Errors
    ///
    /// Returns an error if the tree cannot be opened or if any entry fails to
    /// read or parse.
    pub fn originated_mcast(&self) -> Result<HashSet<MulticastOrigin>, Error> {
        let tree = self.persistent_data.open_tree(MCAST_ORIGINATE)?;
        tree.iter()
            .map(|item| {
                let (_key, value) = item?;
                Ok(serde_json::from_slice(&value)?)
            })
            .collect()
    }

    /// Remove persisted multicast origins.
    pub fn withdraw_mcast(
        &self,
        origins: &HashSet<MulticastOrigin>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(MCAST_ORIGINATE)?;
        for origin in origins {
            // Withdraw by identity, regardless of the supplied metric.
            tree.remove(mcast_origin_key(origin)?.as_str())?;
        }
        tree.flush()?;
        Ok(())
    }

    /// Snapshot multicast paths through local origins and imported routes.
    pub fn snapshot_mcast_paths<'a>(
        &self,
        origins: impl IntoIterator<Item = &'a MulticastOrigin>,
        peer_router_id: &RouterId,
    ) -> McastPathSnapshot {
        let origins: Vec<_> = origins.into_iter().collect();
        let imported = {
            let data = lock!(self.data);
            origins
                .iter()
                .filter_map(|origin| {
                    data.imported_mcast.shortest_path(origin, peer_router_id)
                })
                .map(|route| (route.origin.clone(), route.clone()))
                .collect()
        };
        self.path_snapshot(&origins, imported)
    }

    /// Snapshot multicast paths through local origins only.
    pub fn snapshot_local_mcast_paths<'a>(
        &self,
        origins: impl IntoIterator<Item = &'a MulticastOrigin>,
    ) -> McastPathSnapshot {
        let origins: Vec<_> = origins.into_iter().collect();
        self.path_snapshot(&origins, HashMap::new())
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
        let removed = lock!(self.data)
            .imported_mcast
            .edit(&self.mcast_wake)
            .extract_link(nexthop, ifname);

        RemovedNexthopRoutes {
            underlay: HashSet::new(),
            tunnel: HashSet::new(),
            multicast: removed,
        }
    }

    /// Origins imported via `nexthop` on `ifname` before `seq` that are not in
    /// `announced`.
    pub fn stale_mcast_by_nexthop(
        &self,
        nexthop: Ipv6Addr,
        ifname: &str,
        seq: u64,
        announced: &HashSet<MulticastOrigin>,
    ) -> Vec<MulticastOrigin> {
        lock!(self.data)
            .imported_mcast
            .stale(nexthop, ifname, seq, announced)
    }

    /// Read local origins to complete the snapshot of `imported`.
    ///
    /// NOTE: Callers must not hold the data lock because local origins are read
    /// from the persistent store without it. This makes the snapshot
    /// non-atomic: `imported` was read under the lock, and the two halves
    /// could diverge.
    ///
    /// A failed origin read leaves `originated` as `None`.
    fn path_snapshot(
        &self,
        origins: &[&MulticastOrigin],
        imported: HashMap<MulticastOrigin, MulticastRoute>,
    ) -> McastPathSnapshot {
        let originated = self
            .lookup_originated_mcast(origins)
            .inspect_err(|e| {
                error!(self.log, "lookup originated multicast origins: {e}");
            })
            .ok();
        McastPathSnapshot {
            imported,
            originated,
        }
    }

    fn lookup_originated_mcast(
        &self,
        origins: &[&MulticastOrigin],
    ) -> Result<HashSet<MulticastOrigin>, Error> {
        let tree = self.persistent_data.open_tree(MCAST_ORIGINATE)?;
        let mut originated = HashSet::new();
        for origin in origins {
            if let Some(value) = tree.get(mcast_origin_key(origin)?.as_str())? {
                originated.insert(serde_json::from_slice(&value)?);
            }
        }
        Ok(originated)
    }
}

/// Persistent origin key, excluding metric as in `PartialEq` and `Hash`.
fn mcast_origin_key(origin: &MulticastOrigin) -> Result<String, Error> {
    Ok(serde_json::to_string(&(
        origin.overlay_group(),
        origin.underlay_group(),
        origin.vni(),
        origin.source(),
    ))?)
}

/// A batch of multicast imports and removals.
#[derive(Debug, Clone, Copy)]
pub struct MulticastRibChange<'a> {
    pub ifname: &'a str,
    pub import: &'a HashSet<MulticastRoute>,
    pub remove: &'a HashSet<MulticastRoute>,
    /// Remove only routes imported before this sequence number.
    /// Pull reconciliation uses this sequence to preserve concurrent pushes.
    pub imported_before: Option<u64>,
}

impl<'a> MulticastRibChange<'a> {
    /// A change without a pull sequence, as used for push withdrawals.
    pub fn new(
        ifname: &'a str,
        import: &'a HashSet<MulticastRoute>,
        remove: &'a HashSet<MulticastRoute>,
    ) -> Self {
        Self {
            ifname,
            import,
            remove,
            imported_before: None,
        }
    }
}

/// Imported routes and local origins used for multicast update
/// reconciliation.
#[derive(Debug, Clone)]
pub struct McastPathSnapshot {
    imported: HashMap<MulticastOrigin, MulticastRoute>,
    originated: Option<HashSet<MulticastOrigin>>,
}

impl McastPathSnapshot {
    pub fn imported(
        &self,
        origin: &MulticastOrigin,
    ) -> Option<&MulticastRoute> {
        self.imported.get(origin)
    }

    /// Local origins, or `None` on a failed read.
    /// An unreadable origin set cannot establish a final withdrawal.
    pub fn originated(&self) -> Option<&HashSet<MulticastOrigin>> {
        self.originated.as_ref()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use camino_tempfile::Utf8TempDir;
    use ddm_api_types::db::TunnelRoute;
    use ddm_api_types::net::{
        OverlayMulticast, TunnelOrigin, UnderlayMulticastIpv6, Vni,
    };
    use ddm_protocol::v4::MulticastPathHop;
    use pretty_assertions::assert_eq;
    use slog::Logger;
    use tokio::sync::watch;

    use super::*;

    const NO_PEER: RouterId = RouterId::new(String::new());

    fn test_db() -> (Utf8TempDir, Db) {
        let dir = Utf8TempDir::new().unwrap();
        let log = Logger::root(slog::Discard, slog::o!());
        let db = Db::new(dir.path().as_str(), log).unwrap();
        (dir, db)
    }

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
        db.splice_imported_mcast(MulticastRibChange::new(
            "test0",
            routes,
            &HashSet::new(),
        ));
    }

    pub(crate) fn corrupt_mcast_origin_store(
        db: &Db,
        origin: &MulticastOrigin,
    ) {
        let tree = db.persistent_data.open_tree(MCAST_ORIGINATE).unwrap();
        tree.insert(
            mcast_origin_key(origin).unwrap().as_str(),
            "not-an-origin",
        )
        .unwrap();
        tree.flush().unwrap();
    }

    /// A corrupt origin entry fails on reads that touch it, while other origins
    /// and imported routes remain available to read.
    #[test]
    fn corrupt_origin_store_fails_closed() {
        let (_dir, db) = test_db();
        let good = mcast_origin("233.252.0.1", "ff04::1");
        let bad = mcast_origin("233.252.0.2", "ff04::2");
        let route = MulticastRoute {
            origin: bad.clone(),
            nexthop: "fe80::a".parse().unwrap(),
            path: Vec::new(),
        };
        db.originate_mcast(&HashSet::from([good.clone()])).unwrap();
        db.splice_imported_mcast(MulticastRibChange::new(
            "test0",
            &HashSet::from([route.clone()]),
            &HashSet::new(),
        ));
        assert_eq!(db.originated_mcast().unwrap().len(), 1);

        corrupt_mcast_origin_store(&db, &bad);

        assert!(db.originated_mcast().is_err());

        let paths = db.snapshot_mcast_paths([&bad], &NO_PEER);
        assert!(paths.originated().is_none());
        assert_eq!(paths.imported(&bad), Some(&route));

        assert_eq!(
            db.snapshot_mcast_paths([&good], &NO_PEER).originated(),
            Some(&HashSet::from([good])),
        );
    }

    /// A path snapshot includes persisted local origins and current imports.
    #[test]
    fn snapshot_mcast_paths_reads_both_sources() {
        let (_dir, db) = test_db();

        // Distinct overlay/underlay groups so identity-based equality on
        // `MulticastOrigin` keeps the persisted and imported origins apart.
        let local_origin =
            mcast_origin("233.252.0.1", "ff04::1").with_metric(10);
        let imported_origin =
            mcast_origin("233.252.0.2", "ff04::2").with_metric(20);
        let route = route(imported_origin, "fe80::2");

        db.originate_mcast(&HashSet::from([local_origin.clone()]))
            .unwrap();
        db.splice_imported_mcast(MulticastRibChange::new(
            "test0",
            &HashSet::from([route.clone()]),
            &HashSet::new(),
        ));

        let paths =
            db.snapshot_mcast_paths([&local_origin, &route.origin], &NO_PEER);
        let imported = paths.imported(&route.origin).unwrap();
        assert_eq!(imported, &route);
        assert_eq!(imported.origin.metric(), 20);
        assert_eq!(imported.path, route.path);
        let originated = paths.originated().unwrap();
        assert_eq!(originated.get(&local_origin).unwrap().metric(), 10);
        assert_eq!(originated, &HashSet::from([local_origin]));
    }

    /// The origin store keys on identity, meaning that metric can
    /// never split an entry.
    #[test]
    fn origin_store_keys_on_identity_not_metric() {
        let (_dir, db) = test_db();

        // Re-originating with a changed metric overwrites the stored entry.
        db.originate_mcast(&HashSet::from([mcast_origin(
            "233.252.0.1",
            "ff04::1",
        )
        .with_metric(10)]))
            .unwrap();
        db.originate_mcast(&HashSet::from([mcast_origin(
            "233.252.0.1",
            "ff04::1",
        )
        .with_metric(20)]))
            .unwrap();

        let stored = db.originated_mcast().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored.iter().next().unwrap().metric(), 20);

        // A withdraw with the default metric still matches.
        db.withdraw_mcast(&HashSet::from([mcast_origin(
            "233.252.0.1",
            "ff04::1",
        )]))
        .unwrap();
        assert!(db.originated_mcast().unwrap().is_empty());
    }

    /// Only the multicast routes via the given nexthop are removed.
    #[test]
    fn remove_nexthop_mcast_routes_is_scoped_to_the_peer() {
        let (_dir, db) = test_db();

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
        let (_dir, db) = test_db();

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

    /// The stale set excludes other peers, announced origins, and later
    /// imports.
    #[test]
    fn stale_mcast_by_nexthop_filters() {
        let (_dir, db) = test_db();
        let peer: Ipv6Addr = "fe80::a".parse().unwrap();

        let announced =
            route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let unannounced =
            route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::a");
        let other_peer =
            route(mcast_origin("233.252.0.3", "ff04::3"), "fe80::b");
        import(
            &db,
            &HashSet::from([
                announced.clone(),
                unannounced.clone(),
                other_peer,
            ]),
        );
        let other_link =
            route(mcast_origin("233.252.0.5", "ff04::5"), "fe80::a");
        db.splice_imported_mcast(MulticastRibChange::new(
            "test1",
            &HashSet::from([other_link.clone()]),
            &HashSet::new(),
        ));

        let seq = db.next_mcast_seq();
        let late = route(mcast_origin("233.252.0.4", "ff04::4"), "fe80::a");
        import(&db, &HashSet::from([late]));

        let stale = db.stale_mcast_by_nexthop(
            peer,
            "test0",
            seq,
            &HashSet::from([announced.origin.clone()]),
        );
        assert_eq!(stale, vec![unannounced.origin]);

        let stale = db.stale_mcast_by_nexthop(
            peer,
            "test1",
            seq,
            &HashSet::from([announced.origin]),
        );
        assert_eq!(stale, vec![other_link.origin]);
    }

    /// Remove an untouched route and preserve imports made at or after the
    /// pull sequence.
    #[test]
    fn stale_removal_skips_routes_imported_at_or_after_the_pull_seq() {
        let (_dir, db) = test_db();

        let prev = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let refreshed =
            route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::a");
        import(&db, &HashSet::from([prev.clone(), refreshed.clone()]));

        let pull_seq = db.next_mcast_seq();

        // A concurrent push re-announces `refreshed` and adds a `new` route
        // while the pull is reading a snapshot that contains neither of these.
        let new = route(mcast_origin("233.252.0.3", "ff04::3"), "fe80::a");
        import(&db, &HashSet::from([refreshed.clone(), new.clone()]));

        // Even if the reader's candidate set was computed before the push was
        // applied, the bounded removal skips anything (re)imported since.
        let candidates = HashSet::from([
            prev.clone(),
            MulticastRoute {
                path: Vec::new(),
                ..refreshed.clone()
            },
            MulticastRoute {
                path: Vec::new(),
                ..new.clone()
            },
        ]);
        let removed = db
            .splice_imported_mcast(MulticastRibChange {
                ifname: "test0",
                import: &HashSet::new(),
                remove: &candidates,
                imported_before: Some(pull_seq),
            })
            .removed;

        assert_eq!(removed, HashSet::from([prev]));
        assert_eq!(
            db.imported_mcast_links()
                .into_iter()
                .collect::<HashSet<_>>(),
            HashSet::from([
                (refreshed, "test0".to_string()),
                (new, "test0".to_string()),
            ]),
        );
    }

    #[test]
    fn shortest_path_falls_back_after_removal_and_expiry() {
        let (_dir, db) = test_db();
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

        db.splice_imported_mcast(MulticastRibChange::new(
            "test0",
            &HashSet::new(),
            &HashSet::from([low.clone()]),
        ));
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
        edit.insert(&peer_in_path, "test0", 1);
        edit.insert(&long, "test0", 2);
        edit.insert(&short, "test0", 3);
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
        edit.insert(&low_nexthop, "test0", 1);
        edit.insert(&low_metric, "test0", 2);
        drop(edit);

        let picked = imported.shortest_path(&origin, &"peer".into()).unwrap();
        assert_eq!(picked.nexthop, low_metric.nexthop);

        imported.edit(&wake).insert(&shorter, "test0", 3);
        let picked = imported.shortest_path(&origin, &"peer".into()).unwrap();
        assert_eq!(picked.nexthop, shorter.nexthop);
    }

    #[test]
    fn imported_mcast_drops_emptied_origins() {
        let mut imported = ImportedMcast::default();
        let wake = watch::Sender::new(0);
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");

        let mut edit = imported.edit(&wake);
        edit.insert(&a, "test0", 1);
        assert_eq!(edit.remove(&a, "test0", None), Some(a.clone()));
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
        assert_eq!(edit.insert(&a, "tfportrear0_0", 1), Inserted::New);
        assert_eq!(edit.insert(&a, "tfportrear1_0", 2), Inserted::New);
        drop(edit);
        assert_eq!(*wake.borrow(), 1);

        assert_eq!(
            imported.edit(&wake).insert(&a, "tfportrear0_0", 3),
            Inserted::Unchanged
        );
        assert_eq!(*wake.borrow(), 1);
        assert_eq!(imported.links().count(), 2);

        assert_eq!(
            imported.edit(&wake).remove(&a, "tfportrear0_0", None),
            Some(a.clone())
        );
        assert_eq!(ifnames(&imported), vec!["tfportrear1_0"]);

        let mut edit = imported.edit(&wake);
        edit.insert(&a, "tfportrear0_0", 4);
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
        let (_dir, db) = test_db();
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let splice = |routes: &HashSet<MulticastRoute>| {
            db.splice_imported_mcast(MulticastRibChange::new(
                "test0",
                routes,
                &HashSet::new(),
            ))
            .imported
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
        let (_dir, db) = test_db();
        let shared = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::1");
        let unique = route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::1");
        let other = route(mcast_origin("233.252.0.3", "ff04::3"), "fe80::2");
        db.splice_imported_mcast(MulticastRibChange::new(
            "tfportrear0_0",
            &HashSet::from([shared.clone(), unique.clone(), other.clone()]),
            &HashSet::new(),
        ));
        db.splice_imported_mcast(MulticastRibChange::new(
            "tfportrear1_0",
            &HashSet::from([shared.clone()]),
            &HashSet::new(),
        ));

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
        let (_dir, db) = test_db();
        let mut rx = db.subscribe_mcast_sweep();
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let b = route(mcast_origin("233.252.0.2", "ff04::2"), "fe80::a");

        import(&db, &HashSet::from([a.clone()]));
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();

        import(&db, &HashSet::from([b.clone()]));
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();

        db.splice_imported_mcast(MulticastRibChange::new(
            "test0",
            &HashSet::new(),
            &HashSet::from([b.clone()]),
        ));
        assert!(rx.has_changed().unwrap());
    }

    #[test]
    fn non_membership_changes_do_not_wake_subscribers() {
        let (_dir, db) = test_db();
        let mut rx = db.subscribe_mcast_sweep();
        let a = route(mcast_origin("233.252.0.1", "ff04::1"), "fe80::a");
        let absent = route(mcast_origin("233.252.0.9", "ff04::9"), "fe80::b");

        let pull_seq = db.next_mcast_seq();
        import(&db, &HashSet::from([a.clone()]));
        rx.borrow_and_update();

        import(&db, &HashSet::from([a.clone()]));
        let mut rerouted = a.clone();
        rerouted.path.push(MulticastPathHop::new(
            "other".into(),
            "fe80::3".parse().unwrap(),
        ));
        import(&db, &HashSet::from([rerouted]));

        import(&db, &HashSet::new());
        db.splice_imported_mcast(MulticastRibChange::new(
            "test0",
            &HashSet::new(),
            &HashSet::from([absent.clone()]),
        ));
        let removed = db
            .splice_imported_mcast(MulticastRibChange {
                ifname: "test0",
                import: &HashSet::new(),
                remove: &HashSet::from([a.clone()]),
                imported_before: Some(pull_seq),
            })
            .removed;
        assert!(removed.is_empty());
        db.remove_nexthop_mcast_routes(absent.nexthop, "test0");
        db.remove_nexthop_routes(absent.nexthop, "test0");

        assert!(!rx.has_changed().unwrap());
    }
}
