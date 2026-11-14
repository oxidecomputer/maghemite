// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multicast push requests and pull route collection.
//!
//! This module checks received paths for loops through the local router and
//! applies imports and removals to the DB.

use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::Arc;

use ddm_api_types::db::{MulticastRoute, RouterKind};
use ddm_protocol::RouterId;
use ddm_protocol::v4::{
    MulticastPathHop, MulticastPathVector, MulticastUpdate,
};
use dropshot::HttpError;
use slog::Logger;

use super::{HandlerContext, push_update};
use crate::db::MulticastRibChange;
use crate::discovery::Version;
use crate::exchange::ExchangeError;
use crate::sm::{Config, SmContext};
use crate::{dbg, trc};
use mg_common::lock;

pub(crate) fn announce_multicast(
    ctx: &SmContext,
    config: Config,
    groups: HashSet<MulticastPathVector>,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = MulticastUpdate::announce(groups);
    push_update(ctx, config, update.into(), addr, version, rt, log)
}

pub(crate) fn withdraw_multicast(
    ctx: &SmContext,
    config: Config,
    groups: HashSet<MulticastPathVector>,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = MulticastUpdate::withdraw(groups);
    push_update(ctx, config, update.into(), addr, version, rt, log)
}

/// Collect multicast routes for pull responses.
///
/// Routes learned from the requesting peer are disregarded, ensuring that a
/// peer never reads its own announcements back through this router.
pub(super) fn collect_multicast(
    ctx: &HandlerContext,
) -> Result<HashSet<MulticastPathVector>, HttpError> {
    let mut multicast = HashSet::new();
    let hop =
        MulticastPathHop::new(ctx.ctx.router_id.clone(), ctx.ctx.config.addr);

    let peer_router_id = lock!(ctx.ctx.iface.peer_identity)
        .as_ref()
        .map(|peer| peer.router_id.clone());
    if let Some(peer_router_id) = peer_router_id
        && ctx.ctx.config.kind == RouterKind::Transit
    {
        multicast.extend(
            ctx.ctx
                .db
                .shortest_path_mcast(&peer_router_id)
                .into_iter()
                .map(|route| {
                    let mut path = route.path;
                    path.push(hop.clone());
                    MulticastPathVector {
                        origin: route.origin,
                        path,
                    }
                }),
        );
    }

    let originated_mcast = ctx
        .ctx
        .db
        .originated_mcast()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    multicast.extend(originated_mcast.into_iter().map(|origin| {
        MulticastPathVector {
            origin,
            path: vec![hop.clone()],
        }
    }));

    Ok(multicast)
}

/// The import and removal state after applying a multicast update, along with
/// the local hop appended to announcements when they are redistributed.
pub(super) struct AppliedMulticastUpdate {
    imported: HashSet<MulticastRoute>,
    removed: HashSet<MulticastRoute>,
    hop: MulticastPathHop,
}

impl From<AppliedMulticastUpdate> for MulticastUpdate {
    fn from(applied: AppliedMulticastUpdate) -> Self {
        let hop = applied.hop;
        MulticastUpdate {
            announce: applied
                .imported
                .into_iter()
                .map(|route| {
                    MulticastPathVector {
                        origin: route.origin,
                        path: route.path,
                    }
                    .with_hop(hop.clone())
                })
                .collect(),
            withdraw: applied
                .removed
                .into_iter()
                .map(|route| MulticastPathVector {
                    origin: route.origin,
                    path: Vec::new(),
                })
                .collect(),
        }
    }
}

/// Apply multicast imports and removals from [`partition_multicast_update`].
pub(super) fn apply_multicast_update(
    ctx: &SmContext,
    import: HashSet<MulticastRoute>,
    remove: &HashSet<MulticastRoute>,
    imported_before: Option<u64>,
) -> AppliedMulticastUpdate {
    let batch = MulticastRibChange {
        import: &import,
        remove,
        imported_before,
    };

    let removed = ctx.db.update_imported_mcast(batch);
    AppliedMulticastUpdate {
        imported: import,
        removed,
        hop: MulticastPathHop::new(ctx.router_id.clone(), ctx.config.addr),
    }
}

/// Partition an update into imports and removals for `peer_addr`.
///
/// A path that already contains this router is considered a loop. An
/// announcement with a looped path removes the existing route via `peer_addr`,
/// as the peer's path to the group now runs back through this router.
///
/// A withdrawal with a looped path is an echo of our own withdrawal and is
/// ignored.
pub(super) fn partition_multicast_update(
    update: &MulticastUpdate,
    router_id: &RouterId,
    peer_addr: Ipv6Addr,
    log: &Logger,
    if_name: &str,
) -> (HashSet<MulticastRoute>, HashSet<MulticastRoute>) {
    let mut import = HashSet::new();
    let mut remove = HashSet::new();
    // Replacement announcements can return to a router in their path,
    // invalidating its old route through the sender. A clean vector for
    // the same (origin, peer) takes precedence.
    for path_vector in &update.announce {
        let route = MulticastRoute {
            origin: path_vector.origin.clone(),
            nexthop: peer_addr,
            path: path_vector.path.clone(),
        };
        if !path_vector
            .path
            .iter()
            .any(|hop| &hop.router_id == router_id)
        {
            // Cancel an earlier looped vector's removal (unordered input).
            remove.remove(&route);
            import.insert(route);
        } else if !import.contains(&route) {
            dbg!(
                log,
                if_name,
                "looped multicast announce for {} via {peer_addr} \
                 (path length {})",
                path_vector.origin.overlay_group(),
                path_vector.path.len(),
            );
            remove.insert(route);
        }
    }

    for path_vector in &update.withdraw {
        // Ignore echoes of our own withdrawals.
        if path_vector
            .path
            .iter()
            .any(|hop| &hop.router_id == router_id)
        {
            trc!(
                log,
                if_name,
                "dropping multicast withdraw for {}; loop detected \
                 (path length {})",
                path_vector.origin.overlay_group(),
                path_vector.path.len(),
            );
            continue;
        }

        // An empty path still matches the (origin, nexthop) identity.
        remove.insert(MulticastRoute {
            origin: path_vector.origin.clone(),
            nexthop: peer_addr,
            path: Vec::new(),
        });
    }
    // A simultaneous import would receive a sequence number above the pull
    // cutoff.
    import.retain(|route| !remove.contains(route));

    (import, remove)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::Ipv6Addr;

    use ddm_api_types::db::MulticastRoute;
    use ddm_api_types::net::{
        MulticastOrigin, OverlayMulticast, UnderlayMulticastIpv6, Vni,
    };
    use ddm_protocol::v4::{
        MulticastPathHop, MulticastPathVector, MulticastUpdate,
    };
    use slog::{Discard, Logger, o};

    use super::partition_multicast_update;
    use crate::db::{Db, MulticastRibChange};

    const PEER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xa);
    const LOCAL: &str = "local";

    fn origin(last: u16) -> MulticastOrigin {
        MulticastOrigin::new(
            OverlayMulticast::new(
                Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, last).into(),
            )
            .unwrap(),
            UnderlayMulticastIpv6::new(Ipv6Addr::new(
                0xff04, 0, 0, 0, 0, 0, 0, last,
            ))
            .unwrap(),
            Vni::new(77).unwrap(),
            None,
        )
        .unwrap()
    }

    fn hop(router_id: &str) -> MulticastPathHop {
        MulticastPathHop::new(router_id.into(), Ipv6Addr::LOCALHOST)
    }

    fn vector(last: u16, path: &[&str]) -> MulticastPathVector {
        MulticastPathVector {
            origin: origin(last),
            path: path.iter().map(|r| hop(r)).collect(),
        }
    }

    fn route(last: u16) -> MulticastRoute {
        MulticastRoute {
            origin: origin(last),
            nexthop: PEER,
            path: Vec::new(),
        }
    }

    fn partition(
        update: &MulticastUpdate,
    ) -> (HashSet<MulticastRoute>, HashSet<MulticastRoute>) {
        let log = Logger::root(Discard, o!());
        partition_multicast_update(update, &LOCAL.into(), PEER, &log, "test0")
    }

    #[test]
    fn clean_announce_imports() {
        let update =
            MulticastUpdate::announce(HashSet::from([vector(1, &["a"])]));
        let (import, remove) = partition(&update);
        assert_eq!(import, HashSet::from([route(1)]));
        assert!(remove.is_empty());
        assert_eq!(
            import.iter().next().unwrap().path,
            vec![hop("a")],
            "the imported route keeps the announced path",
        );
    }

    #[test]
    fn looped_announce_removes() {
        let update = MulticastUpdate::announce(HashSet::from([vector(
            1,
            &["a", LOCAL],
        )]));
        let (import, remove) = partition(&update);
        assert!(import.is_empty());
        assert_eq!(remove, HashSet::from([route(1)]));
        assert_eq!(
            remove.iter().next().unwrap().path,
            vec![hop("a"), hop(LOCAL)],
        );
    }

    #[test]
    fn clean_announcement_cancels_looped_removal() {
        let update = MulticastUpdate::announce(HashSet::from([
            vector(1, &["a"]),
            vector(1, &["b"]),
        ]));
        let log = Logger::root(Discard, o!());
        for (local, clean) in [("a", "b"), ("b", "a")] {
            let (import, remove) = partition_multicast_update(
                &update,
                &local.into(),
                PEER,
                &log,
                "test0",
            );
            assert_eq!(import, HashSet::from([route(1)]));
            assert!(remove.is_empty());
            assert_eq!(import.iter().next().unwrap().path, vec![hop(clean)]);
        }
    }

    #[test]
    fn announce_and_withdraw_of_the_same_route_removes_it() {
        let update = MulticastUpdate {
            announce: HashSet::from([vector(1, &["a"])]),
            // Route 2 was never imported -> its removal is not reported.
            withdraw: HashSet::from([vector(1, &["a"]), vector(2, &["a"])]),
        };
        let dir = camino_tempfile::tempdir().unwrap();
        let log = Logger::root(Discard, o!());
        let db = Db::new(dir.path().as_str(), log).unwrap();
        let existing = HashSet::from([route(1)]);
        db.update_imported_mcast(MulticastRibChange::new(
            &existing,
            &HashSet::new(),
        ));

        let (import, remove) = partition(&update);
        let removed =
            db.update_imported_mcast(MulticastRibChange::new(&import, &remove));

        assert_eq!(removed, existing);
        assert!(db.imported_mcast().is_empty());
        assert!(import.is_empty());
    }

    #[test]
    fn looped_withdraw_is_dropped() {
        let mut update = MulticastUpdate::withdraw(HashSet::from([vector(
            1,
            &["a", LOCAL],
        )]));
        let (import, remove) = partition(&update);
        assert!(import.is_empty());
        assert!(remove.is_empty());

        update.announce.insert(vector(1, &["a"]));
        let (import, remove) = partition(&update);
        assert_eq!(import, HashSet::from([route(1)]));
        assert!(remove.is_empty());
    }

    #[test]
    fn withdraw_matches_by_identity_regardless_of_path() {
        let update =
            MulticastUpdate::withdraw(HashSet::from([vector(1, &["a", "b"])]));
        let (_import, remove) = partition(&update);
        assert_eq!(remove, HashSet::from([route(1)]));
        assert!(remove.iter().next().unwrap().path.is_empty());
    }
}
