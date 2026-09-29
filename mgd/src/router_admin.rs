// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The multi-router reconciler and router observability endpoints.
//!
//! `multi_router_apply` is the single entry point omicron uses to drive
//! router configuration: it receives the complete desired router list and
//! converges the daemon onto it. Routers absent from the request are torn
//! down, except the daemon-owned "default" router, whose configuration is
//! emptied in place. There is deliberately no per-router CRUD.
//!
//! An apply is serialized against every other configuration writer by
//! [`HandlerContext::apply_lock`]. The whole request is validated before
//! anything is touched, so a request that is invalid anywhere leaves the
//! daemon exactly as it was. Then routers absent from the request are torn
//! down, peers moving between routers are removed from their old router
//! ([`release_moved`]), and each router is converged onto its spec.

use crate::admin::HandlerContext;
use crate::bfd_admin;
use crate::bgp_admin;
use crate::error::Error;
use crate::static_admin::{static_route_key_from_v4, static_route_key_from_v6};
use crate::validation::validate_prefixes;
use dropshot::{
    HttpError, HttpResponseOk, HttpResponseUpdatedNoContent, Path, Query,
    RequestContext, TypedBody,
};
use mg_api_types::bgp::config::{
    ApplyRequest, Neighbor, PeerInfo, UnnumberedNeighbor,
};
use mg_api_types::rib::{Rib, RibQuery};
use mg_api_types::router::{
    MultiRouterApplyRequest, RouterInfo, RouterSelector, RouterSpec,
};
use mg_common::lock;
use oxnet::IpNet;
use rdb::{DEFAULT_ROUTER_ID, RibExt, RouterId, StaticRouteKey};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU8;
use std::sync::Arc;

pub(crate) async fn list_routers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<RouterInfo>>, HttpError> {
    Ok(HttpResponseOk(ctx.context().db.list_routers()))
}

pub(crate) async fn get_router_rib_imported(
    ctx: RequestContext<Arc<HandlerContext>>,
    path: Path<RouterSelector>,
    query: Query<RibQuery>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let rdb = router_db(ctx.context(), &path.into_inner().router)?;
    let query = query.into_inner();
    let imported = rdb.full_rib(query.address_family);
    let filtered = imported.filter_by_protocol(query.protocol);
    Ok(HttpResponseOk(filtered.into_latest_api_rib()))
}

pub(crate) async fn get_router_rib_selected(
    ctx: RequestContext<Arc<HandlerContext>>,
    path: Path<RouterSelector>,
    query: Query<RibQuery>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let rdb = router_db(ctx.context(), &path.into_inner().router)?;
    let query = query.into_inner();
    let selected = rdb.loc_rib(query.address_family);
    let filtered = selected.filter_by_protocol(query.protocol);
    Ok(HttpResponseOk(filtered.into_latest_api_rib()))
}

pub(crate) async fn get_router_neighbors(
    ctx: RequestContext<Arc<HandlerContext>>,
    path: Path<RouterSelector>,
) -> Result<HttpResponseOk<HashMap<String, PeerInfo>>, HttpError> {
    let ctx = ctx.context();
    // 404 for an unknown router; a router with no BGP sessions returns {}.
    let rdb = router_db(ctx, &path.into_inner().router)?;
    let sessions = bgp_admin::rdb_attributed_sessions(ctx, &rdb, None)?;
    Ok(HttpResponseOk(
        sessions
            .iter()
            .map(|s| (s.neighbor.peer.to_string(), s.get_peer_info()))
            .collect(),
    ))
}

/// Resolve a [`RouterSelector`]: a router id if it parses as one, otherwise
/// a router name.
fn router_db(
    ctx: &Arc<HandlerContext>,
    selector: &str,
) -> Result<rdb::RouterDb, HttpError> {
    match selector.parse() {
        Ok(id) => ctx.db.router(rdb::RouterId(id)),
        Err(_) => ctx.db.router_by_name(selector),
    }
    .map_err(|e| Error::from(e).into())
}

/// Generate a random ULA fdxx:xxxx:xxxx:xxxx::1 to serve as a router's TEP.
/// Generated once at router creation and persisted with the router, so it is
/// stable across restarts and re-applies; callers are never asked for a TEP.
pub(crate) fn random_tep_ula() -> std::net::Ipv6Addr {
    let mut r = [0u8; 7];
    rand::fill(&mut r);
    std::net::Ipv6Addr::from([
        0xfd, r[0], r[1], r[2], r[3], r[4], r[5], r[6], 0, 0, 0, 0, 0, 0, 0, 1,
    ])
}

pub(crate) async fn multi_router_apply(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<MultiRouterApplyRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    do_multi_router_apply(ctx.context(), request.into_inner()).await?;
    Ok(HttpResponseUpdatedNoContent())
}

/// Converge the daemon onto `rq`.
///
/// Serialized with every other configuration writer through
/// `apply_lock`. Nothing is mutated on behalf of `rq` until the whole
/// request has been validated.
pub(crate) async fn do_multi_router_apply(
    ctx: &Arc<HandlerContext>,
    rq: MultiRouterApplyRequest,
) -> Result<(), HttpError> {
    let _serialized = ctx.apply_lock.lock().await;
    validate_apply_request(&rq)?;
    for spec in &rq.routers {
        validate_router_spec(spec)?;
    }

    // The default router always exists; a request without it empties it.
    let mut specs = rq.routers;
    if !specs.iter().any(|s| s.id == DEFAULT_ROUTER_ID) {
        specs.push(RouterSpec {
            name: rdb::DEFAULT_ROUTER.to_string(),
            id: DEFAULT_ROUTER_ID,
            bgp: None,
            static4: Vec::new(),
            static6: Vec::new(),
            bfd_peers: Vec::new(),
        });
    }

    for info in ctx.db.list_routers() {
        if !specs.iter().any(|s| s.id == info.id) {
            teardown_router(ctx, info.id).await?;
        }
    }

    // Rename before any router is created, so a name freed by a rename is
    // available to a router created in the same request.
    for spec in &specs {
        if let Ok(rdb) = ctx.db.router(spec.id)
            && rdb.name() != spec.name
        {
            ctx.db
                .rename_router(spec.id, &spec.name)
                .map_err(Error::from)?;
        }
    }

    release_moved(ctx, &specs).await?;

    for spec in &specs {
        let rdb = match ctx.db.router(spec.id) {
            Ok(rdb) => rdb,
            Err(rdb::error::Error::NotFound(_)) => ctx
                .db
                .create_router(RouterInfo {
                    id: spec.id,
                    name: spec.name.clone(),
                    tep: random_tep_ula(),
                })
                .map_err(Error::from)?,
            Err(e) => return Err(Error::from(e).into()),
        };
        ctx.lower.ensure(&rdb, &ctx.log, &ctx.mg_lower_stats);
        apply_bgp(ctx, &rdb, spec).await?;
        apply_static(&rdb, &static_keys(spec)?)?;
        apply_bfd(ctx, &rdb, spec).await?;
    }

    Ok(())
}

/// Structural validation of one spec: everything the apply would otherwise
/// only discover while already mutating.
fn validate_router_spec(spec: &RouterSpec) -> Result<(), HttpError> {
    let bad = |msg: String| {
        HttpError::for_bad_request(
            None,
            format!("router {:?}: {msg}", spec.name),
        )
    };
    if let Some(bgp) = &spec.bgp {
        bgp.listen.parse::<SocketAddr>().map_err(|e| {
            bad(format!("invalid bgp listen address {:?}: {e}", bgp.listen))
        })?;
        validate_prefixes(&bgp.originate)?;
        for (group, peers) in &bgp.peers {
            for p in peers {
                Neighbor::from_bgp_peer_config(
                    bgp.asn,
                    group.clone(),
                    p.clone(),
                )
                .validate_address_families()
                .map_err(|e| bad(format!("bgp peer {}: {e}", p.host.ip())))?;
            }
        }
        for (group, peers) in &bgp.unnumbered_peers {
            for p in peers {
                UnnumberedNeighbor::from_bgp_peer_config(
                    bgp.asn,
                    group.clone(),
                    p.clone(),
                )
                .validate_address_families()
                .map_err(|e| {
                    bad(format!("bgp unnumbered peer {}: {e}", p.interface))
                })?;
            }
        }
    }

    for p in &spec.bfd_peers {
        if p.peer.is_ipv4() != p.listen.is_ipv4() {
            return Err(bad(format!(
                "bfd peer {} and its listen address {} must be the same \
                 address family",
                p.peer, p.listen
            )));
        }
    }

    if (spec.name == rdb::DEFAULT_ROUTER) != (spec.id == DEFAULT_ROUTER_ID) {
        return Err(bad(format!(
            "the {:?} router's id is {DEFAULT_ROUTER_ID}",
            rdb::DEFAULT_ROUTER,
        )));
    }

    static_keys(spec)?;
    Ok(())
}

/// The spec's complete static route set as rdb keys, with the prefixes
/// validated.
fn static_keys(
    spec: &RouterSpec,
) -> Result<BTreeSet<StaticRouteKey>, HttpError> {
    let desired: BTreeSet<StaticRouteKey> = spec
        .static4
        .iter()
        .cloned()
        .map(static_route_key_from_v4)
        .chain(spec.static6.iter().cloned().map(static_route_key_from_v6))
        .collect();
    let prefixes: Vec<IpNet> = desired.iter().map(|r| r.prefix).collect();
    validate_prefixes(&prefixes)?;
    Ok(desired)
}

fn validate_apply_request(
    rq: &MultiRouterApplyRequest,
) -> Result<(), HttpError> {
    let dup = |what: &str, item: &dyn std::fmt::Display| {
        Err(HttpError::for_bad_request(
            None,
            format!("duplicate {what}: {item}"),
        ))
    };

    let mut names = HashSet::new();
    let mut ids = HashSet::new();
    // The BGP dispatcher and the BFD daemon are shared across routers and
    // demux inbound traffic purely by peer address / interface, so these
    // must be unique across the whole router set, not just within one.
    let mut bgp_peers = HashSet::new();
    let mut bgp_interfaces = HashSet::new();
    let mut bfd_peers = HashSet::new();
    for spec in &rq.routers {
        if !names.insert(&spec.name) {
            return dup("router name", &spec.name);
        }
        if !ids.insert(spec.id) {
            return dup("router id", &spec.id);
        }
        if let Some(bgp) = &spec.bgp {
            for p in bgp.peers.values().flatten() {
                let ip = p.host.ip();
                if !bgp_peers.insert(ip) {
                    return dup("bgp peer address", &ip);
                }
            }
            for p in bgp.unnumbered_peers.values().flatten() {
                if !bgp_interfaces.insert(&p.interface) {
                    return dup("bgp peer interface", &p.interface);
                }
            }
        }
        for p in &spec.bfd_peers {
            if !bfd_peers.insert(p.peer) {
                return dup("bfd peer address", &p.peer);
            }
        }
    }
    Ok(())
}

/// Stop everything attached to a router (BGP sessions, BFD sessions), then
/// drop its volatile RIBs and purge its persistent state.
async fn teardown_router(
    ctx: &Arc<HandlerContext>,
    id: RouterId,
) -> Result<(), HttpError> {
    let rdb = ctx.db.router(id).map_err(Error::from)?;

    // Stop the router's mg-lower thread first: on shutdown it withdraws the
    // router's ASIC routes and ddm tunnel advertisements based on the RIB
    // contents, so it must run before the RIB is torn down.
    ctx.lower.stop(id).await;

    delete_bgp_routers(ctx, &rdb).await?;

    let peers: Vec<IpAddr> = rdb
        .get_bfd_neighbors()
        .map_err(Error::from)?
        .into_iter()
        .map(|p| p.peer)
        .collect();
    remove_bfd_peers(ctx, &rdb, &peers).await?;

    ctx.db
        .delete_router(id)
        .map_err(|e| HttpError::from(Error::from(e)))?;
    Ok(())
}

/// Delete every BGP router under this logical router.
async fn delete_bgp_routers(
    ctx: &Arc<HandlerContext>,
    rdb: &rdb::RouterDb,
) -> Result<(), HttpError> {
    let asns: Vec<u32> = lock!(ctx.bgp.router)
        .keys()
        .filter(|(id, _)| *id == rdb.id())
        .map(|(_, asn)| *asn)
        .collect();
    for asn in asns {
        bgp_admin::do_delete_router(ctx, rdb, asn).await?;
    }
    Ok(())
}

/// Remove these BFD peers from the daemon and from the router's config,
/// waiting for any freed-up listeners to fully shut down so the addresses
/// are reusable.
async fn remove_bfd_peers(
    ctx: &Arc<HandlerContext>,
    rdb: &rdb::RouterDb,
    peers: &[IpAddr],
) -> Result<(), HttpError> {
    let handles: Vec<_> = {
        let mut daemon = lock!(ctx.bfd.daemon);
        peers
            .iter()
            .filter_map(|peer| daemon.remove_peer(*peer))
            .collect()
    };
    for handle in handles {
        handle.shutdown().await;
    }
    for peer in peers {
        rdb.remove_bfd_neighbor(*peer).map_err(Error::from)?;
    }
    Ok(())
}

/// Remove from every live router the BGP and BFD peers that `specs` give to
/// a different router, so the new owner can add them whatever order the
/// routers are applied in. Peers no spec wants are left to their router's
/// own apply.
async fn release_moved(
    ctx: &Arc<HandlerContext>,
    specs: &[RouterSpec],
) -> Result<(), HttpError> {
    let mut numbered: HashMap<IpAddr, RouterId> = HashMap::new();
    let mut unnumbered: HashMap<&str, RouterId> = HashMap::new();
    let mut bfd: HashMap<IpAddr, RouterId> = HashMap::new();
    for spec in specs {
        if let Some(bgp) = &spec.bgp {
            for p in bgp.peers.values().flatten() {
                numbered.insert(p.host.ip(), spec.id);
            }
            for p in bgp.unnumbered_peers.values().flatten() {
                unnumbered.insert(p.interface.as_str(), spec.id);
            }
        }
        for p in &spec.bfd_peers {
            bfd.insert(p.peer, spec.id);
        }
    }

    for info in ctx.db.list_routers() {
        let rdb = ctx.db.router(info.id).map_err(Error::from)?;
        let moved =
            |owner: Option<&RouterId>| owner.is_some_and(|o| *o != info.id);

        for nbr in rdb.get_bgp_neighbors().map_err(Error::from)? {
            if moved(numbered.get(&nbr.host.ip())) {
                bgp_admin::helpers::remove_neighbor(
                    ctx.clone(),
                    &rdb,
                    nbr.asn,
                    nbr.host.ip(),
                )
                .await?;
            }
        }
        for nbr in rdb.get_unnumbered_bgp_neighbors().map_err(Error::from)? {
            if moved(unnumbered.get(nbr.interface.as_str())) {
                bgp_admin::helpers::remove_unnumbered_neighbor(
                    ctx.clone(),
                    &rdb,
                    nbr.asn,
                    &nbr.interface,
                )
                .await?;
            }
        }
        let peers: Vec<IpAddr> = rdb
            .get_bfd_neighbors()
            .map_err(Error::from)?
            .into_iter()
            .map(|p| p.peer)
            .filter(|p| moved(bfd.get(p)))
            .collect();
        remove_bfd_peers(ctx, &rdb, &peers).await?;
    }
    Ok(())
}

async fn apply_bgp(
    ctx: &Arc<HandlerContext>,
    rdb: &rdb::RouterDb,
    spec: &RouterSpec,
) -> Result<(), HttpError> {
    let Some(bgp) = &spec.bgp else {
        return delete_bgp_routers(ctx, rdb).await;
    };

    let desired_fanout = bgp.max_paths.unwrap_or(
        NonZeroU8::new(rdb::db::DEFAULT_BESTPATH_FANOUT)
            .expect("default fanout is nonzero"),
    );
    let current_fanout = rdb.get_bestpath_fanout().map_err(|e| {
        HttpError::for_internal_error(format!("get bestpath fanout: {e}"))
    })?;
    // Setting the fanout triggers a full bestpath recompute, so only touch
    // it on a real change.
    if desired_fanout != current_fanout {
        rdb.set_bestpath_fanout(desired_fanout).map_err(|e| {
            HttpError::for_internal_error(format!("set bestpath fanout: {e}"))
        })?;
    }

    // do_bgp_apply creates a missing BGP router with a default id and listen
    // address; creating it here first makes the spec's win.
    bgp_admin::helpers::ensure_router(
        ctx.clone(),
        rdb,
        mg_api_types::bgp::config::Router {
            asn: bgp.asn,
            id: bgp.id,
            listen: bgp.listen.clone(),
            graceful_shutdown: false,
        },
    )
    .await?;

    // Deletes BGP routers with any other ASN and converges the peers.
    bgp_admin::do_bgp_apply(
        ctx,
        rdb,
        ApplyRequest {
            asn: bgp.asn,
            originate: bgp.originate.clone(),
            checker: bgp.checker.clone(),
            shaper: bgp.shaper.clone(),
            peers: bgp.peers.clone(),
            unnumbered_peers: bgp.unnumbered_peers.clone(),
        },
    )
    .await?;

    Ok(())
}

fn apply_static(
    rdb: &rdb::RouterDb,
    desired: &BTreeSet<StaticRouteKey>,
) -> Result<(), HttpError> {
    let current: BTreeSet<StaticRouteKey> = rdb
        .get_static(None)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?
        .into_iter()
        .collect();

    let to_remove: Vec<StaticRouteKey> =
        current.difference(desired).cloned().collect();
    let to_add: Vec<StaticRouteKey> =
        desired.difference(&current).cloned().collect();

    if !to_remove.is_empty() {
        rdb.remove_static_routes(&to_remove)
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    }
    if !to_add.is_empty() {
        rdb.add_static_routes(&to_add)
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    }
    Ok(())
}

/// Converge the router's BFD peers onto the spec. A peer whose config
/// changed is removed and re-added: BFD sessions are cheap to restart.
async fn apply_bfd(
    ctx: &Arc<HandlerContext>,
    rdb: &rdb::RouterDb,
    spec: &RouterSpec,
) -> Result<(), HttpError> {
    let current = rdb.get_bfd_neighbors().map_err(Error::from)?;
    let stale: Vec<IpAddr> = current
        .iter()
        .filter(|p| !spec.bfd_peers.contains(p))
        .map(|p| p.peer)
        .collect();
    remove_bfd_peers(ctx, rdb, &stale).await?;

    for config in &spec.bfd_peers {
        if !current.contains(config) {
            bfd_admin::add_peer(ctx.clone(), rdb.clone(), *config)?;
            rdb.add_bfd_neighbor(*config).map_err(Error::from)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::do_multi_router_apply;
    use crate::admin::HandlerContext;
    use crate::bgp_admin::do_bgp_apply;
    use crate::bgp_admin::tests::{
        POLICY_SOURCE, mixed_req, numbered, test_ctx, unnumbered,
    };
    use dropshot::HttpError;
    use mg_api_types::bfd::{BfdPeerConfig, SessionMode};
    use mg_api_types::bgp::config::{CheckerSource, ShaperSource};
    use mg_api_types::bgp::peer::PeerId;
    use mg_api_types::router::{
        BgpSpec, MultiRouterApplyRequest, RouterId, RouterSpec,
    };
    use mg_api_types::static_routes::StaticRoute4;
    use mg_common::lock;
    use rdb::DEFAULT_ROUTER_ID;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::num::NonZeroU8;
    use std::sync::Arc;

    fn spec(name: &str, asn: u32, peer: &str) -> RouterSpec {
        RouterSpec {
            name: name.into(),
            id: RouterId::new_random(),
            bgp: Some(BgpSpec {
                asn,
                id: asn,
                listen: "[::]:179".into(),
                originate: Vec::default(),
                checker: None,
                shaper: None,
                peers: HashMap::from([(
                    "qsfp0".into(),
                    vec![numbered(peer, "peer", 6)],
                )]),
                unnumbered_peers: HashMap::default(),
                max_paths: None,
            }),
            static4: vec![StaticRoute4 {
                prefix: format!("{peer}/32").parse().unwrap(),
                nexthop: peer.parse().unwrap(),
                vlan_id: None,
                rib_priority: 10,
            }],
            static6: Vec::default(),
            bfd_peers: Vec::default(),
        }
    }

    async fn apply(
        ctx: &Arc<HandlerContext>,
        routers: Vec<RouterSpec>,
    ) -> Result<(), HttpError> {
        do_multi_router_apply(ctx, MultiRouterApplyRequest { routers }).await
    }

    fn router_names(ctx: &Arc<HandlerContext>) -> Vec<String> {
        let mut names: Vec<String> =
            ctx.db.list_routers().into_iter().map(|r| r.name).collect();
        names.sort();
        names
    }

    /// Everything a rejected apply must leave untouched: routers, BGP router
    /// instances, and each router's neighbors and static route count.
    type Snapshot = (
        Vec<String>,
        Vec<(RouterId, u32)>,
        Vec<(String, Vec<IpAddr>, usize)>,
    );

    fn snapshot(ctx: &Arc<HandlerContext>) -> Snapshot {
        let names = router_names(ctx);
        let bgp: Vec<(RouterId, u32)> =
            lock!(ctx.bgp.router).keys().cloned().collect();
        let per_router = ctx
            .db
            .list_routers()
            .iter()
            .map(|info| {
                let rdb = ctx.db.router(info.id).expect("router db");
                let mut nbrs: Vec<IpAddr> = rdb
                    .get_bgp_neighbors()
                    .expect("neighbors")
                    .into_iter()
                    .map(|x| x.host.ip())
                    .collect();
                nbrs.sort();
                (
                    info.name.clone(),
                    nbrs,
                    rdb.get_static(None).expect("statics").len(),
                )
            })
            .collect();
        (names, bgp, per_router)
    }

    /// Id of the router whose BGP instance owns the live session for `ip`.
    fn session_owner(ctx: &Arc<HandlerContext>, ip: &str) -> Option<RouterId> {
        let peer = PeerId::Ip(ip.parse().unwrap());
        let session = lock!(ctx.bgp.sessions).get(&peer).cloned()?;
        lock!(ctx.bgp.router)
            .iter()
            .find(|(_, r)| session.belongs_to(r))
            .map(|((id, _), _)| *id)
    }

    /// Apply a two-router spec (same ASN, distinct peers), then re-apply
    /// with one router removed: the removed router's BGP, static and
    /// persistent state must be fully torn down while the surviving router
    /// is untouched. The "default" router seeded by the test db is
    /// daemon-owned: applies that omit it empty its (here already empty)
    /// configuration but never tear it down.
    #[tokio::test]
    async fn two_router_apply_then_remove() {
        let ctx = test_ctx("two_router_apply_then_remove");

        let r1 = spec("one", 65001, "203.0.113.1");
        let r2 = spec("two", 65001, "203.0.113.2");
        let rq = MultiRouterApplyRequest {
            routers: vec![r1.clone(), r2.clone()],
        };
        do_multi_router_apply(&ctx, rq.clone())
            .await
            .expect("apply two routers");

        assert_eq!(
            router_names(&ctx),
            vec!["default".to_string(), "one".to_string(), "two".to_string()]
        );

        // Same ASN on both routers is allowed; each has its own BGP router
        // instance and its own neighbor/static state.
        for spec in [&r1, &r2] {
            assert!(lock!(ctx.bgp.router).contains_key(&(spec.id, 65001)));
            let rdb = ctx.db.router(spec.id).expect("router db");
            assert_eq!(rdb.id(), spec.id);
            // The TEP is daemon-generated, not caller-supplied: a ULA.
            assert_eq!(rdb.tep().octets()[0], 0xfd);
            let neighbors = rdb.get_bgp_neighbors().expect("neighbors");
            assert_eq!(neighbors.len(), 1);
            assert_eq!(
                neighbors[0].host.ip(),
                spec.bgp.as_ref().unwrap().peers["qsfp0"][0].host.ip(),
            );
            let statics = rdb.get_static(None).expect("static routes");
            assert_eq!(statics.len(), 1);
            assert_eq!(
                statics[0].prefix,
                oxnet::IpNet::from(spec.static4[0].prefix),
            );
        }

        let tep_one = ctx.db.router(r1.id).expect("router db").tep();

        // Re-apply with router "two" removed.
        apply(&ctx, vec![r1.clone()])
            .await
            .expect("re-apply with one router removed");

        assert_eq!(
            router_names(&ctx),
            vec!["default".to_string(), "one".to_string()]
        );
        assert!(ctx.db.router(r2.id).is_err());
        assert!(!lock!(ctx.bgp.router).contains_key(&(r2.id, 65001)));

        // The survivor is untouched, including its generated TEP.
        let rdb = ctx.db.router(r1.id).expect("router db");
        assert_eq!(rdb.get_bgp_neighbors().expect("neighbors").len(), 1);
        assert_eq!(rdb.get_static(None).expect("static routes").len(), 1);
        assert_eq!(rdb.tep(), tep_one);

        // Recreating "two" after a clean teardown must start from a clean
        // slate.
        do_multi_router_apply(&ctx, rq)
            .await
            .expect("re-apply both routers");
        let rdb = ctx.db.router(r2.id).expect("router db");
        assert_eq!(rdb.get_bgp_neighbors().expect("neighbors").len(), 1);
        assert_eq!(rdb.get_static(None).expect("static routes").len(), 1);
    }

    /// A "default" spec configures the daemon-owned default router in
    /// place: its TEP stays the daemon's, its BGP/static state reconciles
    /// like any other router's, and absence from a later apply empties its
    /// configuration while the router itself (id, TEP) stays in place.
    /// Re-applying a peer the default router already has live is an update,
    /// not a claim conflict. The default name and the default id go
    /// together: a spec with only one of them is rejected.
    #[tokio::test]
    async fn default_router_spec_applies_in_place() {
        let ctx = test_ctx("default_router_spec_applies_in_place");

        let daemon_tep = ctx.rdb().expect("default rdb").tep();

        for (name, id) in [
            ("default", RouterId::new_random()),
            ("one", DEFAULT_ROUTER_ID),
        ] {
            let mut s = spec(name, 65000, "203.0.113.7");
            s.id = id;
            let err = apply(&ctx, vec![s])
                .await
                .expect_err("default name/id mismatch must be rejected");
            assert_eq!(err.status_code.as_u16(), 400, "{name} {id}");
        }
        assert_eq!(router_names(&ctx), vec!["default".to_string()]);

        let mut s = spec("default", 65000, "203.0.113.7");
        s.id = DEFAULT_ROUTER_ID;
        apply(&ctx, vec![s.clone()])
            .await
            .expect("apply default spec");

        let rdb = ctx.rdb().expect("default rdb");
        assert_eq!(rdb.tep(), daemon_tep, "daemon TEP kept");
        assert!(
            lock!(ctx.bgp.router).contains_key(&(DEFAULT_ROUTER_ID, 65000))
        );
        let neighbors = rdb.get_bgp_neighbors().expect("neighbors");
        assert_eq!(neighbors.len(), 1);
        assert_eq!(
            neighbors[0].host.ip(),
            "203.0.113.7".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(rdb.get_static(None).expect("statics").len(), 1);

        // Re-apply with an overlapping live peer: update, not a conflict.
        apply(&ctx, vec![s.clone()])
            .await
            .expect("re-apply default spec");

        // Absence = empty the configuration; the router itself stays.
        apply(&ctx, vec![spec("one", 65001, "203.0.113.8")])
            .await
            .expect("apply without default");
        let rdb = ctx.rdb().expect("default rdb");
        assert_eq!(rdb.tep(), daemon_tep, "TEP survives the emptying");
        assert!(rdb.get_bgp_neighbors().expect("neighbors").is_empty());
        assert!(rdb.get_static(None).expect("statics").is_empty());
        assert!(
            !lock!(ctx.bgp.router).contains_key(&(DEFAULT_ROUTER_ID, 65000))
        );
    }

    /// A live router re-applied under a new name keeps its id and all of
    /// its state: it is renamed in place, not torn down and re-created.
    #[tokio::test]
    async fn rename_keeps_router_state() {
        let ctx = test_ctx("rename_keeps_router_state");

        let mut one = spec("one", 65001, "203.0.113.1");
        apply(&ctx, vec![one.clone()]).await.expect("apply one");
        let before = ctx.db.router(one.id).expect("one");

        one.name = "uno".into();
        apply(&ctx, vec![one.clone()]).await.expect("rename");

        assert_eq!(
            router_names(&ctx),
            vec!["default".to_string(), "uno".to_string()]
        );
        let after = ctx.db.router(one.id).expect("uno");
        assert_eq!(after.tep(), before.tep());
        assert_eq!(after.get_bgp_neighbors().expect("neighbors").len(), 1);
        assert_eq!(session_owner(&ctx, "203.0.113.1"), Some(one.id));

        // Two routers may swap names in one apply.
        let mut two = spec("two", 65002, "203.0.113.2");
        apply(&ctx, vec![one.clone(), two.clone()])
            .await
            .expect("apply two");
        (one.name, two.name) = (two.name, one.name);
        apply(&ctx, vec![one.clone(), two.clone()])
            .await
            .expect("swap names");
        assert_eq!(ctx.db.router(one.id).expect("one").name(), "two");
        assert_eq!(ctx.db.router(two.id).expect("two").name(), "uno");
    }

    /// Duplicate router names, ids, or cross-router BGP peer addresses must
    /// be rejected up front.
    #[tokio::test]
    async fn apply_validation_rejects_duplicates() {
        let ctx = test_ctx("apply_validation_rejects_duplicates");

        let good = || {
            (
                spec("one", 65001, "203.0.113.1"),
                spec("two", 65002, "203.0.113.2"),
            )
        };

        let dup_name = {
            let (a, mut b) = good();
            b.name = a.name.clone();
            vec![a, b]
        };
        let dup_id = {
            let (a, mut b) = good();
            b.id = a.id;
            vec![a, b]
        };
        let dup_peer = {
            let (a, mut b) = good();
            b.bgp = a.bgp.clone();
            vec![a, b]
        };

        for routers in [dup_name, dup_id, dup_peer] {
            let err = apply(&ctx, routers)
                .await
                .expect_err("duplicate spec must be rejected");
            assert_eq!(err.status_code.as_u16(), 400);
        }
        assert_eq!(router_names(&ctx), vec!["default".to_string()]);
    }

    /// A request that omits the default router empties it before the other
    /// specs apply, so peers the default router held live are claimable by
    /// another router in the same request.
    #[tokio::test]
    async fn absent_default_frees_its_peers_for_other_routers() {
        let ctx = test_ctx("absent_default_frees_its_peers_for_other_routers");

        // Seed the default router with a numbered (203.0.113.1) and an
        // unnumbered (tfportqsfp1_0) peer through the legacy path.
        do_bgp_apply(
            &ctx,
            &ctx.rdb().expect("default router db"),
            mixed_req(65000, 6),
        )
        .await
        .expect("seed default router");

        let claim = {
            let mut s = spec("one", 65001, "203.0.113.1");
            s.bgp.as_mut().unwrap().unnumbered_peers = HashMap::from([(
                "qsfp1".into(),
                vec![unnumbered("tfportqsfp1_0", "u0", 6)],
            )]);
            s
        };
        let claim_id = claim.id;
        apply(&ctx, vec![claim])
            .await
            .expect("claim the default router's freed peers");

        // The default router was emptied, and "one" owns the peers now.
        let default_rdb = ctx.rdb().expect("default router db");
        assert!(default_rdb.get_bgp_neighbors().expect("nbrs").is_empty());
        assert!(
            default_rdb
                .get_unnumbered_bgp_neighbors()
                .expect("unnumbered nbrs")
                .is_empty()
        );
        assert!(
            !lock!(ctx.bgp.router).contains_key(&(DEFAULT_ROUTER_ID, 65000))
        );
        let rdb = ctx.db.router(claim_id).expect("router db");
        assert_eq!(rdb.get_bgp_neighbors().expect("nbrs").len(), 1);
        assert_eq!(
            rdb.get_unnumbered_bgp_neighbors()
                .expect("unnumbered nbrs")
                .len(),
            1
        );
        assert_eq!(session_owner(&ctx, "203.0.113.1"), Some(claim_id));
    }

    /// max_paths in the spec sets the router's bestpath fanout; omitting it
    /// resets the fanout to the default of 1.
    #[tokio::test]
    async fn max_paths_applied_and_reset_on_omission() {
        let ctx = test_ctx("max_paths_applied_and_reset_on_omission");

        let mut s = spec("one", 65001, "203.0.113.1");
        s.bgp.as_mut().unwrap().max_paths = NonZeroU8::new(4);
        apply(&ctx, vec![s.clone()])
            .await
            .expect("apply with max_paths");
        let rdb = ctx.db.router(s.id).expect("router db");
        assert_eq!(
            rdb.get_bestpath_fanout().expect("fanout"),
            NonZeroU8::new(4).unwrap()
        );

        s.bgp.as_mut().unwrap().max_paths = None;
        apply(&ctx, vec![s])
            .await
            .expect("re-apply without max_paths");
        assert_eq!(
            rdb.get_bestpath_fanout().expect("fanout"),
            NonZeroU8::new(1).unwrap()
        );
    }

    /// checker/shaper sources in the spec are loaded on apply and unloaded
    /// when a later apply omits them.
    #[tokio::test]
    async fn policy_applied_via_spec() {
        let ctx = test_ctx("policy_applied_via_spec");

        let mut s = spec("one", 65001, "203.0.113.1");
        s.bgp.as_mut().unwrap().checker = Some(CheckerSource {
            asn: 65001,
            code: POLICY_SOURCE.to_string(),
        });
        s.bgp.as_mut().unwrap().shaper = Some(ShaperSource {
            asn: 65001,
            code: POLICY_SOURCE.to_string(),
        });
        apply(&ctx, vec![s.clone()])
            .await
            .expect("apply with policy");
        {
            let routers = lock!(ctx.bgp.router);
            let rtr = routers.get(&(s.id, 65001)).expect("bgp router");
            assert_eq!(
                rtr.policy.checker_source(),
                Some(POLICY_SOURCE.to_string())
            );
            assert_eq!(
                rtr.policy.shaper_source(),
                Some(POLICY_SOURCE.to_string())
            );
        }

        s.bgp.as_mut().unwrap().checker = None;
        s.bgp.as_mut().unwrap().shaper = None;
        apply(&ctx, vec![s.clone()])
            .await
            .expect("re-apply without policy");
        {
            let routers = lock!(ctx.bgp.router);
            let rtr = routers.get(&(s.id, 65001)).expect("bgp router");
            assert!(rtr.policy.checker_source().is_none());
            assert!(rtr.policy.shaper_source().is_none());
        }
    }

    /// A-01/A-10: a request whose problem sits in a *later* spec — where a
    /// list-order apply would already have reconciled the earlier routers —
    /// is rejected as a whole with zero mutation: no router created, the
    /// existing router's neighbors and statics untouched.
    #[tokio::test]
    async fn late_invalid_request_causes_no_mutation() {
        let ctx = test_ctx("late_invalid_request_causes_no_mutation");

        let one = spec("one", 65001, "203.0.113.1");
        apply(&ctx, vec![one.clone()]).await.expect("apply one");
        let before = snapshot(&ctx);

        let two = || spec("two", 65002, "203.0.113.2");
        let cases: Vec<(&str, RouterSpec)> = vec![
            ("invalid static prefix", {
                let mut s = two();
                s.static4[0].prefix = "224.0.0.0/24".parse().unwrap();
                s
            }),
            ("invalid bgp listen address", {
                let mut s = two();
                s.bgp.as_mut().unwrap().listen = "not-a-socket-addr".into();
                s
            }),
            ("invalid originate prefix", {
                let mut s = two();
                s.bgp.as_mut().unwrap().originate =
                    vec!["224.0.0.0/24".parse().unwrap()];
                s
            }),
            ("mixed-family bfd peer", {
                let mut s = two();
                s.bfd_peers = vec![BfdPeerConfig {
                    peer: "203.0.113.9".parse().unwrap(),
                    listen: "::1".parse().unwrap(),
                    required_rx: 1_000_000,
                    detection_threshold: NonZeroU8::new(3).unwrap(),
                    mode: SessionMode::SingleHop,
                }];
                s
            }),
        ];
        for (what, two) in cases {
            let two_id = two.id;
            // "one" is listed first and unchanged; the invalid spec is last.
            let err =
                apply(&ctx, vec![one.clone(), two]).await.expect_err(what);
            assert_eq!(
                err.status_code.as_u16(),
                400,
                "{what}: {}",
                err.external_message
            );
            assert_eq!(snapshot(&ctx), before, "{what} mutated state");
            assert!(ctx.db.router(two_id).is_err(), "{what} created a router");
        }
    }

    /// A-01: two applies racing each other serialize; the final state is
    /// exactly one of the two requested states, never an interleaving.
    #[tokio::test]
    async fn concurrent_applies_serialize_to_one_consistent_state() {
        let ctx =
            test_ctx("concurrent_applies_serialize_to_one_consistent_state");

        let a = spec("one", 65001, "203.0.113.1");
        let b = spec("two", 65002, "203.0.113.2");
        let (ra, rb) = tokio::join!(
            apply(&ctx, vec![a.clone()]),
            apply(&ctx, vec![b.clone()])
        );
        ra.expect("apply a");
        rb.expect("apply b");

        let names = router_names(&ctx);
        let bgp: Vec<(RouterId, u32)> =
            lock!(ctx.bgp.router).keys().cloned().collect();
        let is = |s: &RouterSpec, asn: u32| {
            names == vec!["default".to_string(), s.name.clone()]
                && bgp == vec![(s.id, asn)]
        };
        assert!(
            is(&a, 65001) || is(&b, 65002),
            "mixed final state: routers {names:?}, bgp {bgp:?}"
        );
    }

    /// A-01/A-08: moving a peer from one named router to another in a single
    /// apply converges regardless of the order the specs are listed in,
    /// because a moving peer is removed from its old router before any
    /// router is applied. The live sessions end up owned by the right router.
    #[tokio::test]
    async fn peer_transfer_between_named_routers_is_order_independent() {
        for one_first in [true, false] {
            let ctx = test_ctx(&format!(
                "peer_transfer_between_named_routers_one_first_{one_first}"
            ));
            let one = spec("one", 65001, "203.0.113.1");
            let two = spec("two", 65002, "203.0.113.2");
            apply(&ctx, vec![one.clone(), two.clone()])
                .await
                .expect("initial apply");
            assert_eq!(session_owner(&ctx, "203.0.113.1"), Some(one.id));
            assert_eq!(session_owner(&ctx, "203.0.113.2"), Some(two.id));

            // Swap the two routers' peers (and statics).
            let mut one2 = one.clone();
            let mut two2 = two.clone();
            one2.bgp.as_mut().unwrap().peers =
                two.bgp.as_ref().unwrap().peers.clone();
            one2.static4 = two.static4.clone();
            two2.bgp.as_mut().unwrap().peers =
                one.bgp.as_ref().unwrap().peers.clone();
            two2.static4 = one.static4.clone();
            let rq = if one_first {
                vec![one2, two2]
            } else {
                vec![two2, one2]
            };
            apply(&ctx, rq).await.expect("swap converges");

            let nbr = |id: RouterId| {
                let n = ctx.db.router(id).unwrap().get_bgp_neighbors().unwrap();
                assert_eq!(n.len(), 1, "{id} neighbors: {n:?}");
                n[0].host.ip().to_string()
            };
            assert_eq!(nbr(one.id), "203.0.113.2");
            assert_eq!(nbr(two.id), "203.0.113.1");
            assert_eq!(session_owner(&ctx, "203.0.113.2"), Some(one.id));
            assert_eq!(session_owner(&ctx, "203.0.113.1"), Some(two.id));
        }
    }

    /// A BFD peer moving between routers converges in one apply when its
    /// new router is listed before its old one, in both directions.
    #[tokio::test]
    async fn bfd_peer_transfer_new_owner_listed_first() {
        let ctx = test_ctx("bfd_peer_transfer_new_owner_listed_first");
        let peer = BfdPeerConfig {
            peer: "203.0.113.9".parse().unwrap(),
            listen: "127.0.0.1".parse().unwrap(),
            required_rx: 1_000_000,
            detection_threshold: NonZeroU8::new(3).unwrap(),
            mode: SessionMode::SingleHop,
        };
        let mut from = spec("one", 65001, "203.0.113.1");
        let mut to = spec("two", 65002, "203.0.113.2");
        from.bfd_peers = vec![peer];
        apply(&ctx, vec![from.clone(), to.clone()])
            .await
            .expect("initial apply");

        let bfd = |id: RouterId| {
            ctx.db.router(id).unwrap().get_bfd_neighbors().unwrap()
        };
        // Move the peer to "two", then back to "one".
        for _ in 0..2 {
            from.bfd_peers.clear();
            to.bfd_peers = vec![peer];
            apply(&ctx, vec![to.clone(), from.clone()])
                .await
                .expect("move converges");
            assert_eq!(bfd(to.id), vec![peer]);
            assert!(bfd(from.id).is_empty());
            assert_eq!(lock!(ctx.bfd.daemon).sessions_iter().count(), 1);
            std::mem::swap(&mut from, &mut to);
        }
    }
}
