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
use mg_api_types::bfd::BfdPeerConfig;
use mg_api_types::bgp::config::{ApplyRequest, PeerInfo};
use mg_api_types::rib::{Rib, RibQuery};
use mg_api_types::router::{
    MultiRouterApplyRequest, RouterInfo, RouterSelector, RouterSpec,
};
use mg_common::lock;
use oxnet::IpNet;
use rdb::{RibExt, StaticRouteKey};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
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
    let name = path.into_inner().router;
    let ctx = ctx.context();
    // 404 for an unknown router; a router with no BGP sessions returns {}.
    let rdb = router_db(ctx, &name)?;
    let sessions = bgp_admin::rdb_attributed_sessions(ctx, &rdb, None)?;
    Ok(HttpResponseOk(
        sessions
            .iter()
            .map(|s| (s.neighbor.peer.to_string(), s.get_peer_info()))
            .collect(),
    ))
}

fn router_db(
    ctx: &Arc<HandlerContext>,
    name: &str,
) -> Result<rdb::RouterDb, HttpError> {
    ctx.db.router(name).map_err(|e| Error::from(e).into())
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

pub(crate) async fn do_multi_router_apply(
    ctx: &Arc<HandlerContext>,
    rq: MultiRouterApplyRequest,
) -> Result<(), HttpError> {
    validate_apply_request(&rq)?;

    // Retry cleanup of switch tables left dirty by earlier failed
    // teardowns; their table indexes stay tombstoned until dpd confirms
    // they are clean.
    ctx.lower
        .scrub_orphaned_switch_indexes(&ctx.db, &ctx.log)
        .await;

    // Tear down routers that are absent from the desired list. A change of
    // identity (uuid) is also handled as teardown followed by re-creation
    // below: the uuid scopes persistent state and platform programming, so
    // rebuilding is simpler and safer than editing in place.
    let desired: BTreeMap<&str, &RouterSpec> =
        rq.routers.iter().map(|s| (s.name.as_str(), s)).collect();
    for info in ctx.db.list_routers() {
        // The default router's lifecycle is daemon-owned: a "default" spec
        // configures it in place (never teardown/re-create — its uuid and
        // TEP are the daemon's, the spec's id is ignored). Absence from the
        // desired list empties its configuration in place; doing so here,
        // alongside the teardowns, frees peers that another spec in this
        // request may be claiming.
        if info.name == rdb::DEFAULT_ROUTER {
            if !desired.contains_key(rdb::DEFAULT_ROUTER) {
                let rdb = router_db(ctx, &info.name)?;
                apply_router_spec(
                    ctx,
                    &rdb,
                    RouterSpec {
                        name: info.name.clone(),
                        id: info.id,
                        bgp: None,
                        static4: Vec::new(),
                        static6: Vec::new(),
                        bfd_peers: Vec::new(),
                    },
                )
                .await?;
            }
            continue;
        }
        match desired.get(info.name.as_str()) {
            Some(spec) if spec.id == info.id => {}
            _ => teardown_router(ctx, &info.name).await?,
        }
    }

    // Apply the default router's spec first: it may drop live peer claims
    // that another router in the same request is picking up.
    let mut routers = rq.routers;
    routers.sort_by_key(|s| s.name != rdb::DEFAULT_ROUTER);
    for spec in routers {
        let rdb = match ctx.db.router(&spec.name) {
            Ok(rdb) => rdb,
            Err(_) => ctx
                .db
                .create_router(RouterInfo {
                    id: spec.id,
                    name: spec.name.clone(),
                    tep: random_tep_ula(),
                })
                .map_err(|e| HttpError::from(Error::from(e)))?,
        };
        ctx.lower.ensure(&rdb, &ctx.log, &ctx.mg_lower_stats);
        apply_router_spec(ctx, &rdb, spec).await?;
    }

    Ok(())
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
    name: &str,
) -> Result<(), HttpError> {
    let rdb = router_db(ctx, name)?;

    // Stop the router's mg-lower thread first: on shutdown it withdraws the
    // router's ASIC routes and ddm tunnel advertisements based on the RIB
    // contents, so it must run before the RIB is torn down. `clean` records
    // whether dpd confirmed the router's switch table was emptied.
    let clean = ctx.lower.stop(name).await;
    if !clean {
        slog::warn!(
            ctx.log,
            "teardown of router {name} could not confirm its switch table is \
             clean; tombstoning its switch table index"
        );
    }

    let asns: Vec<u32> = lock!(ctx.bgp.router)
        .keys()
        .filter(|(n, _)| n == name)
        .map(|(_, asn)| *asn)
        .collect();
    for asn in asns {
        bgp_admin::do_delete_router(ctx, &rdb, asn).await?;
    }

    remove_bfd_peers(ctx, name, |_, _| true).await;

    ctx.db
        .delete_router(name, clean)
        .map_err(|e| HttpError::from(Error::from(e)))?;
    Ok(())
}

/// Remove this router's BFD sessions matching `unwanted`, waiting for any
/// freed-up listeners to fully shut down so the addresses are reusable.
async fn remove_bfd_peers(
    ctx: &Arc<HandlerContext>,
    router: &str,
    unwanted: impl Fn(&IpAddr, BfdPeerConfig) -> bool,
) {
    let mut handles = Vec::new();
    {
        let mut daemon = lock!(ctx.bfd.daemon);
        let peers: Vec<IpAddr> = daemon
            .router_sessions_iter(router)
            .filter(|(addr, session)| {
                let listen = match daemon.listen_addr_for_peer(addr) {
                    Some(l) => l.ip(),
                    // No listener means the session is in a broken state;
                    // treat as removable.
                    None => return true,
                };
                unwanted(
                    addr,
                    BfdPeerConfig {
                        peer: **addr,
                        listen,
                        required_rx: session.required_rx_micros(),
                        detection_threshold: session.detection_threshold(),
                        mode: session.mode(),
                    },
                )
            })
            .map(|(addr, _)| *addr)
            .collect();
        for peer in peers {
            if let Some(handle) = daemon.remove_peer(peer) {
                handles.push(handle);
            }
        }
    }
    for handle in handles {
        handle.shutdown().await;
    }
}

async fn apply_router_spec(
    ctx: &Arc<HandlerContext>,
    rdb: &rdb::RouterDb,
    spec: RouterSpec,
) -> Result<(), HttpError> {
    apply_bgp(ctx, rdb, &spec).await?;
    apply_static(rdb, &spec)?;
    apply_bfd(ctx, rdb, spec).await?;
    Ok(())
}

async fn apply_bgp(
    ctx: &Arc<HandlerContext>,
    rdb: &rdb::RouterDb,
    spec: &RouterSpec,
) -> Result<(), HttpError> {
    // Drop any BGP router under this logical router whose ASN is no longer
    // the desired one (or all of them if BGP is being disabled).
    let desired_asn = spec.bgp.as_ref().map(|b| b.asn);
    let stale: Vec<u32> = lock!(ctx.bgp.router)
        .keys()
        .filter(|(n, asn)| n == &spec.name && Some(*asn) != desired_asn)
        .map(|(_, asn)| *asn)
        .collect();
    for asn in stale {
        bgp_admin::do_delete_router(ctx, rdb, asn).await?;
    }

    let Some(bgp) = &spec.bgp else {
        return Ok(());
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
    spec: &RouterSpec,
) -> Result<(), HttpError> {
    let desired: BTreeSet<StaticRouteKey> = spec
        .static4
        .iter()
        .cloned()
        .map(static_route_key_from_v4)
        .chain(spec.static6.iter().cloned().map(static_route_key_from_v6))
        .collect();

    let prefixes: Vec<IpNet> = desired.iter().map(|r| r.prefix).collect();
    validate_prefixes(&prefixes)?;

    let current: BTreeSet<StaticRouteKey> = rdb
        .get_static(None)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?
        .into_iter()
        .collect();

    let to_remove: Vec<StaticRouteKey> =
        current.difference(&desired).cloned().collect();
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

async fn apply_bfd(
    ctx: &Arc<HandlerContext>,
    rdb: &rdb::RouterDb,
    spec: RouterSpec,
) -> Result<(), HttpError> {
    let desired: BTreeMap<IpAddr, BfdPeerConfig> =
        spec.bfd_peers.into_iter().map(|p| (p.peer, p)).collect();

    // Remove sessions that are unwanted or whose config changed (a changed
    // config is remove + re-add: BFD sessions are cheap to restart).
    remove_bfd_peers(ctx, &spec.name, |addr, current| {
        desired.get(addr) != Some(&current)
    })
    .await;

    let existing: HashSet<IpAddr> = lock!(ctx.bfd.daemon)
        .router_sessions_iter(&spec.name)
        .map(|(addr, _)| *addr)
        .collect();
    for (addr, config) in desired {
        if !existing.contains(&addr) {
            bfd_admin::add_peer(ctx.clone(), rdb.clone(), config)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::do_multi_router_apply;
    use crate::bgp_admin::do_bgp_apply;
    use crate::bgp_admin::tests::{
        POLICY_SOURCE, mixed_req, numbered, test_ctx, unnumbered,
    };
    use mg_api_types::bgp::config::{CheckerSource, ShaperSource};
    use mg_api_types::router::{
        BgpSpec, MultiRouterApplyRequest, RouterId, RouterSpec,
    };
    use mg_api_types::static_routes::StaticRoute4;
    use mg_common::lock;
    use std::collections::HashMap;
    use std::num::NonZeroU8;

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

        let mut names: Vec<String> =
            ctx.db.list_routers().into_iter().map(|r| r.name).collect();
        names.sort();
        assert_eq!(
            names,
            vec!["default".to_string(), "one".to_string(), "two".to_string()]
        );

        // Same ASN on both routers is allowed; each has its own BGP router
        // instance and its own neighbor/static state.
        for spec in [&r1, &r2] {
            assert!(
                lock!(ctx.bgp.router).contains_key(&(spec.name.clone(), 65001))
            );
            let rdb = ctx.db.router(&spec.name).expect("router db");
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

        let tep_one = ctx.db.router("one").expect("router db").tep();

        // Re-apply with router "two" removed.
        do_multi_router_apply(
            &ctx,
            MultiRouterApplyRequest {
                routers: vec![r1.clone()],
            },
        )
        .await
        .expect("re-apply with one router removed");

        let mut names: Vec<String> =
            ctx.db.list_routers().into_iter().map(|r| r.name).collect();
        names.sort();
        assert_eq!(names, vec!["default".to_string(), "one".to_string()]);
        assert!(ctx.db.router("two").is_err());
        assert!(
            !lock!(ctx.bgp.router).contains_key(&("two".to_string(), 65001))
        );

        // The survivor is untouched, including its generated TEP.
        let rdb = ctx.db.router("one").expect("router db");
        assert_eq!(rdb.get_bgp_neighbors().expect("neighbors").len(), 1);
        assert_eq!(rdb.get_static(None).expect("static routes").len(), 1);
        assert_eq!(rdb.tep(), tep_one);

        // Recreating "two" after teardown must start from a clean slate.
        do_multi_router_apply(&ctx, rq)
            .await
            .expect("re-apply both routers");
        let rdb = ctx.db.router("two").expect("router db");
        assert_eq!(rdb.get_bgp_neighbors().expect("neighbors").len(), 1);
        assert_eq!(rdb.get_static(None).expect("static routes").len(), 1);
    }

    /// A "default" spec configures the daemon-owned default router in
    /// place: its id and TEP stay the daemon's (the spec's id is ignored),
    /// its BGP/static state reconciles like any other router's, and
    /// absence from a later apply empties its configuration while the
    /// router itself (id, TEP) stays in place. Re-applying a peer the
    /// default router already has live is an update, not a claim conflict.
    #[tokio::test]
    async fn default_router_spec_applies_in_place() {
        let ctx = test_ctx("default_router_spec_applies_in_place");

        let before = ctx.db.router("default").expect("default rdb");
        let daemon_id = before.id();
        let daemon_tep = before.tep();

        let s = spec("default", 65000, "203.0.113.7");
        do_multi_router_apply(
            &ctx,
            MultiRouterApplyRequest {
                routers: vec![s.clone()],
            },
        )
        .await
        .expect("apply default spec");

        let rdb = ctx.db.router("default").expect("default rdb");
        assert_eq!(rdb.id(), daemon_id, "daemon id kept, spec id ignored");
        assert_eq!(rdb.tep(), daemon_tep, "daemon TEP kept");
        assert!(
            lock!(ctx.bgp.router).contains_key(&("default".to_string(), 65000))
        );
        let neighbors = rdb.get_bgp_neighbors().expect("neighbors");
        assert_eq!(neighbors.len(), 1);
        assert_eq!(
            neighbors[0].host.ip(),
            "203.0.113.7".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(rdb.get_static(None).expect("statics").len(), 1);

        // Re-apply with an overlapping live peer: update, not a conflict.
        do_multi_router_apply(
            &ctx,
            MultiRouterApplyRequest {
                routers: vec![s.clone()],
            },
        )
        .await
        .expect("re-apply default spec");

        // Absence = empty the configuration; the router itself stays.
        do_multi_router_apply(
            &ctx,
            MultiRouterApplyRequest {
                routers: vec![spec("one", 65001, "203.0.113.8")],
            },
        )
        .await
        .expect("apply without default");
        let rdb = ctx.db.router("default").expect("default rdb");
        assert_eq!(rdb.id(), daemon_id, "id survives the emptying");
        assert_eq!(rdb.tep(), daemon_tep, "TEP survives the emptying");
        assert!(rdb.get_bgp_neighbors().expect("neighbors").is_empty());
        assert!(rdb.get_static(None).expect("statics").is_empty());
        assert!(
            !lock!(ctx.bgp.router)
                .contains_key(&("default".to_string(), 65000))
        );
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
            let err = do_multi_router_apply(
                &ctx,
                MultiRouterApplyRequest { routers },
            )
            .await
            .expect_err("duplicate spec must be rejected");
            assert_eq!(err.status_code.as_u16(), 400);
        }
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
        do_multi_router_apply(
            &ctx,
            MultiRouterApplyRequest {
                routers: vec![claim],
            },
        )
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
            !lock!(ctx.bgp.router)
                .contains_key(&("default".to_string(), 65000))
        );
        let rdb = ctx.db.router("one").expect("router db");
        assert_eq!(rdb.get_bgp_neighbors().expect("nbrs").len(), 1);
        assert_eq!(
            rdb.get_unnumbered_bgp_neighbors()
                .expect("unnumbered nbrs")
                .len(),
            1
        );
    }

    /// max_paths in the spec sets the router's bestpath fanout; omitting it
    /// resets the fanout to the default of 1.
    #[tokio::test]
    async fn max_paths_applied_and_reset_on_omission() {
        let ctx = test_ctx("max_paths_applied_and_reset_on_omission");

        let mut s = spec("one", 65001, "203.0.113.1");
        s.bgp.as_mut().unwrap().max_paths = NonZeroU8::new(4);
        do_multi_router_apply(
            &ctx,
            MultiRouterApplyRequest {
                routers: vec![s.clone()],
            },
        )
        .await
        .expect("apply with max_paths");
        let rdb = ctx.db.router("one").expect("router db");
        assert_eq!(
            rdb.get_bestpath_fanout().expect("fanout"),
            NonZeroU8::new(4).unwrap()
        );

        s.bgp.as_mut().unwrap().max_paths = None;
        do_multi_router_apply(
            &ctx,
            MultiRouterApplyRequest { routers: vec![s] },
        )
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
        do_multi_router_apply(
            &ctx,
            MultiRouterApplyRequest {
                routers: vec![s.clone()],
            },
        )
        .await
        .expect("apply with policy");
        {
            let routers = lock!(ctx.bgp.router);
            let rtr = routers
                .get(&("one".to_string(), 65001))
                .expect("bgp router");
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
        do_multi_router_apply(
            &ctx,
            MultiRouterApplyRequest { routers: vec![s] },
        )
        .await
        .expect("re-apply without policy");
        {
            let routers = lock!(ctx.bgp.router);
            let rtr = routers
                .get(&("one".to_string(), 65001))
                .expect("bgp router");
            assert!(rtr.policy.checker_source().is_none());
            assert!(rtr.policy.shaper_source().is_none());
        }
    }
}
