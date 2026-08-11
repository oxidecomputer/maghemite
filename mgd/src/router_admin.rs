// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The multi-router reconciler and router observability endpoints.
//!
//! `multi_router_apply` is the single entry point omicron uses to drive
//! router configuration: it receives the complete desired router list and
//! converges the daemon onto it. There is deliberately no per-router CRUD.

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
use mg_api_types::bgp::config::ApplyRequest;
use mg_api_types::rib::{Rib, RibQuery};
use mg_api_types::router::{
    MultiRouterApplyRequest, RouterInfo, RouterSelector, RouterSpec,
};
use mg_common::lock;
use oxnet::IpNet;
use rdb::{RibExt, StaticRouteKey};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
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

fn router_db(
    ctx: &Arc<HandlerContext>,
    name: &str,
) -> Result<rdb::RouterDb, HttpError> {
    ctx.db.router(name).map_err(|e| Error::from(e).into())
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

    // Tear down routers that are absent from the desired list. A change of
    // identity (uuid) or TEP is also handled as teardown followed by
    // re-creation below: both scope persistent state and platform
    // programming, so rebuilding is simpler and safer than editing in place.
    let desired: BTreeMap<&str, &RouterSpec> =
        rq.routers.iter().map(|s| (s.name.as_str(), s)).collect();
    for info in ctx.db.list_routers() {
        match desired.get(info.name.as_str()) {
            Some(spec) if spec.id == info.id && spec.tep == info.tep => {}
            _ => teardown_router(ctx, &info.name).await?,
        }
    }

    for spec in rq.routers {
        let rdb = match ctx.db.router(&spec.name) {
            Ok(rdb) => rdb,
            Err(_) => ctx
                .db
                .create_router(RouterInfo {
                    id: spec.id,
                    name: spec.name.clone(),
                    tep: spec.tep,
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
    let mut teps = HashSet::new();
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
        if !teps.insert(spec.tep) {
            return dup("router tep", &spec.tep);
        }
        if let Some(bgp) = &spec.bgp {
            for p in bgp.peers.values().flatten() {
                if !bgp_peers.insert(p.host.ip()) {
                    return dup("bgp peer address", &p.host.ip());
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
    // contents, so it must run before the RIB is torn down.
    ctx.lower.stop(name).await;

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
        .delete_router(name)
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
    use crate::bgp_admin::tests::{numbered, test_ctx};
    use mg_api_types::router::{
        BgpSpec, MultiRouterApplyRequest, RouterId, RouterSpec,
    };
    use mg_api_types::static_routes::StaticRoute4;
    use mg_common::lock;
    use std::collections::HashMap;

    fn spec(name: &str, tep: &str, asn: u32, peer: &str) -> RouterSpec {
        RouterSpec {
            name: name.into(),
            id: RouterId::new_random(),
            tep: tep.parse().unwrap(),
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
    /// is untouched. The "default" router seeded by the test db is absent
    /// from the desired list, so the first apply also tears it down.
    #[tokio::test]
    async fn two_router_apply_then_remove() {
        let ctx = test_ctx("two_router_apply_then_remove");

        let r1 = spec("one", "fd00::1", 65001, "203.0.113.1");
        let r2 = spec("two", "fd00::2", 65001, "203.0.113.2");
        let rq = MultiRouterApplyRequest {
            routers: vec![r1.clone(), r2.clone()],
        };
        do_multi_router_apply(&ctx, rq.clone())
            .await
            .expect("apply two routers");

        let mut names: Vec<String> =
            ctx.db.list_routers().into_iter().map(|r| r.name).collect();
        names.sort();
        assert_eq!(names, vec!["one".to_string(), "two".to_string()]);

        // Same ASN on both routers is allowed; each has its own BGP router
        // instance and its own neighbor/static state.
        for spec in [&r1, &r2] {
            assert!(
                lock!(ctx.bgp.router).contains_key(&(spec.name.clone(), 65001))
            );
            let rdb = ctx.db.router(&spec.name).expect("router db");
            assert_eq!(rdb.id(), spec.id);
            assert_eq!(rdb.tep(), spec.tep);
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

        // Re-apply with router "two" removed.
        do_multi_router_apply(
            &ctx,
            MultiRouterApplyRequest {
                routers: vec![r1.clone()],
            },
        )
        .await
        .expect("re-apply with one router removed");

        let names: Vec<String> =
            ctx.db.list_routers().into_iter().map(|r| r.name).collect();
        assert_eq!(names, vec!["one".to_string()]);
        assert!(ctx.db.router("two").is_err());
        assert!(
            !lock!(ctx.bgp.router).contains_key(&("two".to_string(), 65001))
        );

        // The survivor is untouched.
        let rdb = ctx.db.router("one").expect("router db");
        assert_eq!(rdb.get_bgp_neighbors().expect("neighbors").len(), 1);
        assert_eq!(rdb.get_static(None).expect("static routes").len(), 1);

        // Recreating "two" after teardown must start from a clean slate.
        do_multi_router_apply(&ctx, rq)
            .await
            .expect("re-apply both routers");
        let rdb = ctx.db.router("two").expect("router db");
        assert_eq!(rdb.get_bgp_neighbors().expect("neighbors").len(), 1);
        assert_eq!(rdb.get_static(None).expect("static routes").len(), 1);
    }

    /// Duplicate router names, ids, teps, or cross-router BGP peer
    /// addresses must be rejected up front.
    #[tokio::test]
    async fn apply_validation_rejects_duplicates() {
        let ctx = test_ctx("apply_validation_rejects_duplicates");

        let good = || {
            (
                spec("one", "fd00::1", 65001, "203.0.113.1"),
                spec("two", "fd00::2", 65002, "203.0.113.2"),
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
        let dup_tep = {
            let (a, mut b) = good();
            b.tep = a.tep;
            vec![a, b]
        };
        let dup_peer = {
            let (a, mut b) = good();
            b.bgp = a.bgp.clone();
            vec![a, b]
        };

        for routers in [dup_name, dup_id, dup_tep, dup_peer] {
            let err = do_multi_router_apply(
                &ctx,
                MultiRouterApplyRequest { routers },
            )
            .await
            .expect_err("duplicate spec must be rejected");
            assert_eq!(err.status_code.as_u16(), 400);
        }
    }
}
