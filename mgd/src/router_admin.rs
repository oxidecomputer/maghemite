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
//! [`HandlerContext::apply_lock`] and runs in two steps: [`plan_apply`]
//! validates the whole request — its own shape and its fit against the live
//! daemon state — without touching anything, then [`execute_apply`] carries
//! the plan out in fixed phases (teardown, release, claim). A request that
//! is invalid anywhere therefore leaves the daemon exactly as it was.

use crate::admin::HandlerContext;
use crate::bfd_admin;
use crate::bgp_admin;
use crate::error::Error;
use crate::static_admin::{static_route_key_from_v4, static_route_key_from_v6};
use crate::validation::validate_prefixes;
use dropshot::{
    ClientErrorStatusCode, HttpError, HttpResponseOk,
    HttpResponseUpdatedNoContent, Path, Query, RequestContext, TypedBody,
};
use mg_api_types::bfd::BfdPeerConfig;
use mg_api_types::bgp::config::{
    ApplyRequest, Neighbor, PeerInfo, UnnumberedNeighbor,
};
use mg_api_types::rib::{Rib, RibQuery};
use mg_api_types::router::{
    MultiRouterApplyRequest, RouterInfo, RouterSelector, RouterSpec,
};
use mg_common::lock;
use oxnet::IpNet;
use rdb::{RibExt, StaticRouteKey};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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

/// Converge the daemon onto `rq`.
///
/// Serialized with every other configuration writer through
/// `apply_lock`. Nothing is mutated on behalf of `rq` until the whole
/// request has been validated against the live state ([`plan_apply`]).
pub(crate) async fn do_multi_router_apply(
    ctx: &Arc<HandlerContext>,
    rq: MultiRouterApplyRequest,
) -> Result<(), HttpError> {
    let _serialized = ctx.apply_lock.lock().await;

    // Retry cleanup of switch tables left dirty by earlier failed
    // teardowns first: their table indexes stay tombstoned until dpd
    // confirms they are clean, and a tombstone that scrubs clean now must
    // not block a legitimate re-creation in this request. This repairs
    // earlier state; it is not a mutation on behalf of `rq`.
    ctx.lower
        .scrub_orphaned_switch_indexes(&ctx.db, &ctx.log)
        .await;

    let plan = plan_apply(ctx, rq)?;
    execute_apply(ctx, plan).await
}

/// A validated, fully resolved apply. Building one touches no daemon state.
struct ApplyPlan {
    /// Live routers to tear down before anything is created: absent from
    /// the request, or present under a different id (a change of identity
    /// is teardown followed by re-creation, since the uuid scopes all
    /// persistent state and platform programming).
    teardown: Vec<String>,
    /// The daemon-owned default router is absent from the request and must
    /// have its configuration emptied in place.
    empty_default: bool,
    /// Desired routers in application order: the default router first.
    routers: Vec<RouterPlan>,
}

struct RouterPlan {
    spec: RouterSpec,
    /// Validated complete static route set.
    statics: BTreeSet<StaticRouteKey>,
    /// Validated complete BFD peer set, by peer address.
    bfd: BTreeMap<IpAddr, BfdPeerConfig>,
    /// The router does not exist (or is being re-created) and must be
    /// created before its spec is applied.
    create: bool,
}

impl RouterPlan {
    /// The plan that empties an existing router's configuration.
    fn empty(info: &RouterInfo) -> Self {
        RouterPlan {
            spec: RouterSpec {
                name: info.name.clone(),
                id: info.id,
                bgp: None,
                static4: Vec::new(),
                static6: Vec::new(),
                bfd_peers: Vec::new(),
            },
            statics: BTreeSet::new(),
            bfd: BTreeMap::new(),
            create: false,
        }
    }
}

fn conflict(msg: String) -> HttpError {
    HttpError::for_client_error(None, ClientErrorStatusCode::CONFLICT, msg)
}

/// Validate `rq` — its own shape, then its fit against the live routers and
/// tombstones — and resolve it into an [`ApplyPlan`]. Pure: reads daemon
/// state, mutates nothing.
fn plan_apply(
    ctx: &Arc<HandlerContext>,
    rq: MultiRouterApplyRequest,
) -> Result<ApplyPlan, HttpError> {
    validate_apply_request(&rq)?;

    let live = ctx.db.list_routers();
    let default_id = live
        .iter()
        .find(|r| r.name == rdb::DEFAULT_ROUTER)
        .map(|r| r.id);
    let tombstones = ctx
        .db
        .orphaned_switch_indexes()
        .map_err(|e| HttpError::from(Error::from(e)))?;

    for spec in &rq.routers {
        validate_router_spec(spec)?;
        if spec.name == rdb::DEFAULT_ROUTER {
            // The default spec's id is ignored: that router's identity is
            // the daemon's.
            continue;
        }
        if Some(spec.id) == default_id {
            return Err(HttpError::for_bad_request(
                None,
                format!(
                    "router {:?}: id {} is the daemon-owned default \
                     router's id",
                    spec.name, spec.id
                ),
            ));
        }
        if let Some((_, index)) =
            tombstones.iter().find(|(id, _)| *id == spec.id)
        {
            return Err(conflict(format!(
                "router {:?}: id {} is tombstoned (switch table {index} \
                 awaits a clean scrub) and cannot be reused yet",
                spec.name, spec.id
            )));
        }
        if let Some(other) =
            live.iter().find(|r| r.id == spec.id && r.name != spec.name)
        {
            return Err(conflict(format!(
                "router {:?}: id {} belongs to live router {:?}",
                spec.name, spec.id, other.name
            )));
        }
    }

    let desired: BTreeMap<&str, &RouterSpec> =
        rq.routers.iter().map(|s| (s.name.as_str(), s)).collect();
    let mut teardown = Vec::new();
    let mut empty_default = false;
    for info in &live {
        if info.name == rdb::DEFAULT_ROUTER {
            empty_default = !desired.contains_key(rdb::DEFAULT_ROUTER);
            continue;
        }
        match desired.get(info.name.as_str()) {
            Some(spec) if spec.id == info.id => {}
            _ => teardown.push(info.name.clone()),
        }
    }

    // The default router is applied first: it may drop live peer claims
    // that another router in the same request is picking up.
    let mut specs = rq.routers;
    specs.sort_by_key(|s| s.name != rdb::DEFAULT_ROUTER);
    let mut routers = Vec::with_capacity(specs.len());
    for spec in specs {
        let statics = static_keys(&spec)?;
        let bfd = spec.bfd_peers.iter().map(|p| (p.peer, *p)).collect();
        let create = spec.name != rdb::DEFAULT_ROUTER
            && !live.iter().any(|r| r.name == spec.name && r.id == spec.id);
        routers.push(RouterPlan {
            spec,
            statics,
            bfd,
            create,
        });
    }

    Ok(ApplyPlan {
        teardown,
        empty_default,
        routers,
    })
}

/// Carry out a plan in fixed phases.
async fn execute_apply(
    ctx: &Arc<HandlerContext>,
    plan: ApplyPlan,
) -> Result<(), HttpError> {
    // 1. Tear down routers that are absent, or present under a new id.
    for name in &plan.teardown {
        teardown_router(ctx, name).await?;
    }

    // 2. Release: every surviving router first drops the BGP and BFD peers
    //    it no longer wants (an absent default router drops everything), so
    //    a peer moving between routers is free before anyone claims it —
    //    whatever order the specs were listed in.
    if plan.empty_default {
        let rdb = router_db(ctx, rdb::DEFAULT_ROUTER)?;
        let info = RouterInfo {
            id: rdb.id(),
            name: rdb.name().to_string(),
            tep: rdb.tep(),
        };
        apply_router_plan(ctx, &rdb, RouterPlan::empty(&info)).await?;
    }
    for rp in plan.routers.iter().filter(|rp| !rp.create) {
        let rdb = router_db(ctx, &rp.spec.name)?;
        release_bgp(ctx, &rdb, &rp.spec).await?;
        release_bfd(ctx, rp).await;
    }

    // 3. Claim: create missing routers, then converge each onto its spec.
    for rp in plan.routers {
        let rdb = if rp.create {
            ctx.db
                .create_router(RouterInfo {
                    id: rp.spec.id,
                    name: rp.spec.name.clone(),
                    tep: random_tep_ula(),
                })
                .map_err(|e| HttpError::from(Error::from(e)))?
        } else {
            router_db(ctx, &rp.spec.name)?
        };
        ctx.lower.ensure(&rdb, &ctx.log, &ctx.mg_lower_stats);
        apply_router_plan(ctx, &rdb, rp).await?;
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
        // The default spec's id is ignored on apply (the daemon owns that
        // router's identity), so it takes no part in duplicate accounting.
        if spec.name != rdb::DEFAULT_ROUTER && !ids.insert(spec.id) {
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

/// Release phase for an existing router: drop the BGP routers and peers its
/// spec no longer wants, so those peers are claimable by other routers in
/// the same apply. The claim phase (`apply_bgp`) then only adds/updates.
async fn release_bgp(
    ctx: &Arc<HandlerContext>,
    rdb: &rdb::RouterDb,
    spec: &RouterSpec,
) -> Result<(), HttpError> {
    delete_stale_bgp_routers(ctx, rdb, spec).await?;

    let Some(bgp) = &spec.bgp else {
        return Ok(());
    };

    let wanted_addrs: HashSet<IpAddr> =
        bgp.peers.values().flatten().map(|p| p.host.ip()).collect();
    let wanted_ifxs: HashSet<&str> = bgp
        .unnumbered_peers
        .values()
        .flatten()
        .map(|p| p.interface.as_str())
        .collect();

    let numbered = rdb
        .get_bgp_neighbors()
        .map_err(|e| HttpError::from(Error::from(e)))?;
    for nbr in numbered {
        if nbr.asn == bgp.asn && !wanted_addrs.contains(&nbr.host.ip()) {
            bgp_admin::helpers::remove_neighbor(
                ctx.clone(),
                rdb,
                nbr.asn,
                nbr.host.ip(),
            )
            .await?;
        }
    }
    let unnumbered = rdb
        .get_unnumbered_bgp_neighbors()
        .map_err(|e| HttpError::from(Error::from(e)))?;
    for nbr in unnumbered {
        if nbr.asn == bgp.asn && !wanted_ifxs.contains(nbr.interface.as_str()) {
            bgp_admin::helpers::remove_unnumbered_neighbor(
                ctx.clone(),
                rdb,
                nbr.asn,
                &nbr.interface,
            )
            .await?;
        }
    }
    Ok(())
}

/// Release phase for BFD: drop this router's sessions that are unwanted or
/// whose config changed (a changed config is remove + re-add: BFD sessions
/// are cheap to restart).
async fn release_bfd(ctx: &Arc<HandlerContext>, rp: &RouterPlan) {
    remove_bfd_peers(ctx, &rp.spec.name, |addr, current| {
        rp.bfd.get(addr) != Some(&current)
    })
    .await;
}

/// Drop any BGP router under this logical router whose ASN is no longer the
/// desired one (or all of them if BGP is being disabled).
async fn delete_stale_bgp_routers(
    ctx: &Arc<HandlerContext>,
    rdb: &rdb::RouterDb,
    spec: &RouterSpec,
) -> Result<(), HttpError> {
    let desired_asn = spec.bgp.as_ref().map(|b| b.asn);
    let stale: Vec<u32> = lock!(ctx.bgp.router)
        .keys()
        .filter(|(n, asn)| n == &spec.name && Some(*asn) != desired_asn)
        .map(|(_, asn)| *asn)
        .collect();
    for asn in stale {
        bgp_admin::do_delete_router(ctx, rdb, asn).await?;
    }
    Ok(())
}

async fn apply_router_plan(
    ctx: &Arc<HandlerContext>,
    rdb: &rdb::RouterDb,
    rp: RouterPlan,
) -> Result<(), HttpError> {
    apply_bgp(ctx, rdb, &rp.spec).await?;
    apply_static(rdb, &rp.statics)?;
    apply_bfd(ctx, rdb, rp).await?;
    Ok(())
}

async fn apply_bgp(
    ctx: &Arc<HandlerContext>,
    rdb: &rdb::RouterDb,
    spec: &RouterSpec,
) -> Result<(), HttpError> {
    delete_stale_bgp_routers(ctx, rdb, spec).await?;

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

async fn apply_bfd(
    ctx: &Arc<HandlerContext>,
    rdb: &rdb::RouterDb,
    rp: RouterPlan,
) -> Result<(), HttpError> {
    // Unwanted or changed sessions were dropped in the release phase for
    // existing routers; for a freshly created router this is a no-op.
    release_bfd(ctx, &rp).await;

    let existing: HashSet<IpAddr> = lock!(ctx.bfd.daemon)
        .router_sessions_iter(&rp.spec.name)
        .map(|(addr, _)| *addr)
        .collect();
    for (addr, config) in rp.bfd {
        if !existing.contains(&addr) {
            bfd_admin::add_peer(ctx.clone(), rdb.clone(), config)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::do_multi_router_apply;
    use crate::admin::HandlerContext;
    use crate::bgp_admin::do_bgp_apply;
    use crate::bgp_admin::helpers;
    use crate::bgp_admin::tests::{
        POLICY_SOURCE, mixed_req, numbered, test_ctx, unnumbered,
    };
    use crate::error::Error;
    use dropshot::HttpError;
    use mg_api_types::bfd::{BfdPeerConfig, SessionMode};
    use mg_api_types::bgp::config::{
        ApplyRequest, CheckerSource, Neighbor, ShaperSource,
    };
    use mg_api_types::bgp::peer::PeerId;
    use mg_api_types::router::{
        BgpSpec, MultiRouterApplyRequest, RouterId, RouterSpec,
    };
    use mg_api_types::static_routes::StaticRoute4;
    use mg_common::lock;
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
        Vec<(String, u32)>,
        Vec<(String, Vec<IpAddr>, usize)>,
    );

    fn snapshot(ctx: &Arc<HandlerContext>) -> Snapshot {
        let names = router_names(ctx);
        let bgp: Vec<(String, u32)> =
            lock!(ctx.bgp.router).keys().cloned().collect();
        let per_router = names
            .iter()
            .map(|n| {
                let rdb = ctx.db.router(n).expect("router db");
                let mut nbrs: Vec<IpAddr> = rdb
                    .get_bgp_neighbors()
                    .expect("neighbors")
                    .into_iter()
                    .map(|x| x.host.ip())
                    .collect();
                nbrs.sort();
                (
                    n.clone(),
                    nbrs,
                    rdb.get_static(None).expect("statics").len(),
                )
            })
            .collect();
        (names, bgp, per_router)
    }

    /// Name of the router whose BGP instance owns the live session for `ip`.
    fn session_owner(ctx: &Arc<HandlerContext>, ip: &str) -> Option<String> {
        let peer = PeerId::Ip(ip.parse().unwrap());
        let session = lock!(ctx.bgp.sessions).get(&peer).cloned()?;
        lock!(ctx.bgp.router)
            .iter()
            .find(|(_, r)| session.belongs_to(r))
            .map(|((name, _), _)| name.clone())
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
        apply(&ctx, vec![r1.clone()])
            .await
            .expect("re-apply with one router removed");

        assert_eq!(
            router_names(&ctx),
            vec!["default".to_string(), "one".to_string()]
        );
        assert!(ctx.db.router("two").is_err());
        assert!(
            !lock!(ctx.bgp.router).contains_key(&("two".to_string(), 65001))
        );
        // The teardown was clean (test platform), so nothing is tombstoned.
        assert!(ctx.db.orphaned_switch_indexes().unwrap().is_empty());

        // The survivor is untouched, including its generated TEP.
        let rdb = ctx.db.router("one").expect("router db");
        assert_eq!(rdb.get_bgp_neighbors().expect("neighbors").len(), 1);
        assert_eq!(rdb.get_static(None).expect("static routes").len(), 1);
        assert_eq!(rdb.tep(), tep_one);

        // Recreating "two" after a clean teardown must start from a clean
        // slate.
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
        apply(&ctx, vec![s.clone()])
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
        apply(&ctx, vec![s.clone()])
            .await
            .expect("re-apply default spec");

        // Absence = empty the configuration; the router itself stays.
        apply(&ctx, vec![spec("one", 65001, "203.0.113.8")])
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
        assert_eq!(session_owner(&ctx, "203.0.113.1").as_deref(), Some("one"));
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
        let rdb = ctx.db.router("one").expect("router db");
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
        apply(&ctx, vec![s]).await.expect("re-apply without policy");
        {
            let routers = lock!(ctx.bgp.router);
            let rtr = routers
                .get(&("one".to_string(), 65001))
                .expect("bgp router");
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
            assert!(ctx.db.router("two").is_err(), "{what} created a router");
        }
    }

    /// A-09: a named router may not claim the daemon-owned default router's
    /// uuid — rejected at preflight (400), not by a conflict after the
    /// teardown phase has already run.
    #[tokio::test]
    async fn named_router_cannot_use_the_default_router_id() {
        let ctx = test_ctx("named_router_cannot_use_the_default_router_id");
        let default_id = ctx.rdb().expect("default rdb").id();

        let one = spec("one", 65001, "203.0.113.1");
        apply(&ctx, vec![one.clone()]).await.expect("apply one");
        let before = snapshot(&ctx);

        // Listed after "one", which would otherwise have been torn down
        // (absent from the request) before the conflict surfaced.
        let mut thief = spec("two", 65002, "203.0.113.2");
        thief.id = default_id;
        let err = apply(&ctx, vec![thief])
            .await
            .expect_err("default id must be rejected");
        assert_eq!(err.status_code.as_u16(), 400, "{}", err.external_message);
        assert_eq!(snapshot(&ctx), before);
        assert_eq!(ctx.rdb().expect("default rdb").id(), default_id);
    }

    /// A-09: the default spec's id is ignored, so it does not count in
    /// duplicate-id accounting: a named router may carry the same id the
    /// caller happened to put on the default spec.
    #[tokio::test]
    async fn default_spec_id_is_ignored_for_duplicate_accounting() {
        let ctx =
            test_ctx("default_spec_id_is_ignored_for_duplicate_accounting");
        let daemon_id = ctx.rdb().expect("default rdb").id();

        let one = spec("one", 65001, "203.0.113.1");
        let mut default = spec("default", 65000, "203.0.113.7");
        default.id = one.id;
        apply(&ctx, vec![default, one.clone()])
            .await
            .expect("default's ignored id may repeat a named router's id");

        assert_eq!(ctx.db.router("one").expect("one").id(), one.id);
        assert_eq!(ctx.rdb().expect("default rdb").id(), daemon_id);
    }

    /// A-03: a router torn down while dpd could not confirm its switch table
    /// clean leaves a tombstone; until a later scrub releases it, the uuid
    /// cannot come back (under any name) and a fresh router does not get
    /// the tombstoned table index. After the scrub the uuid is usable.
    #[tokio::test]
    async fn tombstoned_router_id_is_rejected_until_scrubbed() {
        let ctx = test_ctx("tombstoned_router_id_is_rejected_until_scrubbed");
        let hook = ctx.lower.test_hook().expect("test lower").clone();

        let one = spec("one", 65001, "203.0.113.1");
        let two = spec("two", 65002, "203.0.113.2");
        apply(&ctx, vec![one.clone(), two.clone()])
            .await
            .expect("apply both");
        let two_index = ctx.db.router("two").expect("two").switch_index();

        // dpd is "unreachable" for two's teardown: the table index stays
        // tombstoned and the scrub cannot confirm it clean yet.
        lock!(hook.dirty_on_stop).insert("two".into());
        *lock!(hook.scrub_clean) = false;
        apply(&ctx, vec![one.clone()]).await.expect("tear two down");
        assert_eq!(
            ctx.db.orphaned_switch_indexes().unwrap(),
            vec![(two.id, two_index)]
        );
        let before = snapshot(&ctx);

        // Same uuid, same or new name: refused before any mutation.
        for name in ["two", "three"] {
            let mut back = two.clone();
            back.name = name.into();
            let err = apply(&ctx, vec![one.clone(), back])
                .await
                .expect_err("tombstoned id must be rejected");
            assert_eq!(
                err.status_code.as_u16(),
                409,
                "{}",
                err.external_message
            );
            assert!(err.external_message.contains("tombstoned"));
            assert_eq!(snapshot(&ctx), before);
            assert!(ctx.db.router(name).is_err());
        }

        // A router with a fresh uuid is fine and gets a different index.
        let fresh = spec("two", 65002, "203.0.113.2");
        apply(&ctx, vec![one.clone(), fresh.clone()])
            .await
            .expect("fresh uuid");
        assert_ne!(
            ctx.db.router("two").expect("two").switch_index(),
            two_index
        );
        assert_eq!(
            ctx.db.orphaned_switch_indexes().unwrap(),
            vec![(two.id, two_index)]
        );

        // dpd now confirms the table clean: the next apply's scrub releases
        // the tombstone and the old uuid may be created again.
        *lock!(hook.scrub_clean) = true;
        let mut back = spec("three", 65003, "203.0.113.3");
        back.id = two.id;
        apply(&ctx, vec![one.clone(), fresh, back])
            .await
            .expect("re-create after scrub");
        assert!(ctx.db.orphaned_switch_indexes().unwrap().is_empty());
        assert_eq!(ctx.db.router("three").expect("three").id(), two.id);
    }

    /// A-01: two applies racing each other serialize; the final state is
    /// exactly one of the two requested states, never an interleaving.
    #[tokio::test]
    async fn concurrent_applies_serialize_to_one_consistent_state() {
        let ctx =
            test_ctx("concurrent_applies_serialize_to_one_consistent_state");

        let a = vec![spec("one", 65001, "203.0.113.1")];
        let b = vec![spec("two", 65002, "203.0.113.2")];
        let (ra, rb) = tokio::join!(apply(&ctx, a), apply(&ctx, b));
        ra.expect("apply a");
        rb.expect("apply b");

        let names = router_names(&ctx);
        let bgp: Vec<(String, u32)> =
            lock!(ctx.bgp.router).keys().cloned().collect();
        let is = |name: &str, asn: u32| {
            names == vec!["default".to_string(), name.to_string()]
                && bgp == vec![(name.to_string(), asn)]
        };
        assert!(
            is("one", 65001) || is("two", 65002),
            "mixed final state: routers {names:?}, bgp {bgp:?}"
        );
    }

    /// A-01/A-08: moving a peer from one named router to another in a single
    /// apply converges regardless of the order the specs are listed in,
    /// because every router releases its unwanted peers before any router
    /// claims new ones. The live sessions end up owned by the right router.
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
            assert_eq!(
                session_owner(&ctx, "203.0.113.1").as_deref(),
                Some("one")
            );
            assert_eq!(
                session_owner(&ctx, "203.0.113.2").as_deref(),
                Some("two")
            );

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

            let nbr = |name: &str| {
                let n =
                    ctx.db.router(name).unwrap().get_bgp_neighbors().unwrap();
                assert_eq!(n.len(), 1, "{name} neighbors: {n:?}");
                n[0].host.ip().to_string()
            };
            assert_eq!(nbr("one"), "203.0.113.2");
            assert_eq!(nbr("two"), "203.0.113.1");
            assert_eq!(
                session_owner(&ctx, "203.0.113.2").as_deref(),
                Some("one")
            );
            assert_eq!(
                session_owner(&ctx, "203.0.113.1").as_deref(),
                Some("two")
            );
        }
    }

    /// A-08: the legacy per-neighbor endpoints act as the default router and
    /// cannot delete, update, create over, or re-apply a peer that a named
    /// router owns; the refusal (409) changes nothing.
    #[tokio::test]
    async fn legacy_peer_mutations_respect_named_router_ownership() {
        let ctx =
            test_ctx("legacy_peer_mutations_respect_named_router_ownership");

        let one = spec("one", 65001, "203.0.113.1");
        apply(&ctx, vec![one.clone()]).await.expect("apply one");
        let peer: IpAddr = "203.0.113.1".parse().unwrap();

        // The default router runs the same ASN with no peers of its own, so
        // the legacy paths resolve a BGP router and reach the session layer.
        let default_rdb = ctx.rdb().expect("default rdb");
        let empty = ApplyRequest {
            asn: 65001,
            originate: Vec::new(),
            checker: None,
            shaper: None,
            peers: HashMap::new(),
            unnumbered_peers: HashMap::new(),
        };
        do_bgp_apply(&ctx, &default_rdb, empty.clone())
            .await
            .expect("default router with no peers");
        let before = snapshot(&ctx);

        // Legacy delete of the named router's peer.
        let err =
            helpers::remove_neighbor(ctx.clone(), &default_rdb, 65001, peer)
                .await
                .err()
                .expect("foreign delete must be refused");
        assert!(matches!(err, Error::Conflict(_)), "{err}");
        assert_eq!(HttpError::from(err).status_code.as_u16(), 409);
        assert_eq!(session_owner(&ctx, "203.0.113.1").as_deref(), Some("one"));
        assert_eq!(snapshot(&ctx), before, "legacy delete mutated state");

        // Legacy create (ensure = false) and update (ensure = true).
        let nbr = Neighbor::from_bgp_peer_config(
            65001,
            "qsfp0".into(),
            numbered("203.0.113.1", "peer", 9),
        );
        for ensure in [false, true] {
            let err = helpers::add_neighbor(
                ctx.clone(),
                &default_rdb,
                nbr.clone(),
                ensure,
            )
            .expect_err("foreign create/update must be refused");
            assert!(matches!(err, Error::Conflict(_)), "{err}");
            assert_eq!(snapshot(&ctx), before, "legacy add mutated state");
        }

        // Legacy apply listing the named router's peer.
        let mut steal = empty;
        steal.peers = HashMap::from([(
            "qsfp0".to_string(),
            vec![numbered("203.0.113.1", "peer", 6)],
        )]);
        let err = do_bgp_apply(&ctx, &default_rdb, steal)
            .await
            .err()
            .expect("foreign legacy apply must be refused");
        assert_eq!(err.status_code.as_u16(), 409, "{}", err.external_message);
        assert_eq!(snapshot(&ctx), before, "legacy apply mutated state");
        assert_eq!(session_owner(&ctx, "203.0.113.1").as_deref(), Some("one"));

        // The owner's own re-apply is still an update, not a conflict. (It
        // also empties the absent default router, dropping the BGP instance
        // seeded above; "one" itself is unchanged.)
        apply(&ctx, vec![one]).await.expect("owner re-apply");
        let after = snapshot(&ctx);
        assert_eq!(after.0, before.0, "routers changed");
        assert_eq!(after.2, before.2, "neighbors/statics changed");
        assert_eq!(session_owner(&ctx, "203.0.113.1").as_deref(), Some("one"));
        assert!(
            !lock!(ctx.bgp.router)
                .contains_key(&("default".to_string(), 65001))
        );
    }

    /// A-08: BFD peers are attributed to their router; the legacy remove
    /// (acting as the default router) and a foreign add are refused, while
    /// the owning router can remove its peer.
    #[tokio::test]
    async fn legacy_bfd_mutations_respect_named_router_ownership() {
        let ctx =
            test_ctx("legacy_bfd_mutations_respect_named_router_ownership");

        let mut one = spec("one", 65001, "203.0.113.1");
        let bfd = BfdPeerConfig {
            peer: "203.0.113.11".parse().unwrap(),
            listen: "127.0.0.1".parse().unwrap(),
            required_rx: 1_000_000,
            detection_threshold: NonZeroU8::new(3).unwrap(),
            mode: SessionMode::SingleHop,
        };
        one.bfd_peers = vec![bfd];
        apply(&ctx, vec![one.clone()])
            .await
            .expect("apply one with bfd");
        let owner = |ctx: &Arc<HandlerContext>| {
            lock!(ctx.bfd.daemon)
                .router_for_peer(&bfd.peer)
                .map(str::to_string)
        };
        assert_eq!(owner(&ctx).as_deref(), Some("one"));

        // Legacy remove acts as the default router: refused, peer stays.
        let err = lock!(ctx.bfd.daemon)
            .remove_peer_owned(rdb::DEFAULT_ROUTER, bfd.peer)
            .err()
            .expect("foreign bfd remove must be refused");
        assert!(matches!(
            err,
            bfd::RemovePeerError::PeerOwnedByOtherRouter { .. }
        ));
        assert_eq!(owner(&ctx).as_deref(), Some("one"));

        // A foreign add of the same peer is a conflict.
        let err = crate::bfd_admin::add_peer(
            ctx.clone(),
            ctx.rdb().expect("default rdb"),
            bfd,
        )
        .expect_err("foreign bfd add must be refused");
        assert_eq!(err.status_code.as_u16(), 409, "{}", err.external_message);
        assert_eq!(owner(&ctx).as_deref(), Some("one"));

        // The owner drops it by no longer listing it.
        one.bfd_peers.clear();
        apply(&ctx, vec![one]).await.expect("owner drops bfd peer");
        assert_eq!(owner(&ctx), None);
    }
}
