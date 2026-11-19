// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::UNIT_DAEMON;
use crate::admin::{DEFAULT_ROUTER_ID, DEFAULT_ROUTER_NAME, HandlerContext};
use crate::bfd_admin;
use crate::bgp_admin;
use crate::error::Error;
use crate::log::dlog;
use crate::static_admin::{static_route_key_from_v4, static_route_key_from_v6};
use crate::validation::validate_prefixes;
use bgp::policy::{load_checker, load_shaper};
use dropshot::{
    HttpError, HttpResponseOk, Path, Query, RequestContext, TypedBody,
};
use mg_api_types::bfd::BfdPeerInfo;
use mg_api_types::bgp::config::{
    ApplyRequest, Neighbor, PeerInfo, UnnumberedNeighbor,
};
use mg_api_types::bgp::peer::PeerId;
use mg_api_types::rib::{Rib, RibQuery};
use mg_api_types::router::{
    ApplyRoutersRequest, ApplyRoutersResponse, BgpSpec, RouterInfo,
    RouterNotApplied, RouterSelector, RouterSpec,
};
use mg_common::lock;
use oxnet::IpNet;
use rdb::{RibExt, RouterId, StaticRouteKey};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU8;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

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
    let router_db = find_router(ctx.context(), &path.into_inner().router)?;
    let query = query.into_inner();
    let imported = router_db.full_rib(query.address_family);
    let filtered = imported.filter_by_protocol(query.protocol);
    Ok(HttpResponseOk(filtered.into_latest_api_rib()))
}

pub(crate) async fn get_router_rib_selected(
    ctx: RequestContext<Arc<HandlerContext>>,
    path: Path<RouterSelector>,
    query: Query<RibQuery>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let router_db = find_router(ctx.context(), &path.into_inner().router)?;
    let query = query.into_inner();
    let selected = router_db.loc_rib(query.address_family);
    let filtered = selected.filter_by_protocol(query.protocol);
    Ok(HttpResponseOk(filtered.into_latest_api_rib()))
}

pub(crate) async fn get_router_neighbors(
    ctx: RequestContext<Arc<HandlerContext>>,
    path: Path<RouterSelector>,
) -> Result<HttpResponseOk<HashMap<String, PeerInfo>>, HttpError> {
    let ctx = ctx.context();
    let router_db = find_router(ctx, &path.into_inner().router)?;
    let sessions: Vec<_> = lock!(ctx.bgp.router)
        .iter()
        .filter(|((id, _), _)| *id == router_db.id())
        .flat_map(|(_, r)| r.sessions())
        .collect();
    let peers = sessions
        .iter()
        .map(|s| (s.neighbor.peer.to_string(), s.get_peer_info()))
        .collect();
    Ok(HttpResponseOk(peers))
}

pub(crate) async fn get_router_bfd_peers(
    ctx: RequestContext<Arc<HandlerContext>>,
    path: Path<RouterSelector>,
) -> Result<HttpResponseOk<Vec<BfdPeerInfo>>, HttpError> {
    let ctx = ctx.context();
    let router_db = find_router(ctx, &path.into_inner().router)?;
    Ok(HttpResponseOk(bfd_admin::get_peers(ctx, &router_db)?))
}

/// Find a router by id or name.
fn find_router(
    ctx: &Arc<HandlerContext>,
    selector: &str,
) -> Result<rdb::RouterDb, Error> {
    match selector.parse() {
        Ok(id) => ctx.db.router(RouterId(id)),
        Err(_) => ctx.db.router_by_name(selector),
    }
    .map_err(Error::from)
}

/// Generate a random ULA fdxx:xxxx:xxxx:xxxx::1 as a router's tunnel endpoint.
pub(crate) fn random_tep_ula() -> Ipv6Addr {
    let mut r = [0u8; 7];
    rand::fill(&mut r);
    Ipv6Addr::from([
        0xfd, r[0], r[1], r[2], r[3], r[4], r[5], r[6], 0, 0, 0, 0, 0, 0, 0, 1,
    ])
}

/// A `PUT /routers` request and where to send its result.
pub(crate) type ApplyMessage = (
    ApplyRoutersRequest,
    oneshot::Sender<Result<ApplyRoutersResponse, HttpError>>,
);

pub(crate) async fn apply_routers(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ApplyRoutersRequest>,
) -> Result<HttpResponseOk<ApplyRoutersResponse>, HttpError> {
    let gone = |what: &str| {
        HttpError::for_internal_error(format!("the apply task {what}"))
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    ctx.context()
        .apply_tx
        .send((request.into_inner(), reply_tx))
        .await
        .map_err(|_| gone("is not running"))?;
    reply_rx
        .await
        .map_err(|_| gone("dropped the request"))?
        .map(HttpResponseOk)
}

/// Apply `PUT /routers` requests one at a time.
pub(crate) async fn run_apply_task(
    ctx: Arc<HandlerContext>,
    mut requests: mpsc::Receiver<ApplyMessage>,
) {
    while let Some((rq, reply)) = requests.recv().await {
        let ctx = ctx.clone();
        let apply =
            tokio::spawn(async move { do_apply_routers(&ctx, rq).await });
        let result = apply.await.unwrap_or_else(|e| {
            Err(HttpError::for_internal_error(format!("apply failed: {e}")))
        });
        let _ = reply.send(result);
    }
}

/// Apply one router at a time. Return routers that couldn't be applied.
/// Assumes one apply runs at a time.
pub(crate) async fn do_apply_routers(
    ctx: &Arc<HandlerContext>,
    rq: ApplyRoutersRequest,
) -> Result<ApplyRoutersResponse, HttpError> {
    validate_apply_request(&rq)?;

    let mut not_applied = Vec::new();
    let mut record_not_applied = |id: RouterId, name: &str, reason: String| {
        dlog!(
            ctx.log,
            error,
            "router {name} not applied: {reason}";
            "router_id" => id.to_string()
        );
        not_applied.push(RouterNotApplied {
            id,
            name: name.to_string(),
            reason,
        });
    };

    let with_duplicates = routers_with_duplicate_neighbors(&rq.routers);
    let names: BTreeMap<RouterId, String> =
        rq.routers.iter().map(|s| (s.id, s.name.clone())).collect();
    // Only valid specs with unique neighbors are applied.
    let mut specs = Vec::new();
    for spec in rq.routers {
        let valid = match with_duplicates.get(&spec.id) {
            Some(reason) => Err(Error::InvalidRequest(reason.clone()).into()),
            None => validate_router_spec(&spec),
        };
        match valid {
            Ok(()) => specs.push(spec),
            Err(e) => {
                record_not_applied(spec.id, &spec.name, e.internal_message)
            }
        }
    }

    // The default router always exists for legacy endpoints.
    let default_spec =
        (!names.contains_key(&DEFAULT_ROUTER_ID)).then(|| RouterSpec {
            name: DEFAULT_ROUTER_NAME.to_string(),
            id: DEFAULT_ROUTER_ID,
            bgp: None,
            static4: Vec::new(),
            static6: Vec::new(),
            bfd_peers: Vec::new(),
        });

    for info in ctx.db.list_routers() {
        if info.id != DEFAULT_ROUTER_ID
            && !names.contains_key(&info.id)
            && let Err(e) = teardown_router(ctx, info.id).await
        {
            let reason = format!("failed to remove: {}", e.internal_message);
            record_not_applied(info.id, &info.name, reason);
        }
    }

    // Rename before creating routers so that we can exchange names.
    let new_names: BTreeMap<RouterId, String> =
        specs.iter().map(|s| (s.id, s.name.clone())).collect();
    ctx.db.rename_routers(&new_names).map_err(Error::from)?;

    for spec in specs.iter().chain(&default_spec) {
        if let Err(e) = apply_router(ctx, spec).await {
            record_not_applied(spec.id, &spec.name, e.internal_message);
        }
    }
    Ok(ApplyRoutersResponse { not_applied })
}

/// Apply changes to a router, creating or updating it.
/// Assumes `spec` is valid and has no neighbor with another router.
async fn apply_router(
    ctx: &Arc<HandlerContext>,
    spec: &RouterSpec,
) -> Result<(), HttpError> {
    let router_db = match ctx.db.router(spec.id) {
        Err(rdb::error::Error::NotFound(_)) => {
            ctx.db.create_router(RouterInfo {
                id: spec.id,
                name: spec.name.clone(),
                tep: random_tep_ula(),
            })
        }
        found => found,
    }
    .map_err(Error::from)?;

    apply_max_paths(&router_db, spec)?;
    apply_bgp(ctx, &router_db, spec).await?;
    apply_static(&router_db, spec)?;
    apply_bfd(ctx, &router_db, spec).await?;
    Ok(())
}

/// Validate the router spec before applying.
fn validate_router_spec(spec: &RouterSpec) -> Result<(), HttpError> {
    if let Some(bgp) = &spec.bgp {
        validate_prefixes(&bgp.originate)?;
        if let Some(code) = &bgp.checker {
            load_checker(code)
                .map_err(|e| Error::InvalidRequest(format!("checker: {e}")))?;
        }
        if let Some(code) = &bgp.shaper {
            load_shaper(code)
                .map_err(|e| Error::InvalidRequest(format!("shaper: {e}")))?;
        }
        for (group, peers) in &bgp.peers {
            for p in peers {
                let nbr = Neighbor::from_bgp_peer_config(
                    bgp.asn,
                    group.clone(),
                    p.clone(),
                );
                nbr.validate_address_families().map_err(|e| {
                    Error::InvalidRequest(format!(
                        "bgp peer {}: {e}",
                        p.host.ip()
                    ))
                })?;
            }
        }
        for (group, peers) in &bgp.unnumbered_peers {
            for p in peers {
                let nbr = UnnumberedNeighbor::from_bgp_peer_config(
                    bgp.asn,
                    group.clone(),
                    p.clone(),
                );
                nbr.validate_address_families().map_err(|e| {
                    Error::InvalidRequest(format!(
                        "bgp unnumbered peer {}: {e}",
                        p.interface
                    ))
                })?;
            }
        }
    }

    for p in &spec.bfd_peers {
        if p.peer.is_ipv4() != p.listen.is_ipv4() {
            return Err(Error::InvalidRequest(format!(
                "bfd peer {} and its listen address {} must be the same \
                 address family",
                p.peer, p.listen
            ))
            .into());
        }
    }

    let prefixes: Vec<IpNet> = spec
        .static4
        .iter()
        .map(|r| r.prefix.into())
        .chain(spec.static6.iter().map(|r| r.prefix.into()))
        .collect();
    validate_prefixes(&prefixes)?;
    Ok(())
}

/// Check for router name/id conflict, non-empty names, and that default is
/// correctly named.
fn validate_apply_request(rq: &ApplyRoutersRequest) -> Result<(), Error> {
    let mut names = HashSet::new();
    let mut ids = HashSet::new();
    for spec in &rq.routers {
        let reason = if !names.insert(&spec.name) {
            format!("duplicate router name: {}", spec.name)
        } else if !ids.insert(spec.id) {
            format!("duplicate router id: {}", spec.id)
        } else if spec.name.is_empty() {
            format!("router {}: the name can't be empty", spec.id)
        } else if spec.name.parse::<uuid::Uuid>().is_ok() {
            // Technically a name could be a UUID, which would be massively
            // confusing.
            format!("router {:?}: the name can't be a UUID", spec.name)
        } else if (spec.name == DEFAULT_ROUTER_NAME)
            != (spec.id == DEFAULT_ROUTER_ID)
        {
            format!(
                "router {:?}: the {:?} router's id is {DEFAULT_ROUTER_ID}",
                spec.name, DEFAULT_ROUTER_NAME,
            )
        } else {
            continue;
        };
        return Err(Error::InvalidRequest(reason));
    }
    Ok(())
}

/// Return the routers that are conflicting due to neighbors.
fn routers_with_duplicate_neighbors(
    routers: &[RouterSpec],
) -> HashMap<RouterId, String> {
    let mut bgp_owner: HashMap<PeerId, RouterId> = HashMap::new();
    let mut bfd_owner: HashMap<IpAddr, RouterId> = HashMap::new();
    let mut with_duplicates = HashMap::new();
    let mut report = |first: RouterId, second: RouterId, reason: String| {
        with_duplicates
            .entry(first)
            .or_insert_with(|| reason.clone());
        with_duplicates.entry(second).or_insert(reason);
    };
    for spec in routers {
        for peer in spec.bgp.iter().flat_map(|bgp| bgp.peer_ids()) {
            if let Some(first) = bgp_owner.insert(peer.clone(), spec.id) {
                report(first, spec.id, format!("duplicate bgp peer: {peer}"));
            }
        }
        for p in &spec.bfd_peers {
            if let Some(first) = bfd_owner.insert(p.peer, spec.id) {
                let reason = format!("duplicate bfd peer: {}", p.peer);
                report(first, spec.id, reason);
            }
        }
    }
    with_duplicates
}

/// Stop a router's BGP and BFD sessions, then delete the router.
/// Assumes `id` is not the default router.
async fn teardown_router(
    ctx: &Arc<HandlerContext>,
    id: RouterId,
) -> Result<(), HttpError> {
    let router_db = ctx.db.router(id).map_err(Error::from)?;

    delete_bgp_routers(ctx, &router_db).await?;

    let peers: Vec<IpAddr> = bfd_admin::peers(ctx)?
        .into_iter()
        .filter(|(owner, _)| *owner == id)
        .map(|(_, peer)| peer.peer)
        .collect();
    remove_bfd_peers(ctx, &peers).await;

    ctx.db.delete_router(id).map_err(Error::from)?;
    Ok(())
}

/// Delete every BGP router of this router.
async fn delete_bgp_routers(
    ctx: &Arc<HandlerContext>,
    router_db: &rdb::RouterDb,
) -> Result<(), HttpError> {
    let asns: Vec<u32> = lock!(ctx.bgp.router)
        .keys()
        .filter(|(id, _)| *id == router_db.id())
        .map(|(_, asn)| *asn)
        .collect();
    for asn in asns {
        bgp_admin::do_delete_router(ctx, router_db, asn).await?;
    }
    Ok(())
}

/// Remove these BFD peers from the daemon, waiting for any freed-up
/// listeners to fully shut down so the addresses are reusable.
async fn remove_bfd_peers(ctx: &Arc<HandlerContext>, peers: &[IpAddr]) {
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
}

/// Remove the peers in `bgp` from every router other than `id`.
/// Assumes no other router in the request has these peers.
async fn take_bgp_peers(
    ctx: &Arc<HandlerContext>,
    id: RouterId,
    bgp: &BgpSpec,
) -> Result<(), HttpError> {
    let peers: HashSet<PeerId> = bgp.peer_ids().collect();

    let others = ctx.db.list_routers().into_iter().filter(|r| r.id != id);
    for info in others {
        let router_db = ctx.db.router(info.id).map_err(Error::from)?;

        let numbered = router_db.get_bgp_neighbors().map_err(Error::from)?;
        let taken = numbered
            .iter()
            .filter(|nbr| peers.contains(&PeerId::Ip(nbr.host.ip())));
        for nbr in taken {
            bgp_admin::helpers::remove_neighbor(
                ctx.clone(),
                &router_db,
                nbr.asn,
                nbr.host.ip(),
            )
            .await?;
        }

        let unnumbered = router_db
            .get_unnumbered_bgp_neighbors()
            .map_err(Error::from)?;
        let taken = unnumbered.iter().filter(|nbr| {
            peers.contains(&PeerId::Interface(nbr.interface.clone()))
        });
        for nbr in taken {
            bgp_admin::helpers::remove_unnumbered_neighbor(
                ctx.clone(),
                &router_db,
                nbr.asn,
                &nbr.interface,
            )
            .await?;
        }
    }
    Ok(())
}

fn apply_max_paths(
    router_db: &rdb::RouterDb,
    spec: &RouterSpec,
) -> Result<(), Error> {
    let desired = spec.bgp.as_ref().and_then(|bgp| bgp.max_paths).unwrap_or(
        NonZeroU8::new(rdb::db::DEFAULT_BESTPATH_FANOUT)
            .expect("default fanout is nonzero"),
    );
    // Only trigger a full bestpath recompute it it changes.
    if desired != router_db.get_bestpath_fanout()? {
        router_db.set_bestpath_fanout(desired)?;
    }
    Ok(())
}

async fn apply_bgp(
    ctx: &Arc<HandlerContext>,
    router_db: &rdb::RouterDb,
    spec: &RouterSpec,
) -> Result<(), HttpError> {
    let Some(bgp) = &spec.bgp else {
        return delete_bgp_routers(ctx, router_db).await;
    };
    take_bgp_peers(ctx, router_db.id(), bgp).await?;

    let request = ApplyRequest {
        asn: bgp.asn,
        originate: bgp.originate.clone(),
        checker: None,
        shaper: None,
        peers: bgp.peers.clone(),
        unnumbered_peers: bgp.unnumbered_peers.clone(),
    };
    // Deletes BGP routers with any other ASN and converges the peers.
    bgp_admin::do_bgp_apply(ctx, router_db, request).await?;

    bgp_admin::helpers::apply_policy(
        ctx,
        router_db.id(),
        bgp.asn,
        bgp.checker.clone(),
        bgp.shaper.clone(),
    )
    .await
}

fn apply_static(
    router_db: &rdb::RouterDb,
    spec: &RouterSpec,
) -> Result<(), Error> {
    let desired: BTreeSet<StaticRouteKey> = spec
        .static4
        .iter()
        .cloned()
        .map(static_route_key_from_v4)
        .chain(spec.static6.iter().cloned().map(static_route_key_from_v6))
        .collect();
    let current: BTreeSet<StaticRouteKey> =
        router_db.get_static(None)?.into_iter().collect();

    let to_remove: Vec<StaticRouteKey> =
        current.difference(&desired).cloned().collect();
    let to_add: Vec<StaticRouteKey> =
        desired.difference(&current).cloned().collect();

    if !to_remove.is_empty() {
        router_db.remove_static_routes(&to_remove)?;
    }
    if !to_add.is_empty() {
        router_db.add_static_routes(&to_add)?;
    }
    Ok(())
}

/// Apply the spec's BFD peers. Peers that changed or moved are re-added.
/// Assumes no other router in the request has these peers.
async fn apply_bfd(
    ctx: &Arc<HandlerContext>,
    router_db: &rdb::RouterDb,
    spec: &RouterSpec,
) -> Result<(), HttpError> {
    let id = router_db.id();
    let wanted: HashSet<IpAddr> =
        spec.bfd_peers.iter().map(|p| p.peer).collect();
    let current = bfd_admin::peers(ctx)?;
    let stale: Vec<IpAddr> = current
        .iter()
        .filter(|(owner, peer)| {
            if *owner == id {
                !spec.bfd_peers.contains(peer)
            } else {
                wanted.contains(&peer.peer)
            }
        })
        .map(|(_, peer)| peer.peer)
        .collect();
    remove_bfd_peers(ctx, &stale).await;

    let missing = spec
        .bfd_peers
        .iter()
        .filter(|config| !current.contains(&(id, **config)));
    for config in missing {
        bfd_admin::add_peer(ctx.clone(), router_db.clone(), *config)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{do_apply_routers, find_router};
    use crate::admin::HandlerContext;
    use crate::admin::test::test_ctx;
    use crate::bfd_admin;
    use crate::bgp_admin::tests::{POLICY_SOURCE, numbered};
    use dropshot::HttpError;
    use mg_api_types::bfd::{BfdPeerConfig, SessionMode};
    use mg_api_types::bgp::peer::PeerId;
    use mg_api_types::router::{
        ApplyRoutersRequest, ApplyRoutersResponse, BgpSpec, RouterId,
        RouterSpec,
    };
    use mg_api_types::static_routes::StaticRoute4;
    use mg_common::lock;
    use rdb::{DEFAULT_ROUTER_ID, DEFAULT_ROUTER_NAME};
    use std::any::Any;
    use std::collections::{BTreeSet, HashMap};
    use std::net::{IpAddr, Ipv6Addr};
    use std::num::NonZeroU8;
    use std::sync::Arc;

    fn spec(name: &str, asn: u32, peer: &str) -> RouterSpec {
        RouterSpec {
            name: name.into(),
            id: RouterId::new_random(),
            bgp: Some(BgpSpec {
                asn,
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

    /// Apply `routers` and assert that all were successfully applied.
    async fn apply_all_routers(
        ctx: &Arc<HandlerContext>,
        routers: Vec<RouterSpec>,
    ) -> Result<(), HttpError> {
        let response =
            do_apply_routers(ctx, ApplyRoutersRequest { routers }).await?;
        assert_eq!(response.not_applied, Vec::new());
        Ok(())
    }

    fn not_applied_ids(response: &ApplyRoutersResponse) -> Vec<RouterId> {
        response.not_applied.iter().map(|r| r.id).collect()
    }

    fn router_names(ctx: &Arc<HandlerContext>) -> Vec<String> {
        let mut names: Vec<String> =
            ctx.db.list_routers().into_iter().map(|r| r.name).collect();
        names.sort();
        names
    }

    /// A snapshot of the state a rejected apply must preserve.
    #[derive(Debug, PartialEq)]
    struct Snapshot {
        bgp_routers: Vec<(RouterId, u32)>,
        routers: Vec<RouterSnapshot>,
    }

    #[derive(Debug, PartialEq)]
    struct RouterSnapshot {
        name: String,
        tep: Ipv6Addr,
        bgp_neighbors: BTreeSet<IpAddr>,
        static_routes: usize,
    }

    fn router_snapshot(
        ctx: &Arc<HandlerContext>,
        id: RouterId,
    ) -> RouterSnapshot {
        let routers = ctx.db.list_routers();
        let info = routers.iter().find(|r| r.id == id).expect("router");
        let router_db = ctx.db.router(id).expect("router db");
        let neighbors = router_db.get_bgp_neighbors().expect("neighbors");
        let statics = router_db.get_static(None).expect("statics");
        RouterSnapshot {
            name: info.name.clone(),
            tep: info.tep,
            bgp_neighbors: neighbors.iter().map(|n| n.host.ip()).collect(),
            static_routes: statics.len(),
        }
    }

    fn snapshot(ctx: &Arc<HandlerContext>) -> Snapshot {
        let routers = ctx.db.list_routers();
        Snapshot {
            bgp_routers: lock!(ctx.bgp.router).keys().cloned().collect(),
            routers: routers
                .iter()
                .map(|r| router_snapshot(ctx, r.id))
                .collect(),
        }
    }

    /// Id of the router whose BGP router owns the live session for `ip`.
    fn session_owner(ctx: &Arc<HandlerContext>, ip: &str) -> Option<RouterId> {
        let peer = PeerId::Ip(ip.parse().unwrap());
        lock!(ctx.bgp.router)
            .iter()
            .find(|(_, r)| r.get_session(peer.clone()).is_some())
            .map(|((id, _), _)| *id)
    }

    /// A router that is not in the request is removed, with its BGP router.
    /// The other routers are not touched.
    #[tokio::test]
    async fn missing_routers_are_removed() {
        let ctx = test_ctx("missing_routers_are_removed");
        let one = spec("one", 65001, "203.0.113.1");
        let two = spec("two", 65002, "203.0.113.2");
        apply_all_routers(&ctx, vec![one.clone(), two.clone()])
            .await
            .expect("apply both");
        let one_before = router_snapshot(&ctx, one.id);

        apply_all_routers(&ctx, vec![one.clone()])
            .await
            .expect("apply one");

        assert_eq!(
            router_names(&ctx),
            vec!["default".to_string(), "one".to_string()]
        );
        assert!(!lock!(ctx.bgp.router).contains_key(&(two.id, 65002)));
        assert_eq!(router_snapshot(&ctx, one.id), one_before);
    }

    /// The default router is configured like any other router, but it is
    /// never removed. A request without it empties its configuration.
    #[tokio::test]
    async fn default_router_is_not_removed() {
        let ctx = test_ctx("default_router_is_not_removed");

        let daemon_tep = ctx.default_router().expect("default router db").tep();

        let mut s = spec("default", 65000, "203.0.113.7");
        s.id = DEFAULT_ROUTER_ID;
        apply_all_routers(&ctx, vec![s.clone()])
            .await
            .expect("apply default spec");

        let configured = RouterSnapshot {
            name: DEFAULT_ROUTER_NAME.to_string(),
            tep: daemon_tep,
            bgp_neighbors: BTreeSet::from(["203.0.113.7".parse().unwrap()]),
            static_routes: 1,
        };
        assert_eq!(router_snapshot(&ctx, DEFAULT_ROUTER_ID), configured);
        assert!(
            lock!(ctx.bgp.router).contains_key(&(DEFAULT_ROUTER_ID, 65000))
        );

        // Absence = empty the configuration; the router itself stays.
        apply_all_routers(&ctx, vec![spec("one", 65001, "203.0.113.8")])
            .await
            .expect("apply without default");
        let emptied = RouterSnapshot {
            bgp_neighbors: BTreeSet::new(),
            static_routes: 0,
            ..configured
        };
        assert_eq!(router_snapshot(&ctx, DEFAULT_ROUTER_ID), emptied);
        assert!(
            !lock!(ctx.bgp.router).contains_key(&(DEFAULT_ROUTER_ID, 65000))
        );
    }

    /// The router spec is applied and what is left out is unset.
    #[tokio::test]
    async fn spec_is_applied() {
        let ctx = test_ctx("spec_is_applied");
        let mut s = spec("one", 65001, "203.0.113.1");
        let id = s.id;
        let bgp = s.bgp.as_mut().unwrap();
        bgp.max_paths = NonZeroU8::new(4);
        bgp.checker = Some(POLICY_SOURCE.to_string());
        bgp.shaper = Some(POLICY_SOURCE.to_string());
        apply_all_routers(&ctx, vec![s.clone()])
            .await
            .expect("apply");

        let router_db = ctx.db.router(id).expect("router db");
        let fanout = || router_db.get_bestpath_fanout().expect("fanout").get();
        let policy = || {
            let routers = lock!(ctx.bgp.router);
            let rtr = routers.get(&(id, 65001)).expect("bgp router");
            (rtr.policy.checker_source(), rtr.policy.shaper_source())
        };

        let neighbors = router_db.get_bgp_neighbors().expect("neighbors");
        let neighbors: Vec<IpAddr> =
            neighbors.iter().map(|n| n.host.ip()).collect();
        assert_eq!(neighbors, ["203.0.113.1".parse::<IpAddr>().unwrap()]);
        let statics = router_db.get_static(None).expect("static routes");
        let prefixes: Vec<oxnet::IpNet> =
            statics.iter().map(|r| r.prefix).collect();
        assert_eq!(prefixes, [oxnet::IpNet::from(s.static4[0].prefix)]);
        assert_eq!(fanout(), 4);
        assert_eq!(
            policy(),
            (
                Some(POLICY_SOURCE.to_string()),
                Some(POLICY_SOURCE.to_string())
            )
        );

        // Left out of the spec.
        let bgp = s.bgp.as_mut().unwrap();
        bgp.max_paths = None;
        bgp.checker = None;
        bgp.shaper = None;
        s.static4.clear();
        apply_all_routers(&ctx, vec![s.clone()])
            .await
            .expect("apply less");
        assert!(router_db.get_static(None).expect("statics").is_empty());
        assert_eq!(fanout(), 1);
        assert_eq!(policy(), (None, None));

        // A spec without BGP.
        s.bgp.as_mut().unwrap().max_paths = NonZeroU8::new(4);
        apply_all_routers(&ctx, vec![s.clone()])
            .await
            .expect("apply max_paths");
        s.bgp = None;
        apply_all_routers(&ctx, vec![s])
            .await
            .expect("apply without bgp");
        assert_eq!(fanout(), 1);
        assert!(!lock!(ctx.bgp.router).contains_key(&(id, 65001)));
    }

    /// An idempotent apply (including renames) and doesn't reset BGP/BFD
    /// sessions.
    #[tokio::test]
    async fn apply_is_idempotent() {
        let ctx = test_ctx("apply_is_idempotent");
        let mut one = spec("one", 65001, "203.0.113.1");
        let two = spec("two", 65002, "203.0.113.2");
        one.bfd_peers = vec![BfdPeerConfig {
            peer: "2001:db8::9".parse().unwrap(),
            listen: "::1".parse().unwrap(),
            required_rx: 1_000_000,
            detection_threshold: NonZeroU8::new(3).unwrap(),
            mode: SessionMode::SingleHop,
        }];
        let sessions = || {
            let bgp = |spec: &RouterSpec, ip: &str| -> Arc<dyn Any> {
                let asn = spec.bgp.as_ref().unwrap().asn;
                lock!(ctx.bgp.router)
                    .get(&(spec.id, asn))
                    .expect("bgp router")
                    .get_session(PeerId::Ip(ip.parse().unwrap()))
                    .expect("bgp session")
            };
            let daemon = lock!(ctx.bfd.daemon);
            let (_, bfd) = daemon.sessions_iter().next().expect("bfd session");
            let bfd: Arc<dyn Any> = bfd.counters().clone();
            vec![bgp(&one, "203.0.113.1"), bgp(&two, "203.0.113.2"), bfd]
        };

        apply_all_routers(&ctx, vec![one.clone(), two.clone()])
            .await
            .expect("apply");
        let state = snapshot(&ctx);
        let one_before = router_snapshot(&ctx, one.id);
        let before = sessions();
        let sessions_kept = || {
            before
                .iter()
                .zip(sessions())
                .all(|(a, b)| Arc::ptr_eq(a, &b))
        };

        apply_all_routers(&ctx, vec![one.clone(), two.clone()])
            .await
            .expect("apply again");
        assert_eq!(snapshot(&ctx), state);
        assert!(sessions_kept());

        let mut renamed = one.clone();
        renamed.name = "uno".into();
        apply_all_routers(&ctx, vec![renamed, two.clone()])
            .await
            .expect("apply a new name");
        let expected = RouterSnapshot {
            name: "uno".to_string(),
            ..one_before
        };
        assert_eq!(router_snapshot(&ctx, one.id), expected);
        assert!(sessions_kept());
    }

    /// BGP and BFD peers can move between routers.
    #[tokio::test]
    async fn peer_moves_between_routers() {
        let ctx = test_ctx("peer_moves_between_routers");
        let bfd_peer = BfdPeerConfig {
            peer: "203.0.113.9".parse().unwrap(),
            listen: "127.0.0.1".parse().unwrap(),
            required_rx: 1_000_000,
            detection_threshold: NonZeroU8::new(3).unwrap(),
            mode: SessionMode::SingleHop,
        };
        let mut one = spec("one", 65001, "203.0.113.1");
        let mut two = spec("two", 65002, "203.0.113.2");
        one.bfd_peers = vec![bfd_peer];
        apply_all_routers(&ctx, vec![one.clone(), two.clone()])
            .await
            .expect("apply");

        // The routers swap their BGP peers (and static routes), and the BFD
        // peer goes from "one" to "two".
        std::mem::swap(
            &mut one.bgp.as_mut().unwrap().peers,
            &mut two.bgp.as_mut().unwrap().peers,
        );
        std::mem::swap(&mut one.static4, &mut two.static4);
        std::mem::swap(&mut one.bfd_peers, &mut two.bfd_peers);
        apply_all_routers(&ctx, vec![two.clone(), one.clone()])
            .await
            .expect("apply the move");

        let bgp_peer = |id: RouterId| {
            let n = ctx.db.router(id).unwrap().get_bgp_neighbors().unwrap();
            assert_eq!(n.len(), 1, "{id} neighbors: {n:?}");
            n[0].host.ip().to_string()
        };
        assert_eq!(bgp_peer(one.id), "203.0.113.2");
        assert_eq!(bgp_peer(two.id), "203.0.113.1");
        assert_eq!(session_owner(&ctx, "203.0.113.2"), Some(one.id));
        assert_eq!(session_owner(&ctx, "203.0.113.1"), Some(two.id));

        let bfd_owners: Vec<RouterId> = bfd_admin::peers(&ctx)
            .unwrap()
            .into_iter()
            .map(|(owner, _)| owner)
            .collect();
        assert_eq!(bfd_owners, vec![two.id]);
    }

    /// Duplicate names/ids/peers are rejected, along with conflicts with the
    /// default router.
    #[tokio::test]
    async fn apply_validation_rejects_duplicates() {
        let ctx = test_ctx("apply_validation_rejects_duplicates");

        let valid_configuration = || {
            (
                spec("one", 65001, "203.0.113.1"),
                spec("two", 65002, "203.0.113.2"),
            )
        };

        let dup_name = {
            let (a, mut b) = valid_configuration();
            b.name = a.name.clone();
            vec![a, b]
        };
        let dup_id = {
            let (a, mut b) = valid_configuration();
            b.id = a.id;
            vec![a, b]
        };
        let dup_peer = {
            let (a, mut b) = valid_configuration();
            b.bgp = a.bgp.clone();
            vec![a, b]
        };

        let uuid_name = {
            let (a, mut b) = valid_configuration();
            b.name = "4d3c2b1a-0000-4000-8000-000000000001".to_string();
            vec![a, b]
        };
        let empty_name = {
            let (a, mut b) = valid_configuration();
            b.name = String::new();
            vec![a, b]
        };

        let default_name = {
            let (a, mut b) = valid_configuration();
            b.name = DEFAULT_ROUTER_NAME.to_string();
            vec![a, b]
        };
        let default_id = {
            let (a, mut b) = valid_configuration();
            b.id = DEFAULT_ROUTER_ID;
            vec![a, b]
        };

        for routers in [
            dup_name,
            dup_id,
            uuid_name,
            empty_name,
            default_name,
            default_id,
        ] {
            let err = apply_all_routers(&ctx, routers)
                .await
                .expect_err("request must be rejected");
            assert_eq!(err.status_code.as_u16(), 400);
        }
        assert_eq!(router_names(&ctx), vec!["default".to_string()]);

        let three = spec("three", 65003, "203.0.113.3");
        let mut routers = dup_peer;
        let dup_ids: Vec<RouterId> = routers.iter().map(|s| s.id).collect();
        routers.push(three);
        let response = do_apply_routers(&ctx, ApplyRoutersRequest { routers })
            .await
            .expect("apply");
        assert_eq!(not_applied_ids(&response), dup_ids);
        assert_eq!(
            router_names(&ctx),
            vec!["default".to_string(), "three".to_string()]
        );
    }

    /// An invalid router configuration is reported and doesn't impede valid
    /// routers in the same request.
    #[tokio::test]
    async fn invalid_router_is_reported_and_not_applied() {
        let ctx = test_ctx("invalid_router_is_reported_and_not_applied");

        let one = spec("one", 65001, "203.0.113.1");
        apply_all_routers(&ctx, vec![one.clone()])
            .await
            .expect("apply one");
        let before = snapshot(&ctx);

        let two = || spec("two", 65002, "203.0.113.2");
        let cases: Vec<(&str, RouterSpec)> = vec![
            ("invalid static prefix", {
                let mut s = two();
                s.static4[0].prefix = "224.0.0.0/24".parse().unwrap();
                s
            }),
            ("invalid originate prefix", {
                let mut s = two();
                s.bgp.as_mut().unwrap().originate =
                    vec!["224.0.0.0/24".parse().unwrap()];
                s
            }),
            ("invalid checker", {
                let mut s = two();
                s.bgp.as_mut().unwrap().checker = Some("fn open(".to_string());
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
            let request = ApplyRoutersRequest {
                routers: vec![one.clone(), two.clone()],
            };
            let response = do_apply_routers(&ctx, request).await.expect(what);
            assert_eq!(not_applied_ids(&response), vec![two_id], "{what}");
            assert_eq!(snapshot(&ctx), before, "{what} mutated state");

            // The same spec sent for the existing router "one", with a new
            // name.
            let changed = RouterSpec {
                id: one.id,
                name: "uno".to_string(),
                ..two
            };
            let request = ApplyRoutersRequest {
                routers: vec![changed],
            };
            let response = do_apply_routers(&ctx, request).await.expect(what);
            assert_eq!(not_applied_ids(&response), vec![one.id], "{what}");
            assert_eq!(snapshot(&ctx), before, "{what} changed a router");
        }
    }

    #[tokio::test]
    async fn find_router_by_id_or_name() {
        let ctx = test_ctx("find_router_by_id_or_name");
        let one = spec("one", 65001, "203.0.113.1");
        apply_all_routers(&ctx, vec![one.clone()])
            .await
            .expect("apply one");

        for selector in [one.id.to_string(), "one".to_string()] {
            let found = find_router(&ctx, &selector).expect("find router");
            assert_eq!(found.id(), one.id);
        }
        for selector in [RouterId::new_random().to_string(), "two".to_string()]
        {
            let err = find_router(&ctx, &selector).err().expect("unknown");
            assert_eq!(HttpError::from(err).status_code.as_u16(), 404);
        }
    }
}
