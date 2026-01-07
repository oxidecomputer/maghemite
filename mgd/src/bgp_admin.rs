// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(clippy::type_complexity)]
use crate::validation::{validate_prefixes_v4, validate_prefixes_v6};
use crate::{admin::HandlerContext, error::Error, log::bgp_log};
use bgp::{
    BGP_PORT,
    config::RouterConfig,
    connection::BgpConnection,
    connection_tcp::BgpConnectionTcp,
    messages::Afi,
    params::*,
    router::{LoadPolicyError, Router},
    session::{
        AdminEvent, FsmEvent, FsmStateKind, MessageHistory, MessageHistoryV1,
        SessionEndpoint, SessionInfo,
    },
};
use dropshot::{
    ClientErrorStatusCode, HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, Query, RequestContext, TypedBody,
};
use mg_api::{
    AsnSelector, BestpathFanoutRequest, BestpathFanoutResponse, FsmEventBuffer,
    FsmHistoryRequest, FsmHistoryResponse, MessageDirection,
    MessageHistoryRequest, MessageHistoryRequestV1, MessageHistoryResponse,
    MessageHistoryResponseV1, NeighborResetRequest, NeighborSelector, Rib,
};
use mg_common::lock;
use rdb::{AddressFamily, Asn, BgpRouterInfo, ImportExportPolicy, Prefix};
use rdb::{ImportExportPolicy4, ImportExportPolicy6};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{
    Arc, Mutex,
    mpsc::{Sender, channel},
};
use std::time::Duration;

const UNIT_BGP: &str = "bgp";
const DEFAULT_BGP_LISTEN: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, BGP_PORT, 0, 0));

#[derive(Clone)]
pub struct BgpContext {
    pub(crate) router: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
    addr_to_session:
        Arc<Mutex<BTreeMap<IpAddr, SessionEndpoint<BgpConnectionTcp>>>>,
}

impl BgpContext {
    pub fn new(
        addr_to_session: Arc<
            Mutex<BTreeMap<IpAddr, SessionEndpoint<BgpConnectionTcp>>>,
        >,
    ) -> Self {
        Self {
            router: Arc::new(Mutex::new(BTreeMap::new())),
            addr_to_session,
        }
    }
}

macro_rules! get_router {
    ($ctx:expr, $asn:expr) => {
        lock!($ctx.bgp.router)
            .get(&$asn)
            .ok_or(Error::NotFound("no bgp router configured".into()))
    };
}

pub async fn read_routers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<bgp::params::Router>>, HttpError> {
    let ctx = ctx.context();
    let routers = ctx
        .db
        .get_bgp_routers()
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;
    let mut result = Vec::new();

    for (asn, info) in routers.iter() {
        result.push(bgp::params::Router {
            asn: *asn,
            id: info.id,
            listen: info.listen.clone(),
            graceful_shutdown: info.graceful_shutdown,
        });
    }

    Ok(HttpResponseOk(result))
}

pub async fn create_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<bgp::params::Router>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();

    let mut guard = lock!(ctx.bgp.router);
    if guard.get(&rq.asn).is_some() {
        return Err(HttpError::for_client_error_with_status(
            Some("bgp router with specified ASN exists".into()),
            ClientErrorStatusCode::CONFLICT,
        ));
    }

    Ok(helpers::add_router(ctx.clone(), rq, &mut guard)?)
}

pub async fn read_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<bgp::params::Router>, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();

    let routers = ctx
        .db
        .get_bgp_routers()
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;

    let info = routers.get(&rq.asn).ok_or(HttpError::for_not_found(
        None,
        format!("asn: {} not found in db", rq.asn),
    ))?;

    Ok(HttpResponseOk(bgp::params::Router {
        asn: rq.asn,
        id: info.id,
        listen: info.listen.clone(),
        graceful_shutdown: info.graceful_shutdown,
    }))
}

pub async fn update_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<bgp::params::Router>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    Ok(helpers::ensure_router(ctx.clone(), rq).await?)
}

pub async fn delete_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let db = ctx.db.clone();

    db.remove_bgp_router(rq.asn)
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;

    let mut routers = lock!(ctx.bgp.router);
    if let Some(r) = routers.remove(&rq.asn) {
        r.shutdown()
    };

    Ok(HttpResponseUpdatedNoContent())
}

pub async fn read_neighbors(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<Vec<NeighborV1>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let nbrs = ctx
        .db
        .get_bgp_neighbors()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    let result = nbrs
        .into_iter()
        .filter(|x| x.asn == rq.asn)
        .map(|x| NeighborV1::from_rdb_neighbor_info(rq.asn, &x))
        .collect();

    Ok(HttpResponseOk(result))
}

pub async fn create_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NeighborV1>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    helpers::add_neighbor_v1(ctx.clone(), rq, false)?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn read_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<NeighborSelector>,
) -> Result<HttpResponseOk<NeighborV1>, HttpError> {
    let rq = request.into_inner();
    let db_neighbors = ctx.context().db.get_bgp_neighbors().map_err(|e| {
        HttpError::for_internal_error(format!("get neighbors kv tree: {e}"))
    })?;
    let neighbor_info = db_neighbors
        .iter()
        .find(|n| n.host.ip() == rq.addr)
        .ok_or(HttpError::for_not_found(
            None,
            format!("neighbor {} not found in db", rq.addr),
        ))?;

    let result = NeighborV1::from_rdb_neighbor_info(rq.asn, neighbor_info);
    Ok(HttpResponseOk(result))
}

pub async fn update_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NeighborV1>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    helpers::add_neighbor_v1(ctx.clone(), rq, true)?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn delete_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<NeighborSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    Ok(helpers::remove_neighbor(ctx.clone(), rq.asn, rq.addr).await?)
}

pub async fn clear_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NeighborResetRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    Ok(helpers::reset_neighbor(ctx.clone(), rq.asn, rq.addr, rq.op).await?)
}

// V3 API handlers (new Neighbor type with optional per-AF configs)
pub async fn read_neighbors_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<Vec<Neighbor>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let nbrs = ctx
        .db
        .get_bgp_neighbors()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    let result = nbrs
        .into_iter()
        .filter(|x| x.asn == rq.asn)
        .map(|x| Neighbor::from_rdb_neighbor_info(rq.asn, &x))
        .collect();

    Ok(HttpResponseOk(result))
}

pub async fn create_neighbor_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Neighbor>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    helpers::add_neighbor(ctx.clone(), rq, false)?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn read_neighbor_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<NeighborSelector>,
) -> Result<HttpResponseOk<Neighbor>, HttpError> {
    let rq = request.into_inner();
    let db_neighbors = ctx.context().db.get_bgp_neighbors().map_err(|e| {
        HttpError::for_internal_error(format!("get neighbors kv tree: {e}"))
    })?;
    let neighbor_info = db_neighbors
        .iter()
        .find(|n| n.host.ip() == rq.addr)
        .ok_or(HttpError::for_not_found(
            None,
            format!("neighbor {} not found in db", rq.addr),
        ))?;

    let result = Neighbor::from_rdb_neighbor_info(rq.asn, neighbor_info);
    Ok(HttpResponseOk(result))
}

pub async fn update_neighbor_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Neighbor>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    helpers::add_neighbor(ctx.clone(), rq, true)?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn delete_neighbor_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<NeighborSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    Ok(helpers::remove_neighbor(ctx.clone(), rq.asn, rq.addr).await?)
}

pub async fn create_origin4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Origin4>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();

    // Validate prefixes before processing
    validate_prefixes_v4(&rq.prefixes)?;

    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .create_origin4(prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

pub async fn read_origin4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<Origin4>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let mut originated = get_router!(ctx, rq.asn)?
        .db
        .get_origin4()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    // stable output order for clients
    originated.sort();

    Ok(HttpResponseOk(Origin4 {
        asn: rq.asn,
        prefixes: originated,
    }))
}

pub async fn update_origin4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Origin4>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();

    // Validate prefixes before processing
    validate_prefixes_v4(&rq.prefixes)?;

    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .set_origin4(prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

pub async fn delete_origin4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .clear_origin4()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseDeleted())
}

pub async fn create_origin6(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Origin6>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();

    // Validate prefixes before processing
    validate_prefixes_v6(&rq.prefixes)?;

    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .create_origin6(prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

pub async fn read_origin6(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<Origin6>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let mut originated = get_router!(ctx, rq.asn)?
        .db
        .get_origin6()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    // stable output order for clients
    originated.sort();

    Ok(HttpResponseOk(Origin6 {
        asn: rq.asn,
        prefixes: originated,
    }))
}

pub async fn update_origin6(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Origin6>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();

    // Validate prefixes before processing
    validate_prefixes_v6(&rq.prefixes)?;

    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .set_origin6(prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

pub async fn delete_origin6(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .clear_origin6()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseDeleted())
}

pub async fn get_exported(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AsnSelector>,
) -> Result<HttpResponseOk<HashMap<IpAddr, Vec<Prefix>>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let r = get_router!(ctx, rq.asn)?.clone();
    let orig4 = r.db.get_origin4().map_err(|e| {
        HttpError::for_internal_error(format!("error getting origin: {e}"))
    })?;
    let neighs = r.db.get_bgp_neighbors().map_err(|e| {
        HttpError::for_internal_error(format!("error getting neighbors: {e}"))
    })?;
    let mut exported = HashMap::new();

    for n in neighs {
        if r.get_session(n.host.ip())
            .filter(|s| s.state() == FsmStateKind::Established)
            .is_none()
        {
            continue;
        }

        let mut orig_routes: Vec<Prefix> = orig4
            .clone()
            .iter()
            .map(|p| rdb::Prefix::from(*p))
            .collect();

        // Combine per-AF export policies into legacy format for filtering
        let allow_export = ImportExportPolicy::from_per_af_policies(
            &n.allow_export4,
            &n.allow_export6,
        );
        let mut exported_routes: Vec<Prefix> = match allow_export {
            ImportExportPolicy::NoFiltering => orig_routes,
            ImportExportPolicy::Allow(epol) => {
                orig_routes.retain(|p| epol.contains(p));
                orig_routes
            }
        };

        // stable output order for clients
        exported_routes.sort();
        exported.insert(n.host.ip(), exported_routes);
    }

    Ok(HttpResponseOk(exported))
}

pub async fn get_imported(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AsnSelector>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let imported = get_router!(ctx, rq.asn)?
        .db
        .full_rib(Some(AddressFamily::Ipv4));
    Ok(HttpResponseOk(imported.into()))
}

pub async fn get_selected(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AsnSelector>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let selected = get_router!(ctx, rq.asn)?
        .db
        .loc_rib(Some(AddressFamily::Ipv4));
    Ok(HttpResponseOk(selected.into()))
}

pub async fn get_neighbors(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV1>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let mut peers = HashMap::new();
    let routers = lock!(ctx.bgp.router);
    let r = routers
        .get(&rq.asn)
        .ok_or(HttpError::for_not_found(None, "ASN not found".to_string()))?;

    for s in lock!(r.sessions).values() {
        let dur = s.current_state_duration().as_millis() % u64::MAX as u128;

        // If the session runner has a primary connection, pull the config and
        // runtime state from it. If not, just use the config owned by the
        // session runner as both the config and runtime state.
        let (conf_holdtime, neg_holdtime, conf_keepalive, neg_keepalive) =
            if let Some(primary) = s.primary_connection() {
                let clock = primary.connection().clock();
                (
                    clock.timers.config_hold_time,
                    lock!(clock.timers.hold).interval,
                    clock.timers.config_keepalive_time,
                    lock!(clock.timers.keepalive).interval,
                )
            } else {
                let session_info = lock!(s.session);
                (
                    session_info.hold_time,
                    session_info.hold_time,
                    session_info.keepalive_time,
                    session_info.keepalive_time,
                )
            };

        let pi = PeerInfoV2 {
            state: s.state(),
            asn: s.remote_asn(),
            duration_millis: dur as u64,
            timers: PeerTimersV1 {
                hold: DynamicTimerInfoV1 {
                    configured: conf_holdtime,
                    negotiated: neg_holdtime,
                },
                keepalive: DynamicTimerInfoV1 {
                    configured: conf_keepalive,
                    negotiated: neg_keepalive,
                },
            },
        };

        peers.insert(s.neighbor.host.ip(), PeerInfoV1::from(pi));
    }

    Ok(HttpResponseOk(peers))
}

pub async fn get_neighbors_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV2>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let mut peers = HashMap::new();
    let routers = lock!(ctx.bgp.router);
    let r = routers
        .get(&rq.asn)
        .ok_or(HttpError::for_not_found(None, "ASN not found".to_string()))?;

    for s in lock!(r.sessions).values() {
        let dur = s.current_state_duration().as_millis() % u64::MAX as u128;

        let (conf_holdtime, neg_holdtime, conf_keepalive, neg_keepalive) =
            if let Some(primary) = s.primary_connection() {
                let clock = primary.connection().clock();
                (
                    clock.timers.config_hold_time,
                    lock!(clock.timers.hold).interval,
                    clock.timers.config_keepalive_time,
                    lock!(clock.timers.keepalive).interval,
                )
            } else {
                let session_info = lock!(s.session);
                (
                    session_info.hold_time,
                    session_info.hold_time,
                    session_info.keepalive_time,
                    session_info.keepalive_time,
                )
            };

        peers.insert(
            s.neighbor.host.ip(),
            PeerInfoV2 {
                state: s.state(),
                asn: s.remote_asn(),
                duration_millis: dur as u64,
                timers: PeerTimersV1 {
                    hold: DynamicTimerInfoV1 {
                        configured: conf_holdtime,
                        negotiated: neg_holdtime,
                    },
                    keepalive: DynamicTimerInfoV1 {
                        configured: conf_keepalive,
                        negotiated: neg_keepalive,
                    },
                },
            },
        );
    }

    Ok(HttpResponseOk(peers))
}

pub async fn get_neighbors_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfo>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let mut peers = HashMap::new();

    // Clone sessions while holding locks, then release them
    let sessions: Vec<_> = {
        let routers = lock!(ctx.bgp.router);
        let r = routers.get(&rq.asn).ok_or(HttpError::for_not_found(
            None,
            "ASN not found".to_string(),
        ))?;
        lock!(r.sessions).values().cloned().collect()
    };

    for s in sessions.iter() {
        let peer_ip = s.neighbor.host.ip();
        peers.insert(peer_ip, s.get_peer_info());
    }

    Ok(HttpResponseOk(peers))
}

pub async fn bgp_apply(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ApplyRequestV1>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    // Convert v1 request to current format (hardcodes IPv4-only)
    do_bgp_apply(ctx.context(), ApplyRequest::from(request.into_inner())).await
}

pub async fn bgp_apply_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ApplyRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    do_bgp_apply(ctx.context(), request.into_inner()).await
}

async fn do_bgp_apply(
    ctx: &Arc<HandlerContext>,
    rq: ApplyRequest,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let log = ctx.log.clone();

    // Validate originate prefixes before processing
    validate_prefixes_v4(&rq.originate)?;

    bgp_log!(log, info, "bgp apply: {rq:#?}";
        "params" => format!("{rq:?}")
    );

    #[derive(Debug, Eq)]
    struct Nbr {
        addr: IpAddr,
        asn: u32,
    }

    impl Hash for Nbr {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.addr.hash(state);
        }
    }

    impl PartialEq for Nbr {
        fn eq(&self, other: &Nbr) -> bool {
            self.addr.eq(&other.addr)
        }
    }

    let groups = ctx
        .db
        .get_bgp_neighbors()
        .map_err(Error::Db)?
        .into_iter()
        .map(|x| x.group)
        .collect::<HashSet<_>>();

    // Turn any peer groups that are resident in the db but not in the apply
    // request into empty groups so the difference functions below remove
    // any peers from entire groups that have been removed.
    let mut peers = rq.peers.clone();
    for g in &groups {
        if !peers.contains_key(g) {
            peers.insert(g.clone(), Vec::default());
        }
    }

    for (group, peers) in &peers {
        let current: Vec<rdb::BgpNeighborInfo> = ctx
            .db
            .get_bgp_neighbors()
            .map_err(Error::Db)?
            .into_iter()
            .filter(|x| &x.group == group)
            .collect();

        let current_nbr_addrs: HashSet<Nbr> = current
            .iter()
            .map(|x| Nbr {
                addr: x.host.ip(),
                asn: x.asn,
            })
            .collect();

        let specified_nbr_addrs: HashSet<Nbr> = peers
            .iter()
            .map(|x| Nbr {
                addr: x.host.ip(),
                asn: rq.asn,
            })
            .collect();

        let to_delete = current_nbr_addrs.difference(&specified_nbr_addrs);
        let to_add = specified_nbr_addrs.difference(&current_nbr_addrs);
        let to_modify = current_nbr_addrs.intersection(&specified_nbr_addrs);

        bgp_log!(log, info, "nbr: current {current:#?}");
        bgp_log!(log, info, "nbr: adding {to_add:#?}");
        bgp_log!(log, info, "nbr: removing {to_delete:#?}");

        let mut nbr_config = Vec::new();
        for nbr in to_add {
            let cfg = peers
                .iter()
                .find(|x| x.host.ip() == nbr.addr)
                .ok_or(Error::NotFound(nbr.addr.to_string()))?;
            nbr_config.push((nbr, cfg));
        }

        for nbr in to_modify {
            let spec = peers
                .iter()
                .find(|x| x.host.ip() == nbr.addr)
                .ok_or(Error::NotFound(nbr.addr.to_string()))?;

            let tgt = Neighbor::from_bgp_peer_config(
                nbr.asn,
                group.clone(),
                spec.clone(),
            );

            let curr = Neighbor::from_rdb_neighbor_info(
                nbr.asn,
                current
                    .iter()
                    .find(|x| x.host.ip() == nbr.addr)
                    .ok_or(Error::NotFound(nbr.addr.to_string()))?,
            );

            if tgt != curr {
                nbr_config.push((nbr, spec));
            }
        }

        // TODO all the db modification that happens below needs to happen in a
        // transaction.

        helpers::ensure_router(
            ctx.clone(),
            bgp::params::Router {
                asn: rq.asn,
                id: rq.asn,
                listen: DEFAULT_BGP_LISTEN.to_string(), //TODO as parameter
                graceful_shutdown: false,               // TODO as parameter
            },
        )
        .await?;

        for (nbr, cfg) in nbr_config {
            helpers::add_neighbor(
                ctx.clone(),
                Neighbor::from_bgp_peer_config(
                    nbr.asn,
                    group.clone(),
                    cfg.clone(),
                ),
                true,
            )?;
        }

        for nbr in to_delete {
            helpers::remove_neighbor(ctx.clone(), nbr.asn, nbr.addr).await?;

            let mut routers = lock!(ctx.bgp.router);
            let mut remove = false;
            if let Some(r) = routers.get(&nbr.asn) {
                remove = lock!(r.sessions).is_empty();
            }
            if remove && let Some(r) = routers.remove(&nbr.asn) {
                r.shutdown()
            };
        }
    }

    get_router!(ctx, rq.asn)?
        .set_origin4(rq.originate.clone().into_iter().map(Into::into).collect())
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

// Common helper for fetching message history with optional filtering
fn get_message_history_filtered(
    ctx: &Arc<HandlerContext>,
    asn: u32,
    peer: Option<IpAddr>,
    direction: Option<MessageDirection>,
) -> Result<HashMap<IpAddr, MessageHistory>, HttpError> {
    let mut result = HashMap::new();

    // Determine which peers to fetch history for
    let peers_to_query: Vec<IpAddr> = if let Some(peer_addr) = peer {
        if lock!(get_router!(ctx, asn)?.sessions).contains_key(&peer_addr) {
            vec![peer_addr]
        } else {
            vec![]
        }
    } else {
        lock!(get_router!(ctx, asn)?.sessions)
            .keys()
            .copied()
            .collect()
    };

    // Fetch history for each peer
    for addr in peers_to_query {
        if let Some(session) = lock!(get_router!(ctx, asn)?.sessions).get(&addr)
        {
            let mut history = lock!(session.message_history).clone();

            // Apply direction filter if specified
            if let Some(dir) = direction {
                match dir {
                    MessageDirection::Sent => {
                        history.received.clear();
                    }
                    MessageDirection::Received => {
                        history.sent.clear();
                    }
                }
            }

            result.insert(addr, history);
        }
    }

    Ok(result)
}

pub async fn message_history(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<MessageHistoryRequestV1>,
) -> Result<HttpResponseOk<MessageHistoryResponseV1>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let mut result = HashMap::new();

    for (addr, session) in lock!(get_router!(ctx, rq.asn)?.sessions).iter() {
        let mh = lock!(session.message_history).clone();
        result.insert(*addr, MessageHistoryV1::from(mh));
    }

    Ok(HttpResponseOk(MessageHistoryResponseV1 { by_peer: result }))
}

pub async fn message_history_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<MessageHistoryRequest>,
) -> Result<HttpResponseOk<MessageHistoryResponse>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let by_peer =
        get_message_history_filtered(ctx, rq.asn, rq.peer, rq.direction)?;
    Ok(HttpResponseOk(MessageHistoryResponse { by_peer }))
}

// FSM event history handler
pub async fn fsm_history(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<FsmHistoryRequest>,
) -> Result<HttpResponseOk<FsmHistoryResponse>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let mut result = HashMap::new();

    // Determine which buffer to use (default to major)
    let use_all_buffer = matches!(rq.buffer, Some(FsmEventBuffer::All));

    // Filter by specific peer if requested
    if let Some(peer_addr) = rq.peer {
        if let Some(session) =
            lock!(get_router!(ctx, rq.asn)?.sessions).get(&peer_addr)
        {
            let full_history = lock!(session.fsm_event_history).clone();
            let events = if use_all_buffer {
                full_history.all.into_iter().collect()
            } else {
                full_history.major.into_iter().collect()
            };
            result.insert(peer_addr, events);
        }
    } else {
        // Return history for all peers
        for (addr, session) in lock!(get_router!(ctx, rq.asn)?.sessions).iter()
        {
            let full_history = lock!(session.fsm_event_history).clone();
            let events = if use_all_buffer {
                full_history.all.into_iter().collect()
            } else {
                full_history.major.into_iter().collect()
            };
            result.insert(*addr, events);
        }
    }

    Ok(HttpResponseOk(FsmHistoryResponse { by_peer: result }))
}

pub async fn create_checker(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<CheckerSource>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::load_policy(ctx, rq.asn, PolicySource::Checker(rq.code), false)
        .await
}

pub async fn read_checker(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<CheckerSource>, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    match lock!(ctx.bgp.router).get(&rq.asn) {
        None => Err(HttpError::for_not_found(
            None,
            String::from("ASN not found"),
        )),
        Some(rtr) => match rtr.policy.checker_source() {
            Some(source) => Ok(HttpResponseOk(CheckerSource {
                code: source,
                asn: rq.asn,
            })),
            None => Err(HttpError::for_not_found(
                None,
                String::from("checker source not found"),
            )),
        },
    }
}

pub async fn update_checker(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<CheckerSource>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::load_policy(ctx, rq.asn, PolicySource::Checker(rq.code), true)
        .await
}

pub async fn delete_checker(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::unload_policy(ctx, rq.asn, PolicyKind::Checker).await
}

pub async fn create_shaper(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ShaperSource>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::load_policy(ctx, rq.asn, PolicySource::Shaper(rq.code), false)
        .await
}

pub async fn read_shaper(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<ShaperSource>, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    match lock!(ctx.bgp.router).get(&rq.asn) {
        None => Err(HttpError::for_not_found(
            None,
            String::from("ASN not found"),
        )),
        Some(rtr) => match rtr.policy.shaper_source() {
            Some(source) => Ok(HttpResponseOk(ShaperSource {
                code: source,
                asn: rq.asn,
            })),
            None => Err(HttpError::for_not_found(
                None,
                String::from("shaper source not found"),
            )),
        },
    }
}

pub async fn update_shaper(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ShaperSource>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::load_policy(ctx, rq.asn, PolicySource::Shaper(rq.code), true).await
}

pub async fn delete_shaper(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::unload_policy(ctx, rq.asn, PolicyKind::Shaper).await
}

pub async fn read_bestpath_fanout(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<BestpathFanoutResponse>, HttpError> {
    let ctx = ctx.context();
    let fanout = ctx
        .db
        .get_bestpath_fanout()
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;

    Ok(HttpResponseOk(BestpathFanoutResponse { fanout }))
}

pub async fn update_bestpath_fanout(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<BestpathFanoutRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();

    ctx.db
        .set_bestpath_fanout(rq.fanout)
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;

    Ok(HttpResponseUpdatedNoContent())
}

pub(crate) mod helpers {
    use bgp::router::{EnsureSessionResult, UnloadPolicyError};

    use super::*;

    pub(crate) async fn ensure_router(
        ctx: Arc<HandlerContext>,
        rq: bgp::params::Router,
    ) -> Result<HttpResponseUpdatedNoContent, Error> {
        let mut guard = lock!(ctx.bgp.router);
        if let Some(current) = guard.get(&rq.asn) {
            current.graceful_shutdown(rq.graceful_shutdown)?;
            return Ok(HttpResponseUpdatedNoContent());
        }

        add_router(ctx.clone(), rq, &mut guard)
    }

    pub(crate) async fn remove_neighbor(
        ctx: Arc<HandlerContext>,
        asn: u32,
        addr: IpAddr,
    ) -> Result<HttpResponseDeleted, Error> {
        bgp_log!(ctx.log, info, "remove neighbor (addr {addr}, asn {asn})");

        ctx.db.remove_bgp_prefixes_from_peer(&addr);
        ctx.db.remove_bgp_neighbor(addr)?;
        get_router!(&ctx, asn)?.delete_session(addr);

        Ok(HttpResponseDeleted())
    }

    pub(crate) fn add_neighbor_v1(
        ctx: Arc<HandlerContext>,
        rq: NeighborV1,
        ensure: bool,
    ) -> Result<(), Error> {
        let log = &ctx.log;
        bgp_log!(log, info, "add neighbor {}", rq.host.ip();
            "params" => format!("{rq:#?}")
        );

        let (event_tx, event_rx) = channel();

        // V1 API is IPv4-only; extract only IPv4 policies
        let allow_import4 = rq.allow_import.as_ipv4_policy();
        let allow_export4 = rq.allow_export.as_ipv4_policy();

        // XXX: Do we really want both rq and info?
        //      SessionInfo and Neighbor types could probably be merged.
        let info = SessionInfo {
            passive_tcp_establishment: rq.passive,
            remote_asn: rq.remote_asn,
            min_ttl: rq.min_ttl,
            md5_auth_key: rq.md5_auth_key.clone(),
            multi_exit_discriminator: rq.multi_exit_discriminator,
            communities: rq.communities.clone().into_iter().collect(),
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            // V1 API is IPv4-only; IPv6 support didn't exist in legacy API
            ipv4_unicast: Some(Ipv4UnicastConfig {
                nexthop: None,
                import_policy: allow_import4.clone(),
                export_policy: allow_export4.clone(),
            }),
            ipv6_unicast: None,
            vlan_id: rq.vlan_id,
            remote_id: None,
            bind_addr: None,
            connect_retry_time: Duration::from_secs(rq.connect_retry),
            keepalive_time: Duration::from_secs(rq.keepalive),
            hold_time: Duration::from_secs(rq.hold_time),
            idle_hold_time: Duration::from_secs(rq.idle_hold_time),
            delay_open_time: Duration::from_secs(rq.delay_open),
            resolution: Duration::from_millis(rq.resolution),
            // insert default values for fields not present in the v1 API
            idle_hold_jitter: None,
            connect_retry_jitter: Some(JitterRange {
                min: 0.75,
                max: 1.0,
            }),
            deterministic_collision_resolution: false,
        };

        let start_session = if ensure {
            match get_router!(&ctx, rq.asn)?.ensure_session(
                rq.clone().into(),
                None,
                event_tx.clone(),
                event_rx,
                info,
            )? {
                EnsureSessionResult::New(_) => true,
                EnsureSessionResult::Updated(_) => false,
            }
        } else {
            get_router!(&ctx, rq.asn)?.new_session(
                rq.clone().into(),
                None,
                event_tx.clone(),
                event_rx,
                info,
            )?;
            true
        };

        ctx.db.add_bgp_neighbor(rdb::BgpNeighborInfo {
            asn: rq.asn,
            remote_asn: rq.remote_asn,
            min_ttl: rq.min_ttl,
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
            group: rq.group.clone(),
            passive: rq.passive,
            md5_auth_key: rq.md5_auth_key,
            multi_exit_discriminator: rq.multi_exit_discriminator,
            communities: rq.communities,
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            allow_import4,
            allow_export4,
            vlan_id: rq.vlan_id,

            // V1 API is IPv4-only and doesn't support nexthop override
            ipv4_enabled: true,
            ipv6_enabled: false,
            allow_import6: ImportExportPolicy6::NoFiltering,
            allow_export6: ImportExportPolicy6::NoFiltering,
            nexthop4: None,
            nexthop6: None,
        })?;

        if start_session {
            start_bgp_session(&event_tx)?;
        }

        Ok(())
    }

    pub(crate) fn add_neighbor(
        ctx: Arc<HandlerContext>,
        rq: Neighbor,
        ensure: bool,
    ) -> Result<(), Error> {
        let log = &ctx.log;
        bgp_log!(log, info, "add neighbor {}", rq.host.ip();
            "params" => format!("{rq:#?}")
        );

        // Validate that at least one AF is enabled
        rq.validate_address_families()
            .map_err(Error::InvalidRequest)?;

        // Validate nexthop address families
        rq.validate_nexthop().map_err(Error::InvalidRequest)?;

        let (event_tx, event_rx) = channel();

        // Build SessionInfo with optional per-AF config directly from the new Neighbor type
        let info = SessionInfo {
            passive_tcp_establishment: rq.passive,
            remote_asn: rq.remote_asn,
            min_ttl: rq.min_ttl,
            md5_auth_key: rq.md5_auth_key.clone(),
            multi_exit_discriminator: rq.multi_exit_discriminator,
            communities: rq.communities.clone().into_iter().collect(),
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            ipv4_unicast: rq.ipv4_unicast.clone(),
            ipv6_unicast: rq.ipv6_unicast.clone(),
            vlan_id: rq.vlan_id,
            remote_id: None,
            bind_addr: None,
            connect_retry_time: Duration::from_secs(rq.connect_retry),
            keepalive_time: Duration::from_secs(rq.keepalive),
            hold_time: Duration::from_secs(rq.hold_time),
            idle_hold_time: Duration::from_secs(rq.idle_hold_time),
            delay_open_time: Duration::from_secs(rq.delay_open),
            resolution: Duration::from_millis(rq.resolution),
            idle_hold_jitter: rq.idle_hold_jitter,
            connect_retry_jitter: rq.connect_retry_jitter,
            deterministic_collision_resolution: rq
                .deterministic_collision_resolution,
        };

        let start_session = if ensure {
            match get_router!(&ctx, rq.asn)?.ensure_session(
                rq.clone().into(),
                None,
                event_tx.clone(),
                event_rx,
                info,
            )? {
                EnsureSessionResult::New(_) => true,
                EnsureSessionResult::Updated(_) => false,
            }
        } else {
            get_router!(&ctx, rq.asn)?.new_session(
                rq.clone().into(),
                None,
                event_tx.clone(),
                event_rx,
                info,
            )?;
            true
        };

        // Extract per-AF policies and nexthop for database storage
        let (allow_import4, allow_export4, nexthop4) = match &rq.ipv4_unicast {
            Some(cfg) => (
                cfg.import_policy.clone(),
                cfg.export_policy.clone(),
                cfg.nexthop,
            ),
            None => (
                ImportExportPolicy4::NoFiltering,
                ImportExportPolicy4::NoFiltering,
                None,
            ),
        };

        let (allow_import6, allow_export6, nexthop6) = match &rq.ipv6_unicast {
            Some(cfg) => (
                cfg.import_policy.clone(),
                cfg.export_policy.clone(),
                cfg.nexthop,
            ),
            None => (
                ImportExportPolicy6::NoFiltering,
                ImportExportPolicy6::NoFiltering,
                None,
            ),
        };

        ctx.db.add_bgp_neighbor(rdb::BgpNeighborInfo {
            asn: rq.asn,
            remote_asn: rq.remote_asn,
            min_ttl: rq.min_ttl,
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
            group: rq.group.clone(),
            passive: rq.passive,
            md5_auth_key: rq.md5_auth_key,
            multi_exit_discriminator: rq.multi_exit_discriminator,
            communities: rq.communities,
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            // Derive enablement from whether the AF config is present
            ipv4_enabled: rq.ipv4_unicast.is_some(),
            ipv6_enabled: rq.ipv6_unicast.is_some(),
            allow_import4,
            allow_export4,
            allow_import6,
            allow_export6,
            nexthop4,
            nexthop6,
            vlan_id: rq.vlan_id,
        })?;

        if start_session {
            start_bgp_session(&event_tx)?;
        }

        Ok(())
    }

    pub(crate) async fn reset_neighbor(
        ctx: Arc<HandlerContext>,
        asn: u32,
        addr: IpAddr,
        op: NeighborResetOp,
    ) -> Result<HttpResponseUpdatedNoContent, Error> {
        bgp_log!(ctx.log, info, "clear neighbor {addr}, asn {asn}";
            "op" => format!("{op:?}")
        );

        let session = get_router!(ctx, asn)?
            .get_session(addr)
            .ok_or(Error::NotFound("session for bgp peer not found".into()))?;

        // XXX: Add IPv6 support -- needs API update
        match op {
            NeighborResetOp::Hard => session
                .event_tx
                .send(FsmEvent::Admin(AdminEvent::Reset))
                .map_err(|e| {
                    Error::InternalCommunication(format!(
                        "failed to reset bgp session {e}",
                    ))
                })?,
            NeighborResetOp::SoftInbound => {
                // XXX: check if neighbor has negotiated route refresh cap
                session
                    .event_tx
                    .send(FsmEvent::Admin(AdminEvent::SendRouteRefresh(
                        Afi::Ipv4,
                    )))
                    .map_err(|e| {
                        Error::InternalCommunication(format!(
                            "failed to generate route refresh {e}"
                        ))
                    })?
            }
            NeighborResetOp::SoftOutbound => session
                .event_tx
                .send(FsmEvent::Admin(AdminEvent::ReAdvertiseRoutes(Afi::Ipv4)))
                .map_err(|e| {
                    Error::InternalCommunication(format!(
                        "failed to trigger outbound update {e}"
                    ))
                })?,
        }

        Ok(HttpResponseUpdatedNoContent())
    }

    pub(crate) fn add_router(
        ctx: Arc<HandlerContext>,
        rq: bgp::params::Router,
        routers: &mut BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>,
    ) -> Result<HttpResponseUpdatedNoContent, Error> {
        let cfg = RouterConfig {
            asn: Asn::FourOctet(rq.asn),
            id: rq.id,
        };

        let db = ctx.db.clone();

        let router = Arc::new(Router::<BgpConnectionTcp>::new(
            cfg,
            ctx.log.clone(),
            db.clone(),
            ctx.bgp.addr_to_session.clone(),
        ));

        router.run();

        routers.insert(rq.asn, router);
        db.add_bgp_router(
            rq.asn,
            BgpRouterInfo {
                id: rq.id,
                listen: rq.listen.clone(),
                graceful_shutdown: rq.graceful_shutdown,
            },
        )?;

        Ok(HttpResponseUpdatedNoContent())
    }

    fn start_bgp_session<Cnx: BgpConnection>(
        event_tx: &Sender<FsmEvent<Cnx>>,
    ) -> Result<(), Error> {
        event_tx
            .send(FsmEvent::Admin(AdminEvent::ManualStart))
            .map_err(|e| {
                Error::InternalCommunication(format!(
                    "failed to start bgp session {e}",
                ))
            })
    }

    pub async fn load_policy(
        ctx: &Arc<HandlerContext>,
        asn: u32,
        policy: PolicySource,
        overwrite: bool,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        match lock!(ctx.bgp.router).get(&asn) {
            None => {
                return Err(HttpError::for_not_found(
                    None,
                    String::from("ASN not found"),
                ));
            }
            Some(rtr) => {
                let load_result = match &policy {
                    PolicySource::Checker(code) => {
                        rtr.policy.load_checker(code, overwrite)
                    }
                    PolicySource::Shaper(code) => {
                        rtr.policy.load_shaper(code, overwrite)
                    }
                };
                match load_result {
                    Err(LoadPolicyError::Compilation(e)) => {
                        // The program failed to compile, return a bad request error
                        // with the error string from the compiler.
                        return Err(HttpError::for_bad_request(
                            None,
                            e.to_string(),
                        ));
                    }
                    Err(LoadPolicyError::Conflict) => {
                        return Err(HttpError::for_client_error_with_status(
                            Some("policy already loaded".to_string()),
                            ClientErrorStatusCode::CONFLICT,
                        ));
                    }
                    Ok(previous) => match &policy {
                        PolicySource::Checker(_) => {
                            rtr.send_admin_event(AdminEvent::CheckerChanged(
                                previous,
                            ))
                            .map_err(|e| {
                                HttpError::for_internal_error(format!(
                                    "send event: {e}"
                                ))
                            })?;
                        }
                        PolicySource::Shaper(_) => {
                            rtr.send_admin_event(AdminEvent::ShaperChanged(
                                previous,
                            ))
                            .map_err(|e| {
                                HttpError::for_internal_error(format!(
                                    "send event: {e}"
                                ))
                            })?;
                        }
                    },
                }
            }
        }
        Ok(HttpResponseUpdatedNoContent())
    }

    pub async fn unload_policy(
        ctx: &Arc<HandlerContext>,
        asn: u32,
        policy: PolicyKind,
    ) -> Result<HttpResponseDeleted, HttpError> {
        match lock!(ctx.bgp.router).get(&asn) {
            None => {
                return Err(HttpError::for_not_found(
                    None,
                    String::from("ASN not found"),
                ));
            }
            Some(rtr) => {
                let unload_result = match policy {
                    PolicyKind::Checker => rtr.policy.unload_checker(),
                    PolicyKind::Shaper => rtr.policy.unload_shaper(),
                };
                match unload_result {
                    Err(UnloadPolicyError::NotFound) => {
                        return Err(HttpError::for_not_found(
                            None,
                            "no policy loaded".to_string(),
                        ));
                    }
                    Ok(previous) => {
                        rtr.send_admin_event(AdminEvent::ShaperChanged(Some(
                            previous,
                        )))
                        .map_err(|e| {
                            HttpError::for_internal_error(format!(
                                "send event: {e}"
                            ))
                        })?;
                    }
                }
            }
        }
        Ok(HttpResponseDeleted())
    }
}

#[cfg(test)]
mod tests {
    use super::do_bgp_apply;
    use crate::{
        admin::HandlerContext, bfd_admin::BfdContext, bgp_admin::BgpContext,
    };
    use bgp::params::{ApplyRequestV1, BgpPeerConfigV1};
    use mg_common::stats::MgLowerStats;
    use rdb::Db;
    use std::{
        collections::{BTreeMap, HashMap},
        env::temp_dir,
        fs::{create_dir_all, remove_dir_all},
        net::{Ipv6Addr, SocketAddr},
        sync::{Arc, Mutex},
    };

    #[tokio::test]
    async fn apply_remove_entire_group() {
        let tmpdir = temp_dir();
        let tmpdir = format!(
            "{}/maghemite-test/apply_remove_entire_group",
            tmpdir.to_str().unwrap()
        );
        if std::fs::exists(&tmpdir).unwrap() {
            remove_dir_all(&tmpdir).unwrap();
        }
        create_dir_all(&tmpdir).unwrap();
        println!("tmpdir is {tmpdir}");
        let dbdir = format!("{tmpdir}/test.db");
        let log =
            mg_common::log::init_file_logger("apply_remove_entire_group.log");

        let ctx = Arc::new(HandlerContext {
            tep: Ipv6Addr::UNSPECIFIED,
            bgp: BgpContext::new(Arc::new(Mutex::new(BTreeMap::new()))),
            bfd: BfdContext::new(log.clone()),
            log: log.clone(),
            db: Db::new(dbdir.as_str(), log.clone()).unwrap(),
            mg_lower_stats: Arc::new(MgLowerStats::default()),
            stats_server_running: Mutex::new(false),
            oximeter_port: 0,
        });

        let mut peers = HashMap::new();
        peers.insert(
            String::from("qsfp0"),
            vec![BgpPeerConfigV1 {
                host: SocketAddr::new("203.0.113.1".parse().unwrap(), 179),
                name: String::from("bob"),
                hold_time: 3,
                idle_hold_time: 1,
                delay_open: 1,
                connect_retry: 1,
                keepalive: 1,
                resolution: 1,
                passive: false,
                remote_asn: None,
                min_ttl: None,
                md5_auth_key: None,
                multi_exit_discriminator: None,
                communities: Vec::default(),
                local_pref: None,
                enforce_first_as: false,
                allow_import: rdb::ImportExportPolicy::NoFiltering,
                allow_export: rdb::ImportExportPolicy::NoFiltering,
                vlan_id: None,
            }],
        );
        peers.insert(
            String::from("qsfp1"),
            vec![BgpPeerConfigV1 {
                host: SocketAddr::new("203.0.113.2".parse().unwrap(), 179),
                name: String::from("alice"),
                hold_time: 3,
                idle_hold_time: 1,
                delay_open: 1,
                connect_retry: 1,
                keepalive: 1,
                resolution: 1,
                passive: false,
                remote_asn: None,
                min_ttl: None,
                md5_auth_key: None,
                multi_exit_discriminator: None,
                communities: Vec::default(),
                local_pref: None,
                enforce_first_as: false,
                allow_import: rdb::ImportExportPolicy::NoFiltering,
                allow_export: rdb::ImportExportPolicy::NoFiltering,
                vlan_id: None,
            }],
        );

        let mut req = ApplyRequestV1 {
            asn: 47,
            originate: Vec::default(),
            checker: None,
            shaper: None,
            peers,
        };

        do_bgp_apply(&ctx, req.clone().into())
            .await
            .expect("bgp apply request");

        assert_eq!(
            ctx.db.get_bgp_neighbors().expect("get bgp neighbors").len(),
            2,
        );

        req.peers.remove("qsfp0");

        do_bgp_apply(&ctx, req.clone().into())
            .await
            .expect("bgp apply request");

        assert_eq!(
            ctx.db.get_bgp_neighbors().expect("get bgp neighbors").len(),
            1,
        );
    }
}
