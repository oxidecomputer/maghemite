// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(clippy::type_complexity)]
use crate::bgp_param as resource;
use crate::{admin::HandlerContext, bgp_param::*, error::Error, register};
use bgp::router::LoadPolicyError;
use bgp::session::FsmStateKind;
use bgp::{
    config::RouterConfig,
    connection::BgpConnection,
    connection_tcp::BgpConnectionTcp,
    messages::{Afi, Message, RouteRefreshMessage, Safi},
    router::Router,
    session::{FsmEvent, SessionInfo},
    BGP_PORT,
};
use dropshot::{
    endpoint, ApiDescription, ClientErrorStatusCode, HttpError,
    HttpResponseDeleted, HttpResponseOk, HttpResponseUpdatedNoContent, Query,
    RequestContext, TypedBody,
};
use mg_common::lock;
use rdb::{Asn, BgpRouterInfo, ImportExportPolicy, Prefix};
use slog::info;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{
    mpsc::{channel, Sender},
    Arc, Mutex,
};

const DEFAULT_BGP_LISTEN: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, BGP_PORT, 0, 0));

#[derive(Clone)]
pub struct BgpContext {
    pub(crate) router: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
    addr_to_session:
        Arc<Mutex<BTreeMap<IpAddr, Sender<FsmEvent<BgpConnectionTcp>>>>>,
}

impl BgpContext {
    pub fn new(
        addr_to_session: Arc<
            Mutex<BTreeMap<IpAddr, Sender<FsmEvent<BgpConnectionTcp>>>>,
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

pub(crate) fn api_description(api: &mut ApiDescription<Arc<HandlerContext>>) {
    //
    // Config API
    //

    // Router configuration
    register!(api, read_routers);
    register!(api, create_router);
    register!(api, read_router);
    register!(api, update_router);
    register!(api, delete_router);

    // Neighbor configuration
    register!(api, read_neighbors);
    register!(api, create_neighbor);
    register!(api, read_neighbor);
    register!(api, update_neighbor);
    register!(api, delete_neighbor);
    register!(api, clear_neighbor);

    // Origin configuration
    register!(api, create_origin4);
    register!(api, read_origin4);
    register!(api, update_origin4);
    register!(api, delete_origin4);

    // Policy checker configuration
    register!(api, create_checker);
    register!(api, read_checker);
    register!(api, update_checker);
    register!(api, delete_checker);

    // Policy shaper configuration
    register!(api, create_shaper);
    register!(api, read_shaper);
    register!(api, update_shaper);
    register!(api, delete_shaper);

    // Omicron API XXX? use normal API now that it's somewhat civilized?
    register!(api, bgp_apply);

    //
    // Status API
    //

    register!(api, get_neighbors);
    register!(api, get_exported);
    register!(api, get_imported);
    register!(api, get_selected);
    register!(api, message_history);
}

#[endpoint { method = GET, path = "/bgp/config/routers" }]
pub async fn read_routers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<resource::Router>>, HttpError> {
    let ctx = ctx.context();
    let routers = ctx
        .db
        .get_bgp_routers()
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;
    let mut result = Vec::new();

    for (asn, info) in routers.iter() {
        result.push(resource::Router {
            asn: *asn,
            id: info.id,
            listen: info.listen.clone(),
            graceful_shutdown: info.graceful_shutdown,
        });
    }

    Ok(HttpResponseOk(result))
}

#[endpoint { method = PUT, path = "/bgp/config/router" }]
pub async fn create_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<resource::Router>,
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

#[endpoint { method = GET, path = "/bgp/config/router" }]
pub async fn read_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<resource::Router>, HttpError> {
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

    Ok(HttpResponseOk(resource::Router {
        asn: rq.asn,
        id: info.id,
        listen: info.listen.clone(),
        graceful_shutdown: info.graceful_shutdown,
    }))
}

#[endpoint { method = POST, path = "/bgp/config/router" }]
pub async fn update_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<resource::Router>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    Ok(helpers::ensure_router(ctx.clone(), rq).await?)
}

#[endpoint { method = DELETE, path = "/bgp/config/router" }]
pub async fn delete_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let mut routers = lock!(ctx.context().bgp.router);
    if let Some(r) = routers.remove(&rq.asn) {
        r.shutdown()
    };

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/bgp/config/neighbors" }]
pub async fn read_neighbors(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<Vec<resource::Neighbor>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let nbrs = ctx
        .db
        .get_bgp_neighbors()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    let result = nbrs
        .into_iter()
        .filter(|x| x.asn == rq.asn)
        .map(|x| resource::Neighbor::from_rdb_neighbor_info(rq.asn, &x))
        .collect();

    Ok(HttpResponseOk(result))
}

#[endpoint { method = PUT, path = "/bgp/config/neighbor" }]
pub async fn create_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<resource::Neighbor>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    helpers::add_neighbor(ctx.clone(), rq, false)?;
    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/bgp/config/neighbor" }]
pub async fn read_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<NeighborSelector>,
) -> Result<HttpResponseOk<resource::Neighbor>, HttpError> {
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

    let result =
        resource::Neighbor::from_rdb_neighbor_info(rq.asn, neighbor_info);
    Ok(HttpResponseOk(result))
}

#[endpoint { method = POST, path = "/bgp/config/neighbor" }]
pub async fn update_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<resource::Neighbor>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    helpers::add_neighbor(ctx.clone(), rq, true)?;
    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = DELETE, path = "/bgp/config/neighbor" }]
pub async fn delete_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<NeighborSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    Ok(helpers::remove_neighbor(ctx.clone(), rq.asn, rq.addr).await?)
}

#[endpoint { method = POST, path = "/bgp/clear/neighbor" }]
pub async fn clear_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NeighborResetRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    Ok(helpers::reset_neighbor(ctx.clone(), rq.asn, rq.addr, rq.op).await?)
}

#[endpoint { method = PUT, path = "/bgp/config/origin4" }]
pub async fn create_origin4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<resource::Origin4>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .create_origin4(prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/bgp/config/origin4" }]
pub async fn read_origin4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<resource::Origin4>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let mut originated = get_router!(ctx, rq.asn)?
        .db
        .get_origin4()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    // stable output order for clients
    originated.sort();

    Ok(HttpResponseOk(resource::Origin4 {
        asn: rq.asn,
        prefixes: originated,
    }))
}

#[endpoint { method = POST, path = "/bgp/config/origin4" }]
pub async fn update_origin4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<resource::Origin4>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .set_origin4(prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = DELETE, path = "/bgp/config/origin4" }]
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

#[endpoint { method = GET, path = "/bgp/status/exported" }]
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

        let mut exported_routes: Vec<Prefix> = match n.allow_export {
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

#[endpoint { method = GET, path = "/bgp/status/imported" }]
pub async fn get_imported(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AsnSelector>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let imported = get_router!(ctx, rq.asn)?.db.full_rib();
    Ok(HttpResponseOk(imported.into()))
}

#[endpoint { method = GET, path = "/bgp/status/selected" }]
pub async fn get_selected(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AsnSelector>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let selected = get_router!(ctx, rq.asn)?.db.loc_rib();
    Ok(HttpResponseOk(selected.into()))
}

#[endpoint { method = GET, path = "/bgp/status/neighbors" }]
pub async fn get_neighbors(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfo>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let mut peers = HashMap::new();
    let routers = lock!(ctx.bgp.router);
    let r = routers
        .get(&rq.asn)
        .ok_or(HttpError::for_not_found(None, "ASN not found".to_string()))?;

    for s in lock!(r.sessions).values() {
        let dur = s.current_state_duration().as_millis() % u64::MAX as u128;
        peers.insert(
            s.neighbor.host.ip(),
            PeerInfo {
                state: s.state(),
                asn: s.remote_asn(),
                duration_millis: dur as u64,
                timers: PeerTimers {
                    hold: DynamicTimerInfo {
                        configured: *s
                            .clock
                            .timers
                            .hold_configured_interval
                            .lock()
                            .unwrap(),
                        negotiated: s
                            .clock
                            .timers
                            .hold_timer
                            .lock()
                            .unwrap()
                            .interval,
                    },
                    keepalive: DynamicTimerInfo {
                        configured: *s
                            .clock
                            .timers
                            .keepalive_configured_interval
                            .lock()
                            .unwrap(),
                        negotiated: s
                            .clock
                            .timers
                            .keepalive_timer
                            .lock()
                            .unwrap()
                            .interval,
                    },
                },
            },
        );
    }

    Ok(HttpResponseOk(peers))
}

#[endpoint { method = POST, path = "/bgp/omicron/apply" }]
pub async fn bgp_apply(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ApplyRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let log = ctx.context().log.clone();
    let rq = request.into_inner();

    info!(log, "apply: {rq:#?}");

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

    for (group, peers) in &rq.peers {
        let current: Vec<rdb::BgpNeighborInfo> = ctx
            .context()
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

        info!(log, "nbr: current {current:#?}");
        info!(log, "nbr: adding {to_add:#?}");
        info!(log, "nbr: removing {to_delete:#?}");

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

            let tgt = resource::Neighbor::from_bgp_peer_config(
                nbr.asn,
                group.clone(),
                spec.clone(),
            );

            let curr = resource::Neighbor::from_rdb_neighbor_info(
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
            ctx.context().clone(),
            resource::Router {
                asn: rq.asn,
                id: rq.asn,
                listen: DEFAULT_BGP_LISTEN.to_string(), //TODO as parameter
                graceful_shutdown: false,               // TODO as parameter
            },
        )
        .await?;

        for (nbr, cfg) in nbr_config {
            helpers::add_neighbor(
                ctx.context().clone(),
                resource::Neighbor::from_bgp_peer_config(
                    nbr.asn,
                    group.clone(),
                    cfg.clone(),
                ),
                true,
            )?;
        }

        for nbr in to_delete {
            helpers::remove_neighbor(ctx.context().clone(), nbr.asn, nbr.addr)
                .await?;

            let mut routers = lock!(ctx.context().bgp.router);
            let mut remove = false;
            if let Some(r) = routers.get(&nbr.asn) {
                remove = lock!(r.sessions).is_empty();
            }
            if remove {
                if let Some(r) = routers.remove(&nbr.asn) {
                    r.shutdown()
                };
            }
        }
    }

    get_router!(ctx.context(), rq.asn)?
        .set_origin4(rq.originate.clone().into_iter().map(Into::into).collect())
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/bgp/message-history" }]
pub async fn message_history(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<MessageHistoryRequest>,
) -> Result<HttpResponseOk<MessageHistoryResponse>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let mut result = HashMap::new();

    for (addr, session) in lock!(get_router!(ctx, rq.asn)?.sessions).iter() {
        result.insert(*addr, lock!(session.message_history).clone());
    }

    Ok(HttpResponseOk(MessageHistoryResponse { by_peer: result }))
}

#[endpoint { method = PUT, path = "/bgp/config/checker" }]
pub async fn create_checker(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<CheckerSource>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::load_policy(ctx, rq.asn, PolicySource::Checker(rq.code), false)
        .await
}

#[endpoint { method = GET, path = "/bgp/config/checker" }]
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

#[endpoint { method = POST, path = "/bgp/config/checker" }]
pub async fn update_checker(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<CheckerSource>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::load_policy(ctx, rq.asn, PolicySource::Checker(rq.code), true)
        .await
}

#[endpoint { method = DELETE, path = "/bgp/config/checker" }]
pub async fn delete_checker(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::unload_policy(ctx, rq.asn, PolicyKind::Checker).await
}

#[endpoint { method = PUT, path = "/bgp/config/shaper" }]
pub async fn create_shaper(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ShaperSource>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::load_policy(ctx, rq.asn, PolicySource::Shaper(rq.code), false)
        .await
}

#[endpoint { method = GET, path = "/bgp/config/shaper" }]
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

#[endpoint { method = POST, path = "/bgp/config/shaper" }]
pub async fn update_shaper(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ShaperSource>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::load_policy(ctx, rq.asn, PolicySource::Shaper(rq.code), true).await
}

#[endpoint { method = DELETE, path = "/bgp/config/shaper" }]
pub async fn delete_shaper(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::unload_policy(ctx, rq.asn, PolicyKind::Shaper).await
}

pub(crate) mod helpers {
    use bgp::router::{EnsureSessionResult, UnloadPolicyError};

    use super::*;

    pub(crate) async fn ensure_router(
        ctx: Arc<HandlerContext>,
        rq: resource::Router,
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
        info!(ctx.log, "remove neighbor: {}", addr);

        ctx.db.remove_bgp_peer_prefixes(&addr);
        ctx.db.remove_bgp_neighbor(addr)?;
        get_router!(&ctx, asn)?.delete_session(addr);

        Ok(HttpResponseDeleted())
    }

    pub(crate) fn add_neighbor(
        ctx: Arc<HandlerContext>,
        rq: resource::Neighbor,
        ensure: bool,
    ) -> Result<(), Error> {
        let log = &ctx.log;
        info!(log, "add neighbor: {:#?}", rq);

        let (event_tx, event_rx) = channel();

        let info = SessionInfo {
            passive_tcp_establishment: rq.passive,
            remote_asn: rq.remote_asn,
            min_ttl: rq.min_ttl,
            md5_auth_key: rq.md5_auth_key.clone(),
            multi_exit_discriminator: rq.multi_exit_discriminator,
            communities: rq.communities.clone().into_iter().collect(),
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            allow_import: rq.allow_import.clone(),
            allow_export: rq.allow_export.clone(),
            vlan_id: rq.vlan_id,
            ..Default::default()
        };

        let start_session = if ensure {
            match get_router!(&ctx, rq.asn)?.ensure_session(
                rq.clone().into(),
                DEFAULT_BGP_LISTEN,
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
                DEFAULT_BGP_LISTEN,
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
            allow_import: rq.allow_import.clone(),
            allow_export: rq.allow_export.clone(),
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
        op: resource::NeighborResetOp,
    ) -> Result<HttpResponseUpdatedNoContent, Error> {
        info!(ctx.log, "clear neighbor: {}", addr);

        let session = get_router!(ctx, asn)?
            .get_session(addr)
            .ok_or(Error::NotFound("session for bgp peer not found".into()))?;

        match op {
            resource::NeighborResetOp::Hard => {
                session.event_tx.send(FsmEvent::Reset).map_err(|e| {
                    Error::InternalCommunication(format!(
                        "failed to reset bgp session {e}",
                    ))
                })?
            }
            resource::NeighborResetOp::SoftInbound => session
                .event_tx
                .send(FsmEvent::RouteRefreshNeeded)
                .map_err(|e| {
                    Error::InternalCommunication(format!(
                        "failed to generate route refresh {e}"
                    ))
                })?,
            resource::NeighborResetOp::SoftOutbound => session
                .event_tx
                .send(FsmEvent::Message(Message::RouteRefresh(
                    RouteRefreshMessage {
                        afi: Afi::Ipv4 as u16,
                        safi: Safi::NlriUnicast as u8,
                    },
                )))
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
        rq: resource::Router,
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
        event_tx.send(FsmEvent::ManualStart).map_err(|e| {
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
                            rtr.send_event(FsmEvent::CheckerChanged(previous))
                                .map_err(|e| {
                                    HttpError::for_internal_error(format!(
                                        "send event: {e}"
                                    ))
                                })?;
                        }
                        PolicySource::Shaper(_) => {
                            rtr.send_event(FsmEvent::ShaperChanged(previous))
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
                        rtr.send_event(FsmEvent::ShaperChanged(Some(previous)))
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
