// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{admin::HandlerContext, bgp_param::*, error::Error, register};
use bgp::{
    config::RouterConfig,
    connection::BgpConnection,
    connection_tcp::BgpConnectionTcp,
    messages::Prefix,
    router::Router,
    session::{FsmEvent, SessionInfo},
    BGP_PORT,
};
use dropshot::{
    endpoint, ApiDescription, HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, RequestContext, TypedBody,
};
use http::status::StatusCode;
use rdb::{Asn, BgpRouterInfo, Prefix4};
use slog::info;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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

macro_rules! lock {
    ($mtx:expr) => {
        $mtx.lock().expect("lock mutex")
    };
}

macro_rules! get_router {
    ($ctx:expr, $asn:expr) => {
        lock!($ctx.bgp.router)
            .get(&$asn)
            .ok_or(Error::NotFound("no bgp router configured".into()))
    };
}

pub(crate) fn api_description(api: &mut ApiDescription<Arc<HandlerContext>>) {
    register!(api, get_routers);
    register!(api, new_router);
    register!(api, ensure_router);
    register!(api, delete_router);

    register!(api, add_neighbor);
    register!(api, ensure_neighbor);
    register!(api, delete_neighbor);
    register!(api, neighbor_detail);

    register!(api, originate4);
    register!(api, withdraw4);
    register!(api, get_originated4);

    register!(api, get_imported);
    register!(api, get_selected);

    register!(api, bgp_apply);

    register!(api, load_checker);
    register!(api, get_checker_source);
    register!(api, load_shaper);
    register!(api, get_shaper_source);

    register!(api, graceful_shutdown);
    register!(api, message_history);
}

#[endpoint { method = GET, path = "/bgp/routers" }]
pub async fn get_routers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<RouterInfo>>, HttpError> {
    let rs = lock!(ctx.context().bgp.router);
    let mut result = Vec::new();

    for r in rs.values() {
        let mut peers = BTreeMap::new();
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
                            configured: s.clock.timers.hold_configured_interval,
                            negotiated: s
                                .clock
                                .timers
                                .hold_timer
                                .lock()
                                .unwrap()
                                .interval,
                        },
                        keepalive: DynamicTimerInfo {
                            configured: s
                                .clock
                                .timers
                                .keepalive_configured_interval,
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
        result.push(RouterInfo {
            asn: match r.config.asn {
                Asn::TwoOctet(asn) => asn.into(),
                Asn::FourOctet(asn) => asn,
            },
            peers,
            graceful_shutdown: r.in_graceful_shutdown(),
        });
    }

    Ok(HttpResponseOk(result))
}

#[endpoint { method = PUT, path = "/bgp/router" }]
pub async fn ensure_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NewRouterRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    Ok(helpers::ensure_router(ctx.clone(), rq).await?)
}

#[endpoint { method = POST, path = "/bgp/router" }]
pub async fn new_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NewRouterRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();

    let mut guard = lock!(ctx.bgp.router);
    if guard.get(&rq.asn).is_some() {
        return Err(HttpError::for_status(
            Some("bgp router with specified ASN exists".into()),
            StatusCode::CONFLICT,
        ));
    }

    Ok(helpers::add_router(ctx.clone(), rq, &mut guard)?)
}

#[endpoint { method = DELETE, path = "/bgp/router" }]
pub async fn delete_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<DeleteRouterRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let mut routers = lock!(ctx.context().bgp.router);
    if let Some(r) = routers.remove(&rq.asn) {
        r.shutdown()
    };

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = POST, path = "/bgp/neighbor" }]
pub async fn add_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddNeighborRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    helpers::add_neighbor(ctx.clone(), rq, false)?;
    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/bgp/neighbor" }]
pub async fn neighbor_detail(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NeighborSelector>,
) -> Result<HttpResponseOk<SessionInfo>, HttpError> {
    let rq = request.into_inner();
    let routers = lock!(ctx.context().bgp.router);
    match routers.get(&rq.asn) {
        Some(rtr) => match lock!(rtr.sessions).get(&rq.addr) {
            Some(session) => {
                let mut info = lock!(session.session).clone();
                if let Some(x) = info.md5_auth_key.as_mut() {
                    x.value.clear()
                }
                Ok(HttpResponseOk(info))
            }
            None => {
                Err(HttpError::for_not_found(None, "asn peer address".into()))
            }
        },
        None => Err(HttpError::for_not_found(None, "asn".into())),
    }
}

#[endpoint { method = DELETE, path = "/bgp/neighbor" }]
pub async fn delete_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<DeleteNeighborRequest>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    Ok(helpers::remove_neighbor(ctx.clone(), rq.asn, rq.addr).await?)
}

#[endpoint { method = PUT, path = "/bgp/neighbor" }]
pub async fn ensure_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddNeighborRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    helpers::add_neighbor(ctx.clone(), rq, true)?;
    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = POST, path = "/bgp/originate4" }]
pub async fn originate4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Originate4Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .originate4(prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = POST, path = "/bgp/withdraw4" }]
pub async fn withdraw4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Withdraw4Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .withdraw4(prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/bgp/originate4" }]
pub async fn get_originated4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<GetOriginated4Request>,
) -> Result<HttpResponseOk<Vec<Prefix4>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let originated = get_router!(ctx, rq.asn)?
        .db
        .get_originated4()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseOk(originated))
}

#[endpoint { method = GET, path = "/bgp/imported" }]
pub async fn get_imported(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AsnSelector>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let imported = get_router!(ctx, rq.asn)?.db.full_rib();
    Ok(HttpResponseOk(imported.into()))
}

#[endpoint { method = GET, path = "/bgp/selected" }]
pub async fn get_selected(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AsnSelector>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let rib = get_router!(ctx, rq.asn)?.db.loc_rib();
    let selected = rib.lock().unwrap().clone();
    Ok(HttpResponseOk(selected.into()))
}

#[endpoint { method = POST, path = "/bgp/graceful_shutdown" }]
pub async fn graceful_shutdown(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<GracefulShutdownRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    get_router!(ctx, rq.asn)?
        .graceful_shutdown(rq.enabled)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = POST, path = "/bgp/apply" }]
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

        // TODO all the db modification that happens below needs to happen in a
        // transaction.

        helpers::ensure_router(
            ctx.context().clone(),
            NewRouterRequest {
                asn: rq.asn,
                id: rq.asn,
                listen: DEFAULT_BGP_LISTEN.to_string(), //TODO as parameter
            },
        )
        .await?;

        for (nbr, cfg) in nbr_config {
            helpers::add_neighbor(
                ctx.context().clone(),
                AddNeighborRequest::from_bgp_peer_config(
                    nbr.asn,
                    group.clone(),
                    cfg.clone(),
                ),
                false,
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

    let current_originate: BTreeSet<Prefix4> = ctx
        .context()
        .db
        .get_originated4()
        .map_err(Error::Db)?
        .into_iter()
        .collect();

    let specified_originate: BTreeSet<Prefix4> =
        rq.originate.iter().cloned().collect();

    let to_delete = current_originate
        .difference(&specified_originate)
        .map(|x| (*x).into())
        .collect();

    let to_add: Vec<Prefix> = specified_originate
        .difference(&current_originate)
        .map(|x| (*x).into())
        .collect();

    info!(log, "origin: current {current_originate:#?}");
    info!(log, "origin: adding {to_add:#?}");
    info!(log, "origin: removing {to_delete:#?}");

    get_router!(ctx.context(), rq.asn)?
        .originate4(to_add)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    get_router!(ctx.context(), rq.asn)?
        .withdraw4(to_delete)
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

    for (addr, session) in
        get_router!(ctx, rq.asn)?.sessions.lock().unwrap().iter()
    {
        result.insert(*addr, session.message_history.lock().unwrap().clone());
    }

    Ok(HttpResponseOk(MessageHistoryResponse { by_peer: result }))
}

#[endpoint { method = GET, path = "/bgp/checker" }]
pub async fn get_checker_source(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AsnSelector>,
) -> Result<HttpResponseOk<String>, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    match ctx.bgp.router.lock().unwrap().get(&rq.asn) {
        None => Err(HttpError::for_not_found(
            None,
            String::from("ASN not found"),
        )),
        Some(rtr) => match rtr.policy.checker_source() {
            Some(source) => Ok(HttpResponseOk(source)),
            None => Err(HttpError::for_not_found(
                None,
                String::from("checker source not found"),
            )),
        },
    }
}

#[endpoint { method = PUT, path = "/bgp/checker" }]
pub async fn load_checker(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<LoadPolicyRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    match ctx.bgp.router.lock().unwrap().get(&rq.asn) {
        None => {
            return Err(HttpError::for_not_found(
                None,
                String::from("ASN not found"),
            ));
        }
        Some(rtr) => {
            if let Err(e) = rtr.policy.load_checker(&rq.code) {
                // The program failed to compile, return a bad request error
                // with the error string from the compiler.
                return Err(HttpError::for_bad_request(None, e.to_string()));
            }
        }
    }
    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = PUT, path = "/bgp/shaper" }]
pub async fn load_shaper(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<LoadPolicyRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    match ctx.bgp.router.lock().unwrap().get(&rq.asn) {
        None => {
            return Err(HttpError::for_not_found(
                None,
                String::from("ASN not found"),
            ));
        }
        Some(rtr) => {
            if let Err(e) = rtr.policy.load_shaper(&rq.code) {
                // The program failed to compile, return a bad request error
                // with the error string from the compiler.
                return Err(HttpError::for_bad_request(None, e.to_string()));
            }
        }
    }
    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/bgp/shaper" }]
pub async fn get_shaper_source(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AsnSelector>,
) -> Result<HttpResponseOk<String>, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    match ctx.bgp.router.lock().unwrap().get(&rq.asn) {
        None => Err(HttpError::for_not_found(
            None,
            String::from("ASN not found"),
        )),
        Some(rtr) => match rtr.policy.shaper_source() {
            Some(source) => Ok(HttpResponseOk(source)),
            None => Err(HttpError::for_not_found(
                None,
                String::from("shaper source not found"),
            )),
        },
    }
}

pub(crate) mod helpers {
    use super::*;

    pub(crate) async fn ensure_router(
        ctx: Arc<HandlerContext>,
        rq: NewRouterRequest,
    ) -> Result<HttpResponseUpdatedNoContent, Error> {
        let mut guard = lock!(ctx.bgp.router);
        if guard.get(&rq.asn).is_some() {
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

        ctx.db.remove_bgp_neighbor(addr)?;
        get_router!(&ctx, asn)?.delete_session(addr);

        Ok(HttpResponseDeleted())
    }

    pub(crate) fn add_neighbor(
        ctx: Arc<HandlerContext>,
        rq: AddNeighborRequest,
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
            communities: rq.communities.clone(),
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            ..Default::default()
        };

        match get_router!(&ctx, rq.asn)?.new_session(
            rq.clone().into(),
            DEFAULT_BGP_LISTEN,
            event_tx.clone(),
            event_rx,
            info,
        ) {
            Ok(_) => {}
            e @ Err(bgp::error::Error::PeerExists) => {
                if ensure {
                    return Ok(());
                } else {
                    e?;
                }
            }
            e @ Err(_) => {
                e?;
            }
        };

        start_bgp_session(&event_tx)?;

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
        })?;

        start_bgp_session(&event_tx)?;

        Ok(())
    }

    pub(crate) fn add_router(
        ctx: Arc<HandlerContext>,
        rq: NewRouterRequest,
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
}
