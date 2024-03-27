// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::db::{Db, PeerInfo, TunnelRoute};
use crate::exchange::PathVector;
use crate::sm::{AdminEvent, Event, PrefixSet, SmContext};
use dropshot::endpoint;
use dropshot::ApiDescription;
use dropshot::ConfigDropshot;
use dropshot::ConfigLogging;
use dropshot::ConfigLoggingLevel;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::HttpServerStarter;
use dropshot::Path;
use dropshot::RequestContext;
use dropshot::TypedBody;
use mg_common::net::{Ipv6Prefix, TunnelOrigin};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{error, info, warn, Logger};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::spawn;
use tokio::task::JoinHandle;
use uuid::Uuid;

#[derive(Default)]
pub struct RouterStats {
    pub originated_underlay_prefixes: AtomicU64,
    pub originated_tunnel_endpoints: AtomicU64,
}

#[derive(Clone)]
pub struct HandlerContext {
    pub event_channels: Vec<Sender<Event>>,
    pub db: Db,
    pub stats: Arc<RouterStats>,
    pub peers: Vec<SmContext>,
    pub stats_handler: Arc<Mutex<Option<JoinHandle<()>>>>,
    pub log: Logger,
}

pub fn handler(
    addr: IpAddr,
    port: u16,
    context: Arc<Mutex<HandlerContext>>,
    log: Logger,
) -> Result<(), String> {
    let sa: SocketAddr = match addr {
        IpAddr::V4(a) => SocketAddrV4::new(a, port).into(),
        IpAddr::V6(a) => SocketAddrV6::new(a, port, 0, 0).into(),
    };

    let config = ConfigDropshot {
        bind_address: sa,
        request_body_max_bytes: 1024 * 1024 * 1024,
        ..Default::default()
    };

    let ds_log = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Error,
    }
    .to_logger("admin")
    .map_err(|e| e.to_string())?;

    let api = api_description()?;

    info!(log, "admin: listening on {}", sa);

    let log = log.clone();
    spawn(async move {
        let server = HttpServerStarter::new(&config, api, context, &ds_log)
            .map_err(|e| format!("new admin dropshot: {}", e))
            .unwrap();

        match server.start().await {
            Ok(_) => warn!(log, "admin: unexpected server exit"),
            Err(e) => error!(log, "admin: server start error {:?}", e),
        }
    });

    Ok(())
}

#[endpoint { method = GET, path = "/peers" }]
async fn get_peers(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<HashMap<u32, PeerInfo>>, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    Ok(HttpResponseOk(ctx.db.peers()))
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
struct ExpirePathParams {
    addr: Ipv6Addr,
}

#[endpoint { method = DELETE, path = "/peers/{addr}" }]
async fn expire_peer(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    params: Path<ExpirePathParams>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let addr = params.into_inner().addr;
    let ctx = ctx.context().lock().unwrap();

    for e in &ctx.event_channels {
        e.send(Event::Admin(AdminEvent::Expire(addr)))
            .map_err(|e| {
                HttpError::for_internal_error(format!("admin event send: {e}"))
            })?;
    }

    Ok(HttpResponseUpdatedNoContent())
}

type PrefixMap = BTreeMap<Ipv6Addr, HashSet<PathVector>>;

#[endpoint { method = GET, path = "/originated" }]
async fn get_originated(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<HashSet<Ipv6Prefix>>, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let originated = ctx
        .db
        .originated()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseOk(originated))
}

#[endpoint { method = GET, path = "/originated_tunnel_endpoints" }]
async fn get_originated_tunnel_endpoints(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<HashSet<TunnelOrigin>>, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let originated = ctx
        .db
        .originated_tunnel()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseOk(originated))
}

#[endpoint { method = GET, path = "/prefixes" }]
async fn get_prefixes(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<PrefixMap>, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let imported = ctx.db.imported();

    let mut result = PrefixMap::default();

    for route in imported {
        if let Some(entry) = result.get_mut(&route.nexthop) {
            entry.insert(PathVector {
                destination: route.destination,
                path: route.path,
            });
        } else {
            let mut s = HashSet::new();
            s.insert(PathVector {
                destination: route.destination,
                path: route.path,
            });
            result.insert(route.nexthop, s);
        }
    }

    Ok(HttpResponseOk(result))
}

#[endpoint { method = GET, path = "/tunnel_endpoints" }]
async fn get_tunnel_endpoints(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<HashSet<TunnelRoute>>, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let imported = ctx.db.imported_tunnel();
    Ok(HttpResponseOk(imported))
}

#[endpoint { method = PUT, path = "/prefix" }]
async fn advertise_prefixes(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<HashSet<Ipv6Prefix>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let prefixes = request.into_inner();
    ctx.db
        .originate(&prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    for e in &ctx.event_channels {
        e.send(Event::Admin(AdminEvent::Announce(PrefixSet::Underlay(
            prefixes.clone(),
        ))))
        .map_err(|e| {
            HttpError::for_internal_error(format!("admin event send: {e}"))
        })?;
    }

    match ctx.db.originated_count() {
        Ok(count) => ctx
            .stats
            .originated_underlay_prefixes
            .store(count as u64, Ordering::Relaxed),
        Err(e) => {
            error!(
                ctx.log,
                "failed to update originated underlay prefixes stat: {e}"
            )
        }
    }

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = PUT, path = "/tunnel_endpoint" }]
async fn advertise_tunnel_endpoints(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<HashSet<TunnelOrigin>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let endpoints = request.into_inner();
    slog::info!(ctx.log, "advertise tunnel: {:#?}", endpoints);
    ctx.db
        .originate_tunnel(&endpoints)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    for e in &ctx.event_channels {
        e.send(Event::Admin(AdminEvent::Announce(PrefixSet::Tunnel(
            endpoints.clone(),
        ))))
        .map_err(|e| {
            HttpError::for_internal_error(format!("admin event send: {e}"))
        })?;
    }

    match ctx.db.originated_tunnel_count() {
        Ok(count) => ctx
            .stats
            .originated_tunnel_endpoints
            .store(count as u64, Ordering::Relaxed),
        Err(e) => {
            error!(
                ctx.log,
                "failed to update originated tunnel endpoints stat: {e}"
            )
        }
    }
    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = DELETE, path = "/prefix" }]
async fn withdraw_prefixes(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<HashSet<Ipv6Prefix>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let prefixes = request.into_inner();
    ctx.db
        .withdraw(&prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    for e in &ctx.event_channels {
        e.send(Event::Admin(AdminEvent::Withdraw(PrefixSet::Underlay(
            prefixes.clone(),
        ))))
        .map_err(|e| {
            HttpError::for_internal_error(format!("admin event send: {e}"))
        })?;
    }

    match ctx.db.originated_count() {
        Ok(count) => ctx
            .stats
            .originated_underlay_prefixes
            .store(count as u64, Ordering::Relaxed),
        Err(e) => {
            error!(
                ctx.log,
                "failed to update originated underlay prefixes stat: {e}"
            )
        }
    }

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = DELETE, path = "/tunnel_endpoint" }]
async fn withdraw_tunnel_endpoints(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<HashSet<TunnelOrigin>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let endpoints = request.into_inner();
    slog::info!(ctx.log, "withdraw tunnel: {:#?}", endpoints);
    ctx.db
        .withdraw_tunnel(&endpoints)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    for e in &ctx.event_channels {
        e.send(Event::Admin(AdminEvent::Withdraw(PrefixSet::Tunnel(
            endpoints.clone(),
        ))))
        .map_err(|e| {
            HttpError::for_internal_error(format!("admin event send: {e}"))
        })?;
    }

    match ctx.db.originated_tunnel_count() {
        Ok(count) => ctx
            .stats
            .originated_tunnel_endpoints
            .store(count as u64, Ordering::Relaxed),
        Err(e) => {
            error!(
                ctx.log,
                "failed to update originated tunel endpoints stat: {e}"
            )
        }
    }

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = PUT, path = "/sync" }]
async fn sync(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().lock().unwrap();

    for e in &ctx.event_channels {
        e.send(Event::Admin(AdminEvent::Sync)).map_err(|e| {
            HttpError::for_internal_error(format!("admin event send: {e}"))
        })?;
    }

    Ok(HttpResponseUpdatedNoContent())
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct EnableStatsRequest {
    addr: IpAddr,
    dns_servers: Vec<SocketAddr>,
    sled_id: Uuid,
    rack_id: Uuid,
}

pub const DDM_STATS_PORT: u16 = 8001;

#[endpoint { method = POST, path = "/enable-stats" }]
async fn enable_stats(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<EnableStatsRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context().lock().unwrap();

    let mut jh = ctx.stats_handler.lock().unwrap();
    if jh.is_none() {
        let hostname = hostname::get()
            .expect("failed to get hostname")
            .to_string_lossy()
            .to_string();
        *jh = Some(
            crate::oxstats::start_server(
                DDM_STATS_PORT,
                ctx.peers.clone(),
                ctx.stats.clone(),
                rq.dns_servers.clone(),
                hostname,
                rq.rack_id,
                rq.sled_id,
                ctx.log.clone(),
            )
            .map_err(|e| {
                HttpError::for_internal_error(format!(
                    "failed to start stats server: {e}"
                ))
            })?,
        );
    }

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = POST, path = "/disable-stats" }]
async fn disable_stats(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let mut jh = ctx.stats_handler.lock().unwrap();
    if let Some(ref h) = *jh {
        h.abort();
    }
    *jh = None;

    Ok(HttpResponseUpdatedNoContent())
}

pub fn api_description(
) -> Result<ApiDescription<Arc<Mutex<HandlerContext>>>, String> {
    let mut api = ApiDescription::new();
    api.register(get_peers)?;
    api.register(expire_peer)?;
    api.register(advertise_prefixes)?;
    api.register(advertise_tunnel_endpoints)?;
    api.register(withdraw_prefixes)?;
    api.register(withdraw_tunnel_endpoints)?;
    api.register(get_prefixes)?;
    api.register(get_tunnel_endpoints)?;
    api.register(get_originated)?;
    api.register(get_originated_tunnel_endpoints)?;
    api.register(sync)?;
    api.register(enable_stats)?;
    api.register(disable_stats)?;
    Ok(api)
}
