// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This file implements the ddm router prefix exchange mechanisms. These
//! mechanisms are responsible for announcing and withdrawing prefix sets to and
//! from peers.
//!
//! This file has a set of request initiators and request handlers for
//! announcing, withdrawing and synchronizing routes with a a given peer.
//! Communication between peers is over HTTP(s) requests.
//!
//! This file only contains basic mechanisms for prefix information exhcnage
//! with peers. How those mechanisms are used in the overal state machine model
//! of a ddm router is defined in the state machine implementation in sm.rs.
//!

use crate::db::{effective_route_set, Route, RouterKind, TunnelRoute};
use crate::discovery::Version;
use crate::sm::{Config, Event, PeerEvent, SmContext};
use crate::{dbg, err, inf, wrn};
use dropshot::endpoint;
use dropshot::ApiDescription;
use dropshot::ConfigDropshot;
use dropshot::ConfigLogging;
use dropshot::ConfigLoggingLevel;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::HttpServerStarter;
use dropshot::RequestContext;
use dropshot::TypedBody;
use hyper::body::Bytes;
use mg_common::net::TunnelOrigin;
use oxnet::Ipv6Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::timeout;

#[derive(Clone)]
pub struct HandlerContext {
    ctx: SmContext,
    peer: Ipv6Addr,
    log: Logger,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UpdateV1 {
    pub announce: HashSet<PathVector>,
    pub withdraw: HashSet<PathVector>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct Update {
    pub underlay: Option<UnderlayUpdate>,
    pub tunnel: Option<TunnelUpdate>,
}

impl From<UpdateV1> for Update {
    fn from(value: UpdateV1) -> Self {
        Update {
            tunnel: None,
            underlay: Some(UnderlayUpdate {
                announce: value.announce,
                withdraw: value.withdraw,
            }),
        }
    }
}

impl From<Update> for UpdateV1 {
    fn from(value: Update) -> Self {
        let (announce, withdraw) = match value.underlay {
            Some(underlay) => (underlay.announce, underlay.withdraw),
            None => (HashSet::new(), HashSet::new()),
        };
        UpdateV1 { announce, withdraw }
    }
}

impl From<UnderlayUpdate> for Update {
    fn from(u: UnderlayUpdate) -> Self {
        Update {
            underlay: Some(u),
            tunnel: None,
        }
    }
}

impl From<TunnelUpdate> for Update {
    fn from(t: TunnelUpdate) -> Self {
        Update {
            underlay: None,
            tunnel: Some(t),
        }
    }
}

impl Update {
    fn announce(pr: PullResponse) -> Self {
        Self {
            underlay: pr.underlay.map(UnderlayUpdate::announce),
            tunnel: pr.tunnel.map(TunnelUpdate::announce),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct PullResponse {
    pub underlay: Option<HashSet<PathVector>>,
    pub tunnel: Option<HashSet<TunnelOrigin>>,
}

impl From<HashSet<PathVector>> for PullResponse {
    fn from(value: HashSet<PathVector>) -> Self {
        PullResponse {
            underlay: Some(value),
            tunnel: None,
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct PathVector {
    pub destination: Ipv6Net,
    pub path: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UnderlayUpdate {
    pub announce: HashSet<PathVector>,
    pub withdraw: HashSet<PathVector>,
}

impl UnderlayUpdate {
    pub fn announce(prefixes: HashSet<PathVector>) -> Self {
        Self {
            announce: prefixes,
            ..Default::default()
        }
    }
    pub fn withdraw(prefixes: HashSet<PathVector>) -> Self {
        Self {
            withdraw: prefixes,
            ..Default::default()
        }
    }
    pub fn with_path_element(&self, element: String) -> Self {
        Self {
            announce: self
                .announce
                .iter()
                .map(|x| {
                    let mut pv = x.clone();
                    pv.path.push(element.clone());
                    pv
                })
                .collect(),
            withdraw: self
                .withdraw
                .iter()
                .map(|x| {
                    let mut pv = x.clone();
                    pv.path.push(element.clone());
                    pv
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct TunnelUpdate {
    pub announce: HashSet<TunnelOrigin>,
    pub withdraw: HashSet<TunnelOrigin>,
}

impl TunnelUpdate {
    pub fn announce(prefixes: HashSet<TunnelOrigin>) -> Self {
        Self {
            announce: prefixes,
            ..Default::default()
        }
    }
    pub fn withdraw(prefixes: HashSet<TunnelOrigin>) -> Self {
        Self {
            withdraw: prefixes,
            ..Default::default()
        }
    }
}

#[derive(Error, Debug)]
pub enum ExchangeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("hyper http error: {0}")]
    HyperHttp(#[from] hyper::http::Error),

    #[error("timeout error: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

pub(crate) fn announce_underlay(
    ctx: &SmContext,
    config: Config,
    prefixes: HashSet<PathVector>,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = UnderlayUpdate::announce(prefixes);
    send_update(ctx, config, update.into(), addr, version, rt, log)
}

pub(crate) fn announce_tunnel(
    ctx: &SmContext,
    config: Config,
    endpoints: HashSet<TunnelOrigin>,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update =
        TunnelUpdate::announce(endpoints.into_iter().map(Into::into).collect());
    send_update(ctx, config, update.into(), addr, version, rt, log)
}

pub(crate) fn withdraw_underlay(
    ctx: &SmContext,
    config: Config,
    prefixes: HashSet<PathVector>,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = UnderlayUpdate::withdraw(prefixes);
    send_update(ctx, config, update.into(), addr, version, rt, log)
}

pub(crate) fn withdraw_tunnel(
    ctx: &SmContext,
    config: Config,
    endpoints: HashSet<TunnelOrigin>,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update =
        TunnelUpdate::withdraw(endpoints.into_iter().map(Into::into).collect());
    send_update(ctx, config, update.into(), addr, version, rt, log)
}

pub(crate) fn do_pull(
    ctx: &SmContext,
    addr: &Ipv6Addr,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<PullResponse, ExchangeError> {
    let uri = format!(
        "http://[{}%{}]:{}/v2/pull",
        addr, ctx.config.if_index, ctx.config.exchange_port,
    );
    let body = do_pull_common(uri, rt)?;
    Ok(serde_json::from_slice(&body)?)
}

pub(crate) fn do_pull_v1(
    ctx: &SmContext,
    addr: &Ipv6Addr,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<HashSet<PathVector>, ExchangeError> {
    let uri = format!(
        "http://[{}%{}]:{}/pull",
        addr, ctx.config.if_index, ctx.config.exchange_port,
    );
    let body = do_pull_common(uri, rt)?;
    Ok(serde_json::from_slice(&body)?)
}

fn do_pull_common(
    uri: String,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<Bytes, ExchangeError> {
    let client = hyper::Client::new();
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri)
        .body(hyper::Body::empty())?;

    let resp = client.request(req);

    let body = rt.block_on(async move {
        match timeout(Duration::from_millis(250), resp).await {
            Ok(response) => match response {
                Ok(data) => {
                    match hyper::body::to_bytes(data.into_body()).await {
                        Ok(data) => Ok(data),
                        Err(e) => Err(ExchangeError::Hyper(e)),
                    }
                }
                Err(e) => Err(ExchangeError::Hyper(e)),
            },
            Err(e) => Err(ExchangeError::Timeout(e)),
        }
    })?;

    Ok(body)
}

pub(crate) fn pull(
    ctx: SmContext,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let pr: PullResponse = match version {
        Version::V1 => do_pull_v1(&ctx, &addr, &rt)?.into(),
        Version::V2 => do_pull(&ctx, &addr, &rt)?,
    };

    let update = Update::announce(pr);

    let hctx = HandlerContext {
        ctx,
        peer: addr,
        log: log.clone(),
    };
    handle_update(&update, &hctx);

    Ok(())
}

fn send_update(
    ctx: &SmContext,
    config: Config,
    update: Update,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    ctx.stats.updates_sent.fetch_add(1, Ordering::Relaxed);
    match version {
        Version::V1 => {
            send_update_v1(ctx, config, update.into(), addr, rt, log)
        }
        Version::V2 => send_update_v2(ctx, config, update, addr, rt, log),
    }
}

fn send_update_v2(
    ctx: &SmContext,
    config: Config,
    update: Update,
    addr: Ipv6Addr,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let payload = serde_json::to_string(&update)?;
    let uri = format!(
        "http://[{}%{}]:{}/v2/push",
        addr, config.if_index, config.exchange_port,
    );
    send_update_common(ctx, uri, payload, config, rt, log)
}

fn send_update_v1(
    ctx: &SmContext,
    config: Config,
    update: UpdateV1,
    addr: Ipv6Addr,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let payload = serde_json::to_string(&update)?;
    let uri = format!(
        "http://[{}%{}]:{}/push",
        addr, config.if_index, config.exchange_port,
    );
    send_update_common(ctx, uri, payload, config, rt, log)
}

fn send_update_common(
    ctx: &SmContext,
    uri: String,
    payload: String,
    config: Config,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let client = hyper::Client::new();
    let req = hyper::Request::builder()
        .method(hyper::Method::PUT)
        .uri(&uri)
        .body(hyper::Body::from(payload))?;

    let resp = client.request(req);

    rt.block_on(async move {
        match timeout(Duration::from_millis(config.exchange_timeout), resp)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                err!(
                    log,
                    config.if_name,
                    "peer request timeout to {}: {}",
                    uri,
                    e,
                );
                ctx.stats.update_send_fail.fetch_add(1, Ordering::Relaxed);
                Err(e.into())
            }
        }
    })
}

pub fn handler(
    ctx: SmContext,
    addr: Ipv6Addr,
    peer: Ipv6Addr,
    log: Logger,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let context = Arc::new(Mutex::new(HandlerContext {
        ctx: ctx.clone(),
        log: log.clone(),
        peer,
    }));

    let sa = SocketAddrV6::new(addr, ctx.config.exchange_port, 0, 0);

    let config = ConfigDropshot {
        bind_address: sa.into(),
        ..Default::default()
    };

    let ds_log = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Error,
    }
    .to_logger("exchange")
    .map_err(|e| e.to_string())?;

    inf!(log, ctx.config.if_name, "exchange: listening on {}", sa);

    let log = log.clone();

    let api = api_description()?;
    let server = ctx.rt.block_on(async move {
        match HttpServerStarter::new(&config, api, context, &ds_log) {
            Ok(s) => Ok(s),
            Err(e) => {
                Err(format!("failed to start exchange server on {addr}: {e}"))
            }
        }
    })?;

    Ok(ctx.rt.spawn(async move {
        match server.start().await {
            Ok(_) => wrn!(
                log,
                ctx.config.if_name,
                "exchange: unexpected server exit"
            ),
            Err(e) => err!(
                log,
                ctx.config.if_name,
                "exchange: server start error {:?}",
                e
            ),
        }
    }))
}

pub fn api_description(
) -> Result<ApiDescription<Arc<Mutex<HandlerContext>>>, String> {
    let mut api = ApiDescription::new();
    api.register(push_handler_v1)?;
    api.register(push_handler)?;
    api.register(pull_handler_v1)?;
    api.register(pull_handler)?;
    Ok(api)
}

#[endpoint { method = PUT, path = "/push" }]
async fn push_handler_v1(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<UpdateV1>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let update_v1 = request.into_inner();
    let update = Update::from(update_v1);
    push_handler_common(ctx, update).await
}

#[endpoint { method = PUT, path = "/v2/push" }]
async fn push_handler(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let update = request.into_inner();
    push_handler_common(ctx, update).await
}

async fn push_handler_common(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    update: Update,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().lock().await.clone();
    tokio::task::spawn_blocking(move || {
        handle_update(&update, &ctx);
    })
    .await
    .map_err(|e| {
        HttpError::for_internal_error(format!("spawn update thread {}", e))
    })?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/pull" }]
async fn pull_handler_v1(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<HashSet<PathVector>>, HttpError> {
    let ctx = ctx.context().lock().await.clone();

    let mut prefixes = HashSet::new();
    // Only transit routers redistribute prefixes
    if ctx.ctx.config.kind == RouterKind::Transit {
        for route in &ctx.ctx.db.imported() {
            // dont redistribute prefixes to their originators
            if route.nexthop == ctx.peer {
                continue;
            }
            let mut pv = PathVector {
                destination: route.destination,
                path: route.path.clone(),
            };
            pv.path.push(ctx.ctx.hostname.clone());
            prefixes.insert(pv);
        }
    }
    let originated = ctx
        .ctx
        .db
        .originated()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    for prefix in &originated {
        let pv = PathVector {
            destination: *prefix,
            path: vec![ctx.ctx.hostname.clone()],
        };
        prefixes.insert(pv);
    }

    Ok(HttpResponseOk(prefixes))
}

#[endpoint { method = GET, path = "/v2/pull" }]
async fn pull_handler(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<PullResponse>, HttpError> {
    let ctx = ctx.context().lock().await.clone();

    let mut underlay = HashSet::new();
    let mut tunnel = HashSet::new();

    // Only transit routers redistribute prefixes
    if ctx.ctx.config.kind == RouterKind::Transit {
        for route in &ctx.ctx.db.imported() {
            // dont redistribute prefixes to their originators
            if route.nexthop == ctx.peer {
                continue;
            }
            let mut pv = PathVector {
                destination: route.destination,
                path: route.path.clone(),
            };
            pv.path.push(ctx.ctx.hostname.clone());
            underlay.insert(pv);
        }
        for route in &ctx.ctx.db.imported_tunnel() {
            if route.nexthop == ctx.peer {
                continue;
            }
            let tv = route.origin;
            tunnel.insert(tv);
        }
    }
    let originated = ctx
        .ctx
        .db
        .originated()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    for prefix in &originated {
        let pv = PathVector {
            destination: *prefix,
            path: vec![ctx.ctx.hostname.clone()],
        };
        underlay.insert(pv);
    }

    let originated_tunnel = ctx
        .ctx
        .db
        .originated_tunnel()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    for prefix in &originated_tunnel {
        let tv = TunnelOrigin {
            overlay_prefix: prefix.overlay_prefix,
            boundary_addr: prefix.boundary_addr,
            vni: prefix.vni,
            metric: prefix.metric,
        };
        tunnel.insert(tv);
    }

    Ok(HttpResponseOk(PullResponse {
        underlay: if underlay.is_empty() {
            None
        } else {
            Some(underlay)
        },
        tunnel: if tunnel.is_empty() {
            None
        } else {
            Some(tunnel)
        },
    }))
}

fn handle_update(update: &Update, ctx: &HandlerContext) {
    ctx.ctx
        .stats
        .updates_received
        .fetch_add(1, Ordering::Relaxed);

    if let Some(underlay_update) = &update.underlay {
        handle_underlay_update(underlay_update, ctx);
    }

    if let Some(tunnel_update) = &update.tunnel {
        handle_tunnel_update(tunnel_update, ctx);
    }

    // distribute updates

    if ctx.ctx.config.kind == RouterKind::Transit {
        dbg!(
            ctx.log,
            ctx.ctx.config.if_name,
            "redistributing update to {} peers",
            ctx.ctx.event_channels.len()
        );

        let underlay = update
            .underlay
            .as_ref()
            .map(|update| update.with_path_element(ctx.ctx.hostname.clone()));

        let push = Update {
            underlay,
            tunnel: update.tunnel.clone(),
        };

        for ec in &ctx.ctx.event_channels {
            ec.send(Event::Peer(PeerEvent::Push(push.clone()))).unwrap();
        }
    }
}

fn handle_tunnel_update(update: &TunnelUpdate, ctx: &HandlerContext) {
    let mut import = HashSet::new();
    let mut remove = HashSet::new();
    let db = &ctx.ctx.db;

    let before = effective_route_set(&db.imported_tunnel());

    for x in &update.announce {
        import.insert(TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: x.overlay_prefix,
                boundary_addr: x.boundary_addr,
                vni: x.vni,
                metric: x.metric,
            },
            nexthop: ctx.peer,
        });
    }
    db.import_tunnel(&import);

    for x in &update.withdraw {
        remove.insert(TunnelRoute {
            origin: TunnelOrigin {
                overlay_prefix: x.overlay_prefix,
                boundary_addr: x.boundary_addr,
                vni: x.vni,
                metric: x.metric,
            },
            nexthop: ctx.peer,
        });
    }
    db.delete_import_tunnel(&remove);

    let after = effective_route_set(&db.imported_tunnel());

    let to_add = after.difference(&before).copied().collect();
    let to_del = before.difference(&after).copied().collect();

    if let Err(e) = crate::sys::add_tunnel_routes(
        &ctx.log,
        &ctx.ctx.config.if_name,
        &to_add,
    ) {
        err!(
            ctx.log,
            ctx.ctx.config.if_name,
            "add tunnel routes: {e}: {:#?}",
            import,
        )
    }

    if let Err(e) = crate::sys::remove_tunnel_routes(
        &ctx.log,
        &ctx.ctx.config.if_name,
        &to_del,
    ) {
        err!(
            ctx.log,
            ctx.ctx.config.if_name,
            "remove tunnel routes: {e}: {:#?}",
            import,
        )
    }

    ctx.ctx
        .stats
        .imported_underlay_prefixes
        .store(ctx.ctx.db.imported_tunnel_count() as u64, Ordering::Relaxed);
}

fn handle_underlay_update(update: &UnderlayUpdate, ctx: &HandlerContext) {
    let mut import = HashSet::new();
    let mut add = Vec::new();
    let db = &ctx.ctx.db;

    for prefix in &update.announce {
        import.insert(Route {
            destination: prefix.destination,
            nexthop: ctx.peer,
            ifname: ctx.ctx.config.if_name.clone(),
            path: prefix.path.clone(),
        });
        let mut r = crate::sys::Route::new(
            prefix.destination.addr().into(),
            prefix.destination.width(),
            ctx.peer.into(),
        );
        r.ifname.clone_from(&ctx.ctx.config.if_name);
        add.push(r);
    }
    db.import(&import);
    crate::sys::add_underlay_routes(
        &ctx.log,
        &ctx.ctx.config,
        add,
        &ctx.ctx.rt,
    );

    let mut withdraw = HashSet::new();
    for prefix in &update.withdraw {
        withdraw.insert(Route {
            destination: prefix.destination,
            nexthop: ctx.peer,
            ifname: ctx.ctx.config.if_name.clone(),
            path: prefix.path.clone(),
        });
    }
    db.delete_import(&withdraw);

    // We cannot simply delete withdrawn routes here. If we have other paths to
    // the destination with the same nexthop, we'll be left with a route in the
    // DB but not the underlying forwarding platform. We cannot delete a
    // (destination, nexthop) pair until all path-vector routes with that tuple
    // are gone. Another way to say this is that while we track routes by path,
    // the underlying forwarding platform only knows about a vector. And since
    // there can be many paths along vector, we can only delete a route from the
    // forwarding platform if the complete vector is gone.
    let mut del = Vec::new();
    for w in &withdraw {
        if db.routes_by_vector(w.destination, w.nexthop).is_empty() {
            let mut r = crate::sys::Route::new(
                w.destination.addr().into(),
                w.destination.width(),
                w.nexthop.into(),
            );
            r.ifname.clone_from(&ctx.ctx.config.if_name);
            del.push(r);
        }
    }
    crate::sys::remove_underlay_routes(
        &ctx.log,
        &ctx.ctx.config.if_name,
        &ctx.ctx.config.dpd,
        del,
        &ctx.ctx.rt,
    );

    ctx.ctx
        .stats
        .imported_underlay_prefixes
        .store(ctx.ctx.db.imported_count() as u64, Ordering::Relaxed);
}
