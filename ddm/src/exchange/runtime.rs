// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Runtime helpers for the ddm prefix exchange protocol: HTTP push/pull
//! initiators and dropshot endpoint handlers, and the route programming
//! plumbing that drains received updates into the local DB and the
//! forwarding platform via [`crate::sys`]. illumos-only.

use super::ExchangeError;
use crate::db::{Route, effective_route_set};
use crate::discovery::Version;
use crate::sm::{Config, Event, PeerEvent, SmContext};
use crate::{dbg, err, inf, wrn};
use ddm_api_types::db::{RouterKind, TunnelRoute};
use ddm_protocol::{v2, v3};
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
use dropshot::{ApiDescriptionRegisterError, endpoint};
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use slog::{Logger, o};
use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

const UNIT_EXCHANGE_SERVER: &str = "exchange_server";

#[derive(Clone)]
pub struct HandlerContext {
    ctx: SmContext,
    peer: Ipv6Addr,
    log: Logger,
}

pub(crate) fn announce_underlay(
    ctx: &SmContext,
    config: Config,
    prefixes: HashSet<v3::PathVector>,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = v3::UnderlayUpdate::announce(prefixes);
    send_update(ctx, config, update.into(), addr, version, rt, log)
}

pub(crate) fn announce_tunnel(
    ctx: &SmContext,
    config: Config,
    endpoints: HashSet<v3::TunnelOrigin>,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = v3::TunnelUpdate::announce(endpoints.into_iter().collect());
    send_update(ctx, config, update.into(), addr, version, rt, log)
}

pub(crate) fn withdraw_underlay(
    ctx: &SmContext,
    config: Config,
    prefixes: HashSet<v3::PathVector>,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = v3::UnderlayUpdate::withdraw(prefixes);
    send_update(ctx, config, update.into(), addr, version, rt, log)
}

pub(crate) fn withdraw_tunnel(
    ctx: &SmContext,
    config: Config,
    endpoints: HashSet<v3::TunnelOrigin>,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = v3::TunnelUpdate::withdraw(endpoints.into_iter().collect());
    send_update(ctx, config, update.into(), addr, version, rt, log)
}

pub(crate) fn do_pull(
    ctx: &SmContext,
    addr: &Ipv6Addr,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<v3::PullResponse, ExchangeError> {
    let uri = format!(
        "http://[{}%{}]:{}/v3/pull",
        addr, ctx.config.if_index, ctx.config.exchange_port,
    );
    let body = do_pull_common(uri, rt)?;
    Ok(serde_json::from_slice(&body)?)
}

pub(crate) fn do_pull_v2(
    ctx: &SmContext,
    addr: &Ipv6Addr,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<v2::PullResponse, ExchangeError> {
    let uri = format!(
        "http://[{}%{}]:{}/v2/pull",
        addr, ctx.config.if_index, ctx.config.exchange_port,
    );
    let body = do_pull_common(uri, rt)?;
    Ok(serde_json::from_slice(&body)?)
}

fn do_pull_common(
    uri: String,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<Bytes, ExchangeError> {
    let client = Client::builder(TokioExecutor::new()).build_http();

    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri)
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = client.request(req);

    rt.block_on(async move {
        let body = timeout(Duration::from_millis(250), resp)
            .await??
            .into_body()
            .collect()
            .await?
            .to_bytes();
        Ok(body)
    })
}

pub(crate) fn pull(
    ctx: SmContext,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let pr: v3::PullResponse = match version {
        Version::V2 => do_pull_v2(&ctx, &addr, &rt)?.into(),
        Version::V3 => do_pull(&ctx, &addr, &rt)?,
    };

    let update = v3::Update::announce(pr);

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
    update: v3::Update,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    ctx.stats.updates_sent.fetch_add(1, Ordering::Relaxed);
    match version {
        Version::V2 => {
            send_update_v2(ctx, config, update.into(), addr, rt, log)
        }
        Version::V3 => send_update_v3(ctx, config, update, addr, rt, log),
    }
}

fn send_update_v2(
    ctx: &SmContext,
    config: Config,
    update: v2::Update,
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

fn send_update_v3(
    ctx: &SmContext,
    config: Config,
    update: v3::Update,
    addr: Ipv6Addr,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let payload = serde_json::to_string(&update)?;
    let uri = format!(
        "http://[{}%{}]:{}/v3/push",
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
    let client = Client::builder(TokioExecutor::new()).build_http();

    let body = http_body_util::Full::<Bytes>::from(payload);
    let req = hyper::Request::builder()
        .method(hyper::Method::PUT)
        .uri(&uri)
        .body(body)
        .unwrap();

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
    .map_err(|e| e.to_string())?
    .new(o!(
        "component" => crate::COMPONENT_DDM,
        "module" => crate::MOD_EXCHANGE,
        "unit" => UNIT_EXCHANGE_SERVER,
    ));

    inf!(log, ctx.config.if_name, "exchange: listening on {}", sa);

    let log = log.clone();

    let api = api_description().map_err(|e| e.to_string())?;
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

pub fn api_description() -> Result<
    ApiDescription<Arc<Mutex<HandlerContext>>>,
    ApiDescriptionRegisterError,
> {
    let mut api = ApiDescription::new();
    api.register(push_handler_v2)?;
    api.register(push_handler)?;
    api.register(pull_handler_v2)?;
    api.register(pull_handler)?;
    Ok(api)
}

#[endpoint { method = PUT, path = "/v2/push" }]
async fn push_handler_v2(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<v2::Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let update_v2 = request.into_inner();
    let update = v3::Update::from(update_v2);
    push_handler_common(ctx, update).await
}

#[endpoint { method = PUT, path = "/v3/push" }]
async fn push_handler(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<v3::Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let update = request.into_inner();
    push_handler_common(ctx, update).await
}

async fn push_handler_common(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    update: v3::Update,
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

#[endpoint { method = GET, path = "/v2/pull" }]
async fn pull_handler_v2(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<v2::PullResponse>, HttpError> {
    let ctx = ctx.context().lock().await.clone();

    let mut underlay = HashSet::new();
    let mut tunnel = HashSet::new();

    // Only transit routers redistribute prefixes
    if ctx.ctx.config.kind == RouterKind::Transit {
        for route in &ctx.ctx.db.imported() {
            // don't redistribute prefixes to their originators
            if route.nexthop == ctx.peer {
                continue;
            }
            let mut pv = v3::PathVector {
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
        let pv = v3::PathVector {
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
        let tv = v3::TunnelOrigin {
            overlay_prefix: prefix.overlay_prefix,
            boundary_addr: prefix.boundary_addr,
            vni: prefix.vni,
            metric: prefix.metric,
        };
        tunnel.insert(tv);
    }

    Ok(HttpResponseOk(v2::PullResponse {
        underlay: if underlay.is_empty() {
            None
        } else {
            Some(underlay.into_iter().map(v2::PathVector::from).collect())
        },
        tunnel: if tunnel.is_empty() {
            None
        } else {
            Some(tunnel.into_iter().map(v2::TunnelOrigin::from).collect())
        },
    }))
}

#[endpoint { method = GET, path = "/v3/pull" }]
async fn pull_handler(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<v3::PullResponse>, HttpError> {
    let ctx = ctx.context().lock().await.clone();

    let mut underlay = HashSet::new();
    let mut tunnel = HashSet::new();

    // Only transit routers redistribute prefixes
    if ctx.ctx.config.kind == RouterKind::Transit {
        for route in &ctx.ctx.db.imported() {
            // don't redistribute prefixes to their originators
            if route.nexthop == ctx.peer {
                continue;
            }
            let mut pv = v3::PathVector {
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
        let pv = v3::PathVector {
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
        let tv = v3::TunnelOrigin {
            overlay_prefix: prefix.overlay_prefix,
            boundary_addr: prefix.boundary_addr,
            vni: prefix.vni,
            metric: prefix.metric,
        };
        tunnel.insert(tv);
    }

    Ok(HttpResponseOk(v3::PullResponse {
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

fn handle_update(update: &v3::Update, ctx: &HandlerContext) {
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

        let push = v3::Update {
            underlay,
            tunnel: update.tunnel.clone(),
        };

        for ec in &ctx.ctx.event_channels {
            ec.send(Event::Peer(PeerEvent::Push(push.clone()))).unwrap();
        }
    }
}

fn handle_tunnel_update(update: &v3::TunnelUpdate, ctx: &HandlerContext) {
    let mut import = HashSet::new();
    let mut remove = HashSet::new();
    let db = &ctx.ctx.db;

    let before = effective_route_set(&db.imported_tunnel());

    for x in &update.announce {
        import.insert(TunnelRoute {
            origin: v3::TunnelOrigin {
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
            origin: v3::TunnelOrigin {
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

fn handle_underlay_update(update: &v3::UnderlayUpdate, ctx: &HandlerContext) {
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
