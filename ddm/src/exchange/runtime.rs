// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Runtime helpers for the ddm prefix exchange protocol: HTTP push/pull
//! initiators and dropshot endpoint handlers, and the route programming
//! plumbing that drains received updates into the local DB and the
//! forwarding platform via [`crate::sys`]. illumos-only.

use super::ExchangeError;
use crate::db::{Route, TunnelRoute, effective_route_set};
use crate::discovery::Version;
use crate::sm::{
    Config, Event, PeerEvent, PeerIdentity, RouteAdvertisementAllowances,
    SmContext,
};
use crate::{err, inf, wrn};
use ddm_api_types::admin::PrefixKind;
use ddm_api_types::db::RouterKind;
use ddm_api_types::net::TunnelOrigin;
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::time::timeout;

const UNIT_EXCHANGE_SERVER: &str = "exchange_server";

/// Fixed for the life of the exchange server, so handlers share it without
/// locking.
pub struct ExchangeHandlerContext {
    ctx: SmContext,
    peer: PeerIdentity,
    tx_allowances: RouteAdvertisementAllowances,
}

pub(crate) fn announce_underlay(
    ctx: &SmContext,
    config: Config,
    prefixes: HashSet<v3::PathVector>,
    peer: &PeerIdentity,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = v3::UnderlayUpdate::announce(prefixes);
    send_update(ctx, config, update.into(), peer, rt, log)
}

pub(crate) fn announce_bootstrap(
    ctx: &SmContext,
    config: Config,
    prefixes: HashSet<v3::PathVector>,
    peer: &PeerIdentity,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = v3::BootstrapUpdate::announce(prefixes);
    send_update(ctx, config, update.into(), peer, rt, log)
}

pub(crate) fn announce_tunnel(
    ctx: &SmContext,
    config: Config,
    endpoints: HashSet<TunnelOrigin>,
    peer: &PeerIdentity,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = v3::TunnelUpdate::announce(
        endpoints
            .into_iter()
            .map(|x| x.to_wire(vec![ctx.router_id.clone()]))
            .collect(),
    );
    send_update(ctx, config, update.into(), peer, rt, log)
}

pub(crate) fn withdraw_underlay(
    ctx: &SmContext,
    config: Config,
    prefixes: HashSet<v3::PathVector>,
    peer: &PeerIdentity,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = v3::UnderlayUpdate::withdraw(prefixes);
    send_update(ctx, config, update.into(), peer, rt, log)
}

pub(crate) fn withdraw_bootstrap(
    ctx: &SmContext,
    config: Config,
    prefixes: HashSet<v3::PathVector>,
    peer: &PeerIdentity,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = v3::BootstrapUpdate::withdraw(prefixes);
    send_update(ctx, config, update.into(), peer, rt, log)
}

pub(crate) fn withdraw_tunnel(
    ctx: &SmContext,
    config: Config,
    endpoints: HashSet<TunnelOrigin>,
    peer: &PeerIdentity,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = v3::TunnelUpdate::withdraw(
        endpoints
            .into_iter()
            .map(|x| x.to_wire(vec![ctx.router_id.clone()]))
            .collect(),
    );
    send_update(ctx, config, update.into(), peer, rt, log)
}

pub(crate) fn do_pull(
    ctx: &SmContext,
    addr: Ipv6Addr,
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
    addr: Ipv6Addr,
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
    ctx: &SmContext,
    peer: &PeerIdentity,
    rt: Arc<tokio::runtime::Handle>,
    stop: Arc<AtomicBool>,
) -> Result<(), ExchangeError> {
    let pr: v3::PullResponse = match peer.version {
        Version::V2 => v3::PullResponse::from_v2(
            do_pull_v2(ctx, peer.addr, &rt)?,
            &peer.hostname,
        ),
        Version::V3 => do_pull(ctx, peer.addr, &rt)?,
    };

    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    handle_pull_response(pr, ctx, peer);

    Ok(())
}

pub(crate) fn send_update(
    ctx: &SmContext,
    config: Config,
    update: v3::Update,
    peer: &PeerIdentity,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    ctx.stats.updates_sent.fetch_add(1, Ordering::Relaxed);
    match peer.version {
        Version::V2 => {
            send_update_v2(ctx, config, update.into(), peer.addr, rt, log)
        }
        Version::V3 => send_update_v3(ctx, config, update, peer.addr, rt, log),
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
        match timeout(config.exchange_timeout, resp).await {
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
    peer: PeerIdentity,
    tx_allowances: RouteAdvertisementAllowances,
    log: Logger,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let context = Arc::new(ExchangeHandlerContext {
        ctx: ctx.clone(),
        peer,
        tx_allowances,
    });

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
    ApiDescription<Arc<ExchangeHandlerContext>>,
    ApiDescriptionRegisterError,
> {
    let mut api = ApiDescription::new();
    api.register(push_handler_v2)?;
    api.register(push_handler)?;
    api.register(pull_handler_v2)?;
    api.register(pull_handler)?;
    Ok(api)
}

#[endpoint {
    method = PUT,
    path = "/v2/push",
}]
async fn push_handler_v2(
    ctx: RequestContext<Arc<ExchangeHandlerContext>>,
    request: TypedBody<v2::Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let peer = &ctx.context().peer.hostname;
    let update = v3::Update::from_v2(request.into_inner(), peer);
    push_handler_common(ctx, update).await
}

#[endpoint {
    method = PUT,
    path = "/v3/push",
}]
async fn push_handler(
    ctx: RequestContext<Arc<ExchangeHandlerContext>>,
    request: TypedBody<v3::Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let update = request.into_inner();
    push_handler_common(ctx, update).await
}

async fn push_handler_common(
    ctx: RequestContext<Arc<ExchangeHandlerContext>>,
    update: v3::Update,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().clone();

    tokio::task::spawn_blocking(move || {
        handle_update(&update, &ctx.ctx, &ctx.peer);
    })
    .await
    .map_err(|e| {
        HttpError::for_internal_error(format!("spawn update thread {}", e))
    })?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint {
    method = GET,
    path = "/v2/pull",
}]
async fn pull_handler_v2(
    ctx: RequestContext<Arc<ExchangeHandlerContext>>,
) -> Result<HttpResponseOk<v2::PullResponse>, HttpError> {
    pull_handler_common(ctx)
        .await
        .map(|res| res.map(Into::into))
}

#[endpoint {
    method = GET,
    path = "/v3/pull",
}]
async fn pull_handler(
    ctx: RequestContext<Arc<ExchangeHandlerContext>>,
) -> Result<HttpResponseOk<v3::PullResponse>, HttpError> {
    pull_handler_common(ctx).await
}

async fn pull_handler_common(
    ctx: RequestContext<Arc<ExchangeHandlerContext>>,
) -> Result<HttpResponseOk<v3::PullResponse>, HttpError> {
    let ctx = ctx.context();

    let mut underlay = HashSet::new();
    let mut bootstrap = HashSet::new();
    let mut tunnel = HashSet::new();

    if ctx.tx_allowances.redistributed {
        for route in &ctx.ctx.db.imported_underlay() {
            // don't redistribute prefixes to their originators
            if route.nexthop == ctx.peer.addr {
                continue;
            }
            let mut pv = v3::PathVector {
                destination: route.destination,
                path: route.path.clone(),
            };
            pv.path.push(ctx.ctx.router_id.clone());
            underlay.insert(pv);
        }
        for route in &ctx.ctx.db.imported_bootstrap() {
            if route.nexthop == ctx.peer.addr {
                continue;
            }
            let mut pv = v3::PathVector {
                destination: route.destination,
                path: route.path.clone(),
            };
            pv.path.push(ctx.ctx.router_id.clone());
            bootstrap.insert(pv);
        }
        for route in ctx.ctx.db.imported_tunnel() {
            if route.nexthop == ctx.peer.addr {
                continue;
            }
            let mut tv = v3::TunnelOrigin::from(route);
            tv.path.push(ctx.ctx.router_id.clone());
            tunnel.insert(tv);
        }
    }

    if ctx.tx_allowances.underlay {
        let originated = ctx.ctx.db.originated_underlay();
        for prefix in &originated {
            let pv = v3::PathVector {
                destination: *prefix,
                path: vec![ctx.ctx.router_id.clone()],
            };
            underlay.insert(pv);
        }
    }

    if ctx.tx_allowances.bootstrap {
        let originated = ctx.ctx.db.originated_bootstrap();
        for prefix in &originated {
            let pv = v3::PathVector {
                destination: *prefix,
                path: vec![ctx.ctx.router_id.clone()],
            };
            bootstrap.insert(pv);
        }
    }

    if ctx.tx_allowances.rack
        && let Some(prefix) = ctx.ctx.db.rack_prefix()
    {
        underlay.insert(v3::PathVector {
            destination: prefix,
            path: vec![ctx.ctx.router_id.clone()],
        });
    }

    if ctx.tx_allowances.tunnel {
        let originated_tunnel = ctx.ctx.db.originated_tunnel();
        tunnel.extend(
            originated_tunnel
                .into_iter()
                .map(|x| x.to_wire(vec![ctx.ctx.router_id.clone()])),
        );
    }

    Ok(HttpResponseOk(v3::PullResponse {
        underlay: if underlay.is_empty() {
            None
        } else {
            Some(underlay)
        },
        bootstrap: if bootstrap.is_empty() {
            None
        } else {
            Some(bootstrap)
        },
        tunnel: if tunnel.is_empty() {
            None
        } else {
            Some(tunnel)
        },
    }))
}

/// Handle a PullResponse we received from the peer (in response to our Pull).
///
/// A PullResponse holds the peer's entire set of routes, not an incremental
/// update. That means we need to _replace_ the set of routes learned from them
/// with the set they stuffed into the PullResponse.
fn handle_pull_response(
    pr: v3::PullResponse,
    ctx: &SmContext,
    peer: &PeerIdentity,
) {
    // Convert what we hold from this peer into wire types for the diff.
    let held_underlay: HashSet<v3::PathVector> = ctx
        .db
        .imported_underlay_from(peer.addr)
        .into_iter()
        .map(v3::PathVector::from)
        .collect();
    let held_bootstrap: HashSet<v3::PathVector> = ctx
        .db
        .imported_bootstrap_from(peer.addr)
        .into_iter()
        .map(v3::PathVector::from)
        .collect();
    let held_tunnel: HashSet<v3::TunnelOrigin> = ctx
        .db
        .imported_tunnel_from(peer.addr)
        .into_iter()
        .map(v3::TunnelOrigin::from)
        .collect();

    let update = v3::Update::from_pull_response(
        pr,
        &held_underlay,
        &held_bootstrap,
        &held_tunnel,
    );

    handle_update(&update, ctx, peer);
}

fn handle_update(update: &v3::Update, ctx: &SmContext, peer: &PeerIdentity) {
    ctx.stats.updates_received.fetch_add(1, Ordering::Relaxed);

    // Path vector loop breaking. An announcement with our router ID in its
    // path has already gone through us: neither import nor redistribute it.
    let sans_loops = update.break_loops(&ctx.router_id);
    if let (Some(u), Some(s)) = (&update.underlay, &sans_loops.underlay) {
        for x in u.announce.difference(&s.announce) {
            wrn!(
                ctx.log,
                ctx.config.if_name,
                "loop detected: dropping underlay announcement: {x:?}"
            );
        }
    }
    if let (Some(b), Some(s)) = (&update.bootstrap, &sans_loops.bootstrap) {
        for x in b.announce.difference(&s.announce) {
            wrn!(
                ctx.log,
                ctx.config.if_name,
                "loop detected: dropping bootstrap announcement: {x:?}"
            );
        }
    }
    if let (Some(t), Some(s)) = (&update.tunnel, &sans_loops.tunnel) {
        for x in t.announce.difference(&s.announce) {
            wrn!(
                ctx.log,
                ctx.config.if_name,
                "loop detected: dropping tunnel announcement: {x:?}"
            );
        }
    }
    let update = &sans_loops;

    if update.is_empty() {
        return;
    }

    if let Some(underlay_update) = &update.underlay {
        handle_standard_update(
            PrefixKind::Underlay,
            &underlay_update.announce,
            &underlay_update.withdraw,
            ctx,
            peer,
        );
    }

    if let Some(bootstrap_update) = &update.bootstrap {
        handle_standard_update(
            PrefixKind::Bootstrap,
            &bootstrap_update.announce,
            &bootstrap_update.withdraw,
            ctx,
            peer,
        );
    }

    if let Some(tunnel_update) = &update.tunnel {
        handle_tunnel_update(tunnel_update, ctx, peer);
    }

    // distribute updates, unless there is nothing to distribute

    if ctx.config.kind == RouterKind::Transit
        && let Err(e) = ctx.tx.send(Event::Peer(PeerEvent::Redistribute(
            Box::new(update.clone()),
        )))
    {
        wrn!(
            ctx.log,
            ctx.config.if_name,
            "failed to send update to SM: {e:?}"
        );
    }
}

fn handle_tunnel_update(
    update: &v3::TunnelUpdate,
    ctx: &SmContext,
    peer: &PeerIdentity,
) {
    let mut import = HashSet::new();
    let mut remove = HashSet::new();
    let db = &ctx.db;

    let before = effective_route_set(&db.imported_tunnel());

    for x in &update.announce {
        import.insert(TunnelRoute::received(x, peer.addr));
    }
    db.import_tunnel(&import);

    for x in &update.withdraw {
        remove.insert(TunnelRoute::received(x, peer.addr));
    }
    db.delete_import_tunnel(&remove);

    // Tunnel routes are programmed into OPTE, which only servers have.
    // Transits keep them in the RIB for redistribution.
    if ctx.config.kind != RouterKind::Server {
        return;
    }

    let after = effective_route_set(&db.imported_tunnel());

    let to_add = after.difference(&before).cloned().collect();
    let to_del = before.difference(&after).cloned().collect();

    if let Err(e) =
        crate::sys::add_tunnel_routes(&ctx.log, &ctx.config.if_name, &to_add)
    {
        err!(
            ctx.log,
            ctx.config.if_name,
            "add tunnel routes: {e}: {:#?}",
            import,
        )
    }

    if let Err(e) =
        crate::sys::remove_tunnel_routes(&ctx.log, &ctx.config.if_name, &to_del)
    {
        err!(
            ctx.log,
            ctx.config.if_name,
            "remove tunnel routes: {e}: {:#?}",
            import,
        )
    }
}

fn handle_standard_update(
    kind: PrefixKind,
    announce: &HashSet<v3::PathVector>,
    withdraw: &HashSet<v3::PathVector>,
    ctx: &SmContext,
    peer: &PeerIdentity,
) {
    let mut import = HashSet::new();
    let mut add = Vec::new();
    let db = &ctx.db;

    let source = match kind {
        PrefixKind::Underlay => ctx.db.underlay_addr().map(|a| a.address()),
        PrefixKind::Bootstrap => Some(ctx.bootstrap_addr),
    };
    for prefix in announce {
        import.insert(Route {
            destination: prefix.destination,
            nexthop: peer.addr,
            addrobj_name: ctx.config.addrobj_name.clone(),
            path: prefix.path.clone(),
            kind,
        });
        if let Some(src) = source {
            let mut r = crate::sys::Route::new(
                prefix.destination.addr().into(),
                prefix.destination.width(),
                peer.addr.into(),
                src,
            );
            r.ifname.clone_from(&ctx.config.if_name);
            add.push(r);
        }
    }
    match kind {
        PrefixKind::Underlay => db.import_underlay(&import),
        PrefixKind::Bootstrap => db.import_bootstrap(&import),
    }
    if source.is_some() {
        crate::sys::add_underlay_routes(&ctx.log, &ctx.config, add, &ctx.rt);
    } else {
        // TODO: nothing installs deferred routes once an underlay address is
        // set, and changing the address leaves installed routes with the old
        // source. They stay out of sys until a peer re-announces them.
        inf!(
            ctx.log,
            ctx.config.if_name,
            "source IP not ready, deferring install of routes into sys"
        )
    }

    let mut delete = HashSet::new();
    for prefix in withdraw {
        delete.insert(Route {
            destination: prefix.destination,
            nexthop: peer.addr,
            addrobj_name: ctx.config.addrobj_name.clone(),
            path: prefix.path.clone(),
            kind,
        });
    }

    // We cannot simply delete withdrawn routes from the forwarding platform.
    // We track routes by path, but the platform only knows about a
    // (destination, nexthop) vector, and there can be many paths along one
    // vector. delete_import returns only the vectors whose last path is gone.
    let mut del = Vec::new();
    for (destination, nexthop) in db.delete_import(kind, &delete) {
        // Route removal does not use the source address.
        let mut r = crate::sys::Route::new(
            destination.addr().into(),
            destination.width(),
            nexthop.into(),
            Ipv6Addr::UNSPECIFIED,
        );
        r.ifname.clone_from(&ctx.config.if_name);
        del.push(r);
    }
    crate::sys::remove_underlay_routes(
        &ctx.log,
        &ctx.config.if_name,
        &ctx.config.dpd,
        del,
        &ctx.rt,
    );
}
