// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Runtime helpers for the ddm prefix exchange protocol: HTTP push/pull
//! initiators and dropshot endpoint handlers, and the route programming
//! plumbing that drains received updates into the local DB and the
//! forwarding platform via [`crate::sys`]. illumos-only.

use super::{ExchangeError, reconcile_multicast_withdrawals};
use crate::db::{Route, effective_route_set};
use crate::discovery::Version;
use crate::sm::{Config, Event, PeerEvent, SmContext};
use crate::{dbg, err, inf, trc, wrn};
use ddm_api_types::db::{MulticastRoute, RouterKind, TunnelRoute};
use ddm_api_types::net::MulticastOrigin;
use ddm_protocol::v3::{PathVector, TunnelOrigin};
use ddm_protocol::v4::{
    MulticastPathHop, MulticastPathVector, MulticastUpdate, PullResponse,
    Update,
};
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
use mg_common::lock;
use slog::{Logger, o};
use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

const UNIT_EXCHANGE_SERVER: &str = "exchange_server";

/// Bound on an entire pull request, from dispatch through to reading the full
/// response. Pulls run on state machine threads, so a stalled peer must not
/// block event handling.
const PULL_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Clone)]
pub struct HandlerContext {
    ctx: SmContext,
    peer: Ipv6Addr,
    log: Logger,
}

/// How an update's imported routes propagate beyond the local DB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateMode {
    /// Import into the local DB only.
    ImportOnly,
    /// Import and re-announce to this router's other peers. Only transit
    /// routers act on this. Server routers treat it as [`Self::ImportOnly`].
    Redistribute,
}

/// A handle to a running exchange server, pairing the server task with the
/// shared request context so the state machine can rebind the peer address
/// on renumber without restarting the server.
///
/// A renumber occurs when a peer's link-local unicast address changes.
/// [`crate::discovery`] detects the change and re-advertises the neighbor
/// under the new address. The neighbor is still the same router, so the
/// exchange server keeps running and only the nexthop address it assigns to
/// imports changes.
pub struct ExchangeHandle {
    thread: tokio::task::JoinHandle<()>,
    context: Arc<Mutex<HandlerContext>>,
}

impl ExchangeHandle {
    pub fn abort(&self) {
        self.thread.abort();
    }

    /// Rebind the handler's peer address after a renumber. The handler
    /// assigns this address as the nexthop on every route it imports, so it
    /// must track the state machine's view of the peer or else, post-renumber
    /// imports leak under the prior address.
    pub fn renumber_peer(&self, peer: Ipv6Addr) {
        // Safe to block: callers run on state machine threads, outside
        // the runtime.
        self.context.blocking_lock().peer = peer;
    }
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

pub(crate) fn announce_multicast(
    ctx: &SmContext,
    config: Config,
    groups: HashSet<MulticastPathVector>,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = MulticastUpdate::announce(groups);
    send_update(ctx, config, update.into(), addr, version, rt, log)
}

pub(crate) fn withdraw_multicast(
    ctx: &SmContext,
    config: Config,
    groups: HashSet<MulticastPathVector>,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let update = MulticastUpdate::withdraw(groups);
    send_update(ctx, config, update.into(), addr, version, rt, log)
}

pub(crate) fn do_pull_v4(
    ctx: &SmContext,
    addr: &Ipv6Addr,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<PullResponse, ExchangeError> {
    let if_index = ctx.config.if_index;
    let port = ctx.config.exchange_port;
    let uri = format!("http://[{addr}%{if_index}]:{port}/v4/pull");
    let body = do_pull_common(uri, rt)?;
    Ok(serde_json::from_slice(&body)?)
}

pub(crate) fn do_pull_v3(
    ctx: &SmContext,
    addr: &Ipv6Addr,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<v3::PullResponse, ExchangeError> {
    let if_index = ctx.config.if_index;
    let port = ctx.config.exchange_port;
    let uri = format!("http://[{addr}%{if_index}]:{port}/v3/pull");
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

fn require_success<B>(
    response: hyper::Response<B>,
) -> Result<hyper::Response<B>, ExchangeError> {
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(ExchangeError::Status(response.status()))
    }
}

/// Fetch a pull response body, accepting only successful HTTP responses.
///
/// The status is checked before the body reaches a versioned decoder. This is
/// especially important for V4, whose optional response fields could otherwise
/// make a Dropshot JSON error look like an empty route set.
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

    // The timeout covers reading the body too, since a peer that stalls
    // mid-response would otherwise block indefinitely.
    rt.block_on(async move {
        timeout(PULL_TIMEOUT, async {
            let resp = require_success(resp.await?)?;
            Ok(resp.into_body().collect().await?.to_bytes())
        })
        .await?
    })
}

/// Pull the peer's routes and import them.
///
/// When `mode` is [`UpdateMode::Redistribute`] and this router is a transit,
/// the imported set is also announced to the other peers. The initial pull on
/// entering the exchange state redistributes. The periodic pull imports only.
/// Each router runs its own periodic pull, so a route learned here still
/// reaches every router through that router's pull. Redistributing on every
/// cycle would only resend updates transit peers already hold in steady
/// state.
///
/// A non-successful HTTP response aborts the pull before decoding or
/// reconciliation, leaving the routes previously imported from that peer
/// unchanged.
pub(crate) fn pull(
    ctx: SmContext,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
    mode: UpdateMode,
) -> Result<(), ExchangeError> {
    let pr: PullResponse = match version {
        Version::V2 => {
            v3::PullResponse::from(do_pull_v2(&ctx, &addr, &rt)?).into()
        }
        Version::V3 => do_pull_v3(&ctx, &addr, &rt)?.into(),
        Version::V4 => do_pull_v4(&ctx, &addr, &rt)?,
    };

    // A multicast-capable peer's pull response carries its complete
    // advertisable multicast set, so an imported multicast route from this
    // peer that is absent from the response indicates a withdraw we missed.
    // Therefore, we synthesize withdraws for the absentee vectors so that the
    // periodic pull repairs subtractive as well as additive drift.
    //
    // Underlay and tunnel imports keep their push-only withdraw semantics.
    // Multicast reconciliation matters more because a stale import holds a
    // DPD replication member. Reconciliation applies only to peers that
    // negotiated wire protocol version 4 or later, the first version to
    // carry multicast. An earlier response has no multicast half, and its
    // converted empty set must not be read as a full withdraw.
    let mcast_withdraw: HashSet<MulticastPathVector> = if version < Version::V4
    {
        HashSet::new()
    } else {
        let announced: HashSet<MulticastOrigin> = pr
            .multicast
            .iter()
            .flatten()
            .filter_map(|pv| MulticastOrigin::try_from(&pv.origin).ok())
            .collect();
        ctx.db
            .imported_mcast()
            .iter()
            .filter(|route| {
                route.nexthop == addr && !announced.contains(&route.origin)
            })
            .map(|route| MulticastPathVector {
                origin: (&route.origin).into(),
                path: Vec::new(),
            })
            .collect()
    };

    let mut update = Update::announce(pr);
    if !mcast_withdraw.is_empty() {
        dbg!(
            log,
            ctx.config.if_name,
            "pull reconcile: withdrawing {} stale multicast routes",
            mcast_withdraw.len(),
        );
        match update.multicast.as_mut() {
            Some(m) => m.withdraw = mcast_withdraw,
            None => {
                update.multicast =
                    Some(MulticastUpdate::withdraw(mcast_withdraw))
            }
        }
    }

    let handler = HandlerContext {
        ctx,
        peer: addr,
        log,
    };
    handle_update(&update, &handler, mode);

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
    // The update arrives in the latest wire form. Downconvert through
    // consecutive versions when a peer negotiated an older protocol.
    // Conversion drops content the peer's version cannot represent (multicast
    // did not exist before V4, for example), so the downconverted form can
    // be empty. We skip the send in that case rather than emit an empty
    // payload.
    let (payload, path) = match version {
        Version::V2 => {
            let update = v2::Update::from(v3::Update::from(update));
            if update.underlay.is_none() && update.tunnel.is_none() {
                return Ok(());
            }
            (serde_json::to_string(&update)?, "v2")
        }
        Version::V3 => {
            let update = v3::Update::from(update);
            if update.underlay.is_none() && update.tunnel.is_none() {
                return Ok(());
            }
            (serde_json::to_string(&update)?, "v3")
        }
        Version::V4 => (serde_json::to_string(&update)?, "v4"),
    };
    ctx.stats.updates_sent.fetch_add(1, Ordering::Relaxed);
    let if_index = config.if_index;
    let port = config.exchange_port;
    let uri = format!("http://[{addr}%{if_index}]:{port}/{path}/push");
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

    // A completed request only counts as delivered when the peer's handler
    // reported success. Connection failures and error statuses must surface as
    // errors so the state machine can expire the peer.
    rt.block_on(async move {
        let result: Result<(), ExchangeError> = async {
            let resp =
                timeout(Duration::from_millis(config.exchange_timeout), resp)
                    .await??;
            require_success(resp)?;
            Ok(())
        }
        .await;
        if let Err(e) = &result {
            err!(log, config.if_name, "peer update to {uri} failed: {e}");
            ctx.stats.update_send_fail.fetch_add(1, Ordering::Relaxed);
        }
        result
    })
}

pub fn handler(
    ctx: SmContext,
    addr: Ipv6Addr,
    peer: Ipv6Addr,
    log: Logger,
) -> Result<ExchangeHandle, String> {
    let context = Arc::new(Mutex::new(HandlerContext {
        ctx: ctx.clone(),
        log: log.clone(),
        peer,
    }));
    let handler_ctx = Arc::clone(&context);

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

    let thread = ctx.rt.spawn(async move {
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
    });

    Ok(ExchangeHandle {
        thread,
        context: handler_ctx,
    })
}

pub fn api_description() -> Result<
    ApiDescription<Arc<Mutex<HandlerContext>>>,
    ApiDescriptionRegisterError,
> {
    let mut api = ApiDescription::new();
    api.register(push_handler_v2)?;
    api.register(push_handler_v3)?;
    api.register(push_handler_v4)?;
    api.register(pull_handler_v2)?;
    api.register(pull_handler_v3)?;
    api.register(pull_handler_v4)?;
    Ok(api)
}

#[endpoint {
    method = PUT,
    path = "/v2/push",
}]
async fn push_handler_v2(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<v2::Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let update_v2 = request.into_inner();
    let update = Update::from(v3::Update::from(update_v2));
    push_handler_common(ctx, update).await
}

#[endpoint { method = PUT, path = "/v3/push" }]
async fn push_handler_v3(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<v3::Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let update = Update::from(request.into_inner());
    push_handler_common(ctx, update).await
}

#[endpoint { method = PUT, path = "/v4/push" }]
async fn push_handler_v4(
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
        handle_update(&update, &ctx, UpdateMode::Redistribute);
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
            let mut path_vector = PathVector {
                destination: route.destination,
                path: route.path.clone(),
            };
            path_vector.path.push(ctx.ctx.hostname.clone());
            underlay.insert(path_vector);
        }
        for route in &ctx.ctx.db.imported_tunnel() {
            if route.nexthop == ctx.peer {
                continue;
            }
            tunnel.insert(route.origin);
        }
    }
    let originated = ctx
        .ctx
        .db
        .originated()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    for prefix in &originated {
        let path_vector = PathVector {
            destination: *prefix,
            path: vec![ctx.ctx.hostname.clone()],
        };
        underlay.insert(path_vector);
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

/// Collect underlay and tunnel routes for pull responses (shared by V3/V4).
fn collect_underlay_tunnel(
    ctx: &HandlerContext,
) -> Result<(HashSet<PathVector>, HashSet<TunnelOrigin>), HttpError> {
    let mut underlay = HashSet::new();
    let mut tunnel = HashSet::new();

    if ctx.ctx.config.kind == RouterKind::Transit {
        for route in &ctx.ctx.db.imported() {
            if route.nexthop == ctx.peer {
                continue;
            }
            let mut path_vector = PathVector {
                destination: route.destination,
                path: route.path.clone(),
            };
            path_vector.path.push(ctx.ctx.hostname.clone());
            underlay.insert(path_vector);
        }
        for route in &ctx.ctx.db.imported_tunnel() {
            if route.nexthop == ctx.peer {
                continue;
            }
            tunnel.insert(route.origin);
        }
    }

    let originated = ctx
        .ctx
        .db
        .originated()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    for prefix in &originated {
        underlay.insert(PathVector {
            destination: *prefix,
            path: vec![ctx.ctx.hostname.clone()],
        });
    }

    let originated_tunnel = ctx
        .ctx
        .db
        .originated_tunnel()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    for prefix in &originated_tunnel {
        tunnel.insert(TunnelOrigin {
            overlay_prefix: prefix.overlay_prefix,
            boundary_addr: prefix.boundary_addr,
            vni: prefix.vni,
            metric: prefix.metric,
        });
    }

    Ok((underlay, tunnel))
}

/// Collect multicast routes for V4 pull responses.
fn collect_multicast(
    ctx: &HandlerContext,
) -> Result<HashSet<MulticastPathVector>, HttpError> {
    let mut multicast = HashSet::new();

    if ctx.ctx.config.kind == RouterKind::Transit {
        for route in &ctx.ctx.db.imported_mcast() {
            if route.nexthop == ctx.peer {
                continue;
            }
            let hop = MulticastPathHop::new(
                ctx.ctx.hostname.clone(),
                ctx.ctx.config.addr,
            );
            let mut path = route.path.clone();
            path.push(hop);
            multicast.insert(MulticastPathVector {
                origin: (&route.origin).into(),
                path,
            });
        }
    }

    let originated_mcast = ctx
        .ctx
        .db
        .originated_mcast()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    for origin in &originated_mcast {
        let hop = MulticastPathHop::new(
            ctx.ctx.hostname.clone(),
            ctx.ctx.config.addr,
        );
        multicast.insert(MulticastPathVector {
            origin: origin.into(),
            path: vec![hop],
        });
    }

    Ok(multicast)
}

#[endpoint { method = GET, path = "/v3/pull" }]
async fn pull_handler_v3(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<v3::PullResponse>, HttpError> {
    let ctx = ctx.context().lock().await.clone();
    let (underlay, tunnel) = collect_underlay_tunnel(&ctx)?;
    Ok(HttpResponseOk(v3::PullResponse {
        underlay: crate::non_empty(underlay),
        tunnel: crate::non_empty(tunnel),
    }))
}

#[endpoint { method = GET, path = "/v4/pull" }]
async fn pull_handler_v4(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<PullResponse>, HttpError> {
    let ctx = ctx.context().lock().await.clone();
    let (underlay, tunnel) = collect_underlay_tunnel(&ctx)?;
    let multicast = collect_multicast(&ctx)?;
    Ok(HttpResponseOk(PullResponse {
        underlay: crate::non_empty(underlay),
        tunnel: crate::non_empty(tunnel),
        multicast: crate::non_empty(multicast),
    }))
}

fn handle_update(update: &Update, ctx: &HandlerContext, mode: UpdateMode) {
    ctx.ctx
        .stats
        .updates_received
        .fetch_add(1, Ordering::Relaxed);

    // Route application and peer cleanup take the same per-interface lock.
    // This lets discovery publish identity and liveness changes without
    // waiting for DPD, OPTE, or datastore work below. Once the lock is held,
    // a brief identity check rejects an update whose peer has already expired
    // or renumbered. Otherwise, the subsequent cleanup waits and removes
    // anything this update imports.
    let _route_update = lock!(ctx.ctx.iface.route_update);
    let current_peer = lock!(ctx.ctx.iface.peer_identity)
        .as_ref()
        .map(|peer| peer.addr);
    if current_peer != Some(ctx.peer) {
        inf!(
            ctx.log,
            ctx.ctx.config.if_name,
            "discarding update from stale peer {}",
            ctx.peer,
        );
        return;
    }

    if let Some(underlay_update) = &update.underlay {
        handle_underlay_update(underlay_update, ctx);
    }

    if let Some(tunnel_update) = &update.tunnel {
        handle_tunnel_update(tunnel_update, ctx);
    }

    // Only transit routers redistribute, so demote the mode on a server
    // before it reaches the multicast handler. Only the redistribution path
    // reconciles against a reachability snapshot, so only it pays for
    // capturing one.
    let mode = if ctx.ctx.config.kind == RouterKind::Transit {
        mode
    } else {
        UpdateMode::ImportOnly
    };
    let mcast_reachability = update
        .multicast
        .as_ref()
        .and_then(|mu| handle_multicast_update(mu, ctx, mode));

    // Event delivery from different interfaces is intentionally not globally
    // ordered. A reversed pair can expose an older multicast view until the
    // next successful V4 pull, whose complete response repairs missing and
    // stale imports. This avoids a global lock on every multicast change.
    if mode == UpdateMode::Redistribute {
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

        // Multicast loop prevention is asymmetric with the underlay. The
        // underlay filters on send, skipping any route whose nexthop is the
        // destination peer. Multicast drops, on receipt, any
        // announcement whose path already carries our router_id. The path
        // check is required because a replacement announcement goes to every
        // peer, so a peer can appear mid-path rather than as the nexthop,
        // and paths can cross several transits, forming loops longer than
        // the immediate echo.
        //
        // The same filter applies here before redistributing. A peer already
        // in a vector's path would drop it anyway, but a peer that is not
        // would import a looped path.
        let hostname = &ctx.ctx.hostname;

        // The snapshot came from the `handle_multicast_update` modification, so
        // reconciliation reads state consistent with the local application.
        let multicast =
            update
                .multicast
                .as_ref()
                .zip(mcast_reachability.as_ref())
                .map(|(update, reachability)| {
                    let hop = MulticastPathHop::new(
                        hostname.clone(),
                        ctx.ctx.config.addr,
                    );

                    let is_loop_free = |path_vector: &&MulticastPathVector| {
                        !path_vector
                            .path
                            .iter()
                            .any(|hop| &hop.router_id == hostname)
                    };

                    let mut reconciled = reconcile_multicast_withdrawals(
                        update.withdraw.iter().filter(is_loop_free),
                        reachability,
                        &hop,
                    );
                    reconciled.announce.extend(
                        update.announce.iter().filter(is_loop_free).map(
                            |path_vector| path_vector.with_hop(hop.clone()),
                        ),
                    );
                    reconciled
                });

        let push = Arc::new(Update {
            underlay,
            tunnel: update.tunnel.clone(),
            multicast,
        });

        for ec in &ctx.ctx.event_channels {
            if let Err(e) =
                ec.send(Event::Peer(PeerEvent::Push(Arc::clone(&push))))
            {
                err!(
                    ctx.log,
                    ctx.ctx.config.if_name,
                    "deliver redistributed update: {e}",
                );
            }
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

fn handle_multicast_update(
    update: &MulticastUpdate,
    ctx: &HandlerContext,
    mode: UpdateMode,
) -> Option<crate::db::MulticastReachability> {
    let db = &ctx.ctx.db;
    let hostname = &ctx.ctx.hostname;

    let mut import = HashSet::new();
    let mut remove = HashSet::new();
    // A replacement is broadcast to every peer, including peers already in
    // its path. For such a peer, the looped announce implicitly invalidates
    // its old route through the sender. A clean vector for the same
    // `(origin, peer)` in this update takes precedence.
    for path_vector in &update.announce {
        // Promote the wire origin to the validated form. Peer-supplied routes
        // are otherwise trusted, but the underlay group reaches DPD directly,
        // so a promotion enforces its ff04::/64 invariant (and the VNI range)
        // before the route can be stored. An invalid origin is dropped rather
        // than tracking a group DPD would refuse to program.
        let origin = match MulticastOrigin::try_from(&path_vector.origin) {
            Ok(origin) => origin,
            Err(e) => {
                wrn!(
                    ctx.log,
                    ctx.ctx.config.if_name,
                    "dropping multicast announce for {}; {e}",
                    path_vector.origin.overlay_group,
                );
                continue;
            }
        };

        let route = MulticastRoute {
            origin,
            nexthop: ctx.peer,
            path: path_vector.path.clone(),
        };
        if path_vector
            .path
            .iter()
            .any(|hop| &hop.router_id == hostname)
        {
            if !import.contains(&route) {
                dbg!(
                    ctx.log,
                    ctx.ctx.config.if_name,
                    "removing multicast route for {} via {}; \
                     looped announce (path length {})",
                    path_vector.origin.overlay_group,
                    ctx.peer,
                    path_vector.path.len(),
                );
                remove.insert(route);
            }
        } else {
            // This also cancels an implicit removal if a looped vector for
            // the same route appeared earlier in the unordered announce set.
            remove.remove(&route);
            import.insert(route);
        }
    }

    for path_vector in &update.withdraw {
        // A withdrawal whose path already contains this router is an echo of
        // a local redistribution and must not be acted on.
        if path_vector
            .path
            .iter()
            .any(|hop| &hop.router_id == hostname)
        {
            trc!(
                ctx.log,
                ctx.ctx.config.if_name,
                "dropping multicast withdraw for {}; loop detected \
                 (path length {})",
                path_vector.origin.overlay_group,
                path_vector.path.len(),
            );
            continue;
        }

        // A withdraw carrying an invalid origin cannot match a stored route,
        // since storage only admits promoted origins, so drop it here too.
        let origin = match MulticastOrigin::try_from(&path_vector.origin) {
            Ok(origin) => origin,
            Err(e) => {
                wrn!(
                    ctx.log,
                    ctx.ctx.config.if_name,
                    "dropping multicast withdraw for {}; {e}",
                    path_vector.origin.overlay_group,
                );
                continue;
            }
        };

        // Route identity is (origin, nexthop), so an empty path matches.
        remove.insert(MulticastRoute {
            origin,
            nexthop: ctx.peer,
            path: Vec::new(),
        });
    }

    // Atomic import + delete + diff under a single lock. The redistribution
    // path also reconciles against a post-modification reachability snapshot,
    // captured under that same lock scope.
    let (delta, reachability) = match mode {
        UpdateMode::Redistribute => {
            let (delta, reachability) =
                db.update_imported_mcast_with_reachability(&import, &remove);
            (delta, Some(reachability))
        }
        UpdateMode::ImportOnly => {
            (db.update_imported_mcast(&import, &remove), None)
        }
    };

    // Notify the multicast sweep of each affected underlay group so it
    // reconciles the group's DPD members. Only the sweep writes to DPD.
    //
    // This handler records the import and signals, deriving the notification
    // from the effective diff rather than the requested sets avoids waking the
    // sweep for routes that were already present or already absent.
    crate::mcast::notify_affected_groups(
        delta.added.iter().chain(delta.removed.iter()),
        &ctx.ctx.mcast_notify,
    );

    reachability
}
