// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HTTP route exchange, DB updates, and route programming.
//! Requires illumos for [`crate::sys`].

use super::{ExchangeError, UpdateMode};
use crate::db::{Route, effective_route_set};
use crate::discovery::Version;
use crate::sm::{Config, Event, ExchangeSession, PeerEvent, SmContext};
use crate::{dbg, err, inf, wrn};
use ddm_api_types::db::{RouterKind, TunnelRoute};
use ddm_protocol::v3::{PathVector, TunnelOrigin};
use ddm_protocol::v4::{
    MulticastOrigin, MulticastPathVector, MulticastUpdate, PullResponse, Update,
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
use http_body_util::{BodyExt, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use mg_common::lock;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{Logger, o};
use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::time::timeout;

mod mcast;

pub(crate) use mcast::{announce_multicast, withdraw_multicast};
use mcast::{
    apply_multicast_update, collect_multicast, partition_multicast_update,
};

const UNIT_EXCHANGE_SERVER: &str = "exchange_server";

/// Body cap for exchange push requests at all protocol versions.
///
/// Oversized pushes are rejected. Periodic pulls repair missed multicast
/// updates.
pub(crate) const MAX_EXCHANGE_BODY_BYTES: usize = 1024 * 1024;

/// Body cap for pull responses at all protocol versions.
///
/// A pull returns the peer's full snapshot in a single response, so the cap is
/// sized well above the push limit.
const MAX_PULL_BODY_BYTES: usize = 64 * 1024 * 1024;

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    JsonSchema,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
enum PullSections {
    #[default]
    All,
    /// Disregard underlay and tunnel sections, as periodic resyncs repair only
    /// the multicast section.
    Multicast,
}

/// Query parameters for a pull at V4 and later.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    JsonSchema,
    Serialize,
    Deserialize,
)]
struct PullScanParams {
    #[serde(default)]
    sections: PullSections,
}

/// Query selecting [`PullSections::Multicast`].
const MULTICAST_ONLY_QUERY: &str = "sections=multicast";

#[derive(Clone)]
pub struct HandlerContext {
    ctx: SmContext,
    peer: Ipv6Addr,
    session: Arc<ExchangeSession>,
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
    push_update(ctx, config, update.into(), addr, version, rt, log)
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
    let update = v3::TunnelUpdate::announce(endpoints);
    push_update(ctx, config, update.into(), addr, version, rt, log)
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
    push_update(ctx, config, update.into(), addr, version, rt, log)
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
    let update = v3::TunnelUpdate::withdraw(endpoints);
    push_update(ctx, config, update.into(), addr, version, rt, log)
}

/// Fetch the peer's full snapshot at `version`, converted to the latest
/// [`PullResponse`].
///
/// At V4 and later, `multicast_only` asks the peer to leave out the underlay
/// and tunnel sections. Earlier versions always return the full set.
fn do_pull(
    ctx: &SmContext,
    addr: &Ipv6Addr,
    version: Version,
    rt: &Arc<tokio::runtime::Handle>,
    multicast_only: bool,
) -> Result<PullResponse, ExchangeError> {
    let if_index = ctx.config.if_index;
    let port = ctx.config.exchange_port;
    let timeout = ctx.config.exchange_timeout;
    let path = match version {
        Version::V2 => "v2",
        Version::V3 => "v3",
        Version::V4 => "v4",
    };
    let mut uri = format!("http://[{addr}%{if_index}]:{port}/{path}/pull");
    if version >= Version::V4 && multicast_only {
        uri = format!("{uri}?{MULTICAST_ONLY_QUERY}");
    }

    let body = fetch_pull_body(uri, timeout, MAX_PULL_BODY_BYTES, rt)?;

    Ok(match version {
        Version::V2 => v3::PullResponse::from(serde_json::from_slice::<
            v2::PullResponse,
        >(&body)?)
        .into(),
        Version::V3 => {
            serde_json::from_slice::<v3::PullResponse>(&body)?.into()
        }
        Version::V4 => {
            let (pr, dropped) = decode_v4_pull(&body)?;
            if let Some(e) = dropped.first() {
                wrn!(
                    ctx.log,
                    ctx.config.if_name,
                    "exchange pull: dropped {} invalid multicast entries, \
                     first: {e}",
                    dropped.len(),
                );
            }
            pr
        }
    })
}

/// A V4 pull response with each multicast entry left undecoded.
#[derive(Deserialize)]
struct V4PullEntries {
    underlay: Option<HashSet<v3::PathVector>>,
    tunnel: Option<HashSet<v3::TunnelOrigin>>,
    multicast: Option<Vec<serde_json::Value>>,
}

/// Decode a V4 pull response, dropping multicast entries that fail to decode.
///
/// Without this, one invalid origin would fail the entire response and block
/// the peer's underlay and tunnel imports.
///
/// Returns the response along with the errors for any dropped entries.
///
/// # Errors
///
/// Returns an error if the body or its underlay or tunnel sections fail to
/// decode.
fn decode_v4_pull(
    body: &[u8],
) -> Result<(PullResponse, Vec<serde_json::Error>), serde_json::Error> {
    let entries: V4PullEntries = serde_json::from_slice(body)?;
    let mut dropped = Vec::new();
    let multicast = entries.multicast.map(|values| {
        values
            .into_iter()
            .filter_map(|v| {
                serde_json::from_value::<MulticastPathVector>(v)
                    .map_err(|e| dropped.push(e))
                    .ok()
            })
            .collect()
    });
    let pr = PullResponse {
        underlay: entries.underlay,
        tunnel: entries.tunnel,
        multicast,
    };
    Ok((pr, dropped))
}

/// Check that the exchange server at `addr` responds without reading the
/// response body.
///
/// Any HTTP status counts as being up.
///
/// The startup check waits for response headers. The pull worker handles
/// body reads and decoding.
pub(crate) fn probe_exchange_server(
    ctx: &SmContext,
    addr: &Ipv6Addr,
    version: Version,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<(), ExchangeError> {
    let if_index = ctx.config.if_index;
    let port = ctx.config.exchange_port;
    let path = match version {
        Version::V2 => "v2",
        Version::V3 => "v3",
        Version::V4 => "v4",
    };
    let uri = format!("http://[{addr}%{if_index}]:{port}/{path}/pull");
    let client = Client::builder(TokioExecutor::new()).build_http();
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri)
        .body(http_body_util::Empty::<Bytes>::new())
        .map_err(|e| ExchangeError::InvalidUri(e.to_string()))?;
    rt.block_on(async move {
        timeout(ctx.config.exchange_timeout, client.request(req)).await??;
        Ok(())
    })
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
/// Check the status before decoding. V4's optional fields can otherwise allow
/// a JSON error response to be decoded as an empty route set.
fn fetch_pull_body(
    uri: String,
    timeout_dur: Duration,
    limit: usize,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<Bytes, ExchangeError> {
    let client = Client::builder(TokioExecutor::new()).build_http();

    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri)
        .body(http_body_util::Empty::<Bytes>::new())
        .map_err(|e| ExchangeError::InvalidUri(e.to_string()))?;

    let resp = client.request(req);

    // Include body reads in the timeout b/c a peer can stall after headers.
    rt.block_on(async move {
        timeout(timeout_dur, async {
            let resp = require_success(resp.await?)?;
            Limited::new(resp.into_body(), limit)
                .collect()
                .await
                .map(|b| b.to_bytes())
                .map_err(|e| match e.downcast::<hyper::Error>() {
                    Ok(e) => ExchangeError::Hyper(*e),
                    Err(_) => ExchangeError::ResponseTooLarge { limit },
                })
        })
        .await?
    })
}

/// Pull the peer's routes and import them all.
///
/// Initial and admin pulls import all sections and redistribute on transit
/// routers. Periodic pulls import only multicast and do not redistribute.
/// Other peers learn these routes through their own pulls. A periodic pull
/// asks the peer to disregard the underlay and tunnel sections, ensuring
/// that a resync does not transfer or reprogram unmodified unicast routes.
///
/// Withdrawals are synthesized only after the complete snapshot has been
/// imported. A failed pull imports nothing and synthesizes no withdrawals.
///
/// `started_at` is the cutoff for this pull. A route updated during the read
/// stays out of stale-route removal, including a refresh after the scan.
///
/// Underlay and tunnel withdrawals remain push-only at every version.
pub(crate) fn pull(
    ctx: &SmContext,
    addr: Ipv6Addr,
    session: &Arc<ExchangeSession>,
    rt: Arc<tokio::runtime::Handle>,
    stop: Arc<AtomicBool>,
    mode: UpdateMode,
) -> Result<(), ExchangeError> {
    let version = session.version;
    let started_at = ctx.db.next_mcast_seq();

    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    let multicast_only = mode == UpdateMode::ImportOnly;
    let mut pr = do_pull(ctx, &addr, version, &rt, multicast_only)?;
    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }
    if multicast_only {
        pr.underlay = None;
        pr.tunnel = None;
    }

    let update = Update::announce(pr);
    handle_update(&update, ctx, addr, mode, None, session);
    let announced: HashSet<MulticastOrigin> = update
        .multicast
        .into_iter()
        .flat_map(|multicast| multicast.announce)
        .map(|pv| pv.origin)
        .collect();

    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    let withdraw: HashSet<MulticastPathVector> = ctx
        .db
        .stale_mcast_by_nexthop(addr, started_at, &announced)
        .into_iter()
        .map(|origin| MulticastPathVector {
            origin,
            path: Vec::new(),
        })
        .collect();

    if !withdraw.is_empty() {
        dbg!(
            ctx.log,
            ctx.config.if_name,
            "pull reconcile: withdrawing {} stale multicast routes",
            withdraw.len(),
        );
        handle_update(
            &MulticastUpdate::withdraw(withdraw).into(),
            ctx,
            addr,
            mode,
            Some(started_at),
            session,
        );
    }

    Ok(())
}

/// Serialize `update` for `version` and push it to `addr`.
///
/// `update` is the latest [`Update`] and is downconverted through each
/// intermediate version. Any section the peer's version cannot convey is
/// dropped outright, and an update left empty by that is never sent.
///
/// Each new wire version must add an arm here and in [`do_pull`].
fn push_update(
    ctx: &SmContext,
    config: Config,
    update: Update,
    addr: Ipv6Addr,
    version: Version,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
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
        Version::V4 => {
            let payload = serde_json::to_string(&update)?;
            // TODO: chunk pushes under the peer's body limit (1 MiB at V4,
            // or Dropshot's default 1 KiB on previous builds) so that oversized
            // updates arrive without error (client refused or 413'd). Unicast
            // has no periodic pull to repair a dropped push.
            if update.multicast.is_some()
                && payload.len() > MAX_EXCHANGE_BODY_BYTES
            {
                return Err(ExchangeError::MulticastUpdateTooLarge {
                    size: payload.len(),
                    limit: MAX_EXCHANGE_BODY_BYTES,
                });
            }
            (payload, "v4")
        }
    };

    ctx.stats.updates_sent.fetch_add(1, Ordering::Relaxed);
    let if_index = config.if_index;
    let port = config.exchange_port;
    let uri = format!("http://[{addr}%{if_index}]:{port}/{path}/push");
    put_update(ctx, uri, payload, config, rt, log)
}

fn put_update(
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
        let res = async {
            let resp = timeout(config.exchange_timeout, resp).await??;
            require_success(resp).map(drop)
        }
        .await;
        let Err(e) = res else {
            return Ok(());
        };
        err!(log, config.if_name, "peer update to {uri} failed: {e}");
        ctx.stats.update_send_fail.fetch_add(1, Ordering::Relaxed);
        match e {
            ExchangeError::Timeout(_) => Err(e),
            _ => Ok(()),
        }
    })
}

pub fn handler(
    ctx: SmContext,
    addr: Ipv6Addr,
    peer: Ipv6Addr,
    session: Arc<ExchangeSession>,
    log: Logger,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let context = Arc::new(HandlerContext {
        ctx: ctx.clone(),
        peer,
        session,
    });

    let socket_addr = SocketAddrV6::new(addr, ctx.config.exchange_port, 0, 0);

    let config = ConfigDropshot {
        bind_address: socket_addr.into(),
        // Dropshot's default request body cap is 1 KiB, which is too small for
        // multicast updates.
        default_request_body_max_bytes: MAX_EXCHANGE_BODY_BYTES,
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

    inf!(
        log,
        ctx.config.if_name,
        "exchange: listening on {socket_addr}"
    );

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

pub fn api_description()
-> Result<ApiDescription<Arc<HandlerContext>>, ApiDescriptionRegisterError> {
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
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<v2::Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let update_v2 = request.into_inner();
    let update = Update::from(v3::Update::from(update_v2));
    push_handler_common(ctx, update).await
}

#[endpoint {
    method = PUT,
    path = "/v3/push",
}]
async fn push_handler_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<v3::Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let update = Update::from(request.into_inner());
    push_handler_common(ctx, update).await
}

#[endpoint {
    method = PUT,
    path = "/v4/push",
}]
async fn push_handler_v4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let update = request.into_inner();
    push_handler_common(ctx, update).await
}

async fn push_handler_common(
    ctx: RequestContext<Arc<HandlerContext>>,
    update: Update,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().clone();
    let session = ctx.session.clone();
    if update.multicast.is_some() && session.version < Version::V4 {
        return Err(HttpError::for_bad_request(
            None,
            "multicast exchange requires a V4 peer".into(),
        ));
    }

    // TODO: A panic in `handle_update` returns a 500 and leaves the session
    // up with only a partially applied update. Only the pull worker requests
    // expiry on panic. However, unicast does not sync over periodic pulls to
    // repair partial failures, which means a push should probably also
    // request expiry, by way of an event tied to the `ExchangeSession`
    // instead of the pull worker's stop flag.
    tokio::task::spawn_blocking(move || {
        handle_update(
            &update,
            &ctx.ctx,
            ctx.peer,
            UpdateMode::Redistribute,
            None,
            &session,
        );
    })
    .await
    .map_err(|e| {
        HttpError::for_internal_error(format!("spawn update thread {e}"))
    })?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint {
    method = GET,
    path = "/v2/pull",
}]
async fn pull_handler_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<v2::PullResponse>, HttpError> {
    let (underlay, tunnel) = collect_underlay_tunnel(ctx.context())?;
    Ok(HttpResponseOk(v2::PullResponse {
        underlay: non_empty(underlay)
            .map(|s| s.into_iter().map(v2::PathVector::from).collect()),
        tunnel: non_empty(tunnel)
            .map(|s| s.into_iter().map(v2::TunnelOrigin::from).collect()),
    }))
}

fn non_empty<T>(set: HashSet<T>) -> Option<HashSet<T>> {
    (!set.is_empty()).then_some(set)
}

/// Collect underlay and tunnel routes for pull responses.
fn collect_underlay_tunnel(
    ctx: &HandlerContext,
) -> Result<(HashSet<PathVector>, HashSet<TunnelOrigin>), HttpError> {
    let mut underlay = HashSet::new();
    let mut tunnel = HashSet::new();

    // Only transit routers redistribute prefixes
    if ctx.ctx.config.kind == RouterKind::Transit {
        underlay.extend(
            // don't redistribute prefixes to their originators
            ctx.ctx
                .db
                .imported()
                .into_iter()
                .filter(|route| route.nexthop != ctx.peer)
                .map(|route| {
                    let mut pv = PathVector {
                        destination: route.destination,
                        path: route.path,
                    };
                    pv.path.push(ctx.ctx.router_id.to_string());
                    pv
                }),
        );
        tunnel.extend(
            ctx.ctx
                .db
                .imported_tunnel()
                .into_iter()
                .filter(|route| route.nexthop != ctx.peer)
                .map(|route| route.origin),
        );
    }

    let originated = ctx
        .ctx
        .db
        .originated()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    underlay.extend(originated.into_iter().map(|dst| PathVector {
        destination: dst,
        path: vec![ctx.ctx.router_id.to_string()],
    }));

    let originated_tunnel = ctx
        .ctx
        .db
        .originated_tunnel()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    tunnel.extend(originated_tunnel);

    Ok((underlay, tunnel))
}

#[endpoint {
    method = GET,
    path = "/v3/pull",
}]
async fn pull_handler_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<v3::PullResponse>, HttpError> {
    let (underlay, tunnel) = collect_underlay_tunnel(ctx.context())?;
    Ok(HttpResponseOk(v3::PullResponse {
        underlay: non_empty(underlay),
        tunnel: non_empty(tunnel),
    }))
}

#[endpoint {
    method = GET,
    path = "/v4/pull",
}]
async fn pull_handler_v4(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: dropshot::Query<PullScanParams>,
) -> Result<HttpResponseOk<PullResponse>, HttpError> {
    let scan = query.into_inner();
    let ctx = ctx.context();

    let (underlay, tunnel) = if scan.sections == PullSections::All {
        collect_underlay_tunnel(ctx)?
    } else {
        (HashSet::new(), HashSet::new())
    };

    Ok(HttpResponseOk(PullResponse {
        underlay: non_empty(underlay),
        tunnel: non_empty(tunnel),
        multicast: non_empty(collect_multicast(ctx)?),
    }))
}

/// Apply a peer update and queue redistribution on transit routers.
fn handle_update(
    update: &Update,
    ctx: &SmContext,
    peer_addr: Ipv6Addr,
    mode: UpdateMode,
    imported_before: Option<u64>,
    session: &Arc<ExchangeSession>,
) {
    ctx.stats.updates_received.fetch_add(1, Ordering::Relaxed);

    let underlay_change = update.underlay.as_ref().map(|underlay_update| {
        prepare_underlay_update(underlay_update, ctx, peer_addr)
    });
    let tunnel_change = update
        .tunnel
        .as_ref()
        .map(|tunnel_update| prepare_tunnel_update(tunnel_update, peer_addr));
    let mcast_change = update.multicast.as_ref().map(|multicast_update| {
        partition_multicast_update(
            multicast_update,
            &ctx.router_id,
            peer_addr,
            &ctx.log,
            &ctx.config.if_name,
        )
    });

    // Server imports skip redistribution.
    let mode = if ctx.config.kind == RouterKind::Transit {
        mode
    } else {
        UpdateMode::ImportOnly
    };

    let unicast_redistribute = (mode == UpdateMode::Redistribute)
        .then(|| (update.underlay.clone(), update.tunnel.clone()));

    let current_session = ctx.iface.session();
    let current_peer = lock!(ctx.iface.peer_identity)
        .as_ref()
        .map(|peer| peer.addr);
    // Compare session identity even when the negotiated version is unchanged.
    if current_peer != Some(peer_addr)
        || session.is_canceled()
        || !current_session
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, session))
    {
        inf!(
            ctx.log,
            ctx.config.if_name,
            "discarding update from stale peer {peer_addr}",
        );
        return;
    }

    let _update_guard = session.update_guard();
    let underlay_change =
        underlay_change.map(|change| import_underlay_update(change, ctx));
    let tunnel_change =
        tunnel_change.map(|change| import_tunnel_update(change, ctx));
    let mcast_applied = mcast_change.map(|(import, remove)| {
        apply_multicast_update(ctx, import, &remove, imported_before)
    });
    drop(current_session);

    if let Some(change) = underlay_change {
        apply_underlay_update(change, ctx, session);
    }

    if let Some(change) = tunnel_change {
        apply_tunnel_update(change, ctx, session);
    }

    // Redistribute after installing, ensuring that peers do not learn new
    // routes before this router can forward them.
    if let Some((underlay, tunnel)) = unicast_redistribute {
        // Defer reconciliation until a dequeue in order to use a current path
        // snapshot.
        //
        // This state machine handles underlay loop checks specifically.
        let multicast = mcast_applied.map(MulticastUpdate::from).filter(
            |multicast_update| {
                !multicast_update.announce.is_empty()
                    || !multicast_update.withdraw.is_empty()
            },
        );

        let mut redistribute = Update {
            underlay,
            tunnel,
            multicast,
        };

        if session.is_canceled() {
            redistribute = redistribute.withdrawals_only();
            if redistribute.is_empty() {
                return;
            }
        }

        if let Err(e) = ctx.tx.send(Event::Peer(PeerEvent::Redistribute {
            update: Arc::new(redistribute),
            session: session.clone(),
            peer: peer_addr,
        })) {
            wrn!(
                ctx.log,
                ctx.config.if_name,
                "failed to send update to SM: {e:?}"
            );
        }
    }
}

struct TunnelChange {
    import: HashSet<TunnelRoute>,
    remove: HashSet<TunnelRoute>,
}

fn prepare_tunnel_update(
    update: &v3::TunnelUpdate,
    peer_addr: Ipv6Addr,
) -> TunnelChange {
    let import = update
        .announce
        .iter()
        .copied()
        .map(|origin| TunnelRoute {
            origin,
            nexthop: peer_addr,
        })
        .collect();
    let remove = update
        .withdraw
        .iter()
        .copied()
        .map(|origin| TunnelRoute {
            origin,
            nexthop: peer_addr,
        })
        .collect();

    TunnelChange { import, remove }
}

struct TunnelForwardingChange {
    add: HashSet<TunnelRoute>,
    remove: HashSet<TunnelRoute>,
}

fn import_tunnel_update(
    change: TunnelChange,
    ctx: &SmContext,
) -> TunnelForwardingChange {
    let TunnelChange { import, remove } = change;
    let db = &ctx.db;

    let before = effective_route_set(&db.imported_tunnel());
    db.import_tunnel(&import);
    db.delete_import_tunnel(&remove);

    let after = effective_route_set(&db.imported_tunnel());

    ctx.stats
        .imported_underlay_prefixes
        .store(db.imported_tunnel_count() as u64, Ordering::Relaxed);

    TunnelForwardingChange {
        add: after.difference(&before).copied().collect(),
        remove: before.difference(&after).copied().collect(),
    }
}

fn apply_tunnel_update(
    change: TunnelForwardingChange,
    ctx: &SmContext,
    session: &ExchangeSession,
) {
    let TunnelForwardingChange { add, remove } = change;
    if let Err(e) = crate::sys::add_tunnel_routes(
        &ctx.log,
        &ctx.config.if_name,
        &add,
        session.canceled(),
    ) {
        err!(
            ctx.log,
            ctx.config.if_name,
            "add tunnel routes: {e}: {:#?}",
            add,
        )
    }

    if let Err(e) =
        crate::sys::remove_tunnel_routes(&ctx.log, &ctx.config.if_name, &remove)
    {
        err!(
            ctx.log,
            ctx.config.if_name,
            "remove tunnel routes: {e}: {:#?}",
            remove,
        )
    }
}

struct UnderlayChange {
    import: HashSet<Route>,
    add: Vec<crate::sys::Route>,
    withdraw: HashSet<Route>,
}

fn prepare_underlay_update(
    update: &v3::UnderlayUpdate,
    ctx: &SmContext,
    peer_addr: Ipv6Addr,
) -> UnderlayChange {
    let (import, add) = update
        .announce
        .iter()
        // Skip announcements with ourselves in the path e.g. path vector
        // loop breaking.
        .filter(|prefix| {
            !prefix.path.iter().any(|hop| hop == ctx.router_id.as_str())
        })
        .map(|prefix| {
            let route = Route {
                destination: prefix.destination,
                nexthop: peer_addr,
                ifname: ctx.config.if_name.clone(),
                path: prefix.path.clone(),
            };
            let mut r = crate::sys::Route::new(
                prefix.destination.addr().into(),
                prefix.destination.width(),
                peer_addr.into(),
            );
            r.ifname.clone_from(&ctx.config.if_name);
            (route, r)
        })
        .unzip();

    let withdraw = update
        .withdraw
        .iter()
        .map(|prefix| Route {
            destination: prefix.destination,
            nexthop: peer_addr,
            ifname: ctx.config.if_name.clone(),
            path: prefix.path.clone(),
        })
        .collect();

    UnderlayChange {
        import,
        add,
        withdraw,
    }
}

struct UnderlayForwardingChange {
    add: Vec<crate::sys::Route>,
    remove: Vec<crate::sys::Route>,
}

fn import_underlay_update(
    change: UnderlayChange,
    ctx: &SmContext,
) -> UnderlayForwardingChange {
    let UnderlayChange {
        import,
        add,
        withdraw,
    } = change;
    let db = &ctx.db;

    db.import(&import);
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
            r.ifname.clone_from(&ctx.config.if_name);
            del.push(r);
        }
    }

    ctx.stats
        .imported_underlay_prefixes
        .store(db.imported_count() as u64, Ordering::Relaxed);

    UnderlayForwardingChange { add, remove: del }
}

fn apply_underlay_update(
    change: UnderlayForwardingChange,
    ctx: &SmContext,
    session: &ExchangeSession,
) {
    let UnderlayForwardingChange { add, remove } = change;
    crate::sys::add_underlay_routes(
        &ctx.log,
        &ctx.config,
        add,
        &ctx.rt,
        session.canceled(),
    );
    crate::sys::remove_underlay_routes(
        &ctx.log,
        &ctx.config.if_name,
        &ctx.config.dpd,
        remove,
        &ctx.rt,
    );
}

#[cfg(test)]
mod tests {
    use super::{
        ExchangeError, HandlerContext, MAX_PULL_BODY_BYTES,
        MULTICAST_ONLY_QUERY, PullScanParams, PullSections, api_description,
        decode_v4_pull, fetch_pull_body,
    };
    use crate::db::Db;
    use crate::defaults::EXCHANGE_TIMEOUT;
    use crate::discovery::Version;
    use crate::sm::{
        Config, Event, ExchangeSession, InterfaceState, PeerIdentity,
        SessionStats, SmContext,
    };
    use ddm_api_types::db::{MulticastRoute, RouterKind};
    use ddm_api_types::net::{OverlayMulticast, UnderlayMulticastIpv6, Vni};
    use ddm_protocol::{v3, v4};
    use dropshot::test_util::TestContext;
    use dropshot::{
        ApiDescription, ConfigDropshot, HttpError, HttpResponseOk,
        RequestContext, endpoint,
    };
    use hyper::{Method, StatusCode};
    use slog::{Discard, Logger, o};
    use std::collections::HashSet;
    use std::net::Ipv6Addr;
    use std::sync::Arc;
    use std::sync::mpsc::{Receiver, channel};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::runtime::Runtime;

    #[endpoint { method = GET, path = "/unavailable" }]
    async fn pull_unavailable(
        _ctx: RequestContext<()>,
    ) -> Result<HttpResponseOk<v3::PullResponse>, HttpError> {
        Err(HttpError::for_unavail(None, "busy".into()))
    }

    #[endpoint { method = GET, path = "/slow" }]
    async fn pull_slow(
        _ctx: RequestContext<()>,
    ) -> Result<HttpResponseOk<v3::PullResponse>, HttpError> {
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(HttpResponseOk(v3::PullResponse::default()))
    }

    fn fetch(path: &str) -> Result<Vec<u8>, ExchangeError> {
        fetch_with_timeout(path, EXCHANGE_TIMEOUT)
    }

    fn fetch_with_timeout(
        path: &str,
        budget: Duration,
    ) -> Result<Vec<u8>, ExchangeError> {
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut api = ApiDescription::new();
        api.register(pull_unavailable).unwrap();
        api.register(pull_slow).unwrap();

        let log = Logger::root(Discard, o!());
        let server =
            TestContext::new(api, (), &ConfigDropshot::default(), None, log);
        let uri = format!("http://{}{path}", server.server.local_addr());
        let handle = Arc::new(rt.handle().clone());
        let res = fetch_pull_body(uri, budget, MAX_PULL_BODY_BYTES, &handle)
            .map(|b| b.to_vec());
        rt.block_on(server.teardown());
        res
    }

    #[test]
    fn slow_response_times_out() {
        let e =
            fetch_with_timeout("/slow", Duration::from_millis(50)).unwrap_err();
        assert!(matches!(e, ExchangeError::Timeout(_)), "{e}");
    }

    #[test]
    fn stalled_body_times_out() {
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();

        let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        let uri = format!("http://{}/", listener.local_addr().unwrap());
        rt.spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await.unwrap();
            sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1024\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let handle = Arc::new(rt.handle().clone());
        let e = fetch_pull_body(
            uri,
            Duration::from_millis(200),
            MAX_PULL_BODY_BYTES,
            &handle,
        )
        .unwrap_err();
        assert!(matches!(e, ExchangeError::Timeout(_)), "{e}");
    }

    fn pull_body(len: usize, limit: usize) -> Result<Vec<u8>, ExchangeError> {
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();

        let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        let uri = format!("http://{}/", listener.local_addr().unwrap());
        rt.spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await.unwrap();
            let head =
                format!("HTTP/1.1 200 OK\r\ncontent-length: {len}\r\n\r\n");
            sock.write_all(head.as_bytes()).await.unwrap();
            sock.write_all(&vec![b'x'; len]).await.unwrap();
        });

        let handle = Arc::new(rt.handle().clone());
        fetch_pull_body(uri, EXCHANGE_TIMEOUT, limit, &handle)
            .map(|b| b.to_vec())
    }

    #[test]
    fn oversized_response_is_rejected() {
        assert_eq!(pull_body(16, 16).unwrap().len(), 16);
        let e = pull_body(17, 16).unwrap_err();
        assert!(
            matches!(e, ExchangeError::ResponseTooLarge { limit: 16 }),
            "{e}"
        );
    }

    #[test]
    fn server_error_surfaces_as_status() {
        let e = fetch("/unavailable").unwrap_err();
        assert!(
            matches!(e, ExchangeError::Status(StatusCode::SERVICE_UNAVAILABLE)),
            "{e}",
        );
    }

    #[test]
    fn client_error_surfaces_as_status() {
        let e = fetch("/missing").unwrap_err();
        assert!(
            matches!(e, ExchangeError::Status(StatusCode::NOT_FOUND)),
            "{e}"
        );
    }

    const PEER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    type ExchangeServer = TestContext<Arc<HandlerContext>>;

    struct ExchangeFixture {
        ctx: SmContext,
        _events: Receiver<Event>,
        _dir: camino_tempfile::Utf8TempDir,
    }

    impl ExchangeFixture {
        fn new(rt: &Runtime) -> Self {
            let dir = camino_tempfile::tempdir().unwrap();
            let log = Logger::root(Discard, o!());
            let db = Db::new(dir.path().as_str(), log.clone()).unwrap();
            let (tx, events) = channel();
            let iface = Arc::new(InterfaceState::default());
            *iface.peer_identity.lock().unwrap() = Some(PeerIdentity {
                addr: PEER,
                router_id: "peer".into(),
                kind: RouterKind::Transit,
            });
            Self {
                ctx: SmContext {
                    config: Config {
                        if_index: 1,
                        if_name: "test0".into(),
                        aobj_name: "test0/v6".into(),
                        addr: Ipv6Addr::LOCALHOST,
                        solicit_interval: Duration::from_secs(1),
                        discovery_read_timeout: Duration::from_secs(1),
                        ip_addr_wait: Duration::from_secs(1),
                        expire_threshold: Duration::from_secs(3),
                        exchange_timeout: Duration::from_secs(5),
                        kind: RouterKind::Server,
                        exchange_port: 0,
                        dpd: None,
                        rack_id: None,
                        sled_id: None,
                    },
                    db,
                    tx,
                    event_channels: Vec::new(),
                    rt: Arc::new(rt.handle().clone()),
                    router_id: "local".into(),
                    iface,
                    stats: Arc::new(SessionStats::default()),
                    log,
                    discovery_stop: None,
                    first_run: true,
                },
                _events: events,
                _dir: dir,
            }
        }

        fn server(&self, session: Arc<ExchangeSession>) -> ExchangeServer {
            let handler = HandlerContext {
                ctx: self.ctx.clone(),
                peer: PEER,
                session,
            };
            TestContext::new(
                api_description().unwrap(),
                Arc::new(handler),
                &ConfigDropshot::default(),
                None,
                self.ctx.log.clone(),
            )
        }
    }

    fn multicast_announcement() -> (v4::Update, MulticastRoute) {
        let origin = v4::MulticastOrigin::new(
            OverlayMulticast::new("233.252.0.1".parse().unwrap()).unwrap(),
            UnderlayMulticastIpv6::new("ff04::100".parse().unwrap()).unwrap(),
            Vni::new(77).unwrap(),
            None,
        )
        .unwrap();
        let path = vec![v4::MulticastPathHop::new("peer".into(), PEER)];
        let vector = v4::MulticastPathVector {
            origin: origin.clone(),
            path: path.clone(),
        };
        (
            v4::MulticastUpdate::announce(HashSet::from([vector])).into(),
            MulticastRoute {
                origin,
                nexthop: PEER,
                path,
            },
        )
    }

    #[test]
    fn invalid_multicast_entries_do_not_block_the_pull() {
        let (update, route) = multicast_announcement();
        let valid = update.multicast.unwrap().announce;
        let mut invalid =
            serde_json::to_value(valid.iter().next().unwrap()).unwrap();
        invalid["origin"]["source"] = "2001:db8::1".into();
        assert!(
            serde_json::from_value::<v4::MulticastPathVector>(invalid.clone())
                .is_err()
        );

        let underlay = v3::PathVector {
            destination: "fd00:1::/64".parse().unwrap(),
            path: vec!["peer".into()],
        };
        let body = serde_json::json!({
            "underlay": [underlay],
            "multicast": [valid.iter().next().unwrap(), invalid],
        });

        let (pr, dropped) =
            decode_v4_pull(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(dropped.len(), 1);
        assert_eq!(pr.underlay, Some(HashSet::from([underlay])));
        let multicast = pr.multicast.unwrap();
        assert_eq!(multicast.len(), 1);
        assert_eq!(multicast.iter().next().unwrap().origin, route.origin);
    }

    fn publish(ctx: &SmContext, version: Version) -> Arc<ExchangeSession> {
        let session = Arc::new(ExchangeSession::new(version));
        *ctx.iface.session() = Some(session.clone());
        session
    }

    fn push_v4(rt: &Runtime, server: &ExchangeServer, update: &v4::Update) {
        rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                server.client_testctx.make_request(
                    Method::PUT,
                    "/v4/push",
                    Some(update),
                    StatusCode::NO_CONTENT,
                ),
            )
            .await
            .unwrap()
            .unwrap();
        });
    }

    #[test]
    fn stale_push_cannot_restore_multicast_after_session_replacement() {
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        let fixture = ExchangeFixture::new(&rt);
        let ctx = &fixture.ctx;
        let old_session = publish(ctx, Version::V4);
        let old_server = fixture.server(old_session);
        let (update, route) = multicast_announcement();

        push_v4(&rt, &old_server, &update);
        assert_eq!(ctx.db.imported_mcast(), HashSet::from([route.clone()]));

        {
            let mut session = ctx.iface.session();
            *session = Some(Arc::new(ExchangeSession::new(Version::V3)));
            let removed = ctx.db.remove_nexthop_mcast_routes(PEER);
            assert_eq!(removed.multicast, HashSet::from([route.clone()]));
        }
        assert!(ctx.db.imported_mcast().is_empty());
        push_v4(&rt, &old_server, &update);
        assert!(ctx.db.imported_mcast().is_empty());

        let fresh_session = publish(ctx, Version::V4);
        push_v4(&rt, &old_server, &update);
        assert!(ctx.db.imported_mcast().is_empty());

        let fresh_server = fixture.server(fresh_session);
        push_v4(&rt, &fresh_server, &update);
        assert_eq!(ctx.db.imported_mcast(), HashSet::from([route]));

        rt.block_on(fresh_server.teardown());
        rt.block_on(old_server.teardown());
    }

    #[test]
    fn multicast_push_to_v3_session_is_rejected_without_imports() {
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        let fixture = ExchangeFixture::new(&rt);
        let session = publish(&fixture.ctx, Version::V3);
        let server = fixture.server(session);
        let (update, _) = multicast_announcement();

        let error = rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                server.client_testctx.make_request_error_body(
                    Method::PUT,
                    "/v4/push",
                    update,
                    StatusCode::BAD_REQUEST,
                ),
            )
            .await
            .unwrap()
        });
        assert_eq!(error.message, "multicast exchange requires a V4 peer");
        assert!(fixture.ctx.db.imported_mcast().is_empty());

        rt.block_on(server.teardown());
    }

    /// An empty V4 push is valid even when the negotiated version is V3.
    #[test]
    fn push_without_multicast_to_v3_session_is_accepted() {
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        let fixture = ExchangeFixture::new(&rt);
        let session = publish(&fixture.ctx, Version::V3);
        let server = fixture.server(session);

        push_v4(&rt, &server, &v4::Update::default());
        assert!(fixture.ctx.db.imported_mcast().is_empty());

        rt.block_on(server.teardown());
    }

    #[test]
    fn canceled_session_rejects_updates() {
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        let fixture = ExchangeFixture::new(&rt);
        let ctx = &fixture.ctx;
        let session = publish(ctx, Version::V4);
        let server = fixture.server(session.clone());
        let (update, _) = multicast_announcement();

        session.cancel();
        push_v4(&rt, &server, &update);
        assert!(ctx.db.imported_mcast().is_empty());

        rt.block_on(server.teardown());
    }

    #[test]
    fn multicast_only_query_selects_multicast_sections() {
        let scan: PullScanParams =
            serde_urlencoded::from_str(MULTICAST_ONLY_QUERY).unwrap();
        assert_eq!(scan.sections, PullSections::Multicast);

        let scan: PullScanParams = serde_urlencoded::from_str("").unwrap();
        assert_eq!(scan.sections, PullSections::All);
    }

    #[test]
    fn replacement_session_is_not_canceled() {
        let prev = ExchangeSession::new(Version::V4);
        prev.cancel();
        let fresh = ExchangeSession::new(Version::V4);
        assert!(prev.is_canceled());
        assert!(!fresh.is_canceled());
    }
}
