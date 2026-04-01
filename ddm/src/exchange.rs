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
//! This file only contains basic mechanisms for prefix information exchange
//! with peers. How those mechanisms are used in the overall state machine model
//! of a ddm router is defined in the state machine implementation in sm.rs.
//!

use crate::db::{Route, effective_route_set};
use crate::discovery::Version;
use crate::sm::{Config, Event, PeerEvent, SmContext};
use crate::{dbg, err, inf, wrn};
use ddm_types::db::{MulticastRoute, RouterKind, TunnelRoute};
use ddm_types::exchange::{
    MulticastPathHop, MulticastPathVector, PathVector, PathVectorV2,
};
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
use mg_common::net::{TunnelOrigin, TunnelOriginV2};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::Ordering;
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

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 1. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV1 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UpdateV1 {
    pub announce: HashSet<PathVector>,
    pub withdraw: HashSet<PathVector>,
}

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 2. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV2 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UpdateV2 {
    pub underlay: Option<UnderlayUpdateV2>,
    pub tunnel: Option<TunnelUpdateV2>,
}

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 3. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV3 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UpdateV3 {
    pub underlay: Option<UnderlayUpdate>,
    pub tunnel: Option<TunnelUpdate>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct Update {
    pub underlay: Option<UnderlayUpdate>,
    pub tunnel: Option<TunnelUpdate>,
    pub multicast: Option<MulticastUpdate>,
}

impl From<UpdateV1> for Update {
    fn from(value: UpdateV1) -> Self {
        Update {
            tunnel: None,
            underlay: Some(UnderlayUpdate {
                announce: value.announce,
                withdraw: value.withdraw,
            }),
            multicast: None,
        }
    }
}

impl From<UpdateV2> for Update {
    fn from(value: UpdateV2) -> Self {
        Update {
            tunnel: value.tunnel.map(TunnelUpdate::from),
            underlay: value.underlay.map(UnderlayUpdate::from),
            // V2 protocol doesn't support multicast
            multicast: None,
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

impl From<Update> for UpdateV2 {
    fn from(value: Update) -> Self {
        UpdateV2 {
            tunnel: value.tunnel.map(TunnelUpdateV2::from),
            underlay: value.underlay.map(UnderlayUpdateV2::from),
        }
    }
}

impl From<UpdateV3> for Update {
    fn from(value: UpdateV3) -> Self {
        Update {
            underlay: value.underlay,
            tunnel: value.tunnel,
            multicast: None,
        }
    }
}

impl From<Update> for UpdateV3 {
    fn from(value: Update) -> Self {
        UpdateV3 {
            underlay: value.underlay,
            tunnel: value.tunnel,
        }
    }
}

impl From<UnderlayUpdate> for Update {
    fn from(u: UnderlayUpdate) -> Self {
        Update {
            underlay: Some(u),
            tunnel: None,
            multicast: None,
        }
    }
}

impl From<TunnelUpdate> for Update {
    fn from(t: TunnelUpdate) -> Self {
        Update {
            underlay: None,
            tunnel: Some(t),
            multicast: None,
        }
    }
}

impl Update {
    fn announce(pr: PullResponse) -> Self {
        Self {
            underlay: pr.underlay.map(UnderlayUpdate::announce),
            tunnel: pr.tunnel.map(TunnelUpdate::announce),
            multicast: pr.multicast.map(MulticastUpdate::announce),
        }
    }
}

impl From<MulticastUpdate> for Update {
    fn from(m: MulticastUpdate) -> Self {
        Update {
            underlay: None,
            tunnel: None,
            multicast: Some(m),
        }
    }
}

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 3. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV3 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct PullResponseV3 {
    pub underlay: Option<HashSet<PathVector>>,
    pub tunnel: Option<HashSet<TunnelOrigin>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct PullResponse {
    pub underlay: Option<HashSet<PathVector>>,
    pub tunnel: Option<HashSet<TunnelOrigin>>,
    pub multicast: Option<HashSet<MulticastPathVector>>,
}

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 2. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV2 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct PullResponseV2 {
    pub underlay: Option<HashSet<PathVectorV2>>,
    pub tunnel: Option<HashSet<TunnelOriginV2>>,
}

impl From<PullResponseV2> for PullResponse {
    fn from(value: PullResponseV2) -> Self {
        PullResponse {
            underlay: value
                .underlay
                .map(|x| x.into_iter().map(PathVector::from).collect()),
            tunnel: value
                .tunnel
                .map(|x| x.into_iter().map(TunnelOrigin::from).collect()),
            // V2 protocol doesn't support multicast
            multicast: None,
        }
    }
}

impl From<PullResponseV3> for PullResponse {
    fn from(value: PullResponseV3) -> Self {
        PullResponse {
            underlay: value.underlay,
            tunnel: value.tunnel,
            multicast: None,
        }
    }
}

impl From<HashSet<PathVector>> for PullResponse {
    fn from(value: HashSet<PathVector>) -> Self {
        PullResponse {
            underlay: Some(value),
            tunnel: None,
            multicast: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UnderlayUpdate {
    pub announce: HashSet<PathVector>,
    pub withdraw: HashSet<PathVector>,
}

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 2. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV2 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UnderlayUpdateV2 {
    pub announce: HashSet<PathVectorV2>,
    pub withdraw: HashSet<PathVectorV2>,
}

impl From<UnderlayUpdate> for UnderlayUpdateV2 {
    fn from(value: UnderlayUpdate) -> Self {
        UnderlayUpdateV2 {
            announce: value
                .announce
                .into_iter()
                .map(PathVectorV2::from)
                .collect(),
            withdraw: value
                .withdraw
                .into_iter()
                .map(PathVectorV2::from)
                .collect(),
        }
    }
}

impl From<UnderlayUpdateV2> for UnderlayUpdate {
    fn from(value: UnderlayUpdateV2) -> Self {
        UnderlayUpdate {
            announce: value
                .announce
                .into_iter()
                .map(PathVector::from)
                .collect(),
            withdraw: value
                .withdraw
                .into_iter()
                .map(PathVector::from)
                .collect(),
        }
    }
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

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 2. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV2 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct TunnelUpdateV2 {
    pub announce: HashSet<TunnelOriginV2>,
    pub withdraw: HashSet<TunnelOriginV2>,
}

impl From<TunnelUpdateV2> for TunnelUpdate {
    fn from(value: TunnelUpdateV2) -> Self {
        TunnelUpdate {
            announce: value
                .announce
                .into_iter()
                .map(TunnelOrigin::from)
                .collect(),
            withdraw: value
                .withdraw
                .into_iter()
                .map(TunnelOrigin::from)
                .collect(),
        }
    }
}

impl From<TunnelUpdate> for TunnelUpdateV2 {
    fn from(value: TunnelUpdate) -> Self {
        TunnelUpdateV2 {
            announce: value
                .announce
                .into_iter()
                .map(TunnelOriginV2::from)
                .collect(),
            withdraw: value
                .withdraw
                .into_iter()
                .map(TunnelOriginV2::from)
                .collect(),
        }
    }
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

/// Multicast group subscription updates.
///
/// Carries path-vector information for multicast group subscriptions,
/// enabling loop detection and optimal replication point computation.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct MulticastUpdate {
    pub announce: HashSet<MulticastPathVector>,
    pub withdraw: HashSet<MulticastPathVector>,
}

impl MulticastUpdate {
    pub fn announce(groups: HashSet<MulticastPathVector>) -> Self {
        Self {
            announce: groups,
            ..Default::default()
        }
    }
    pub fn withdraw(groups: HashSet<MulticastPathVector>) -> Self {
        Self {
            withdraw: groups,
            ..Default::default()
        }
    }

    /// Add a hop to all path vectors in this update.
    pub fn with_hop(&self, hop: MulticastPathHop) -> Self {
        Self {
            announce: self
                .announce
                .iter()
                .map(|pv| pv.with_hop(hop.clone()))
                .collect(),
            withdraw: self
                .withdraw
                .iter()
                .map(|pv| pv.with_hop(hop.clone()))
                .collect(),
        }
    }
}

#[derive(Error, Debug)]
pub enum ExchangeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("hyper client error: {0}")]
    HyperClient(#[from] hyper_util::client::legacy::Error),

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
    let update = TunnelUpdate::announce(endpoints.into_iter().collect());
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
    let update = TunnelUpdate::withdraw(endpoints.into_iter().collect());
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
) -> Result<PullResponseV3, ExchangeError> {
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
) -> Result<PullResponseV2, ExchangeError> {
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
    let pr: PullResponse = match version {
        Version::V2 => do_pull_v2(&ctx, &addr, &rt)?.into(),
        Version::V3 => do_pull_v3(&ctx, &addr, &rt)?.into(),
        Version::V4 => do_pull_v4(&ctx, &addr, &rt)?,
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
    let (payload, path) = match version {
        Version::V2 => (serde_json::to_string(&UpdateV2::from(update))?, "v2"),
        Version::V3 => (serde_json::to_string(&UpdateV3::from(update))?, "v3"),
        Version::V4 => (serde_json::to_string(&update)?, "v4"),
    };
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
    api.register(push_handler_v3)?;
    api.register(push_handler_v4)?;
    api.register(pull_handler_v2)?;
    api.register(pull_handler_v3)?;
    api.register(pull_handler_v4)?;
    Ok(api)
}

#[endpoint { method = PUT, path = "/v2/push" }]
async fn push_handler_v2(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<UpdateV2>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let update_v2 = request.into_inner();
    let update = Update::from(update_v2);
    push_handler_common(ctx, update).await
}

#[endpoint { method = PUT, path = "/v3/push" }]
async fn push_handler_v3(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<UpdateV3>,
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
) -> Result<HttpResponseOk<PullResponseV2>, HttpError> {
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

    Ok(HttpResponseOk(PullResponseV2 {
        underlay: if underlay.is_empty() {
            None
        } else {
            Some(underlay.into_iter().map(PathVectorV2::from).collect())
        },
        tunnel: if tunnel.is_empty() {
            None
        } else {
            Some(tunnel.into_iter().map(TunnelOriginV2::from).collect())
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
                origin: route.origin.clone(),
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
            origin: origin.clone(),
            path: vec![hop],
        });
    }

    Ok(multicast)
}

fn opt<T>(s: HashSet<T>) -> Option<HashSet<T>> {
    if s.is_empty() { None } else { Some(s) }
}

#[endpoint { method = GET, path = "/v3/pull" }]
async fn pull_handler_v3(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<PullResponseV3>, HttpError> {
    let ctx = ctx.context().lock().await.clone();
    let (underlay, tunnel) = collect_underlay_tunnel(&ctx)?;
    Ok(HttpResponseOk(PullResponseV3 {
        underlay: opt(underlay),
        tunnel: opt(tunnel),
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
        underlay: opt(underlay),
        tunnel: opt(tunnel),
        multicast: opt(multicast),
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

    if let Some(multicast_update) = &update.multicast {
        handle_multicast_update(multicast_update, ctx);
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

        // Add our hop info to multicast path vectors before redistribution
        let multicast = update.multicast.as_ref().map(|update| {
            let hop = MulticastPathHop::new(
                ctx.ctx.hostname.clone(),
                ctx.ctx.config.addr,
            );
            update.with_hop(hop)
        });

        let push = Arc::new(Update {
            underlay,
            tunnel: update.tunnel.clone(),
            multicast,
        });

        for ec in &ctx.ctx.event_channels {
            ec.send(Event::Peer(PeerEvent::Push(Arc::clone(&push))))
                .unwrap();
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

/// Handle multicast group subscription updates from a peer.
///
/// Validation uses path-vector-based RPF rather than unicast-RIB RPF.
/// DDM operates on the underlay while multicast sources are overlay
/// addresses, so traditional (S,G) RPF against the unicast RIB does not
/// apply at this layer. The MRIB RPF module in rdb handles that check
/// before routes are originated into DDM. At the DDM exchange level,
/// the path vector provides loop detection and carries topology
/// information for replication optimization per [RFD 488].
///
/// [RFD 488]: https://rfd.shared.oxide.computer/rfd/0488
fn handle_multicast_update(update: &MulticastUpdate, ctx: &HandlerContext) {
    let db = &ctx.ctx.db;
    let hostname = &ctx.ctx.hostname;

    let mut import = HashSet::new();
    for pv in &update.announce {
        // Path-vector RPF: drop if our router_id appears in the path,
        // indicating the announcement has already traversed us.
        if pv.path.iter().any(|hop| &hop.router_id == hostname) {
            dbg!(
                ctx.log,
                ctx.ctx.config.if_name,
                "dropping multicast announce for {:?} - loop detected \
                 (path length {})",
                pv.origin.overlay_group,
                pv.path.len(),
            );
            continue;
        }

        import.insert(MulticastRoute {
            origin: pv.origin.clone(),
            nexthop: ctx.peer,
            path: pv.path.clone(),
        });
    }

    let mut remove = HashSet::new();
    for pv in &update.withdraw {
        // Empty path is safe: MulticastRoute's PartialEq/Hash exclude
        // the path field, so this matches by (origin, nexthop) only.
        remove.insert(MulticastRoute {
            origin: pv.origin.clone(),
            nexthop: ctx.peer,
            path: Vec::new(),
        });
    }

    // Atomic import + delete + diff under a single lock.
    let (to_add, to_del) = db.update_imported_mcast(&import, &remove);

    if let Err(e) = crate::sys::add_multicast_routes(
        &ctx.log,
        &ctx.ctx.config.if_name,
        &to_add,
    ) {
        err!(
            ctx.log,
            ctx.ctx.config.if_name,
            "add multicast routes: {e}: {to_add:#?}",
        )
    }

    if let Err(e) = crate::sys::remove_multicast_routes(
        &ctx.log,
        &ctx.ctx.config.if_name,
        &to_del,
    ) {
        err!(
            ctx.log,
            ctx.ctx.config.if_name,
            "remove multicast routes: {e}: {to_del:#?}",
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ddm_types::exchange::MulticastPathHop;
    use mg_common::net::{MulticastOrigin, UnderlayMulticastIpv6};
    use std::net::Ipv6Addr;

    fn sample_multicast_update() -> MulticastUpdate {
        let origin = MulticastOrigin {
            overlay_group: "233.252.0.1".parse().unwrap(),
            underlay_group: UnderlayMulticastIpv6::new(Ipv6Addr::new(
                0xff04, 0, 0, 0, 0, 0, 0, 1,
            ))
            .unwrap(),
            vni: 77,
            metric: 0,
            source: None,
        };
        let pv = MulticastPathVector {
            origin,
            path: vec![MulticastPathHop::new(
                "router-1".into(),
                Ipv6Addr::LOCALHOST,
            )],
        };
        MulticastUpdate::announce([pv].into_iter().collect())
    }

    #[test]
    fn v4_update_round_trips() {
        let update = Update {
            underlay: None,
            tunnel: None,
            multicast: Some(sample_multicast_update()),
        };
        let json = serde_json::to_string(&update).unwrap();
        let back: Update = serde_json::from_str(&json).unwrap();
        assert!(back.multicast.is_some());
        assert_eq!(back.multicast.unwrap().announce.len(), 1,);
    }

    #[test]
    fn v4_update_deserializes_as_v3_drops_multicast() {
        let update = Update {
            underlay: None,
            tunnel: None,
            multicast: Some(sample_multicast_update()),
        };
        let json = serde_json::to_string(&update).unwrap();
        // A V3 peer would deserialize this as UpdateV3, silently
        // dropping the unknown multicast field.
        let v3: UpdateV3 = serde_json::from_str(&json).unwrap();
        assert!(v3.underlay.is_none());
        assert!(v3.tunnel.is_none());
    }

    #[test]
    fn v3_update_deserializes_as_v4_multicast_none() {
        let v3 = UpdateV3 {
            underlay: None,
            tunnel: None,
        };
        let json = serde_json::to_string(&v3).unwrap();
        // A V4 peer receiving a V3 update gets multicast: None.
        let update: Update = serde_json::from_str(&json).unwrap();
        assert!(update.multicast.is_none());
    }

    #[test]
    fn v4_pull_response_round_trips() {
        let origin = MulticastOrigin {
            overlay_group: "ff0e::1".parse().unwrap(),
            underlay_group: UnderlayMulticastIpv6::new(Ipv6Addr::new(
                0xff04, 0, 0, 0, 0, 0, 0, 2,
            ))
            .unwrap(),
            vni: 77,
            metric: 0,
            source: None,
        };
        let pv = MulticastPathVector {
            origin,
            path: vec![],
        };
        let resp = PullResponse {
            underlay: None,
            tunnel: None,
            multicast: Some([pv].into_iter().collect()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: PullResponse = serde_json::from_str(&json).unwrap();
        assert!(back.multicast.is_some());
    }

    #[test]
    fn v4_pull_response_deserializes_as_v3() {
        let origin = MulticastOrigin {
            overlay_group: "233.252.0.1".parse().unwrap(),
            underlay_group: UnderlayMulticastIpv6::new(Ipv6Addr::new(
                0xff04, 0, 0, 0, 0, 0, 0, 1,
            ))
            .unwrap(),
            vni: 77,
            metric: 0,
            source: None,
        };
        let pv = MulticastPathVector {
            origin,
            path: vec![],
        };
        let resp = PullResponse {
            underlay: None,
            tunnel: None,
            multicast: Some([pv].into_iter().collect()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        // V3 peer drops the multicast field.
        let v3: PullResponseV3 = serde_json::from_str(&json).unwrap();
        assert!(v3.underlay.is_none());
        assert!(v3.tunnel.is_none());
    }

    #[test]
    fn v3_pull_response_deserializes_as_v4() {
        let v3 = PullResponseV3 {
            underlay: None,
            tunnel: None,
        };
        let json = serde_json::to_string(&v3).unwrap();
        let resp: PullResponse = serde_json::from_str(&json).unwrap();
        assert!(resp.multicast.is_none());
    }

    #[test]
    fn from_conversions_strip_multicast() {
        let update = Update {
            underlay: None,
            tunnel: None,
            multicast: Some(sample_multicast_update()),
        };
        let v3 = UpdateV3::from(update);
        let back = Update::from(v3);
        assert!(back.multicast.is_none());
    }
}
