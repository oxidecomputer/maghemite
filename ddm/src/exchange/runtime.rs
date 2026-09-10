// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HTTP transport for the ddm prefix exchange protocol: the push/pull client
//! and the dropshot server that answers them. illumos-only.
//!
//! Like [`crate::discovery::runtime`], this module moves bytes and makes no
//! decisions. A received push is handed to the owning interface's
//! [`InterfaceSm`](crate::protocol::interface::InterfaceSm) as
//! [`Input::PeerPush`]; a pull is answered straight out of [`Db`], which is the
//! one exchange operation that never touches a state machine.

use super::ExchangeError;
use crate::db::Db;
use crate::discovery::Version;
use crate::protocol::interface::Input;
use crate::{err, inf, wrn};
use ddm_api_types::db::RouterKind;
use ddm_protocol_types::{v2, v3};
use dropshot::ApiDescription;
use dropshot::ApiDescriptionRegisterError;
use dropshot::ConfigDropshot;
use dropshot::ConfigLogging;
use dropshot::ConfigLoggingLevel;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::RequestContext;
use dropshot::TypedBody;
use dropshot::endpoint;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use slog::{Logger, o};
use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const UNIT_EXCHANGE_SERVER: &str = "exchange_server";

/// How long to wait for a peer to answer a pull.
const PULL_TIMEOUT: Duration = Duration::from_millis(250);

/// Where a peer's exchange endpoints live. The scope id is required: peers are
/// addressed by link local address, which is only unambiguous per interface.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Endpoint {
    pub addr: Ipv6Addr,
    pub if_index: u32,
    pub port: u16,
}

impl Endpoint {
    fn uri(&self, path: &str) -> String {
        format!(
            "http://[{}%{}]:{}{}",
            self.addr, self.if_index, self.port, path
        )
    }
}

/// Pull a peer's whole table. Version negotiation happens here so that callers
/// only ever deal in v3.
pub(crate) async fn pull(
    peer: Endpoint,
    version: Version,
) -> Result<v3::PullResponse, ExchangeError> {
    Ok(match version {
        Version::V2 => {
            let body = get(peer.uri("/v2/pull")).await?;
            serde_json::from_slice::<v2::PullResponse>(&body)?.into()
        }
        Version::V3 => {
            let body = get(peer.uri("/v3/pull")).await?;
            serde_json::from_slice(&body)?
        }
    })
}

/// Push an update to a peer.
pub(crate) async fn push(
    peer: Endpoint,
    version: Version,
    update: &v3::Update,
    exchange_timeout: Duration,
) -> Result<(), ExchangeError> {
    let (uri, payload) = match version {
        Version::V2 => (
            peer.uri("/v2/push"),
            serde_json::to_string(&v2::Update::from(update.clone()))?,
        ),
        Version::V3 => (peer.uri("/v3/push"), serde_json::to_string(update)?),
    };

    let client = Client::builder(TokioExecutor::new()).build_http();
    let req = hyper::Request::builder()
        .method(hyper::Method::PUT)
        .uri(&uri)
        .body(http_body_util::Full::<Bytes>::from(payload))
        .unwrap();

    // Only a timeout counts as failure. A peer that answers with an error
    // status has at least answered, and the interface state machine expires a
    // peer on send failure, so treating a transient 5xx as a dead peer would
    // tear down a working session.
    let _ = timeout(exchange_timeout, client.request(req)).await?;
    Ok(())
}

async fn get(uri: String) -> Result<Bytes, ExchangeError> {
    let client = Client::builder(TokioExecutor::new()).build_http();
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri)
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    Ok(timeout(PULL_TIMEOUT, client.request(req))
        .await??
        .into_body()
        .collect()
        .await?
        .to_bytes())
}

#[derive(Clone)]
pub(crate) struct ServerContext {
    pub db: Db,
    pub hostname: String,
    pub kind: RouterKind,

    /// The peer this server was brought up for. Prefixes are never
    /// redistributed back to the router they were learned from.
    pub peer: Ipv6Addr,

    /// Where received pushes go.
    pub ingress: UnboundedSender<Input>,
}

/// A running exchange server. Dropping it stops the server, which is how the
/// interface driver tears one down when its peer expires.
pub(crate) struct Server {
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn start_server(
    context: ServerContext,
    addr: Ipv6Addr,
    port: u16,
    if_name: &str,
    log: &Logger,
) -> Result<Server, String> {
    let sa = SocketAddrV6::new(addr, port, 0, 0);

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

    let api = api_description().map_err(|e| e.to_string())?;

    // Bind synchronously so a bind failure comes back as an error the state
    // machine can retry, rather than surfacing later from a detached task.
    let server = dropshot::ServerBuilder::new(api, Arc::new(context), ds_log)
        .config(ConfigDropshot {
            bind_address: sa.into(),
            ..Default::default()
        })
        .start()
        .map_err(|e| format!("failed to start exchange server on {sa}: {e}"))?;

    inf!(log, if_name, "exchange: listening on {}", sa);

    let log = log.clone();
    let if_name = if_name.to_owned();
    Ok(Server {
        task: tokio::spawn(async move {
            match server.await {
                Ok(()) => {
                    wrn!(log, if_name, "exchange: unexpected server exit")
                }
                Err(e) => err!(log, if_name, "exchange: server error {:?}", e),
            }
        }),
    })
}

fn api_description()
-> Result<ApiDescription<Arc<ServerContext>>, ApiDescriptionRegisterError> {
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
    ctx: RequestContext<Arc<ServerContext>>,
    request: TypedBody<v2::Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    accept(ctx.context(), v3::Update::from(request.into_inner()))
}

#[endpoint {
    method = PUT,
    path = "/v3/push",
}]
async fn push_handler(
    ctx: RequestContext<Arc<ServerContext>>,
    request: TypedBody<v3::Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    accept(ctx.context(), request.into_inner())
}

fn accept(
    ctx: &ServerContext,
    update: v3::Update,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    ctx.ingress
        .send(Input::PeerPush(Box::new(update)))
        .map_err(|e| {
            HttpError::for_internal_error(format!("interface gone: {e}"))
        })?;
    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint {
    method = GET,
    path = "/v2/pull",
}]
async fn pull_handler_v2(
    ctx: RequestContext<Arc<ServerContext>>,
) -> Result<HttpResponseOk<v2::PullResponse>, HttpError> {
    let (underlay, tunnel) = snapshot(ctx.context())?;
    Ok(HttpResponseOk(v2::PullResponse {
        underlay: (!underlay.is_empty())
            .then(|| underlay.into_iter().map(v2::PathVector::from).collect()),
        tunnel: (!tunnel.is_empty())
            .then(|| tunnel.into_iter().map(v2::TunnelOrigin::from).collect()),
    }))
}

#[endpoint {
    method = GET,
    path = "/v3/pull",
}]
async fn pull_handler(
    ctx: RequestContext<Arc<ServerContext>>,
) -> Result<HttpResponseOk<v3::PullResponse>, HttpError> {
    let (underlay, tunnel) = snapshot(ctx.context())?;
    Ok(HttpResponseOk(v3::PullResponse {
        underlay: (!underlay.is_empty()).then_some(underlay),
        tunnel: (!tunnel.is_empty()).then_some(tunnel),
    }))
}

/// Everything this router is willing to tell `ctx.peer` about: what it
/// originates, plus, on a transit router, what it has imported from elsewhere.
type Snapshot = (HashSet<v3::PathVector>, HashSet<v3::TunnelOrigin>);

fn snapshot(ctx: &ServerContext) -> Result<Snapshot, HttpError> {
    let mut underlay = HashSet::new();
    let mut tunnel = HashSet::new();

    if ctx.kind == RouterKind::Transit {
        for route in &ctx.db.imported() {
            if route.nexthop == ctx.peer {
                continue;
            }
            let mut path = route.path.clone();
            path.push(ctx.hostname.clone());
            underlay.insert(v3::PathVector {
                destination: route.destination,
                path,
            });
        }
        for route in &ctx.db.imported_tunnel() {
            if route.nexthop == ctx.peer {
                continue;
            }
            tunnel.insert(route.origin);
        }
    }

    let internal =
        |e: crate::db::Error| HttpError::for_internal_error(e.to_string());

    for prefix in &ctx.db.originated().map_err(internal)? {
        underlay.insert(v3::PathVector {
            destination: *prefix,
            path: vec![ctx.hostname.clone()],
        });
    }

    for origin in &ctx.db.originated_tunnel().map_err(internal)? {
        tunnel.insert(v3::TunnelOrigin {
            overlay_prefix: origin.overlay_prefix,
            boundary_addr: origin.boundary_addr,
            vni: origin.vni,
            metric: origin.metric,
        });
    }

    Ok((underlay, tunnel))
}
