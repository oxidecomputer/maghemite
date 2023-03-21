// Copyright 2022 Oxide Computer Company

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

use crate::db::{Ipv6Prefix, Route, RouterKind};
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
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;

#[derive(Clone)]
pub struct HandlerContext {
    ctx: SmContext,
    peer: Ipv6Addr,
    log: Logger,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct PathVector {
    pub destination: Ipv6Prefix,
    pub path: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
struct Update {
    pub announce: HashSet<PathVector>,
    pub withdraw: HashSet<PathVector>,
}

impl Update {
    fn announce(prefixes: HashSet<PathVector>) -> Self {
        Self {
            announce: prefixes,
            ..Default::default()
        }
    }
    fn withdraw(prefixes: HashSet<PathVector>) -> Self {
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

    #[error("timeout error: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
}

pub(crate) fn announce(
    config: Config,
    prefixes: HashSet<PathVector>,
    addr: Ipv6Addr,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) {
    let update = Update::announce(prefixes);
    send_update(config, update, addr, rt, log);
}

pub(crate) fn withdraw(
    config: Config,
    prefixes: HashSet<PathVector>,
    addr: Ipv6Addr,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) {
    let update = Update::withdraw(prefixes);
    send_update(config, update, addr, rt, log);
}

pub(crate) fn pull(
    ctx: SmContext,
    addr: Ipv6Addr,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<(), ExchangeError> {
    let uri = format!(
        "http://[{}%{}]:{}/pull",
        addr, ctx.config.if_index, ctx.config.exchange_port,
    );
    let client = hyper::Client::new();
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri)
        .body(hyper::Body::empty())
        .unwrap(); //TODO unwrap

    let resp = client.request(req);
    let log_ = log.clone();

    let (tx, rx) = std::sync::mpsc::channel();

    rt.spawn(async move {
        match timeout(Duration::from_millis(250), resp).await {
            Ok(response) => {
                match response {
                    Ok(data) => {
                        let body = hyper::body::to_bytes(data.into_body())
                            .await
                            .unwrap(); //TODO unwrap
                        let pv: HashSet<PathVector> =
                            serde_json::from_slice(&body).unwrap(); //TODO unwrap

                        let update = Update::announce(pv);

                        let hctx = HandlerContext {
                            ctx,
                            peer: addr,
                            log: log_,
                        };
                        handle_update(&update, &hctx);
                        tx.send(Ok(())).unwrap();
                    }
                    Err(e) => {
                        tx.send(Err(ExchangeError::Hyper(e))).unwrap();
                    }
                }
            }
            Err(e) => {
                tx.send(Err(ExchangeError::Timeout(e))).unwrap();
            }
        }
    });

    rx.recv().unwrap()
}

fn send_update(
    config: Config,
    update: Update,
    addr: Ipv6Addr,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) {
    let payload = serde_json::to_string(&update).unwrap(); //TODO unwrap
    let uri = format!(
        "http://[{}%{}]:{}/push",
        addr, config.if_index, config.exchange_port,
    );

    let client = hyper::Client::new();
    let req = hyper::Request::builder()
        .method(hyper::Method::PUT)
        .uri(&uri)
        .body(hyper::Body::from(payload))
        .unwrap(); //TODO unwrap

    let resp = client.request(req);

    rt.spawn(async move {
        match timeout(Duration::from_millis(250), resp).await {
            Ok(_) => {}
            Err(e) => err!(
                log,
                config.if_index,
                "peer request timeout to {}: {}",
                uri,
                e,
            ),
        };
    });
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

    let api = api_description()?;

    inf!(log, ctx.config.if_index, "exchange: listening on {}", sa);

    let log = log.clone();

    Ok(ctx.rt.spawn(async move {
        let server = HttpServerStarter::new(&config, api, context, &ds_log);
        match server.unwrap().start().await {
            Ok(_) => wrn!(
                log,
                ctx.config.if_index,
                "exchange: unexpected server exit"
            ),
            Err(e) => err!(
                log,
                ctx.config.if_index,
                "exchange: server start error {:?}",
                e
            ),
        }
    }))
}

pub fn api_description(
) -> Result<ApiDescription<Arc<Mutex<HandlerContext>>>, String> {
    let mut api = ApiDescription::new();
    api.register(push_handler)?;
    api.register(pull_handler)?;
    Ok(api)
}

#[endpoint { method = PUT, path = "/push" }]
async fn push_handler(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<Update>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let update = request.into_inner();

    handle_update(&update, &ctx);

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/pull" }]
async fn pull_handler(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<HashSet<PathVector>>, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let db = ctx.ctx.db.dump();
    let mut prefixes = HashSet::new();
    // Only transit routers redistribute prefixes
    if ctx.ctx.config.kind == RouterKind::Transit {
        for route in &db.imported {
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
    for prefix in &db.originated {
        let pv = PathVector {
            destination: *prefix,
            path: vec![ctx.ctx.hostname.clone()],
        };
        prefixes.insert(pv);
    }

    Ok(HttpResponseOk(prefixes))
}

fn handle_update(update: &Update, ctx: &HandlerContext) {
    let mut import = HashSet::new();
    let mut add = Vec::new();
    for prefix in &update.announce {
        import.insert(Route {
            destination: prefix.destination,
            nexthop: ctx.peer,
            ifname: ctx.ctx.config.if_name.clone(),
            path: prefix.path.clone(),
        });
        add.push(crate::sys::Route::new(
            prefix.destination.addr.into(),
            prefix.destination.len,
            ctx.peer.into(),
        ));
    }
    ctx.ctx.db.import(&import);
    if let Err(e) =
        crate::sys::add_routes(&ctx.log, &ctx.ctx.config, add, &ctx.ctx.rt)
    {
        err!(ctx.log, ctx.ctx.config.if_index, "add system route: {}", e);
    }

    let mut withdraw = HashSet::new();
    let mut del = Vec::new();
    for prefix in &update.withdraw {
        withdraw.insert(Route {
            destination: prefix.destination,
            nexthop: ctx.peer,
            ifname: ctx.ctx.config.if_name.clone(),
            path: prefix.path.clone(),
        });
        let mut r = crate::sys::Route::new(
            prefix.destination.addr.into(),
            prefix.destination.len,
            ctx.peer.into(),
        );
        r.ifname = ctx.ctx.config.if_name.clone();
        del.push(r);
    }
    ctx.ctx.db.delete_import(&withdraw);
    if let Err(e) = crate::sys::remove_routes(
        &ctx.log,
        &ctx.ctx.config.dpd,
        del,
        &ctx.ctx.rt,
    ) {
        err!(ctx.log, ctx.ctx.config.if_index, "add system route: {}", e);
    }

    // distribute updates

    if ctx.ctx.config.kind == RouterKind::Transit {
        dbg!(
            ctx.log,
            ctx.ctx.config.if_index,
            "redistributing update to {} peers",
            ctx.ctx.event_channels.len()
        );
        let push = crate::sm::Push {
            announce: update
                .announce
                .iter()
                .map(|x| {
                    let mut pv = x.clone();
                    pv.path.push(ctx.ctx.hostname.clone());
                    pv
                })
                .collect(),
            withdraw: update
                .withdraw
                .iter()
                .map(|x| {
                    let mut pv = x.clone();
                    pv.path.push(ctx.ctx.hostname.clone());
                    pv
                })
                .collect(),
        };
        for ec in &ctx.ctx.event_channels {
            ec.send(Event::Peer(PeerEvent::Push(push.clone()))).unwrap();
        }
    }
}
