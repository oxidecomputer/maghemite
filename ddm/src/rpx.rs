//! This file contains route prefix exchange (RPX) functionality for DDM. RPX is
//! the process of advertising prefixes to and consuming prefixes from
//! neighboring routers.
//!
//! In order for exchange to start, a bi-directional peering relationship must
//! be established between routers. Peering sessions, however, are one-way. A
//! router determines a bi-directional peering relationship has been established
//! if the following conditions are met.
//!
//!   1. One way peering with the neigboring router has completed.
//!   2. The router has responded to a hail from the neighboring router and
//!      delivery of that response was succesful.
//!
//! If these preconditions are satisfied for a given neighboring router, prefix
//! exchange will begin for that router.
//!
//! Advertisements are sent out in response to the following events
//!
//!   1. The router has been told to advertise a prefix through its
//!      administrative API.
//!   2. The router has received a request soliciting all of its routes from a
//!      neighboring router.
//!   3. When a router is a transit router, and has received and advertisement
//!      from a peer it will distribute that advertisement to its other peers.
//!
//! When an advertisement is recieved. The router will add each destination
//! address in the advertisement to its routing table via the link-local gateway
//! address from whence the advertisement came. DDM is an "unnumbered" protocol
//! in the sense that gateway addresses are always link-local addresses and thus
//! nexthops are always on the same link as the router.
//!
//! Additionally as stated above, if a router is a transit router, when an
//! advertisement is received it will distribute that advertisiement to its
//! peers. For each peer the advertisement is sent to, the nexthop gateway is
//! modified to be the link-local address of the interface the transit router is
//! distributing the prefix through - as the originating gateway is only local
//! to the transit router, not the router the advertisement is being distributed
//! to. This effectively is saying "this transit router is a gateway for the
//! following set of prefixes", then the transit router will sort out where to
//! route things from there.

use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use dropshot::{
    endpoint, ApiDescription, ConfigDropshot, ConfigLogging,
    ConfigLoggingLevel, HttpError, HttpResponseOk, HttpServerStarter,
    RequestContext, TypedBody,
};
use hyper::body::HttpBody;
use slog::{error, info, trace, warn, Logger};
use tokio::{spawn, sync::Mutex, task::JoinHandle, time::timeout};

use crate::net::Ipv6Prefix;
use crate::peer;
use crate::protocol::{Advertise, RouterKind, Solicit};
use crate::router::{Config, Interface, Router, RouterState};
use crate::sys;

struct HandlerContext {
    log: Logger,
    config: Config,
    router: Arc<Mutex<RouterState>>,
}

pub(crate) fn start_server(
    log: Logger,
    addr: Ipv6Addr,
    port: u16,
    router: Arc<Mutex<RouterState>>,
    config: Config,
) -> Result<JoinHandle<()>, String> {
    let context = HandlerContext {
        router,
        config,
        log: log.clone(),
    };

    let sa = SocketAddrV6::new(addr, port, 0, 0);
    let config = ConfigDropshot {
        bind_address: sa.into(),
        ..Default::default()
    };
    let log = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Error,
    }
    .to_logger("rpx")
    .map_err(|e| e.to_string())?;

    let mut api = ApiDescription::new();
    api.register(advertise_handler).unwrap();
    api.register(solicit_handler).unwrap();

    let server = HttpServerStarter::new(&config, api, context, &log)
        .map_err(|e| format!("new rpx dropshot: {}", e))?;

    Ok(spawn(async move {
        match server.start().await {
            Ok(_) => warn!(log, "rpx: unexpected server exit"),
            Err(e) => error!(log, "rpx: server start error {:?}", e),
        }
    }))
}

async fn ensure_peer_active(
    router: &Arc<Mutex<RouterState>>,
    addr: Ipv6Addr,
) -> Result<Interface, HttpError> {
    match router.lock().await.peer_status_for(addr).await {
        Some((ifx, peer::Status::Active)) => Ok(ifx),
        Some(_) => Err(HttpError::for_bad_request(
            None,
            "peer not active for nexthop: {}".into(),
        )),
        None => Err(HttpError::for_bad_request(
            None,
            "peer not found for nexthop".into(),
        )),
    }
}

#[endpoint {
    method = POST,
    path = "/advertise"
}]
async fn advertise_handler(
    ctx: Arc<RequestContext<HandlerContext>>,
    rq: TypedBody<Advertise>,
) -> Result<HttpResponseOk<()>, HttpError> {
    let context = ctx.context();
    let router = context.router.clone();
    let advertisement = rq.into_inner();

    info!(
        context.log,
        "[{}] received advertisement {:#?}",
        &context.config.name,
        advertisement
    );

    ensure_peer_active(&router, advertisement.nexthop).await?;

    Router::add_remote_prefixes(
        &router,
        advertisement.nexthop,
        advertisement.prefixes.clone(),
    )
    .await;

    if context.config.router_kind == RouterKind::Transit {
        Router::distribute(
            &router,
            &advertisement,
            &context.config,
            &context.log,
        )
        .await;
    }

    // if only in upper-half mode, we're done here
    if context.config.upper_half_only {
        return Ok(HttpResponseOk(()));
    }

    sys::add_routes(&ctx.log, &context.config, advertisement.into())
        .map_err(|e| HttpError::for_internal_error(e))?;

    Ok(HttpResponseOk(()))
}

/// Get all prefixes available through this router in a single advertisement.
#[endpoint {
    method = POST,
    path = "/solicit",
}]
async fn solicit_handler(
    ctx: Arc<RequestContext<HandlerContext>>,
    rq: TypedBody<Solicit>,
) -> Result<HttpResponseOk<Advertise>, HttpError> {
    let context = ctx.context();
    let router = &context.router;
    let router_state = router.lock().await;
    let locals = router_state.local_prefixes.clone();
    let remotes = router_state.remote_prefixes.clone();
    drop(router_state);

    let solicit = rq.into_inner();

    let ifx = match ensure_peer_active(&router, solicit.src).await {
        Ok(ifx) => ifx,
        Err(e) => {
            warn!(context.log, "solicit inactive peer {}: {}", solicit.src, e);
            return Err(e);
        }
    };

    let mut prefixes = locals;
    for (_, x) in remotes {
        prefixes.extend(x.iter());
    }

    let result = Advertise {
        prefixes,
        nexthop: ifx.ll_addr,
    };

    trace!(context.log, "solicit result: {:#?}", result);

    Ok(HttpResponseOk(result))
}

pub async fn advertise(
    nexthop: Ipv6Addr,
    prefixes: HashSet<Ipv6Prefix>,
    scope: i32,
    dest: Ipv6Addr,
    dest_port: u16,
) -> Result<(), String> {
    let msg = Advertise { nexthop, prefixes };

    let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;

    let uri = format!("http://[{}%{}]:{}/advertise", dest, scope, dest_port,);

    let client = hyper::Client::new();
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(&uri)
        .body(hyper::Body::from(json))
        .map_err(|e| e.to_string())?;

    let resp = client.request(req);

    match timeout(Duration::from_millis(250), resp).await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("peer request timeout to {}: {}", uri, e)),
    }
}

pub async fn solicit(
    src: Ipv6Addr,
    scope: i32,
    dest: Ipv6Addr,
    dest_port: u16,
) -> Result<Advertise, String> {
    let msg = Solicit { src };

    let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;

    let uri = format!("http://[{}%{}]:{}/solicit", dest, scope, dest_port,);

    let client = hyper::Client::new();
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(&uri)
        .body(hyper::Body::from(json))
        .map_err(|e| e.to_string())?;

    let resp = client.request(req);

    let mut response = match timeout(Duration::from_millis(250), resp).await {
        Ok(resp) => match resp {
            Ok(r) => match r.status() {
                hyper::StatusCode::OK => r,
                code => {
                    return Err(format!("http response code: {}", code));
                }
            },
            Err(e) => {
                return Err(format!("hyper send request to {}: {}", &uri, e,))
            }
        },
        Err(e) => {
            return Err(format!("peer request timeout to {}: {}", uri, e))
        }
    };

    let body = match response.body_mut().data().await {
        Some(body) => body.map_err(|e| e.to_string())?,
        None => return Err("no body found".to_string()),
    };

    let advertisement: Advertise =
        serde_json::from_slice(body.as_ref()).map_err(|e| e.to_string())?;

    Ok(advertisement)
}
