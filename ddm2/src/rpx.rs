// Router Prefix Exchange

use std::net::{SocketAddrV6, Ipv6Addr};
use std::sync::Arc;
use std::collections::HashSet;
use std::time::Duration;

use tokio::{spawn, time::timeout, task::JoinHandle};
use slog::{warn, error};
use dropshot::{
    endpoint,
    ConfigDropshot,
    ConfigLogging,
    ConfigLoggingLevel,
    ApiDescription,
    HttpServerStarter,
    RequestContext,
    HttpResponseOk,
    HttpError,
    TypedBody,
};

use crate::net::Ipv6Prefix;
use crate::protocol::Advertise;
use crate::router::Router;
use crate::peer;

struct HandlerContext {
    router: Router,
}

pub(crate) fn start_server(
    addr: Ipv6Addr, 
    port: u16,
    router: Router,
) -> Result<JoinHandle<()>, String> {

    let sa = SocketAddrV6::new(addr, port, 0, 0);
    let config = ConfigDropshot {
        bind_address: sa.into(),
        ..Default::default()
    };
    let log =
        ConfigLogging::StderrTerminal{level: ConfigLoggingLevel::Error}
        .to_logger("rpx")
        .map_err(|e| e.to_string())?;

    let mut api = ApiDescription::new();
    api.register(advertise_handler).unwrap();

    let context = HandlerContext{router};

    let server = HttpServerStarter::new(
        &config,
        api,
        context,
        &log,
    ).map_err(|e| format!("new rpx dropshot: {}", e))?;

    Ok(spawn(async move {
        match server.start().await {
            Ok(_) => warn!(log, "rpx: unexpected server exit"),
            Err(e) => error!(log, "rpx: server start error {:?}", e),
        }
    }))
}

#[endpoint {
    method = POST,
    path = "/advertise"
}]
async fn advertise_handler(
    ctx: Arc::<RequestContext::<HandlerContext>>,
    rq: TypedBody<Advertise>,
) -> Result<HttpResponseOk<()>, HttpError> {

    let context = ctx.context();
    let router = &context.router;
    let mut router_state = router.state.lock().await;
    let advertisement = rq.into_inner();

    let mut found = false;
    let peers = router.peer_status().await;
    for (ifx, status) in peers.iter() {
        if ifx.ll_addr == advertisement.nexthop {
            found = true;
            if status != &Some(peer::Status::Active) {
                return Err(
                    HttpError::for_bad_request(
                        None, "peer not active for nexthop".into())
                )
            }
            break;
        }
    }
    if !found {
        return Err(
            HttpError::for_bad_request(None, "peer not found for nexthop".into())
        );
    }

    match router_state.remote_prefixes.get_mut(&advertisement.nexthop) {
        Some(ref mut set) => {
            set.extend(advertisement.prefixes.iter());
        }
        None => {
            router_state.remote_prefixes.insert(
                advertisement.nexthop,
                advertisement.prefixes.clone()
            );
        }
    }

    Ok(HttpResponseOk(()))
}


pub async fn advertise(
    origin: String,
    nexthop: Ipv6Addr,
    prefixes: HashSet::<Ipv6Prefix>,
    scope: i32,
    dest: Ipv6Addr,
    dest_port: u16,
    serial: u64,
) -> Result<(), String> {

    let msg = Advertise{
        origin,
        nexthop,
        prefixes,
        serial,
    };

    let json = serde_json::to_string(&msg)
        .map_err(|e| e.to_string())?;

    let uri = format!("http://[{}%{}]:{}/ping",
        dest,
        scope,
        dest_port,
    );

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
