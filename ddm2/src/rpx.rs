// Router Prefix Exchange
use std::net::{SocketAddrV6, Ipv6Addr};
use std::sync::Arc;
use std::collections::HashSet;

use tokio::{spawn, sync::Mutex, task::JoinHandle};
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
use crate::router::RouterState;

struct HandlerContext {
    state: Arc::<Mutex::<RouterState>>,
}

pub(crate) fn start_server(
    addr: Ipv6Addr, 
    port: u16,
    state: Arc::<Mutex::<RouterState>>,
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

    let context = HandlerContext{state};

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
    let mut router_state = context.state.lock().await;
    let advertisement = rq.into_inner();

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
    _prefixes: &HashSet::<Ipv6Prefix>,
    _dest: Ipv6Addr,
) -> Result<(), String> {
    todo!();
}
