use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use std::sync::Arc;
use tokio::task::JoinHandle;

use dropshot::endpoint;
use dropshot::ApiDescription;
use dropshot::ConfigDropshot;
use dropshot::ConfigLogging;
use dropshot::ConfigLoggingLevel;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpServerStarter;
use dropshot::RequestContext;
use dropshot::TypedBody;
use slog::error;
use slog::info;
use slog::warn;
use slog::Logger;
use tokio::spawn;

use crate::net::Ipv6Prefix;
use crate::peer;
use crate::router::Router;

pub struct HandlerContext {
    pub router: Arc<Router>,
}

#[endpoint { method = GET, path = "/peers" }]
async fn get_peers(
    ctx: Arc<RequestContext<HandlerContext>>,
) -> Result<HttpResponseOk<HashMap<usize, peer::Status>>, HttpError> {
    let mut result = HashMap::new();

    let context = ctx.context();
    let state = context.router.state.lock().await;

    for (ifx, nbr) in &state.interfaces {
        let nbr = match nbr {
            Some(nbr) => nbr,
            None => continue,
        };

        result.insert(ifx.ifnum as usize, nbr.session.status().await);
    }

    Ok(HttpResponseOk(result))
}

type PrefixMap = BTreeMap<Ipv6Addr, HashSet<Ipv6Prefix>>;

#[endpoint { method = GET, path = "/prefixes" }]
async fn get_prefixes(
    ctx: Arc<RequestContext<HandlerContext>>,
) -> Result<HttpResponseOk<PrefixMap>, HttpError> {
    let context = ctx.context();
    let state = context.router.state.lock().await;

    Ok(HttpResponseOk(state.remote_prefixes.clone()))
}

#[endpoint { method = PUT, path = "/prefix" }]
async fn advertise_prefixes(
    ctx: Arc<RequestContext<HandlerContext>>,
    request: TypedBody<HashSet<Ipv6Prefix>>,
) -> Result<HttpResponseOk<()>, HttpError> {
    let context = ctx.context();
    let router = &context.router;

    router
        .advertise(request.into_inner())
        .await
        .map_err(|e| HttpError::for_internal_error(e))?;

    Ok(HttpResponseOk(()))
}

pub fn start_server(
    log: Logger,
    addr: Ipv6Addr,
    port: u16,
    router: Arc<Router>,
) -> Result<JoinHandle<()>, String> {
    let sa = SocketAddrV6::new(addr, port, 0, 0);

    let config = ConfigDropshot {
        bind_address: sa.into(),
        ..Default::default()
    };

    let ds_log = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Error,
    }
    .to_logger("admin")
    .map_err(|e| e.to_string())?;

    let mut api = ApiDescription::new();
    api.register(get_peers).unwrap();
    api.register(get_prefixes).unwrap();
    api.register(advertise_prefixes).unwrap();

    let context = HandlerContext { router };

    let server = HttpServerStarter::new(&config, api, context, &ds_log)
        .map_err(|e| format!("new admin dropshot: {}", e))?;

    info!(log, "admin: listening on {}", sa);

    let log = log.clone();
    Ok(spawn(async move {
        match server.start().await {
            Ok(_) => warn!(log, "admin: unexpected server exit"),
            Err(e) => error!(log, "admin: server start error {:?}", e),
        }
    }))
}

pub fn api_description() -> Result<ApiDescription<HandlerContext>, String> {
    let mut api = ApiDescription::new();
    api.register(get_peers)?;
    api.register(advertise_prefixes)?;
    api.register(get_prefixes)?;
    Ok(api)
}
