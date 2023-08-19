use bgp::config::{PeerConfig, RouterConfig};
use bgp::connection::BgpConnectionTcp;
use bgp::router::Router;
use bgp::session::FsmEvent;
use dropshot::{
    endpoint, ApiDescription, ConfigDropshot, ConfigLogging,
    ConfigLoggingLevel, HttpError, HttpResponseUpdatedNoContent,
    HttpServerStarter, RequestContext, TypedBody,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{error, info, warn, Logger};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::mpsc::channel;
use std::sync::Arc;
use tokio::task::JoinHandle;

pub struct HandlerContext {
    #[allow(dead_code)]
    config: RouterConfig,
    router: Arc<Router<BgpConnectionTcp>>,
    log: Logger,
}

//TODO use bgp::config::PeerConfig instead
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddNeighborRequest {
    pub name: String,
    pub host: SocketAddr,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
}

#[endpoint { method = POST, path = "/neighbor" }]
async fn add_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddNeighborRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let log = ctx.context().log.clone();
    let rq = request.into_inner();
    let db = rdb::Db::new("/var/run/rdb").unwrap();

    info!(log, "add neighbor: {:#?}", rq);

    let (event_tx, event_rx) = channel();

    ctx.context().router.new_session(
        PeerConfig {
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
        },
        "0.0.0.0".parse().unwrap(),
        event_tx.clone(),
        event_rx,
        db,
    );
    event_tx.send(FsmEvent::ManualStart).unwrap();

    Ok(HttpResponseUpdatedNoContent())
}

pub fn start_server(
    log: Logger,
    addr: Ipv6Addr,
    port: u16,
    config: RouterConfig,
    router: Arc<Router<BgpConnectionTcp>>,
) -> Result<JoinHandle<()>, String> {
    let sa = SocketAddrV6::new(addr, port, 0, 0);

    let ds_config = ConfigDropshot {
        bind_address: sa.into(),
        ..Default::default()
    };

    let ds_log = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Error,
    }
    .to_logger("admin")
    .map_err(|e| e.to_string())?;

    let api = api_description();

    let context = Arc::new(HandlerContext {
        config,
        router,
        log: log.clone(),
    });

    let server = HttpServerStarter::new(&ds_config, api, context, &ds_log)
        .map_err(|e| format!("new admin dropshot: {}", e))?;

    info!(log, "admin: listening on {}", sa);

    let log = log.clone();
    Ok(tokio::spawn(async move {
        match server.start().await {
            Ok(_) => warn!(log, "admin: unexpected server exit"),
            Err(e) => error!(log, "admin: server start error {:?}", e),
        }
    }))
}

pub fn api_description() -> ApiDescription<Arc<HandlerContext>> {
    let mut api = ApiDescription::new();
    api.register(add_neighbor).unwrap();
    api
}
