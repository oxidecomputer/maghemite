use bgp::config::{PeerConfig, RouterConfig};
use bgp::connection::BgpConnectionTcp;
use bgp::fanout::Rule4;
use bgp::router::Router;
use bgp::session::FsmEvent;
use dropshot::{
    endpoint, ApiDescription, ConfigDropshot, ConfigLogging,
    ConfigLoggingLevel, HttpError, HttpResponseOk,
    HttpResponseUpdatedNoContent, HttpServerStarter, RequestContext, TypedBody,
};
use rdb::{Policy, PolicyAction, Prefix4, Route4ImportKey, Route4Key};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{error, info, warn, Logger};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
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

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddExportPolicyRequest {
    /// Address of the peer to apply this policy to.
    pub addr: IpAddr,

    /// Prefix this policy applies to
    pub prefix: Prefix4,

    /// Priority of the policy, higher value is higher priority.
    pub priority: u16,

    /// The policy action to apply.
    pub action: PolicyAction,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Originate4Request {
    /// Nexthop to originate.
    pub nexthop: Ipv4Addr,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[endpoint { method = POST, path = "/neighbor" }]
async fn add_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddNeighborRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let log = ctx.context().log.clone();
    let rq = request.into_inner();

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
        "0.0.0.0:179".parse().unwrap(),
        event_tx.clone(),
        event_rx,
    );
    event_tx.send(FsmEvent::ManualStart).unwrap();

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = POST, path = "/export-policy" }]
pub async fn add_export_policy(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddExportPolicyRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();

    ctx.context().router.add_export_policy(
        rq.addr,
        Rule4 {
            prefix: rq.prefix,
            policy: Policy {
                action: rq.action,
                priority: rq.priority,
            },
        },
    );

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = POST, path = "/originate4" }]
pub async fn originate4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Originate4Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();

    ctx.context()
        .router
        .originate4(rq.nexthop, prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/originate4" }]
async fn get_originated4(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<Route4Key>>, HttpError> {
    let originated = ctx
        .context()
        .router
        .db
        .get_originated4()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseOk(originated))
}

#[endpoint { method = GET, path = "/imported4" }]
async fn get_imported4(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<Route4ImportKey>>, HttpError> {
    let imported = ctx.context().router.db.get_imported4();
    Ok(HttpResponseOk(imported))
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
    api.register(add_export_policy).unwrap();
    api.register(originate4).unwrap();
    api.register(get_originated4).unwrap();
    api.register(get_imported4).unwrap();
    api
}
