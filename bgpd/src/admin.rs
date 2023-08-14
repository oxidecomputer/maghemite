use bgp::connection::BgpConnectionTcp;
use bgp::messages::Message;
use bgp::router::Router;
use bgp::session::{Asn, FsmEvent, NeighborInfo, Session, SessionRunner};
use bgp::state::BgpState;
use colored::*;
use dropshot::{
    endpoint, ApiDescription, ConfigDropshot, ConfigLogging,
    ConfigLoggingLevel, HttpError, HttpResponseUpdatedNoContent,
    HttpServerStarter, RequestContext, TypedBody,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{debug, error, info, warn, Logger};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::spawn;
use std::time::Duration;
use tokio::task::JoinHandle;

pub struct HandlerContext {
    config: RouterConfig,
    router: Arc<Router<BgpConnectionTcp>>,
    log: Logger,
}

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

    info!(log, "add neighbor: {:#?}", rq);

    spawn(move || {
        run_session(rq, ctx.context(), log);
    });

    Ok(HttpResponseUpdatedNoContent())
}

fn run_session(rq: AddNeighborRequest, ctx: &HandlerContext, log: Logger) {
    let session = Session::new(
        /*
        Duration::from_secs(rq.hold_time),
        Duration::from_secs(rq.delay_open),
        */
    );

    let (to_session_tx, to_session_rx) = channel();
    let (from_session_tx, from_session_rx) = channel();

    ctx.router
        .addr_to_session
        .lock()
        .unwrap()
        .insert(rq.host.ip(), to_session_tx.clone());

    let bgp_state = Arc::new(Mutex::new(BgpState::default()));

    let neighbor = NeighborInfo {
        name: rq.name,
        host: rq.host,
    };

    let mut runner = SessionRunner::new(
        Duration::from_secs(rq.connect_retry),
        Duration::from_secs(rq.keepalive),
        Duration::from_secs(rq.hold_time),
        Duration::from_secs(rq.idle_hold_time),
        Duration::from_secs(rq.delay_open),
        session,
        to_session_rx,
        from_session_tx,
        bgp_state,
        neighbor.clone(),
        ctx.config.asn,
        ctx.config.id,
        Duration::from_millis(rq.resolution),
        log.clone(),
    );

    let lg = log.clone();
    let j = spawn(move || {
        let rx = from_session_rx;
        loop {
            match rx.recv().unwrap() {
                FsmEvent::Transition(from, to) => {
                    info!(
                        lg,
                        "{} {} {} {} {}",
                        format!("[{}]", neighbor.name).dimmed(),
                        "transition".blue(),
                        from,
                        "->".dimmed(),
                        to,
                    );
                }

                FsmEvent::Message(m) => {
                    if m == Message::KeepAlive {
                        debug!(
                            lg,
                            "{} {} {:#?}",
                            format!("[{}]", neighbor.name).dimmed(),
                            "message".blue(),
                            m,
                        );
                    } else {
                        info!(
                            lg,
                            "{} {} {:#?}",
                            format!("[{}]", neighbor.name).dimmed(),
                            "message".blue(),
                            m,
                        );
                    }
                }

                eve => {
                    info!(lg, "event: {:#?}", eve);
                }
            };
        }
    });

    spawn(move || {
        runner.start();
    });

    to_session_tx.send(FsmEvent::ManualStart).unwrap();

    j.join().unwrap();
}

pub struct RouterConfig {
    pub asn: Asn,
    pub id: u32,
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
