/// This file contains the management interface implementation for the BFD
/// daemon. A REST-style API is provided via Dropshot.
use crate::udp;
use anyhow::Result;
use bfd::{Daemon, PeerState};
use dropshot::endpoint;
use dropshot::ApiDescription;
use dropshot::ConfigDropshot;
use dropshot::ConfigLogging;
use dropshot::ConfigLoggingLevel;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::HttpServerStarter;
use dropshot::Path;
use dropshot::RequestContext;
use dropshot::TypedBody;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{error, info, warn, Logger};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::spawn;

/// Context for Dropshot requests.
#[derive(Clone)]
pub struct HandlerContext {
    /// The underlying deamon being run.
    daemon: Arc<Mutex<Daemon>>,
}

impl HandlerContext {
    fn new(daemon: Arc<Mutex<Daemon>>) -> Self {
        Self { daemon }
    }
}

/// Create a request handler and start the dropshot server in a new thread.
pub fn handler(
    daemon: Arc<Mutex<Daemon>>,
    addr: IpAddr,
    port: u16,
    log: Logger,
) -> Result<()> {
    let context = HandlerContext::new(daemon);

    let sa: SocketAddr = match addr {
        IpAddr::V4(a) => SocketAddrV4::new(a, port).into(),
        IpAddr::V6(a) => SocketAddrV6::new(a, port, 0, 0).into(),
    };

    let config = ConfigDropshot {
        bind_address: sa,
        ..Default::default()
    };

    let ds_log = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Error,
    }
    .to_logger("admin")?;

    let api = api_description();

    info!(log, "admin: listening on {}", sa);

    let log = log.clone();

    spawn(async move {
        let server = HttpServerStarter::new(&config, api, context, &ds_log)
            .map_err(|e| format!("new admin dropshot: {}", e))
            .unwrap();

        match server.start().await {
            Ok(_) => warn!(log, "admin: unexpected server exit"),
            Err(e) => error!(log, "admin: server start error {:?}", e),
        }
    });

    Ok(())
}

/// Get all the peers and their associated BFD state. Peers are identified by IP
/// address.
#[endpoint { method = GET, path = "/peers" }]
async fn get_peers(
    ctx: RequestContext<HandlerContext>,
) -> Result<HttpResponseOk<HashMap<IpAddr, PeerState>>, HttpError> {
    let result = ctx
        .context()
        .daemon
        .lock()
        .unwrap()
        .sessions
        .iter()
        .map(|(addr, session)| (*addr, session.sm.current()))
        .collect();

    Ok(HttpResponseOk(result))
}

/// Request to add a peer to the daemon.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct AddPeerRequest {
    /// Address of the peer to add.
    pub peer: IpAddr,
    /// Address to listen on for control messages from the peer.
    pub listen: IpAddr,
    /// Acceptable time between control messages in microseconds.
    pub required_rx: u64,
    /// Detection threshold for connectivity as a multipler to required_rx
    pub detection_threshold: u8,
}

/// Add a new peer to the daemon. A session for the specified peer will start
/// immediately.
#[endpoint { method = PUT, path = "/peers" }]
async fn add_peer(
    ctx: RequestContext<HandlerContext>,
    request: TypedBody<AddPeerRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let mut daemon = ctx.context().daemon.lock().unwrap();
    let rq = request.into_inner();

    if daemon.sessions.get(&rq.peer).is_some() {
        return Ok(HttpResponseUpdatedNoContent {});
    }

    let ch =
        udp::channel(rq.listen, rq.peer, ctx.log.clone()).map_err(|e| {
            error!(ctx.log, "udp channel: {e}");
            HttpError::for_internal_error(e.to_string())
        })?;

    let timeout = Duration::from_micros(rq.required_rx);
    daemon.add_peer(rq.peer, timeout, rq.detection_threshold, ch);

    Ok(HttpResponseUpdatedNoContent {})
}

/// Request to remove a peer form the daemon.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
struct DeletePeerPathParams {
    /// Address of the peer to remove.
    pub addr: IpAddr,
}

/// Remove the specified peer from the daemon. The associated peer session will
/// be stopped immediately.
#[endpoint { method = DELETE, path = "/peers/{addr}" }]
async fn remove_peer(
    ctx: RequestContext<HandlerContext>,
    params: Path<DeletePeerPathParams>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let mut daemon = ctx.context().daemon.lock().unwrap();
    let rq = params.into_inner();

    daemon.remove_peer(rq.addr);

    Ok(HttpResponseUpdatedNoContent {})
}

/// Get an OpenAPI 3 description of the BFD daemon management API.
pub fn api_description() -> ApiDescription<HandlerContext> {
    let mut api = ApiDescription::new();
    api.register(get_peers).expect("register get_peers");
    api.register(add_peer).expect("register add_peer");
    api.register(remove_peer).expect("register remove_peer");
    api
}

/// Dump a JSON formatted OpenAPI spec to stdout.
pub fn dump_spec() {
    let api = api_description();
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    api.openapi("BFD Admin", "v0.1.0")
        .write(&mut handle)
        .expect("write API to stdout");
}
