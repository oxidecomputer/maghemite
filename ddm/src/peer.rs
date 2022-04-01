use std::sync::Arc;
use tokio::sync::Mutex;
use std::net::{SocketAddr, SocketAddrV6, Ipv6Addr};
use tokio::sync::mpsc::Sender;
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
    HttpServer,
    TypedBody,
};

use crate::protocol::{PEERING_PORT, PeerMessage};

pub(crate) struct PeerHandlerContext {
    tx: Arc::<Mutex::<Sender<PeerMessage>>>,
}

#[endpoint {
    method = POST,
    path = "/peer"
}]
async fn ddm_peer(
    ctx: Arc::<RequestContext::<PeerHandlerContext>>,
    rq: TypedBody<PeerMessage>,
) -> Result<HttpResponseOk<()>, HttpError> {

    let api_context = ctx.context();
    let tx = api_context.tx.lock().await;

    match (*tx).send(rq.into_inner()).await {
        Ok(_) => Ok(HttpResponseOk(())),
        Err(e) => Err(HttpError::for_internal_error(format!(
            "error consuming peer message: {}", e
        ))),
    }

}

pub(crate) fn peer_handler(
    addr: Ipv6Addr, 
    tx: Arc::<Mutex::<Sender<PeerMessage>>>,
    _log: slog::Logger,
) -> Result<HttpServer<PeerHandlerContext>, String> {

    let sa = SocketAddr::V6(
        SocketAddrV6::new(addr, PEERING_PORT, 0, 0)
    );
    let config_dropshot = ConfigDropshot {
        bind_address: sa,
        ..Default::default()
    };

    // this logging gets real noisy with modest message exchange rates
    let log =
        ConfigLogging::StderrTerminal {
            level: ConfigLoggingLevel::Error,
        }
        .to_logger("peer")
        .map_err(|e| e.to_string())?;

    let mut api = ApiDescription::new();
    api.register(ddm_peer).unwrap();

    let api_context = PeerHandlerContext{tx: tx};

    Ok(HttpServerStarter::new(
        &config_dropshot,
        api,
        api_context,
        &log,
    ).map_err(|e| format!("create dropshot peer server: {}", e))?
     .start())
}
