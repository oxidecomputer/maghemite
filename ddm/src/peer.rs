use std::sync::Arc;
use tokio::sync::Mutex;
use std::net::{SocketAddr, SocketAddrV6, Ipv6Addr};
use tokio::sync::mpsc::Sender;
use dropshot::{
    endpoint,
    ConfigDropshot,
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
    log: slog::Logger,
) -> Result<HttpServer<PeerHandlerContext>, String> {

    let sa = SocketAddr::V6(
        SocketAddrV6::new(addr, PEERING_PORT, 0, 0)
    );
    let config_dropshot = ConfigDropshot {
        bind_address: sa,
        ..Default::default()
    };

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
