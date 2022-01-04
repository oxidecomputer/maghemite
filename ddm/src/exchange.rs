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

use crate::protocol::{PREFIX_EXCHANGE_PORT, DdmMessage};

pub(crate) struct PrefixHandlerContext {
    tx: Arc::<Mutex::<Sender<DdmMessage>>>,
}

#[endpoint {
    method = POST,
    path = "/prefix"
}]
async fn ddm_prefix(
    ctx: Arc::<RequestContext::<PrefixHandlerContext>>,
    rq: TypedBody<DdmMessage>,
) -> Result<HttpResponseOk<()>, HttpError> {

    let api_context = ctx.context();
    let tx = api_context.tx.lock().await;

    match (*tx).send(rq.into_inner()).await {
        Ok(_) => Ok(HttpResponseOk(())),
        Err(e) => Err(HttpError::for_internal_error(format!(
            "error consuming prefix exchange message: {}", e
        ))),
    }

}

pub(crate) fn prefix_handler(
    addr: Ipv6Addr, 
    tx: Arc::<Mutex::<Sender<DdmMessage>>>,
    log: slog::Logger,
) -> Result<HttpServer<PrefixHandlerContext>, String> {

    let sa = SocketAddr::V6(
        SocketAddrV6::new(addr, PREFIX_EXCHANGE_PORT, 0, 0)
    );
    let config_dropshot = ConfigDropshot {
        bind_address: sa,
        ..Default::default()
    };

    let mut api = ApiDescription::new();
    api.register(ddm_prefix).unwrap();

    let api_context = PrefixHandlerContext{tx: tx};

    Ok(HttpServerStarter::new(
        &config_dropshot,
        api,
        api_context,
        &log,
    ).map_err(|e| format!("create dropshot prefix exchange server: {}", e))?
     .start())
}
