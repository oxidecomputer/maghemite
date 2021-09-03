// Copyright 2021 Oxide Computer Company

use std::sync::{Arc, Mutex};
use std::net::{SocketAddr, SocketAddrV6, Ipv6Addr};
use std::sync::mpsc::Sender;
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
use rift::LINKINFO_PORT;
use rift_protocol::LinkInfo;

struct LinkHandlerContext {
    tx: Arc::<Mutex::<Sender<LinkInfo>>>,
}

#[endpoint {
    method = POST,
    path = "linkinfo"
}]
async fn riftp_linkinfo(
    ctx: Arc<RequestContext<LinkHandlerContext>>,
    rq: TypedBody<LinkInfo>,
) -> Result<HttpResponseOk<()>, HttpError> {

    let api_context = ctx.context();
    let tx = api_context.tx.lock().unwrap();

    match (*tx).send(rq.into_inner()) {
        Ok(_) => Ok(HttpResponseOk(())),
        Err(e) => Err(HttpError::for_internal_error(format!(
            "error consuming LinkInfo: {}", e
        ))),
    }


}

pub(crate) async fn link_handler(
    addr: Ipv6Addr, 
    tx: Arc::<Mutex::<Sender<LinkInfo>>>,
) -> Result<(), String> {

    let sa = SocketAddr::V6(
        SocketAddrV6::new(addr, LINKINFO_PORT, 0, 0)
    );
    let config_dropshot = ConfigDropshot {
        bind_address: sa,
        ..Default::default()
    };

    let config_logging = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Info,
    };
    let log = config_logging
        .to_logger("riftp_link_handler")
        .map_err(|e| format!("config dropshot logger: {}", e))?;

    let mut api = ApiDescription::new();
    api.register(riftp_linkinfo).unwrap();

    let api_context = LinkHandlerContext{tx: tx};

    let server = HttpServerStarter::new(
        &config_dropshot,
        api,
        api_context,
        &log,
    ).map_err(|e| format!("create dropshot link server: {}", e))?
     .start();

    server.await

}
