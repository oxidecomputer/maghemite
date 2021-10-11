// Copyright 2021 Oxide Computer Company

use tokio::{
    sync::mpsc::{channel, Sender, Receiver},
};
use std::net::{SocketAddr, SocketAddrV6, Ipv6Addr};
use rift::TOPOLOGYINFO_PORT;
use rift_protocol::tie::TIEPacket;
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
use std::sync::Arc;

pub(crate) struct TopologyHandlerContext {
    tx: Sender<TIEPacket>,
}

#[endpoint {
    method = POST,
    path = "/topoinfo"
}]
async fn riftp_topologyinfo(
    ctx: Arc<RequestContext<TopologyHandlerContext>>,
    rq: TypedBody<TIEPacket>,
) -> Result<HttpResponseOk<()>, HttpError> {

    let api_context = ctx.context();

    match api_context.tx.send(rq.into_inner()).await {
        Ok(_) => Ok(HttpResponseOk(())),
        Err(e) => Err(HttpError::for_internal_error(format!(
            "error consuming TIEPacket: {}", e
        ))),
    }


}

pub(crate) fn topology_handler(tx: Sender<TIEPacket>)
-> Result<HttpServer<TopologyHandlerContext>, String> {

    let sa = SocketAddr::V6(
        SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, TOPOLOGYINFO_PORT, 0, 0)
    );
    let config_dropshot = ConfigDropshot{
        bind_address: sa,
        ..Default::default()
    };

    let config_logging = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Info,
    };
    let log = config_logging
        .to_logger("riftp_topology_handler")
        .map_err(|e| format!("config dropshot logger: {}", e))?;

    let mut api = ApiDescription::new();
    api.register(riftp_topologyinfo).unwrap();

    let api_context = TopologyHandlerContext{tx: tx};

    Ok(HttpServerStarter::new(
        &config_dropshot,
        api,
        api_context,
        &log,
    ).map_err(|e| format!("create dropshot topology server: {}", e))?
     .start())


}
