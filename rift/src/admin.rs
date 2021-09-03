// Copyright 2021 Oxide Computer Company

use crate::{Rift, Peer};
use std::sync::{Arc, Mutex};
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
};
use std::collections::HashSet;
use platform::Platform;
use slog::error;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};

impl<P: Platform + std::marker::Send> Rift<P> {

    pub(crate) fn admin_handler(&self) {

        let peers = self.peers.clone();
        let log = self.log.clone();

        tokio::spawn(async move {
            match handler(peers).await {
                Ok(_) => {},
                Err(e) => error!(log, "failed to start adm handler {}", e),
            }
        });

    }

}

struct RiftAdmContext {
    peers: Arc::<Mutex::<HashSet::<Peer>>>,
}

#[endpoint {
    method = GET,
    path = "/peers",
}]
async fn adm_api_get_peers(
    ctx: Arc<RequestContext<RiftAdmContext>>,
) -> Result<HttpResponseOk<Vec::<Peer>>, HttpError> {

    let api_context = ctx.context();

    let mut vec: Vec::<Peer> = Vec::new();
    let peers = api_context.peers.lock().unwrap();

    for x in (*peers).iter() {
        vec.push(*x);
    }

    Ok(HttpResponseOk(vec))

}


async fn handler(
    peers: Arc::<Mutex::<HashSet::<Peer>>>,
) -> Result<(), String> {

    let addr = SocketAddr::V4(
        SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 7000)
    );
    let config_dropshot = ConfigDropshot {
        bind_address: addr,
        ..Default::default()
    };

    let config_logging = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Info,
    };
    let log = config_logging
        .to_logger("rift")
        .map_err(|e| format!("config dropshot logger: {}", e))?;

    let mut api = ApiDescription::new();
    api.register(adm_api_get_peers).unwrap();

    let api_context = RiftAdmContext{
        peers: peers.clone(),
    };

    let server = HttpServerStarter::new(
        &config_dropshot,
        api,
        api_context,
        &log,
    ).map_err(|e| format!("create dropshot adm server: {}", e))?
     .start();

    server.await

}

