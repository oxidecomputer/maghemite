// Copyright 2021 Oxide Computer Company

use crate::{Rift, link::LinkSM, link::LinkSMState, topology::LSDBEntry};
use tokio::sync::Mutex;
use std::sync::Arc;
use std::collections::{HashSet, HashMap};
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
use platform::Platform;
use slog::error;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};

impl<P: Platform + std::marker::Send> Rift<P> {

    pub(crate) fn admin_handler(&self) {

        let log = self.log.clone();
        let links = self.links.clone();
        let lsdb = self.lsdb.clone();

        tokio::spawn(async move {
            match handler(links, lsdb).await {
                Ok(_) => {},
                Err(e) => error!(log, "failed to start adm handler {}", e),
            }
        });

    }

}

struct RiftAdmContext {
    links: Arc::<Mutex::<HashSet::<LinkSM>>>,
    lsdb: Arc::<Mutex::<HashSet<LSDBEntry>>>,
}

#[endpoint { method = GET, path = "/links" }]
async fn adm_api_get_links (
    ctx: Arc<RequestContext<RiftAdmContext>>,
) -> Result<HttpResponseOk<HashMap::<String, LinkSMState>>, HttpError> {

    let api_context = ctx.context();

    let mut result: HashMap::<String, LinkSMState> = HashMap::new();

    {
        let links = api_context.links.lock().await;
        for l in links.iter() {
            let link_state = l.state.lock().await;
            result.insert(l.link_name.clone(), link_state.clone());
        }
    }

    Ok(HttpResponseOk(result))

}

#[endpoint { method = GET, path = "/lsdb" }]
async fn adm_api_get_lsdb (
    ctx: Arc<RequestContext<RiftAdmContext>>,
) -> Result<HttpResponseOk<HashSet<LSDBEntry>>, HttpError> {

    let api_context = ctx.context();
    let result = api_context.lsdb.lock().await.clone();

    Ok(HttpResponseOk(result))

}


async fn handler (
    links: Arc::<Mutex::<HashSet::<LinkSM>>>,
    lsdb: Arc::<Mutex::<HashSet<LSDBEntry>>>,
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
    api.register(adm_api_get_links).unwrap(); //TODO no unwrap
    api.register(adm_api_get_lsdb).unwrap();  //TODO no unwrap

    let api_context = RiftAdmContext{
        links: links.clone(),
        lsdb: lsdb.clone(),
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

