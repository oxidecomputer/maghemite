use crate::bgp_admin;
use bgp_admin::BgpContext;
use dropshot::{ApiDescription, ConfigDropshot, HttpServerStarter};
use slog::o;
use slog::{error, info, warn, Logger};
use std::fs::File;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;

pub struct HandlerContext {
    pub bgp: BgpContext,
    pub log: Logger,
    pub data_dir: String,
}

pub fn start_server(
    log: Logger,
    addr: IpAddr,
    port: u16,
    context: Arc<HandlerContext>,
) -> Result<JoinHandle<()>, String> {
    let sa = SocketAddr::new(addr, port);

    let ds_config = ConfigDropshot {
        bind_address: sa,
        ..Default::default()
    };

    let ds_log = log.new(o!("unit" => "api-server"));

    let api = api_description();

    let server = HttpServerStarter::new(&ds_config, api, context, &ds_log)
        .map_err(|e| format!("new admin dropshot: {}", e))?;

    info!(log, "admin: listening on {}", sa);

    Ok(tokio::spawn(async move {
        match server.start().await {
            Ok(_) => warn!(log, "admin: unexpected server exit"),
            Err(e) => error!(log, "admin: server start error {:?}", e),
        }
    }))
}

pub fn api_description() -> ApiDescription<Arc<HandlerContext>> {
    let mut api = ApiDescription::new();
    api.register(bgp_admin::get_routers).unwrap();
    api.register(bgp_admin::new_router).unwrap();
    api.register(bgp_admin::ensure_router).unwrap();
    api.register(bgp_admin::delete_router).unwrap();
    api.register(bgp_admin::add_neighbor).unwrap();
    api.register(bgp_admin::ensure_neighbor).unwrap();
    api.register(bgp_admin::delete_neighbor).unwrap();
    api.register(bgp_admin::originate4).unwrap();
    api.register(bgp_admin::get_originated4).unwrap();
    api.register(bgp_admin::get_imported4).unwrap();
    api
}

pub fn apigen() {
    let api = api_description();
    let openapi = api.openapi("Maghemite Admin", "v0.1.0");
    let mut out = File::create("mg-admin.json").unwrap();
    openapi.write(&mut out).unwrap();
}
