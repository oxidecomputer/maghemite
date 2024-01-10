// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{bgp_admin, static_admin};
use bgp_admin::BgpContext;
use dropshot::{ApiDescription, ConfigDropshot, HttpServerStarter};
use rdb::Db;
use slog::o;
use slog::{error, info, warn, Logger};
use std::fs::File;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;

pub struct HandlerContext {
    pub tep: Ipv6Addr, // tunnel endpoint address
    pub bgp: BgpContext,
    pub log: Logger,
    pub data_dir: String,
    pub db: Db,
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

macro_rules! register {
    ($api:expr, $endpoint:expr) => {
        $api.register($endpoint).expect(stringify!($endpoint))
    };
}

pub fn api_description() -> ApiDescription<Arc<HandlerContext>> {
    let mut api = ApiDescription::new();

    // bgp
    register!(api, bgp_admin::get_routers);
    register!(api, bgp_admin::new_router);
    register!(api, bgp_admin::ensure_router_handler);
    register!(api, bgp_admin::delete_router);
    register!(api, bgp_admin::add_neighbor_handler);
    register!(api, bgp_admin::ensure_neighbor_handler);
    register!(api, bgp_admin::delete_neighbor);
    register!(api, bgp_admin::originate4);
    register!(api, bgp_admin::withdraw4);
    register!(api, bgp_admin::get_originated4);
    register!(api, bgp_admin::get_imported4);
    register!(api, bgp_admin::bgp_apply);
    register!(api, bgp_admin::graceful_shutdown);

    // static
    register!(api, static_admin::static_add_v4_route);
    register!(api, static_admin::static_remove_v4_route);
    register!(api, static_admin::static_list_v4_routes);

    api
}

pub fn apigen() {
    let api = api_description();
    let openapi = api.openapi("Maghemite Admin", "v0.1.0");
    let mut out = File::create("mg-admin.json").expect("create json api file");
    openapi.write(&mut out).expect("write json api file");
}
