// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{bfd_admin, bgp_admin, static_admin};
use bfd_admin::BfdContext;
use bgp_admin::BgpContext;
use dropshot::{ApiDescription, ConfigDropshot, HttpServerStarter};
use mg_common::stats::MgLowerStats;
use rdb::Db;
use semver::{BuildMetadata, Prerelease, Version};
use slog::o;
use slog::{error, info, warn, Logger};
use std::fs::File;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

pub struct HandlerContext {
    pub tep: Ipv6Addr, // tunnel endpoint address
    pub bgp: BgpContext,
    pub bfd: BfdContext,
    pub log: Logger,
    pub data_dir: String,
    pub db: Db,
    pub mg_lower_stats: Arc<MgLowerStats>,
    pub stats_server_running: Mutex<bool>,
    pub oximeter_port: u16,
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
        default_request_body_max_bytes: 1024 * 1024 * 1024,
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

#[macro_export]
macro_rules! register {
    ($api:expr, $endpoint:expr) => {
        $api.register($endpoint).expect(stringify!($endpoint))
    };
}

pub fn api_description() -> ApiDescription<Arc<HandlerContext>> {
    let mut api = ApiDescription::new();

    bgp_admin::api_description(&mut api);
    static_admin::api_description(&mut api);
    bfd_admin::api_description(&mut api);

    api
}

pub fn apigen() {
    let api = api_description();
    let openapi = api.openapi(
        "Maghemite Admin",
        Version {
            major: 0,
            minor: 1,
            patch: 0,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        },
    );
    let mut out = File::create("mg-admin.json").expect("create json api file");
    openapi.write(&mut out).expect("write json api file");
}
