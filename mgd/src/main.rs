// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use crate::bfd_admin::BfdContext;
use crate::bgp_admin::BgpContext;
use crate::log::dlog;
use bgp::connection_tcp::{BgpConnectionTcp, BgpListenerTcp};
use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};
use mg_common::cli::oxide_cli_style;
use mg_common::lock;
use mg_common::log::init_logger;
use mg_common::stats::MgLowerStats;
use signal::handle_signals;
use slog::Logger;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread::Builder;
use uuid::Uuid;

pub const COMPONENT_MGD: &str = "mgd";
pub const MOD_ADMIN: &str = "admin";
const UNIT_DAEMON: &str = "daemon";

mod admin;
mod bfd_admin;
mod bgp_admin;
mod error;
mod log;
mod oxstats;
mod rib_admin;
mod signal;
mod smf;
mod static_admin;
mod unnumbered_manager;
mod validation;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, styles = oxide_cli_style())]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the mgd routing daemon.
    Run(RunArgs),
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Address to listen on for the admin API.
    #[arg(long, default_value_t = Ipv6Addr::UNSPECIFIED.into())]
    admin_addr: IpAddr,

    /// Port to listen on for the admin API.
    #[arg(long, default_value_t = 4676)]
    admin_port: u16,

    /// Write the socket address to this file, for use with test harnesses that
    /// tell mgd to bind to port 0.
    ///
    /// This file should not exist at process startup, though its parent
    /// directory should.
    #[arg(long)]
    admin_port_file: Option<Utf8PathBuf>,

    /// Do not run a BGP connection dispatcher.
    #[arg(long, default_value_t = false)]
    no_bgp_dispatcher: bool,

    /// Register as an oximemeter producer.
    #[arg(long)]
    with_stats: bool,

    /// DNS servers used to find nexus.
    #[arg(long)]
    dns_servers: Vec<String>,

    /// Port to listen on for the oximeter API.
    #[arg(long, default_value_t = 4677)]
    oximeter_port: u16,

    /// Id of the rack this router is running on.
    #[arg(long)]
    rack_uuid: Option<Uuid>,

    /// Id of the sled this router is running on.
    #[arg(long)]
    sled_uuid: Option<Uuid>,

    /// SocketAddr the MGS service is listening on.
    #[arg(long, default_value = "[::1]:12225")]
    mgs_addr: SocketAddr,

    /// SocketAddr for the BGP Dispatcher to listen on.
    #[arg(long, default_value = "[::]:179")]
    bgp_dispatcher_addr: SocketAddr,
}

fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Run(run_args) => oxide_tokio_rt::run(run(run_args)),
    }
}

async fn run(args: RunArgs) {
    let log = init_logger();

    let (sig_tx, sig_rx) = tokio::sync::mpsc::channel(1);
    handle_signals(sig_rx, log.clone())
        .await
        .expect("set up refresh signal handler");

    let db = rdb::Db::new(log.clone());
    let bgp = init_bgp(&args, &log);

    let tep_ula = get_tunnel_endpoint_ula();
    let bfd = BfdContext::new(log.clone());

    let context = Arc::new(HandlerContext {
        #[cfg(all(feature = "mg-lower", target_os = "illumos"))]
        tep: tep_ula,
        log: log.clone(),
        bgp,
        bfd,
        mg_lower_stats: Arc::new(MgLowerStats::default()),
        db: db.clone(),
        stats_server_running: Mutex::new(false),
        oximeter_port: args.oximeter_port,
    });

    detect_switch_slot(
        context.clone(),
        args.mgs_addr,
        tokio::runtime::Handle::current(),
    );

    if let Err(e) = sig_tx.send(context.clone()).await {
        dlog!(log, error, "error sending handler context to signal handler: {e}";
            "params" => format!("tep {tep_ula}, oximeter_port {}",
                args.oximeter_port
            ),
            "error" => format!("{e}")
        );
    }

    #[cfg(all(feature = "mg-lower", target_os = "illumos"))]
    {
        let rt = Arc::new(tokio::runtime::Handle::current());
        let ctx = context.clone();
        let log = log.clone();
        let db = ctx.db.clone();
        let stats = context.mg_lower_stats.clone();
        let dpd = mg_lower::ProductionDpd {
            client: mg_lower::new_dpd_client(&log),
        };
        let ddm = mg_lower::ProductionDdm {
            client: mg_lower::new_ddm_client(&log),
        };
        let sw = mg_lower::ProductionSwitchZone {};
        Builder::new()
            .name("mg-lower".to_string())
            .spawn(move || {
                mg_lower::run(ctx.tep, db, log, stats, rt, &dpd, &ddm, &sw);
            })
            .expect("failed to start mg-lower");
    }

    let hostname = hostname::get()
        .expect("failed to get hostname")
        .to_string_lossy()
        .to_string();

    if args.with_stats
        && let (Some(rack_uuid), Some(sled_uuid)) =
            (args.rack_uuid, args.sled_uuid)
    {
        let mut is_running = lock!(context.stats_server_running);
        if !*is_running {
            match oxstats::start_server(
                context.clone(),
                &hostname,
                rack_uuid,
                sled_uuid,
                log.clone(),
            ) {
                Ok(_) => *is_running = true,
                Err(e) => {
                    dlog!(log, error, "failed to start stats server: {e}";
                        "params" => format!("hostname {hostname}, rack {rack_uuid}, sled {sled_uuid}"),
                        "error" => format!("{e}")
                    )
                }
            }
        }
    }

    let j = admin::start_server(
        log.clone(),
        args.admin_addr,
        args.admin_port,
        args.admin_port_file,
        context.clone(),
    )
    .expect("start API server");
    j.await.expect("API server quit unexpectedly");
}

fn detect_switch_slot(
    ctx: Arc<HandlerContext>,
    mgs_socket_addr: SocketAddr,
    rt: tokio::runtime::Handle,
) {
    let url = format!("http://{mgs_socket_addr}");
    let client_log = ctx.log.new(slog::o!("unit" => "gateway-client"));
    let task = async move || {
        let client = gateway_client::Client::new(&url, client_log);
        let ctx = ctx.clone();

        loop {
            // check in with gateway
            let gateway_client::types::SpIdentifier { slot, .. } = match client
                .sp_local_switch_id()
                .await
            {
                Ok(v) => *v,
                Err(e) => {
                    slog::error!(ctx.log, "failed to resolve switch slot"; "error" => %e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(10))
                        .await;
                    continue;
                }
            };

            slog::info!(ctx.log, "we are in switch slot {slot}");

            // update db
            let mut db = ctx.db.clone();
            db.set_slot(Some(slot));
            break;
        }
    };

    rt.spawn(task());
}

fn init_bgp(args: &RunArgs, log: &Logger) -> BgpContext {
    let sessions = Arc::new(Mutex::new(bgp::router::SessionMap::new()));

    // Create BgpContext first to get access to unnumbered_manager
    let bgp_context = BgpContext::new(sessions.clone(), log.clone());

    if !args.no_bgp_dispatcher {
        let bgp_dispatcher =
            bgp::dispatcher::Dispatcher::<BgpConnectionTcp>::new(
                sessions.clone(),
                args.bgp_dispatcher_addr.to_string(),
                log.clone(),
                Some(bgp_context.unnumbered_manager.clone()), // Enable link-local connection routing
            );

        let listener_str =
            format!("bgp-dispatcher-{}", bgp_dispatcher.listen_addr());

        Builder::new()
            .name(listener_str.clone())
            .spawn(move || bgp_dispatcher.run::<BgpListenerTcp>())
            .expect("failed to start {listener_str}");
    }

    bgp_context
}

// TODO: check whether this needs to be stable across mgd restarts
fn get_tunnel_endpoint_ula() -> Ipv6Addr {
    // creat the randomized ULA fdxx:xxxx:xxxx:xxxx::1 as a tunnel endpoint
    let mut r = [0u8; 7];
    rand::fill(&mut r);
    Ipv6Addr::from([
        0xfd, r[0], r[1], r[2], r[3], r[4], r[5], r[6], 0, 0, 0, 0, 0, 0, 0, 1,
    ])
}
