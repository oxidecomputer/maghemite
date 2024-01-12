// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use crate::bgp_admin::BgpContext;
use bgp::connection_tcp::{BgpConnectionTcp, BgpListenerTcp};
use bgp::log::init_logger;
use clap::{Parser, Subcommand};
use mg_common::cli::oxide_cli_style;
use rand::Fill;
use rdb::{BgpNeighborInfo, BgpRouterInfo};
use slog::Logger;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::thread::spawn;

mod admin;
mod bgp_admin;
mod error;
mod static_admin;

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
    /// Generate the OpenAPI spec for this router.
    Apigen,
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Address to listen on for the admin API.
    #[arg(long, default_value_t = Ipv6Addr::UNSPECIFIED.into())]
    admin_addr: IpAddr,

    /// Port to listen on for the admin API.
    #[arg(long, default_value_t = 4676)]
    admin_port: u16,

    /// Do not run a BGP connection dispatcher.
    #[arg(long, default_value_t = false)]
    no_bgp_dispatcher: bool,

    /// Where to store the local database
    #[arg(long, default_value = "/var/run")]
    data_dir: String,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Run(run_args) => run(run_args).await,
        Commands::Apigen => admin::apigen(),
    }
}

async fn run(args: RunArgs) {
    let log = init_logger();

    let bgp = init_bgp(&args, &log);
    let db = rdb::Db::new(&format!("{}/rdb", args.data_dir), log.clone())
        .expect("open datastore file");

    let tep_ula = get_tunnel_endpoint_ula(&db);

    let context = Arc::new(HandlerContext {
        tep: tep_ula,
        log: log.clone(),
        bgp,
        data_dir: args.data_dir.clone(),
        db: db.clone(),
    });

    #[cfg(feature = "default")]
    {
        let rt = Arc::new(tokio::runtime::Handle::current());
        let ctx = context.clone();
        let log = log.clone();
        let db = ctx.db.clone();
        std::thread::spawn(move || {
            mg_lower::run(ctx.tep, db, log, rt);
        });
    }

    start_bgp_routers(
        context.clone(),
        db.get_bgp_routers()
            .expect("get BGP routers from datastore"),
        db.get_bgp_neighbors()
            .expect("get BGP neighbors from data store"),
    );

    let j = admin::start_server(
        log.clone(),
        args.admin_addr,
        args.admin_port,
        context.clone(),
    )
    .expect("start API server");
    j.await.expect("API server quit unexpectedly");
}

fn init_bgp(args: &RunArgs, log: &Logger) -> BgpContext {
    let addr_to_session = Arc::new(Mutex::new(BTreeMap::new()));
    if !args.no_bgp_dispatcher {
        let bgp_dispatcher =
            bgp::dispatcher::Dispatcher::<BgpConnectionTcp>::new(
                addr_to_session.clone(),
                "[::]:179".into(),
                log.clone(),
            );

        spawn(move || bgp_dispatcher.run::<BgpListenerTcp>());
    }
    BgpContext::new(addr_to_session)
}

fn start_bgp_routers(
    context: Arc<HandlerContext>,
    routers: HashMap<u32, BgpRouterInfo>,
    neighbors: Vec<BgpNeighborInfo>,
) {
    slog::info!(context.log, "routers: {:#?}", routers);
    let mut guard = context.bgp.router.lock().expect("lock bgp routers");
    for (asn, info) in routers {
        bgp_admin::add_router(
            context.clone(),
            bgp_admin::NewRouterRequest {
                asn,
                id: info.id,
                listen: info.listen.clone(),
            },
            &mut guard,
        )
        .unwrap_or_else(|_| panic!("add BGP router {asn} {info:#?}"));
    }
    drop(guard);

    for nbr in neighbors {
        bgp_admin::ensure_neighbor(
            context.clone(),
            bgp_admin::AddNeighborRequest {
                asn: nbr.asn,
                name: nbr.name.clone(),
                host: nbr.host,
                hold_time: nbr.hold_time,
                idle_hold_time: nbr.idle_hold_time,
                delay_open: nbr.delay_open,
                connect_retry: nbr.connect_retry,
                keepalive: nbr.keepalive,
                resolution: nbr.resolution,
                group: nbr.group.clone(),
                passive: nbr.passive,
            },
        )
        .unwrap_or_else(|_| panic!("add BGP neighbor {nbr:#?}"));
    }
}

fn get_tunnel_endpoint_ula(db: &rdb::Db) -> Ipv6Addr {
    if let Some(addr) = db.get_tep_addr().unwrap() {
        return addr;
    }

    // creat the randomized ULA fdxx:xxxx:xxxx:xxxx::1 as a tunnel endpoint
    let mut rng = rand::thread_rng();
    let mut r = [0u8; 7];
    r.try_fill(&mut rng).unwrap();
    let tep_ula = Ipv6Addr::from([
        0xfd, r[0], r[1], r[2], r[3], r[4], r[5], r[6], 0, 0, 0, 0, 0, 0, 0, 1,
    ]);

    db.set_tep_addr(tep_ula).unwrap();

    tep_ula
}
