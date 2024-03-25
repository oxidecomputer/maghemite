// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use crate::bfd_admin::BfdContext;
use crate::bgp_admin::BgpContext;
use bgp::connection_tcp::{BgpConnectionTcp, BgpListenerTcp};
use bgp::log::init_logger;
use clap::{Parser, Subcommand};
use mg_common::cli::oxide_cli_style;
use mg_common::stats::MgLowerStats;
use rand::Fill;
use rdb::{BfdPeerConfig, BgpNeighborInfo, BgpRouterInfo};
use slog::Logger;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use uuid::Uuid;

mod admin;
mod bfd_admin;
mod bgp_admin;
mod error;
mod oxstats;
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
    let bfd = BfdContext::new(log.clone());

    let context = Arc::new(HandlerContext {
        tep: tep_ula,
        log: log.clone(),
        bgp,
        bfd,
        data_dir: args.data_dir.clone(),
        mg_lower_stats: Arc::new(MgLowerStats::default()),
        db: db.clone(),
    });

    #[cfg(feature = "default")]
    {
        let rt = Arc::new(tokio::runtime::Handle::current());
        let ctx = context.clone();
        let log = log.clone();
        let db = ctx.db.clone();
        let stats = context.mg_lower_stats.clone();
        std::thread::spawn(move || {
            mg_lower::run(ctx.tep, db, log, stats, rt);
        });
    }

    start_bgp_routers(
        context.clone(),
        db.get_bgp_routers()
            .expect("get BGP routers from datastore"),
        db.get_bgp_neighbors()
            .expect("get BGP neighbors from data store"),
    );

    start_bfd_sessions(
        context.clone(),
        db.get_bfd_neighbors()
            .expect("get BFD neighbors from data store"),
    );

    initialize_static_routes(&db);

    let hostname = hostname::get()
        .expect("failed to get hostname")
        .to_string_lossy()
        .to_string();

    let dns_servers: Vec<SocketAddr> = args
        .dns_servers
        .iter()
        .filter(|x| x.as_str() != "unknown")
        .map(|x| x.parse().unwrap())
        .collect();

    if args.with_stats && !dns_servers.is_empty() {
        if let (Some(rack_uuid), Some(sled_uuid)) =
            (args.rack_uuid, args.sled_uuid)
        {
            oxstats::start_server(
                args.admin_addr,
                args.oximeter_port,
                context.clone(),
                dns_servers,
                hostname,
                rack_uuid,
                sled_uuid,
                log.clone(),
            )
            .unwrap();
        }
    }

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
    slog::info!(context.log, "bgp routers: {:#?}", routers);
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

fn start_bfd_sessions(
    context: Arc<HandlerContext>,
    configs: Vec<BfdPeerConfig>,
) {
    slog::info!(context.log, "bfd peers: {:#?}", configs);
    for config in configs {
        bfd_admin::add_peer(context.clone(), config)
            .unwrap_or_else(|e| panic!("failed to add bfd peer {e}"));
    }
}

fn initialize_static_routes(db: &rdb::Db) {
    let routes = db
        .get_static4()
        .expect("failed to get static routes from db");
    for route in &routes {
        db.set_nexthop4(*route, false).unwrap_or_else(|e| {
            panic!("failed to initialize static route {route:#?}: {e}")
        });
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
