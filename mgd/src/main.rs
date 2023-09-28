use crate::admin::HandlerContext;
use crate::bgp_admin::BgpContext;
use bgp::connection::{BgpConnectionTcp, BgpListenerTcp};
use bgp::log::init_logger;
use clap::{Parser, Subcommand};
use mg_common::cli::oxide_cli_style;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::thread::spawn;

mod admin;
mod bgp_admin;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, styles = oxide_cli_style())]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a BGP router instance.
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
    let db = rdb::Db::new(&format!("{}/rdb", args.data_dir)).unwrap();

    let context = Arc::new(HandlerContext {
        log: log.clone(),
        bgp: BgpContext::new(addr_to_session),
        data_dir: args.data_dir.clone(),
        db: db.clone(),
    });

    let routers = db.get_bgp_routers().unwrap();
    {
        slog::info!(log, "routers: {:#?}", routers);
        let mut guard = context.bgp.router.lock().unwrap();
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
            .unwrap(); //TODO unwrap
        }
    }

    let neighbors = db.get_bgp_neighbors().unwrap();
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
            },
            log.clone(),
        )
        .unwrap(); //TODO unwrap
    }

    let j = admin::start_server(
        log.clone(),
        args.admin_addr,
        args.admin_port,
        context.clone(),
    );
    j.unwrap().await.unwrap();
}
