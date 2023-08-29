use crate::admin::api_description;
use bgp::config::RouterConfig;
use bgp::connection::BgpConnectionTcp;
use bgp::connection::BgpListenerTcp;
use bgp::log::init_logger;
use bgp::router::Router;
use bgp::session::Asn;
use clap::{Args, Parser, Subcommand};
use std::fs::File;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::thread::spawn;

mod admin;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a BGP router instance.
    Run(Run),
    /// Generate the OpenAPI spec for this router.
    Apigen,
}

#[derive(Args, Debug)]
struct Run {
    /// Autonomous system number for this router
    asn: u32,

    /// Id for this router
    id: u32,

    /// Listening address <addr>:<port>
    #[arg(short, long, default_value = "0.0.0.0:179")]
    listen: String,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Run(r) => run(r).await,
        Commands::Apigen => apigen().await,
    }
}

async fn apigen() {
    let api = api_description();
    let openapi = api.openapi("BGP Admin", "v0.1.0");
    let mut out = File::create("bgp-admin.json").unwrap();
    openapi.write(&mut out).unwrap();
}

async fn run(run: Run) {
    let cfg = RouterConfig {
        asn: Asn::FourOctet(run.asn),
        id: run.id,
    };
    let log = init_logger();

    //assumes only one router per machine
    let db = rdb::Db::new("/var/run/rdb").unwrap();

    let router = Arc::new(Router::<BgpConnectionTcp>::new(
        run.listen,
        cfg,
        log.clone(),
        db.clone(),
    ));

    let j = admin::start_server(
        log.clone(),
        Ipv6Addr::UNSPECIFIED,
        8000,
        cfg,
        router.clone(),
    );

    spawn(move || {
        router.run::<BgpListenerTcp>();
    });

    let rt = Arc::new(tokio::runtime::Handle::current());
    spawn(move || {
        mg_lower::run(db, log, rt);
    });

    j.unwrap().await.unwrap();
}
