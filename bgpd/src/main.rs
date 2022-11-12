use crate::admin::api_description;
use crate::admin::RouterConfig;
use bgp::router::Dispatcher;
use bgp::session::Asn;
use clap::{Args, Parser, Subcommand};
use slog::{Drain, Logger};
use std::fs::File;
use std::net::Ipv6Addr;
use std::sync::Arc;

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
    let disp = Arc::new(Dispatcher::new(run.listen));
    let d = disp.clone();
    tokio::spawn(async move {
        d.run().await;
    });

    let j = admin::start_server(
        init_logger(),
        Ipv6Addr::UNSPECIFIED,
        8000,
        RouterConfig {
            asn: Asn::FourOctet(run.asn),
            id: run.id,
        },
        disp,
    );

    j.unwrap().await.unwrap();
}

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain)
        .chan_size(0x2000)
        .build()
        .fuse();
    slog::Logger::root(drain, slog::o!())
}
