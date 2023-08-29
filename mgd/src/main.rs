use bgp::log::init_logger;
use clap::{Parser, Subcommand};
use std::net::Ipv6Addr;

mod admin;
mod bgp_admin;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a BGP router instance.
    Run,
    /// Generate the OpenAPI spec for this router.
    Apigen,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Run => run().await,
        Commands::Apigen => admin::apigen(),
    }
}

async fn run() {
    let log = init_logger();
    let j = admin::start_server(log.clone(), Ipv6Addr::UNSPECIFIED, 8000);
    j.unwrap().await.unwrap();
}
