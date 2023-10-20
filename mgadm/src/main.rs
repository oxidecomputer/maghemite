use anyhow::Result;
use clap::{Parser, Subcommand};
use mg_admin_client::Client;
use mg_common::cli::oxide_cli_style;
use slog::Drain;
use slog::Logger;
use std::net::{IpAddr, SocketAddr};

mod bgp;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, styles = oxide_cli_style())]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Address of admin interface
    #[arg(short, long, default_value = "::1")]
    address: IpAddr,

    /// TCP port for admin interface
    #[arg(short, long, default_value_t = 4676)]
    port: u16,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(subcommand)]
    Bgp(bgp::Commands),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let log = init_logger();

    let endpoint =
        format!("http://{}", SocketAddr::new(cli.address, cli.port),);

    let client = Client::new(&endpoint, log.clone());

    match cli.command {
        Commands::Bgp(command) => bgp::commands(command, client).await?,
    }
    Ok(())
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
