use anyhow::Result;
use bgp_admin_client::types;
use bgp_admin_client::Client;
use clap::{Args, Parser, Subcommand};
use slog::Drain;
use slog::Logger;
use std::net::IpAddr;
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Address of admin interface
    #[arg(short, long, default_value = "::1")]
    address: IpAddr,

    /// TCP port for admin interface
    #[arg(short, long, default_value_t = 8000)]
    port: u16,
}

#[derive(Subcommand, Debug)]
enum Commands {
    AddNeighbor(Neighbor),
}

#[derive(Args, Debug)]
struct Neighbor {
    /// Name for this neighbor
    name: String,
    /// Neighbor address
    addr: IpAddr,
    /// Neighbor BGP TCP port.
    #[arg(default_value_t = 179)]
    port: u16,
    #[arg(default_value_t = 30)]
    hold_time: u64,
    #[arg(default_value_t = 30)]
    idle_hold_time: u64,
    #[arg(default_value_t = 5)]
    connect_retry_time: u64,
    #[arg(default_value_t = 20)]
    keepalive_time: u64,
    #[arg(default_value_t = 10)]
    delay_open_time: u64,
    #[arg(default_value_t = 100)]
    resolution: u64,
}

impl From<Neighbor> for types::AddNeighborRequest {
    fn from(n: Neighbor) -> types::AddNeighborRequest {
        types::AddNeighborRequest {
            name: n.name,
            host: SocketAddr::new(n.addr, n.port).to_string(),
            hold_time: n.hold_time,
            idle_hold_time: n.idle_hold_time,
            connect_retry: n.connect_retry_time,
            keepalive: n.keepalive_time,
            delay_open: n.delay_open_time,
            resolution: n.resolution,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let log = init_logger();

    let endpoint =
        format!("http://{}", SocketAddr::new(cli.address, cli.port),);

    let client = Client::new(&endpoint, log.clone());

    match cli.command {
        Commands::AddNeighbor(nbr) => add_neighbor(nbr, client).await,
    }
    Ok(())
}

async fn add_neighbor(nbr: Neighbor, c: Client) {
    let r = c.add_neighbor(&nbr.into()).await.unwrap();
    println!("{:#?}", r);
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
