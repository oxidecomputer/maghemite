use anyhow::Result;
use bgp_admin_client::types;
use bgp_admin_client::Client;
use clap::{Args, Parser, Subcommand};
use rdb::types::{PolicyAction, Prefix4};
use slog::Drain;
use slog::Logger;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
    AddExportPolicy(ExportPolicy),
    Originate4(Originate4),
    GetImported,
    GetOriginated,
}

#[derive(Args, Debug)]
struct ExportPolicy {
    /// Address of the peer to apply this policy to.
    pub addr: IpAddr,

    /// Prefix this policy applies to
    pub prefix: Prefix4,

    /// Priority of the policy, higher value is higher priority.
    pub priority: u16,

    /// The policy action to apply.
    pub action: PolicyAction,
}

#[derive(Args, Debug)]
struct Originate4 {
    /// Nexthop to originate.
    pub nexthop: Ipv4Addr,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
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
        Commands::AddExportPolicy(policy) => {
            add_export_policy(policy, client).await
        }
        Commands::Originate4(originate) => originate4(originate, client).await,
        Commands::GetImported => get_imported(client).await,
        Commands::GetOriginated => get_originated(client).await,
    }
    Ok(())
}

async fn get_imported(c: Client) {
    let imported = c.get_imported4().await.unwrap();
    println!("{:#?}", imported);
}

async fn get_originated(c: Client) {
    let originated = c.get_originated4().await.unwrap();
    println!("{:#?}", originated);
}

async fn add_neighbor(nbr: Neighbor, c: Client) {
    c.add_neighbor(&nbr.into()).await.unwrap();
}

async fn add_export_policy(policy: ExportPolicy, c: Client) {
    c.add_export_policy(&types::AddExportPolicyRequest {
        addr: policy.addr,
        prefix: policy.prefix,
        priority: policy.priority,
        action: policy.action,
    })
    .await
    .unwrap();
}

async fn originate4(originate: Originate4, c: Client) {
    c.originate4(&types::Originate4Request {
        nexthop: originate.nexthop,
        prefixes: originate.prefixes.clone(),
    })
    .await
    .unwrap();
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
