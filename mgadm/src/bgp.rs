use anyhow::Result;
use clap::{Args, Subcommand};
use mg_admin_client::types;
use mg_admin_client::Client;
use rdb::types::{PolicyAction, Prefix4};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Subcommand, Debug)]
pub enum Commands {
    RouterInit(RouterConfig),
    AddNeighbor(Neighbor),
    AddExportPolicy(ExportPolicy),
    Originate4(Originate4),
    GetImported,
    GetOriginated,
}

#[derive(Args, Debug)]
pub struct RouterConfig {
    /// Autonomous system number for this router
    pub asn: u32,

    /// Id for this router
    pub id: u32,

    /// Listening address <addr>:<port>
    pub listen: String,
}

#[derive(Args, Debug)]
pub struct ExportPolicy {
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
pub struct Originate4 {
    /// Nexthop to originate.
    pub nexthop: Ipv4Addr,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[derive(Args, Debug)]
pub struct Neighbor {
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

pub async fn commands(command: Commands, client: Client) -> Result<()> {
    match command {
        Commands::RouterInit(cfg) => init_router(cfg, client).await,
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

async fn init_router(cfg: RouterConfig, c: Client) {
    c.new_router(&types::NewRouterRequest {
        asn: cfg.asn,
        id: cfg.id,
        listen: cfg.listen,
    })
    .await
    .unwrap();
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
