use anyhow::Result;
use clap::{Args, Subcommand};
use colored::*;
use mg_admin_client::types;
use mg_admin_client::Client;
use rdb::types::{PolicyAction, Prefix4};
use std::fs::read_to_string;
use std::io::{stdout, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tabwriter::TabWriter;

#[derive(Subcommand, Debug)]
pub enum Commands {
    GetRouters,
    AddRouter(RouterConfig),
    DeleteRouter { asn: u32 },
    AddNeighbor(Neighbor),
    DeleteNeighbor { asn: u32, addr: IpAddr },
    Originate4(Originate4),
    GetImported { asn: u32 },
    GetOriginated { asn: u32 },
    Apply { filename: String },
}

#[derive(Args, Debug)]
pub struct RouterConfig {
    /// Autonomous system number for this router
    pub asn: u32,

    /// Id for this router
    pub id: u32,

    /// Listening address `<addr>:<port>`
    pub listen: String,
}

#[derive(Args, Debug)]
pub struct ExportPolicy {
    /// Autonomous system number for the router to add the export policy to.
    pub asn: u32,

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
    /// Autonomous system number for the router to originated the prefixes from.
    pub asn: u32,

    /// Nexthop to originate.
    pub nexthop: Ipv4Addr,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[derive(Args, Debug)]
pub struct Neighbor {
    /// Autonomous system number for the router to add the neighbor to.
    pub asn: u32,

    /// Name for this neighbor
    name: String,

    /// Neighbor address
    addr: IpAddr,

    /// Peer group to add the neighbor to.
    group: String,

    /// Neighbor BGP TCP port.
    #[arg(long, default_value_t = 179)]
    port: u16,
    #[arg(long, default_value_t = 30)]
    hold_time: u64,
    #[arg(long, default_value_t = 30)]
    idle_hold_time: u64,
    #[arg(long, default_value_t = 5)]
    connect_retry_time: u64,
    #[arg(long, default_value_t = 20)]
    keepalive_time: u64,
    #[arg(long, default_value_t = 10)]
    delay_open_time: u64,
    #[arg(long, default_value_t = 100)]
    resolution: u64,
}

impl From<Neighbor> for types::AddNeighborRequest {
    fn from(n: Neighbor) -> types::AddNeighborRequest {
        types::AddNeighborRequest {
            asn: n.asn,
            name: n.name,
            host: SocketAddr::new(n.addr, n.port).to_string(),
            hold_time: n.hold_time,
            idle_hold_time: n.idle_hold_time,
            connect_retry: n.connect_retry_time,
            keepalive: n.keepalive_time,
            delay_open: n.delay_open_time,
            resolution: n.resolution,
            group: n.group,
        }
    }
}

pub async fn commands(command: Commands, client: Client) -> Result<()> {
    match command {
        Commands::GetRouters => get_routers(client).await,
        Commands::AddRouter(cfg) => add_router(cfg, client).await,
        Commands::DeleteRouter { asn } => delete_router(asn, client).await,
        Commands::AddNeighbor(nbr) => add_neighbor(nbr, client).await,
        Commands::DeleteNeighbor { asn, addr } => {
            delete_neighbor(asn, addr, client).await
        }
        Commands::Originate4(originate) => originate4(originate, client).await,
        Commands::GetImported { asn } => get_imported(client, asn).await,
        Commands::GetOriginated { asn } => get_originated(client, asn).await,
        Commands::Apply { filename } => apply(filename, client).await,
    }
    Ok(())
}

async fn get_routers(c: Client) {
    let routers = c.get_routers().await.unwrap().into_inner();
    for r in &routers {
        println!("{}: {}", "ASN".dimmed(), r.asn);
        let mut tw = TabWriter::new(stdout());
        writeln!(
            &mut tw,
            "{}\t{}\t{}\t{}",
            "Peer Address".dimmed(),
            "Peer ASN".dimmed(),
            "State".dimmed(),
            "State Duration".dimmed(),
        )
        .unwrap();

        for (addr, info) in &r.peers {
            writeln!(
                &mut tw,
                "{}\t{:?}\t{:?}\t{:}",
                addr,
                info.asn,
                info.state,
                humantime::Duration::from(Duration::from_millis(
                    info.duration_millis
                ),),
            )
            .unwrap();
        }
        tw.flush().unwrap();
        println!();
    }
}

async fn add_router(cfg: RouterConfig, c: Client) {
    c.new_router(&types::NewRouterRequest {
        asn: cfg.asn,
        id: cfg.id,
        listen: cfg.listen,
    })
    .await
    .unwrap();
}

async fn delete_router(asn: u32, c: Client) {
    c.delete_router(&types::DeleteRouterRequest { asn })
        .await
        .unwrap();
}

async fn get_imported(c: Client, asn: u32) {
    let imported = c
        .get_imported4(&types::GetImported4Request { asn })
        .await
        .unwrap();
    println!("{:#?}", imported);
}

async fn get_originated(c: Client, asn: u32) {
    let originated = c
        .get_originated4(&types::GetOriginated4Request { asn })
        .await
        .unwrap();
    println!("{:#?}", originated);
}

async fn add_neighbor(nbr: Neighbor, c: Client) {
    c.add_neighbor_handler(&nbr.into()).await.unwrap();
}

async fn delete_neighbor(asn: u32, addr: IpAddr, c: Client) {
    c.delete_neighbor(&types::DeleteNeighborRequest { asn, addr })
        .await
        .unwrap();
}

async fn originate4(originate: Originate4, c: Client) {
    c.originate4(&types::Originate4Request {
        asn: originate.asn,
        nexthop: originate.nexthop,
        prefixes: originate.prefixes.clone(),
    })
    .await
    .unwrap();
}

async fn apply(filename: String, c: Client) {
    let contents = read_to_string(filename).expect("read file");
    let request: types::ApplyRequest =
        serde_json::from_str(&contents).expect("parse config");
    c.bgp_apply(&request).await.expect("bgp apply");
}
