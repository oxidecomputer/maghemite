// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

fn to_prefix4(p: &types::Prefix4) -> Prefix4 {
    Prefix4 {
        value: p.value,
        length: p.length,
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Get the running set of BGP routers.
    GetRouters,

    /// Add a BGP router.
    AddRouter(RouterConfig),

    /// Delete a BGP router.
    DeleteRouter { asn: u32 },

    /// Add a neighbor to a BGP router.
    AddNeighbor(Neighbor),

    /// Remove a neighbor from a BGP router.
    DeleteNeighbor { asn: u32, addr: IpAddr },

    /// Originate a set of prefixes from a BGP router.
    Originate4(Originate4),

    /// Withdraw a set of prefixes from a BGP router.
    Withdraw4(Withdraw4),

    /// Get the prefixes imported by a BGP router.
    GetImported { asn: u32 },

    /// Get the prefixes originated by a BGP router.
    GetOriginated { asn: u32 },

    /// Apply a BGP peer group configuration.
    Apply { filename: String },

    /// Initiate a graceful shutdown of a BGP router.
    EnableGshut { asn: u32 },

    /// Disable graceful shutdown of a BGP router.
    DisableGshut { asn: u32 },
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

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[derive(Args, Debug)]
pub struct Withdraw4 {
    /// Autonomous system number for the router to originated the prefixes from.
    pub asn: u32,

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

    /// How long to hold connection without keepalive (s).
    #[arg(long, default_value_t = 6)]
    hold_time: u64,

    /// How long a peer is kept in idle before automatic restart (s).
    #[arg(long, default_value_t = 6)]
    idle_hold_time: u64,

    /// How long to wait between connection retries (s).
    #[arg(long, default_value_t = 5)]
    connect_retry_time: u64,

    /// Interval for sending keepalive messages (s).
    #[arg(long, default_value_t = 2)]
    keepalive_time: u64,

    /// How long to delay sending an open message (s).
    #[arg(long, default_value_t = 0)]
    delay_open_time: u64,

    /// Blocking interval for message loops (ms).
    #[arg(long, default_value_t = 100)]
    resolution: u64,

    /// Do not initiate connections, only accept them.
    #[arg(long, default_value_t = false)]
    passive_connection: bool,
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
            passive: n.passive_connection,
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
        Commands::Withdraw4(withdraw) => withdraw4(withdraw, client).await,
        Commands::GetImported { asn } => get_imported(client, asn).await,
        Commands::GetOriginated { asn } => get_originated(client, asn).await,
        Commands::Apply { filename } => apply(filename, client).await,
        Commands::EnableGshut { asn } => {
            graceful_shutdown(asn, true, client).await
        }
        Commands::DisableGshut { asn } => {
            graceful_shutdown(asn, false, client).await
        }
    }
    Ok(())
}

async fn get_routers(c: Client) {
    let routers = c.get_routers().await.unwrap().into_inner();
    for r in &routers {
        let gshut = if r.graceful_shutdown {
            " graceful shutdown".yellow()
        } else {
            "".normal()
        };
        println!("{}: {}{gshut}", "ASN".dimmed(), r.asn);
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
        .unwrap()
        .into_inner();

    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}",
        "Prefix".dimmed(),
        "Nexthop".dimmed(),
        "Peer Id".dimmed(),
        "Priority".dimmed(),
    )
    .unwrap();

    for route in &imported {
        let id = Ipv4Addr::from(route.id);
        writeln!(
            &mut tw,
            "{}\t{}\t{}\t{}",
            to_prefix4(&route.prefix),
            route.nexthop,
            id,
            route.priority,
        )
        .unwrap();
    }

    tw.flush().unwrap();
}

async fn get_originated(c: Client, asn: u32) {
    let originated = c
        .get_originated4(&types::GetOriginated4Request { asn })
        .await
        .unwrap()
        .into_inner();

    let mut tw = TabWriter::new(stdout());
    writeln!(&mut tw, "{}", "Prefix".dimmed()).unwrap();

    for prefix in &originated {
        writeln!(&mut tw, "{}", to_prefix4(prefix)).unwrap();
    }

    tw.flush().unwrap();
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
        prefixes: originate
            .prefixes
            .clone()
            .into_iter()
            .map(|x| types::Prefix4 {
                length: x.length,
                value: x.value,
            })
            .collect(),
    })
    .await
    .unwrap();
}

async fn withdraw4(withdraw: Withdraw4, c: Client) {
    c.withdraw4(&types::Withdraw4Request {
        asn: withdraw.asn,
        prefixes: withdraw
            .prefixes
            .clone()
            .into_iter()
            .map(|x| types::Prefix4 {
                length: x.length,
                value: x.value,
            })
            .collect(),
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

async fn graceful_shutdown(asn: u32, enabled: bool, c: Client) {
    c.graceful_shutdown(&types::GracefulShutdownRequest { asn, enabled })
        .await
        .unwrap();
}
