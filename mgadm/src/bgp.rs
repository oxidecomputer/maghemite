// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Args, Subcommand};
use colored::*;
use mg_admin_client::types::{
    self, NeighborResetOp, NeighborResetRequest, Path,
};
use mg_admin_client::types::{ImportExportPolicy, Rib};
use mg_admin_client::Client;
use rdb::types::{PolicyAction, Prefix4};
use std::collections::BTreeMap;
use std::fs::read_to_string;
use std::io::{stdout, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tabwriter::TabWriter;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage router configuration.
    Config(ConfigSubcommand),

    /// View dynamic router state.
    Status(StatusSubcommand),

    /// Clear dynamic router state.
    Clear(ClearSubcommand),

    /// Omicron control plane commands.
    Omicron(OmicronSubcommand),
}

#[derive(Debug, Args)]
pub struct ConfigSubcommand {
    #[command(subcommand)]
    command: ConfigCmd,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Router management commands.
    Router(RouterSubcommand),

    /// Neighbor mangement commands.
    Neighbor(NeighborSubcommand),

    /// Origin management commands.
    Origin(OriginSubcommand),

    /// Policy management commands.
    Policy(PolicySubcommand),
}

#[derive(Debug, Args)]
pub struct StatusSubcommand {
    #[command(subcommand)]
    command: StatusCmd,
}

#[derive(Subcommand, Debug)]
pub enum StatusCmd {
    /// Get the status of a router's neighbors.
    Neighbors {
        #[clap(env)]
        asn: u32,
    },

    /// Get the prefixes exported by a BGP router.
    Exported {
        #[clap(env)]
        asn: u32,
    },

    /// Get the prefixes imported by a BGP router.
    Imported {
        #[clap(env)]
        asn: u32,
    },

    /// Get the selected paths chosen from imported paths.
    Selected {
        #[clap(env)]
        asn: u32,
    },
}

#[derive(Debug, Args)]
pub struct ClearSubcommand {
    #[command(subcommand)]
    command: ClearCmd,
}

#[derive(Clone, Subcommand, Debug)]
pub enum ClearCmd {
    Neighbor {
        #[clap(env)]
        asn: u32,
        addr: IpAddr,
        #[clap(value_enum)]
        clear_type: NeighborResetOp,
    },
}

#[derive(Debug, Args)]
pub struct OmicronSubcommand {
    #[command(subcommand)]
    command: OmicronCmd,
}

#[derive(Subcommand, Debug)]
pub enum OmicronCmd {
    /// Apply an Omicron BGP configuration.
    Apply { filename: String },
}

#[derive(Debug, Args)]
pub struct RouterSubcommand {
    #[command(subcommand)]
    command: RouterCmd,
}

#[derive(Subcommand, Debug)]
pub enum RouterCmd {
    /// Get the running set of BGP routers.
    List,

    /// Create a router configuration.
    Create(RouterConfig),

    /// Read a router's configuration.
    Read {
        #[clap(env)]
        asn: u32,
    },

    /// Update a router's configuration.
    Update(RouterConfig),

    /// Delete a BGP router.
    Delete {
        #[clap(env)]
        asn: u32,
    },
}

#[derive(Args, Debug)]
pub struct NeighborSubcommand {
    #[command(subcommand)]
    command: NeighborCmd,
}

#[derive(Subcommand, Debug)]
pub enum NeighborCmd {
    /// List the neighbors of a given router.
    List {
        #[clap(env)]
        asn: u32,
    },

    /// Create a neighbor configuration.
    Create(Neighbor),

    /// Read a neighbor configuration.
    Read {
        addr: IpAddr,
        #[clap(env)]
        asn: u32,
    },

    /// Update a neighbor's configuration.
    Update(Neighbor),

    /// Delete a neighbor configuration
    Delete {
        addr: IpAddr,
        #[clap(env)]
        asn: u32,
    },
}

#[derive(Args, Debug)]
pub struct OriginSubcommand {
    #[command(subcommand)]
    command: OriginCmd,
}

#[derive(Subcommand, Debug)]
pub enum OriginCmd {
    Ipv4(Origin4Subcommand),
    //Ipv6, TODO
}

#[derive(Args, Debug)]
pub struct Origin4Subcommand {
    #[command(subcommand)]
    command: Origin4Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Origin4Cmd {
    /// Originate a set of prefixes from a BGP router.
    Create(Originate4),

    /// Read originated prefexes for a BGP router.
    Read {
        #[clap(env)]
        asn: u32,
    },

    /// Update a routers originated prefixes.
    Update(Originate4),

    /// Delete a router's originated prefixes.
    Delete {
        #[clap(env)]
        asn: u32,
    },
}

#[derive(Args, Debug)]
pub struct PolicySubcommand {
    #[command(subcommand)]
    command: PolicyCmd,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// Manage the policy checker for a router.
    Checker(CheckerSubcommand),

    /// Manage the policy shaper for a router.
    Shaper(ShaperSubcommand),
}

#[derive(Args, Debug)]
pub struct CheckerSubcommand {
    #[command(subcommand)]
    command: CheckerCmd,
}

#[derive(Subcommand, Debug)]
pub enum CheckerCmd {
    /// Create a BGP policy checker for the specified router.
    Create {
        file: String,
        #[clap(env)]
        asn: u32,
    },

    /// Read a routers policy checker.
    Read {
        #[clap(env)]
        asn: u32,
    },

    /// Update the BGP policy checker for the specified router.
    Update {
        file: String,
        #[clap(env)]
        asn: u32,
    },

    /// Delete a routers policy checker.
    Delete {
        #[clap(env)]
        asn: u32,
    },
}

#[derive(Args, Debug)]
pub struct ShaperSubcommand {
    #[command(subcommand)]
    command: ShaperCmd,
}

#[derive(Subcommand, Debug)]
pub enum ShaperCmd {
    /// Create a BGP policy checker for the specified router.
    Create {
        file: String,
        #[clap(env)]
        asn: u32,
    },

    /// Read a routers policy checker.
    Read {
        #[clap(env)]
        asn: u32,
    },

    /// Update the BGP policy checker for the specified router.
    Update {
        file: String,
        #[clap(env)]
        asn: u32,
    },

    /// Delete a routers policy checker.
    Delete {
        #[clap(env)]
        asn: u32,
    },
}

#[derive(Args, Debug)]
pub struct RouterConfig {
    /// Id for this router
    pub id: u32,

    /// Listening address `<addr>:<port>`
    pub listen: String,

    /// Gracefully shut this router down according to RFC 8326
    #[clap(long)]
    pub graceful_shutdown: bool,

    /// Autonomous system number for this router
    #[clap(env)]
    pub asn: u32,
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

    /// Autonomous system number for the router to add the export policy to.
    #[clap(env)]
    pub asn: u32,
}

#[derive(Args, Debug)]
pub struct Originate4 {
    /// Autonomous system number for the router to originated the prefixes from.
    #[clap(env)]
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[derive(Args, Debug)]
pub struct Withdraw4 {
    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,

    /// Autonomous system number for the router to originated the prefixes from.
    #[clap(env)]
    pub asn: u32,
}

#[derive(Args, Debug)]
pub struct Neighbor {
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
    #[arg(long, default_value_t = 0)]
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

    /// Autonomous system number for the remote peer.
    #[arg(long)]
    pub remote_asn: Option<u32>,

    /// Minimum acceptable TTL for neighbor.
    #[arg(long)]
    pub min_ttl: Option<u8>,

    /// Authentication key used for TCP-MD5 with remote peer.
    #[arg(long)]
    pub md5_auth_key: Option<String>,

    /// Multi-exit discriminator to send to eBGP peers.
    #[arg(long)]
    pub med: Option<u32>,

    // Communities to attach to update messages.
    #[arg(long)]
    pub communities: Vec<u32>,

    /// Local preference to send to iBGP peers.
    #[arg(long)]
    pub local_pref: Option<u32>,

    /// Ensure that routes received from eBGP peers have the peer's ASN as the
    /// first element in the AS path.
    #[arg(long)]
    pub enforce_first_as: bool,

    #[arg(long)]
    pub vlan_id: Option<u16>,

    #[arg(long)]
    pub allow_export: Option<Vec<Prefix4>>,

    #[arg(long)]
    pub allow_import: Option<Vec<Prefix4>>,

    /// Autonomous system number for the router to add the neighbor to.
    #[clap(env)]
    pub asn: u32,
}

impl From<Neighbor> for types::Neighbor {
    fn from(n: Neighbor) -> types::Neighbor {
        types::Neighbor {
            asn: n.asn,
            remote_asn: n.remote_asn,
            min_ttl: n.min_ttl,
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
            md5_auth_key: n.md5_auth_key.clone(),
            multi_exit_discriminator: n.med,
            communities: n.communities,
            local_pref: n.local_pref,
            enforce_first_as: n.enforce_first_as,
            allow_export: match n.allow_export {
                Some(prefixes) => ImportExportPolicy::Allow(
                    prefixes
                        .clone()
                        .into_iter()
                        .map(|x| {
                            types::Prefix::V4(types::Prefix4 {
                                length: x.length,
                                value: x.value,
                            })
                        })
                        .collect(),
                ),
                None => ImportExportPolicy::NoFiltering,
            },
            allow_import: match n.allow_import {
                Some(prefixes) => ImportExportPolicy::Allow(
                    prefixes
                        .clone()
                        .into_iter()
                        .map(|x| {
                            types::Prefix::V4(types::Prefix4 {
                                length: x.length,
                                value: x.value,
                            })
                        })
                        .collect(),
                ),
                None => ImportExportPolicy::NoFiltering,
            },
            vlan_id: n.vlan_id,
        }
    }
}

pub async fn commands(command: Commands, c: Client) -> Result<()> {
    match command {
        Commands::Config(cmd) => match cmd.command {
            ConfigCmd::Router(cmd) => match cmd.command {
                RouterCmd::List => read_routers(c).await,
                RouterCmd::Create(cfg) => create_router(cfg, c).await,
                RouterCmd::Read { asn } => read_router(asn, c).await,
                RouterCmd::Update(cfg) => update_router(cfg, c).await,
                RouterCmd::Delete { asn } => delete_router(asn, c).await,
            },

            ConfigCmd::Neighbor(cmd) => match cmd.command {
                NeighborCmd::List { asn } => list_nbr(asn, c).await,
                NeighborCmd::Create(nbr) => create_nbr(nbr, c).await,
                NeighborCmd::Read { asn, addr } => read_nbr(asn, addr, c).await,
                NeighborCmd::Update(nbr) => update_nbr(nbr, c).await,
                NeighborCmd::Delete { asn, addr } => {
                    delete_nbr(asn, addr, c).await
                }
            },

            ConfigCmd::Origin(cmd) => match cmd.command {
                OriginCmd::Ipv4(cmd) => match cmd.command {
                    Origin4Cmd::Create(origin) => {
                        create_origin4(origin, c).await
                    }
                    Origin4Cmd::Read { asn } => read_origin4(asn, c).await,
                    Origin4Cmd::Update(origin) => {
                        update_origin4(origin, c).await
                    }
                    Origin4Cmd::Delete { asn } => delete_origin4(asn, c).await,
                },
            },

            ConfigCmd::Policy(cmd) => match cmd.command {
                PolicyCmd::Checker(cmd) => match cmd.command {
                    CheckerCmd::Create { file, asn } => {
                        create_chk(file, asn, c).await
                    }
                    CheckerCmd::Read { asn } => read_chk(asn, c).await,
                    CheckerCmd::Update { file, asn } => {
                        update_chk(file, asn, c).await
                    }
                    CheckerCmd::Delete { asn } => delete_chk(asn, c).await,
                },
                PolicyCmd::Shaper(cmd) => match cmd.command {
                    ShaperCmd::Create { file, asn } => {
                        create_shp(file, asn, c).await
                    }
                    ShaperCmd::Read { asn } => read_shp(asn, c).await,
                    ShaperCmd::Update { file, asn } => {
                        update_shp(file, asn, c).await
                    }
                    ShaperCmd::Delete { asn } => delete_shp(asn, c).await,
                },
            },
        },

        Commands::Status(cmd) => match cmd.command {
            StatusCmd::Neighbors { asn } => get_neighbors(c, asn).await,
            StatusCmd::Exported { asn } => get_exported(c, asn).await,
            StatusCmd::Imported { asn } => get_imported(c, asn).await,
            StatusCmd::Selected { asn } => get_selected(c, asn).await,
        },

        Commands::Clear(cmd) => match cmd.command {
            ClearCmd::Neighbor {
                asn,
                addr,
                clear_type,
            } => clear_nbr(asn, addr, clear_type, c).await,
        },

        Commands::Omicron(cmd) => match cmd.command {
            OmicronCmd::Apply { filename } => apply(filename, c).await,
        },
    }
    Ok(())
}

async fn read_routers(c: Client) {
    let routers = c.read_routers().await.unwrap().into_inner();
    println!("{routers:#?}");
}

async fn create_router(cfg: RouterConfig, c: Client) {
    c.create_router(&types::Router {
        asn: cfg.asn,
        id: cfg.id,
        listen: cfg.listen,
        graceful_shutdown: cfg.graceful_shutdown,
    })
    .await
    .unwrap();
}

async fn update_router(cfg: RouterConfig, c: Client) {
    c.update_router(&types::Router {
        asn: cfg.asn,
        id: cfg.id,
        listen: cfg.listen,
        graceful_shutdown: cfg.graceful_shutdown,
    })
    .await
    .unwrap();
}

async fn read_router(asn: u32, c: Client) {
    let response = c.read_router(asn).await.unwrap();
    println!("{response:#?}");
}

async fn delete_router(asn: u32, c: Client) {
    c.delete_router(asn).await.unwrap();
}

async fn get_neighbors(c: Client, asn: u32) {
    let result = c.get_neighbors(asn).await.unwrap();
    //println!("{result:#?}");
    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}",
        "Peer Address".dimmed(),
        "Peer ASN".dimmed(),
        "State".dimmed(),
        "State Duration".dimmed(),
        "Hold".dimmed(),
        "Keepalive".dimmed(),
    )
    .unwrap();

    for (addr, info) in result.iter() {
        writeln!(
            &mut tw,
            "{}\t{:?}\t{:?}\t{:}\t{}/{}\t{}/{}",
            addr,
            info.asn,
            info.state,
            humantime::Duration::from(Duration::from_millis(
                info.duration_millis
            ),),
            humantime::Duration::from(Duration::from_secs(
                info.timers.hold.configured.secs
            )),
            humantime::Duration::from(Duration::from_secs(
                info.timers.hold.negotiated.secs
            )),
            humantime::Duration::from(Duration::from_secs(
                info.timers.keepalive.configured.secs,
            )),
            humantime::Duration::from(Duration::from_secs(
                info.timers.keepalive.negotiated.secs,
            )),
        )
        .unwrap();
    }
    tw.flush().unwrap();
}

async fn get_exported(c: Client, asn: u32) {
    let exported = c
        .get_exported(&types::AsnSelector { asn })
        .await
        .unwrap()
        .into_inner();

    println!("{exported:#?}");
}

async fn get_imported(c: Client, asn: u32) {
    let imported = c
        .get_imported(&types::AsnSelector { asn })
        .await
        .unwrap()
        .into_inner();

    print_rib(imported);
}

async fn get_selected(c: Client, asn: u32) {
    let selected = c
        .get_selected(&types::AsnSelector { asn })
        .await
        .unwrap()
        .into_inner();

    print_rib(selected);
}

async fn list_nbr(asn: u32, c: Client) {
    let nbrs = c.read_neighbors(asn).await.unwrap();
    println!("{nbrs:#?}");
}

async fn create_nbr(nbr: Neighbor, c: Client) {
    c.create_neighbor(&nbr.into()).await.unwrap();
}

async fn read_nbr(asn: u32, addr: IpAddr, c: Client) {
    let nbr = c.read_neighbor(&addr, asn).await.unwrap().into_inner();
    println!("{nbr:#?}");
}

async fn update_nbr(nbr: Neighbor, c: Client) {
    c.update_neighbor(&nbr.into()).await.unwrap();
}

async fn delete_nbr(asn: u32, addr: IpAddr, c: Client) {
    c.delete_neighbor(&addr, asn).await.unwrap();
}

async fn clear_nbr(
    asn: u32,
    addr: IpAddr,
    op: types::NeighborResetOp,
    c: Client,
) {
    c.clear_neighbor(&NeighborResetRequest { asn, addr, op })
        .await
        .unwrap();
}

async fn create_origin4(originate: Originate4, c: Client) {
    c.create_origin4(&types::Origin4 {
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

async fn update_origin4(originate: Originate4, c: Client) {
    c.update_origin4(&types::Origin4 {
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

async fn delete_origin4(asn: u32, c: Client) {
    c.delete_origin4(asn).await.unwrap();
}

async fn read_origin4(asn: u32, c: Client) {
    let o4 = c.read_origin4(asn).await.unwrap();
    println!("{o4:#?}");
}

async fn apply(filename: String, c: Client) {
    let contents = read_to_string(filename).expect("read file");
    let request: types::ApplyRequest =
        serde_json::from_str(&contents).expect("parse config");
    c.bgp_apply(&request).await.expect("bgp apply");
}

fn print_rib(rib: Rib) {
    type CliRib = BTreeMap<String, Vec<Path>>;

    let mut static_routes = CliRib::new();
    let mut bgp_routes = CliRib::new();
    for (prefix, paths) in rib.0.into_iter() {
        let (br, sr) = paths.into_iter().partition(|p| p.bgp.is_some());
        static_routes.insert(prefix.clone(), sr);
        bgp_routes.insert(prefix, br);
    }

    if static_routes.values().map(|x| x.len()).sum::<usize>() > 0 {
        let mut tw = TabWriter::new(stdout());
        writeln!(
            &mut tw,
            "{}\t{}\t{}",
            "Prefix".dimmed(),
            "Nexthop".dimmed(),
            "RIB Priority".dimmed(),
        )
        .unwrap();

        for (prefix, paths) in static_routes.into_iter() {
            for path in paths.into_iter() {
                writeln!(
                    &mut tw,
                    "{}\t{}\t{:?}",
                    prefix, path.nexthop, path.rib_priority,
                )
                .unwrap();
            }
        }
        println!("{}", "Static Routes".dimmed());
        println!("{}", "=============".dimmed());
        tw.flush().unwrap();
    }

    if bgp_routes.values().map(|x| x.len()).sum::<usize>() > 0 {
        let mut tw = TabWriter::new(stdout());
        writeln!(
            &mut tw,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            "Prefix".dimmed(),
            "Nexthop".dimmed(),
            "RIB Priority".dimmed(),
            "Local Pref".dimmed(),
            "Origin AS".dimmed(),
            "Peer ID".dimmed(),
            "MED".dimmed(),
            "AS Path".dimmed(),
            "Stale".dimmed(),
        )
        .unwrap();

        for (prefix, paths) in bgp_routes.into_iter() {
            for path in paths.into_iter() {
                let bgp = path.bgp.as_ref().unwrap();
                writeln!(
                    &mut tw,
                    "{}\t{}\t{}\t{:?}\t{}\t{}\t{:?}\t{:?}\t{:?}",
                    prefix,
                    path.nexthop,
                    path.rib_priority,
                    bgp.local_pref,
                    bgp.origin_as,
                    Ipv4Addr::from(bgp.id),
                    bgp.med,
                    bgp.as_path,
                    bgp.stale,
                )
                .unwrap();
            }
        }
        println!("{}", "BGP Routes".dimmed());
        println!("{}", "=============".dimmed());
        tw.flush().unwrap();
    }
}

async fn create_chk(filename: String, asn: u32, c: Client) {
    let code = std::fs::read_to_string(filename).unwrap();

    // check that the program is loadable first
    bgp::policy::load_checker(&code).unwrap();

    c.create_checker(&types::CheckerSource { asn, code })
        .await
        .unwrap();
}

async fn read_chk(asn: u32, c: Client) {
    let result = c.read_checker(asn).await.unwrap();
    print!("{result:#?}");
}

async fn update_chk(filename: String, asn: u32, c: Client) {
    let code = std::fs::read_to_string(filename).unwrap();

    // check that the program is loadable first
    bgp::policy::load_checker(&code).unwrap();

    c.update_checker(&types::CheckerSource { asn, code })
        .await
        .unwrap();
}

async fn delete_chk(asn: u32, c: Client) {
    c.delete_checker(asn).await.unwrap();
}

async fn create_shp(filename: String, asn: u32, c: Client) {
    let code = std::fs::read_to_string(filename).unwrap();

    // check that the program is loadable first
    bgp::policy::load_shaper(&code).unwrap();

    c.create_shaper(&types::ShaperSource { asn, code })
        .await
        .unwrap();
}

async fn read_shp(asn: u32, c: Client) {
    let result = c.read_shaper(asn).await.unwrap();
    print!("{result:#?}");
}

async fn update_shp(filename: String, asn: u32, c: Client) {
    let code = std::fs::read_to_string(filename).unwrap();

    // check that the program is loadable first
    bgp::policy::load_shaper(&code).unwrap();

    c.update_shaper(&types::ShaperSource { asn, code })
        .await
        .unwrap();
}

async fn delete_shp(asn: u32, c: Client) {
    c.delete_shaper(asn).await.unwrap();
}
