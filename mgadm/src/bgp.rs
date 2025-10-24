// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use colored::*;
use mg_admin_client::{
    Client,
    types::{
        self, ImportExportPolicy, NeighborResetOp as MgdNeighborResetOp,
        NeighborResetRequest,
    },
};
use rdb::types::{PolicyAction, Prefix, Prefix4, Prefix6};
use std::fs::read_to_string;
use std::io::{Write, stdout};
use std::net::{IpAddr, SocketAddr};
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
}

#[derive(Clone, Debug, ValueEnum)]
#[allow(non_camel_case_types)]
pub enum NeighborResetOp {
    /// Perform a hard reset of the neighbor. This resets the TCP connection.
    hard,
    /// Send a route refresh to the neighbor. Does not reset the TCP connection.
    soft_inbound,
    /// Re-send all originated routes to the neighbor. Does not reset the TCP connection.
    soft_outbound,
}

impl From<NeighborResetOp> for MgdNeighborResetOp {
    fn from(op: NeighborResetOp) -> MgdNeighborResetOp {
        match op {
            NeighborResetOp::hard => MgdNeighborResetOp::Hard,
            NeighborResetOp::soft_inbound => MgdNeighborResetOp::SoftInbound,
            NeighborResetOp::soft_outbound => MgdNeighborResetOp::SoftOutbound,
        }
    }
}

#[derive(Debug, Args)]
pub struct ClearSubcommand {
    #[command(subcommand)]
    command: ClearCmd,
}

#[derive(Subcommand, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum ClearCmd {
    /// Clear the state of the selected BGP neighbor.
    Neighbor {
        /// IP address of the neighbor you want to clear the state of.
        addr: IpAddr,
        #[clap(value_enum)]
        clear_type: NeighborResetOp,
        /// BGP Autonomous System number.  Can be a 16-bit or 32-bit unsigned value.
        #[clap(env)]
        asn: u32,
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
    Ipv6(Origin6Subcommand),
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
pub struct Origin6Subcommand {
    #[command(subcommand)]
    command: Origin6Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Origin6Cmd {
    /// Originate a set of IPv6 prefixes from a BGP router.
    Create(Originate6),

    /// Read originated IPv6 prefixes for a BGP router.
    Read {
        #[clap(env)]
        asn: u32,
    },

    /// Update a router's originated IPv6 prefixes.
    Update(Originate6),

    /// Delete a router's originated IPv6 prefixes.
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
pub struct Originate6 {
    /// Autonomous system number for the router to originated the prefixes from.
    #[clap(env)]
    pub asn: u32,

    /// Set of IPv6 prefixes to originate.
    pub prefixes: Vec<Prefix6>,
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
                        .map(|x| Prefix::V4(Prefix4::new(x.value, x.length)))
                        .collect(),
                ),
                None => ImportExportPolicy::NoFiltering,
            },
            allow_import: match n.allow_import {
                Some(prefixes) => ImportExportPolicy::Allow(
                    prefixes
                        .clone()
                        .into_iter()
                        .map(|x| Prefix::V4(Prefix4::new(x.value, x.length)))
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
                RouterCmd::List => read_routers(c).await?,
                RouterCmd::Create(cfg) => create_router(cfg, c).await?,
                RouterCmd::Read { asn } => read_router(asn, c).await?,
                RouterCmd::Update(cfg) => update_router(cfg, c).await?,
                RouterCmd::Delete { asn } => delete_router(asn, c).await?,
            },

            ConfigCmd::Neighbor(cmd) => match cmd.command {
                NeighborCmd::List { asn } => list_nbr(asn, c).await?,
                NeighborCmd::Create(nbr) => create_nbr(nbr, c).await?,
                NeighborCmd::Read { asn, addr } => {
                    read_nbr(asn, addr, c).await?
                }
                NeighborCmd::Update(nbr) => update_nbr(nbr, c).await?,
                NeighborCmd::Delete { asn, addr } => {
                    delete_nbr(asn, addr, c).await?
                }
            },

            ConfigCmd::Origin(cmd) => match cmd.command {
                OriginCmd::Ipv4(cmd) => match cmd.command {
                    Origin4Cmd::Create(origin) => {
                        create_origin4(origin, c).await?
                    }
                    Origin4Cmd::Read { asn } => read_origin4(asn, c).await?,
                    Origin4Cmd::Update(origin) => {
                        update_origin4(origin, c).await?
                    }
                    Origin4Cmd::Delete { asn } => {
                        delete_origin4(asn, c).await?
                    }
                },
                OriginCmd::Ipv6(cmd) => match cmd.command {
                    Origin6Cmd::Create(origin) => {
                        create_origin6(origin, c).await?
                    }
                    Origin6Cmd::Read { asn } => read_origin6(asn, c).await?,
                    Origin6Cmd::Update(origin) => {
                        update_origin6(origin, c).await?
                    }
                    Origin6Cmd::Delete { asn } => {
                        delete_origin6(asn, c).await?
                    }
                },
            },

            ConfigCmd::Policy(cmd) => match cmd.command {
                PolicyCmd::Checker(cmd) => match cmd.command {
                    CheckerCmd::Create { file, asn } => {
                        create_chk(file, asn, c).await?
                    }
                    CheckerCmd::Read { asn } => read_chk(asn, c).await?,
                    CheckerCmd::Update { file, asn } => {
                        update_chk(file, asn, c).await?
                    }
                    CheckerCmd::Delete { asn } => delete_chk(asn, c).await?,
                },
                PolicyCmd::Shaper(cmd) => match cmd.command {
                    ShaperCmd::Create { file, asn } => {
                        create_shp(file, asn, c).await?
                    }
                    ShaperCmd::Read { asn } => read_shp(asn, c).await?,
                    ShaperCmd::Update { file, asn } => {
                        update_shp(file, asn, c).await?
                    }
                    ShaperCmd::Delete { asn } => delete_shp(asn, c).await?,
                },
            },
        },

        Commands::Status(cmd) => match cmd.command {
            StatusCmd::Neighbors { asn } => get_neighbors(c, asn).await?,
            StatusCmd::Exported { asn } => get_exported(c, asn).await?,
        },

        Commands::Clear(cmd) => match cmd.command {
            ClearCmd::Neighbor {
                asn,
                addr,
                clear_type,
            } => clear_nbr(asn, addr, clear_type, c).await?,
        },

        Commands::Omicron(cmd) => match cmd.command {
            OmicronCmd::Apply { filename } => apply(filename, c).await?,
        },
    }
    Ok(())
}

async fn read_routers(c: Client) -> Result<()> {
    let routers = c.read_routers().await?.into_inner();
    println!("{routers:#?}");
    Ok(())
}

async fn create_router(cfg: RouterConfig, c: Client) -> Result<()> {
    c.create_router(&types::Router {
        asn: cfg.asn,
        id: cfg.id,
        listen: cfg.listen,
        graceful_shutdown: cfg.graceful_shutdown,
    })
    .await?;
    Ok(())
}

async fn update_router(cfg: RouterConfig, c: Client) -> Result<()> {
    c.update_router(&types::Router {
        asn: cfg.asn,
        id: cfg.id,
        listen: cfg.listen,
        graceful_shutdown: cfg.graceful_shutdown,
    })
    .await?;
    Ok(())
}

async fn read_router(asn: u32, c: Client) -> Result<()> {
    let response = c.read_router(asn).await?;
    println!("{response:#?}");
    Ok(())
}

async fn delete_router(asn: u32, c: Client) -> Result<()> {
    c.delete_router(asn).await?;
    Ok(())
}

async fn get_neighbors(c: Client, asn: u32) -> Result<()> {
    let result = c.get_neighbors(asn).await?;
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
    Ok(())
}

async fn get_exported(c: Client, asn: u32) -> Result<()> {
    let exported = c
        .get_exported(&types::AsnSelector { asn })
        .await?
        .into_inner();

    println!("{exported:#?}");
    Ok(())
}

async fn list_nbr(asn: u32, c: Client) -> Result<()> {
    let nbrs = c.read_neighbors(asn).await?;
    println!("{nbrs:#?}");
    Ok(())
}

async fn create_nbr(nbr: Neighbor, c: Client) -> Result<()> {
    c.create_neighbor(&nbr.into()).await?;
    Ok(())
}

async fn read_nbr(asn: u32, addr: IpAddr, c: Client) -> Result<()> {
    let nbr = c.read_neighbor(&addr, asn).await?.into_inner();
    println!("{nbr:#?}");
    Ok(())
}

async fn update_nbr(nbr: Neighbor, c: Client) -> Result<()> {
    c.update_neighbor(&nbr.into()).await?;
    Ok(())
}

async fn delete_nbr(asn: u32, addr: IpAddr, c: Client) -> Result<()> {
    c.delete_neighbor(&addr, asn).await?;
    Ok(())
}

async fn clear_nbr(
    asn: u32,
    addr: IpAddr,
    op: NeighborResetOp,
    c: Client,
) -> Result<()> {
    c.clear_neighbor(&NeighborResetRequest {
        asn,
        addr,
        op: op.into(),
    })
    .await?;
    Ok(())
}

async fn create_origin4(originate: Originate4, c: Client) -> Result<()> {
    c.create_origin4(&types::Origin4 {
        asn: originate.asn,
        prefixes: originate
            .prefixes
            .clone()
            .into_iter()
            .map(|x| Prefix4::new(x.value, x.length))
            .collect(),
    })
    .await?;
    Ok(())
}

async fn update_origin4(originate: Originate4, c: Client) -> Result<()> {
    c.update_origin4(&types::Origin4 {
        asn: originate.asn,
        prefixes: originate
            .prefixes
            .clone()
            .into_iter()
            .map(|x| Prefix4::new(x.value, x.length))
            .collect(),
    })
    .await?;
    Ok(())
}

async fn delete_origin4(asn: u32, c: Client) -> Result<()> {
    c.delete_origin4(asn).await?;
    Ok(())
}

async fn read_origin4(asn: u32, c: Client) -> Result<()> {
    let o4 = c.read_origin4(asn).await?;
    println!("{o4:#?}");
    Ok(())
}

async fn create_origin6(originate: Originate6, c: Client) -> Result<()> {
    c.create_origin6(&types::Origin6 {
        asn: originate.asn,
        prefixes: originate
            .prefixes
            .clone()
            .into_iter()
            .map(|x| Prefix6::new(x.value, x.length))
            .collect(),
    })
    .await?;
    Ok(())
}

async fn update_origin6(originate: Originate6, c: Client) -> Result<()> {
    c.update_origin6(&types::Origin6 {
        asn: originate.asn,
        prefixes: originate
            .prefixes
            .clone()
            .into_iter()
            .map(|x| Prefix6::new(x.value, x.length))
            .collect(),
    })
    .await?;
    Ok(())
}

async fn delete_origin6(asn: u32, c: Client) -> Result<()> {
    c.delete_origin6(asn).await?;
    Ok(())
}

async fn read_origin6(asn: u32, c: Client) -> Result<()> {
    let o6 = c.read_origin6(asn).await?;
    println!("{o6:#?}");
    Ok(())
}

async fn apply(filename: String, c: Client) -> Result<()> {
    let contents = read_to_string(filename)?;
    let request: types::ApplyRequest = serde_json::from_str(&contents)?;
    c.bgp_apply(&request).await?;
    Ok(())
}

async fn create_chk(filename: String, asn: u32, c: Client) -> Result<()> {
    let code = std::fs::read_to_string(filename)?;

    // check that the program is loadable first
    bgp::policy::load_checker(&code)?;

    c.create_checker(&types::CheckerSource { asn, code })
        .await?;
    Ok(())
}

async fn read_chk(asn: u32, c: Client) -> Result<()> {
    let result = c.read_checker(asn).await?;
    print!("{result:#?}");
    Ok(())
}

async fn update_chk(filename: String, asn: u32, c: Client) -> Result<()> {
    let code = std::fs::read_to_string(filename)?;

    // check that the program is loadable first
    bgp::policy::load_checker(&code)?;

    c.update_checker(&types::CheckerSource { asn, code })
        .await?;
    Ok(())
}

async fn delete_chk(asn: u32, c: Client) -> Result<()> {
    c.delete_checker(asn).await?;
    Ok(())
}

async fn create_shp(filename: String, asn: u32, c: Client) -> Result<()> {
    let code = std::fs::read_to_string(filename)?;

    // check that the program is loadable first
    bgp::policy::load_shaper(&code)?;

    c.create_shaper(&types::ShaperSource { asn, code }).await?;
    Ok(())
}

async fn read_shp(asn: u32, c: Client) -> Result<()> {
    let result = c.read_shaper(asn).await?;
    print!("{result:#?}");
    Ok(())
}

async fn update_shp(filename: String, asn: u32, c: Client) -> Result<()> {
    let code = std::fs::read_to_string(filename).unwrap();

    // check that the program is loadable first
    bgp::policy::load_shaper(&code).unwrap();

    c.update_shaper(&types::ShaperSource { asn, code }).await?;
    Ok(())
}

async fn delete_shp(asn: u32, c: Client) -> Result<()> {
    c.delete_shaper(asn).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ipv4_prefix_parsing_in_cli() {
        // Test that IPv4 prefixes can be parsed for CLI usage
        let prefix_str = "192.168.1.0/24";
        let prefix = Prefix4::from_str(prefix_str).expect("parse IPv4 prefix");

        assert_eq!(prefix.value.to_string(), "192.168.1.0");
        assert_eq!(prefix.length, 24);

        // Test Originate4 struct creation (simulating CLI argument parsing)
        let originate4 = Originate4 {
            asn: 65001,
            prefixes: vec![prefix],
        };

        assert_eq!(originate4.asn, 65001);
        assert_eq!(originate4.prefixes.len(), 1);
        assert_eq!(originate4.prefixes[0].value.to_string(), "192.168.1.0");
        assert_eq!(originate4.prefixes[0].length, 24);
    }

    #[test]
    fn test_ipv6_prefix_parsing_in_cli() {
        // Test that IPv6 prefixes can be parsed for CLI usage
        let prefix_str = "2001:db8::/32";
        let prefix = Prefix6::from_str(prefix_str).expect("parse IPv6 prefix");

        assert_eq!(prefix.value.to_string(), "2001:db8::");
        assert_eq!(prefix.length, 32);

        // Test Originate6 struct creation (simulating CLI argument parsing)
        let originate6 = Originate6 {
            asn: 65001,
            prefixes: vec![prefix],
        };

        assert_eq!(originate6.asn, 65001);
        assert_eq!(originate6.prefixes.len(), 1);
        assert_eq!(originate6.prefixes[0].value.to_string(), "2001:db8::");
        assert_eq!(originate6.prefixes[0].length, 32);
    }
}
