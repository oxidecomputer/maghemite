// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use bgp::params::JitterRange;
use clap::{Args, Subcommand, ValueEnum};
use colored::*;
use mg_admin_client::{
    Client,
    types::{
        self, ImportExportPolicy4, ImportExportPolicy6, Ipv4UnicastConfig,
        Ipv6UnicastConfig, NeighborResetOp as MgdNeighborResetOp,
        NeighborResetRequest,
    },
};
use rdb::types::{PolicyAction, Prefix4, Prefix6};
use std::fs::read_to_string;
use std::io::{Write, stdout};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tabwriter::TabWriter;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage router configuration.
    Config(ConfigSubcommand),

    /// View dynamic router state.
    Status(StatusSubcommand),

    /// View event history for BGP sessions.
    History(HistorySubcommand),

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

#[derive(Clone, Debug, ValueEnum)]
#[allow(non_camel_case_types)]
pub enum NeighborDisplayMode {
    /// Display summary information (default).
    summary,
    /// Display detailed information.
    detail,
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

        /// Display mode: summary (default) or detail.
        #[clap(long, value_enum, default_value = "summary")]
        mode: NeighborDisplayMode,
    },

    /// Get the prefixes exported by a BGP router.
    Exported {
        #[clap(env)]
        asn: u32,
    },
}

#[derive(Args, Debug)]
pub struct HistorySubcommand {
    #[command(subcommand)]
    command: HistoryCmd,
}

#[derive(Subcommand, Debug)]
pub enum HistoryCmd {
    /// Get FSM event history for BGP sessions.
    Fsm {
        /// Optional: Filter by specific peer address.
        peer: Option<IpAddr>,

        /// Which buffer to display: 'major' (default) or 'all'.
        #[clap(default_value = "major")]
        buffer: String,

        /// BGP Autonomous System number. Can be specified via ASN env var.
        #[clap(env)]
        asn: Option<u32>,

        /// Number of records to display. Use 'all' or '0' to show everything.
        #[clap(long, default_value = "20")]
        limit: String,

        /// Display full details without truncation.
        #[clap(long)]
        wide: bool,
    },

    /// Get BGP message history for sessions.
    Message {
        /// Peer address to show history for.
        peer: IpAddr,

        /// BGP Autonomous System number. Can be specified via ASN env var.
        #[clap(env)]
        asn: Option<u32>,

        /// Filter by direction: 'sent', 'received', or 'both' (default).
        #[clap(long, default_value = "both")]
        direction: String,

        /// Number of records to display. Use 'all' or '0' to show everything.
        #[clap(long, default_value = "20")]
        limit: String,

        /// Display full message content without truncation.
        #[clap(long)]
        wide: bool,
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

    /// Jitter range for idle hold timer (min,max format, e.g., "0.75,1.0").
    #[arg(long)]
    pub idle_hold_jitter: Option<JitterRange>,

    /// How long to wait between connection retries (s).
    #[arg(long, default_value_t = 5)]
    connect_retry_time: u64,

    /// Jitter range for connect_retry timer (min,max format, e.g., "0.75,1.0").
    #[arg(long)]
    pub connect_retry_jitter: Option<JitterRange>,

    /// Interval for sending keepalive messages (s).
    #[arg(long, default_value_t = 2)]
    keepalive_time: u64,

    /// How long to delay sending an open message (s).
    #[arg(long, default_value_t = 0)]
    delay_open_time: u64,

    /// Enable deterministic collision resolution in Established state.
    #[arg(long, default_value_t = false)]
    pub deterministic_collision_resolution: bool,

    /// Timer granularity in ms (how often do timers tick).
    #[arg(long, default_value_t = 100)]
    clock_resolution: u64,

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

    /// Enable IPv4 unicast address family.
    #[arg(long)]
    pub enable_ipv4: bool,

    /// IPv4 prefixes to allow importing (requires --enable-ipv4).
    #[arg(long, requires = "enable_ipv4")]
    pub allow_import4: Option<Vec<Prefix4>>,

    /// IPv4 prefixes to allow exporting (requires --enable-ipv4).
    #[arg(long, requires = "enable_ipv4")]
    pub allow_export4: Option<Vec<Prefix4>>,

    /// IPv4 nexthop override for this neighbor (requires --enable-ipv4).
    #[arg(long, requires = "enable_ipv4")]
    pub nexthop4: Option<IpAddr>,

    /// Enable IPv6 unicast address family.
    #[arg(long)]
    pub enable_ipv6: bool,

    /// IPv6 prefixes to allow importing (requires --enable-ipv6).
    #[arg(long, requires = "enable_ipv6")]
    pub allow_import6: Option<Vec<Prefix6>>,

    /// IPv6 prefixes to allow exporting (requires --enable-ipv6).
    #[arg(long, requires = "enable_ipv6")]
    pub allow_export6: Option<Vec<Prefix6>>,

    /// IPv6 nexthop override for this neighbor (requires --enable-ipv6).
    #[arg(long, requires = "enable_ipv6")]
    pub nexthop6: Option<IpAddr>,

    /// Autonomous system number for the router to add the neighbor to.
    #[clap(env)]
    pub asn: u32,
}

impl From<Neighbor> for types::Neighbor {
    fn from(n: Neighbor) -> types::Neighbor {
        // Build IPv4 unicast config if enabled
        let ipv4_unicast = if n.enable_ipv4 {
            let import_policy = match n.allow_import4 {
                Some(prefixes) => {
                    ImportExportPolicy4::Allow(prefixes.into_iter().collect())
                }
                None => ImportExportPolicy4::NoFiltering,
            };
            let export_policy = match n.allow_export4 {
                Some(prefixes) => {
                    ImportExportPolicy4::Allow(prefixes.into_iter().collect())
                }
                None => ImportExportPolicy4::NoFiltering,
            };
            Some(Ipv4UnicastConfig {
                nexthop: n.nexthop4,
                import_policy,
                export_policy,
            })
        } else {
            None
        };

        // Build IPv6 unicast config if enabled
        let ipv6_unicast = if n.enable_ipv6 {
            let import_policy = match n.allow_import6 {
                Some(prefixes) => {
                    ImportExportPolicy6::Allow(prefixes.into_iter().collect())
                }
                None => ImportExportPolicy6::NoFiltering,
            };
            let export_policy = match n.allow_export6 {
                Some(prefixes) => {
                    ImportExportPolicy6::Allow(prefixes.into_iter().collect())
                }
                None => ImportExportPolicy6::NoFiltering,
            };
            Some(Ipv6UnicastConfig {
                nexthop: n.nexthop6,
                import_policy,
                export_policy,
            })
        } else {
            None
        };

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
            resolution: n.clock_resolution,
            group: n.group,
            passive: n.passive_connection,
            md5_auth_key: n.md5_auth_key.clone(),
            multi_exit_discriminator: n.med,
            communities: n.communities,
            local_pref: n.local_pref,
            enforce_first_as: n.enforce_first_as,
            ipv4_unicast,
            ipv6_unicast,
            vlan_id: n.vlan_id,
            connect_retry_jitter: n.connect_retry_jitter,
            idle_hold_jitter: n.idle_hold_jitter,
            deterministic_collision_resolution: n
                .deterministic_collision_resolution,
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
            StatusCmd::Neighbors { asn, mode } => {
                get_neighbors(c, asn, mode).await?
            }
            StatusCmd::Exported { asn } => get_exported(c, asn).await?,
        },

        Commands::History(cmd) => match cmd.command {
            HistoryCmd::Fsm {
                asn,
                peer,
                buffer,
                limit,
                wide,
            } => {
                let asn = asn.ok_or_else(|| {
                    anyhow::anyhow!("ASN is required. Specify it on the command line or set the ASN environment variable.")
                })?;
                get_fsm_history(c, asn, peer, &buffer, &limit, wide).await?
            }
            HistoryCmd::Message {
                asn,
                peer,
                direction,
                limit,
                wide,
            } => {
                let asn = asn.ok_or_else(|| {
                    anyhow::anyhow!("ASN is required. Specify it on the command line or set the ASN environment variable.")
                })?;
                get_message_history(c, asn, peer, &direction, &limit, wide)
                    .await?
            }
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

async fn get_neighbors(
    c: Client,
    asn: u32,
    mode: NeighborDisplayMode,
) -> Result<()> {
    let result = c.get_neighbors_v3(asn).await?;
    let mut sorted: Vec<_> = result.iter().collect();
    sorted.sort_by_key(|(ip, _)| ip.parse::<IpAddr>().ok());

    match mode {
        NeighborDisplayMode::summary => {
            display_neighbors_summary(&sorted)?;
        }
        NeighborDisplayMode::detail => {
            display_neighbors_detail(&sorted)?;
        }
    }

    Ok(())
}

/// Format a Duration as decimal seconds (e.g., "4.300s", "0.100s", "10.000s")
fn format_duration_decimal(d: Duration) -> String {
    let secs = d.as_secs();
    let millis = d.subsec_millis();
    format!("{}.{:03}s", secs, millis)
}

fn display_neighbors_summary(
    neighbors: &[(&String, &bgp::params::PeerInfo)],
) -> Result<()> {
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

    for (addr, info) in neighbors.iter() {
        writeln!(
            &mut tw,
            "{}\t{:?}\t{:?}\t{:}\t{}/{}\t{}/{}",
            addr,
            info.asn,
            info.fsm_state,
            humantime::Duration::from(Duration::from_millis(
                info.fsm_state_duration
            ),),
            humantime::Duration::from(info.timers.hold.configured),
            humantime::Duration::from(info.timers.hold.negotiated),
            humantime::Duration::from(info.timers.keepalive.configured),
            humantime::Duration::from(info.timers.keepalive.negotiated),
        )
        .unwrap();
    }
    tw.flush().unwrap();
    Ok(())
}

fn display_neighbors_detail(
    neighbors: &[(&String, &bgp::params::PeerInfo)],
) -> Result<()> {
    for (i, (addr, info)) in neighbors.iter().enumerate() {
        if i > 0 {
            println!();
        }

        println!("{}", "=".repeat(80));
        println!("{}", format!("Neighbor: {}", addr).bold());
        println!("{}", "=".repeat(80));

        println!("\n{}", "Basic Information:".bold());
        println!("  Name: {}", info.name);
        println!("  Peer Group: {}", info.peer_group);
        println!("  FSM State: {:?}", info.fsm_state);
        println!(
            "  FSM State Duration: {}",
            humantime::Duration::from(Duration::from_millis(
                info.fsm_state_duration
            ))
        );
        if let Some(asn) = info.asn {
            println!("  Peer ASN: {}", asn);
        }
        if let Some(id) = info.id {
            println!("  Peer Router ID: {}", Ipv4Addr::from(id));
        }

        println!("\n{}", "Connection:".bold());
        println!("  Local: {}:{}", info.local_ip, info.local_tcp_port);
        println!("  Remote: {}:{}", info.remote_ip, info.remote_tcp_port);

        println!("\n{}", "Address Families:".bold());
        println!("  IPv4 Unicast:");
        println!("    Import Policy: {:?}", info.ipv4_unicast.import_policy);
        println!("    Export Policy: {:?}", info.ipv4_unicast.export_policy);
        if let Some(nh) = info.ipv4_unicast.nexthop {
            println!("    Nexthop: {}", nh);
        }

        println!("  IPv6 Unicast:");
        println!("    Import Policy: {:?}", info.ipv6_unicast.import_policy);
        println!("    Export Policy: {:?}", info.ipv6_unicast.export_policy);
        if let Some(nh) = info.ipv6_unicast.nexthop {
            println!("    Nexthop: {}", nh);
        }

        println!("\n{}", "Timers:".bold());
        println!(
            "  Hold Time: configured={}, negotiated={}, remaining={}",
            format_duration_decimal(info.timers.hold.configured),
            format_duration_decimal(info.timers.hold.negotiated),
            format_duration_decimal(info.timers.hold.remaining),
        );
        println!(
            "  Keepalive: configured={}, negotiated={}, remaining={}",
            format_duration_decimal(info.timers.keepalive.configured),
            format_duration_decimal(info.timers.keepalive.negotiated),
            format_duration_decimal(info.timers.keepalive.remaining),
        );
        println!(
            "  Connect Retry: configured={}, remaining={}",
            format_duration_decimal(info.timers.connect_retry.configured),
            format_duration_decimal(info.timers.connect_retry.remaining),
        );
        match info.timers.connect_retry_jitter {
            Some(jitter) => {
                println!("    Jitter: {}-{}", jitter.min, jitter.max)
            }
            None => println!("    Jitter: none"),
        }
        println!(
            "  Idle Hold: configured={}, remaining={}",
            format_duration_decimal(info.timers.idle_hold.configured),
            format_duration_decimal(info.timers.idle_hold.remaining),
        );
        match info.timers.idle_hold_jitter {
            Some(jitter) => {
                println!("    Jitter: {}-{}", jitter.min, jitter.max)
            }
            None => println!("    Jitter: none"),
        }
        println!(
            "  Delay Open: configured={}, remaining={}",
            format_duration_decimal(info.timers.delay_open.configured),
            format_duration_decimal(info.timers.delay_open.remaining),
        );

        if !info.received_capabilities.is_empty() {
            println!("\n{}", "Received Capabilities:".bold());
            for cap in &info.received_capabilities {
                println!("  {:?}", cap);
            }
        }

        println!("\n{}", "Counters:".bold());
        println!("  Prefixes:");
        println!("    Advertised: {}", info.counters.prefixes_advertised);
        println!("    Imported: {}", info.counters.prefixes_imported);

        println!("  Messages Sent:");
        println!("    Opens: {}", info.counters.opens_sent);
        println!("    Updates: {}", info.counters.updates_sent);
        println!("    Keepalives: {}", info.counters.keepalives_sent);
        println!("    Route Refresh: {}", info.counters.route_refresh_sent);
        println!("    Notifications: {}", info.counters.notifications_sent);

        println!("  Messages Received:");
        println!("    Opens: {}", info.counters.opens_received);
        println!("    Updates: {}", info.counters.updates_received);
        println!("    Keepalives: {}", info.counters.keepalives_received);
        println!(
            "    Route Refresh: {}",
            info.counters.route_refresh_received
        );
        println!(
            "    Notifications: {}",
            info.counters.notifications_received
        );

        println!("  FSM Transitions:");
        println!(
            "    To Established: {}",
            info.counters.transitions_to_established
        );
        println!("    To Idle: {}", info.counters.transitions_to_idle);
        println!("    To Connect: {}", info.counters.transitions_to_connect);

        println!("  Connections:");
        println!(
            "    Active Accepted: {}",
            info.counters.active_connections_accepted
        );
        println!(
            "    Active Declined: {}",
            info.counters.active_connections_declined
        );
        println!(
            "    Passive Accepted: {}",
            info.counters.passive_connections_accepted
        );
        println!(
            "    Passive Declined: {}",
            info.counters.passive_connections_declined
        );
        println!(
            "    Connection Retries: {}",
            info.counters.connection_retries
        );

        // Error Counters
        println!("\n{}", "Error Counters:".bold());
        println!(
            "  TCP Connection Failures: {}",
            info.counters.tcp_connection_failure
        );
        println!("  MD5 Auth Failures: {}", info.counters.md5_auth_failures);
        println!(
            "  Hold Timer Expirations: {}",
            info.counters.hold_timer_expirations
        );
        println!(
            "  Update Nexthop Missing: {}",
            info.counters.update_nexhop_missing
        );
        println!(
            "  Open Handle Failures: {}",
            info.counters.open_handle_failures
        );
        println!(
            "  Notification Send Failures: {}",
            info.counters.notification_send_failure
        );
        println!("  Connector Panics: {}", info.counters.connector_panics);
    }

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
    let nbrs = c.read_neighbors_v2(asn).await?;
    println!("{nbrs:#?}");
    Ok(())
}

async fn create_nbr(nbr: Neighbor, c: Client) -> Result<()> {
    c.create_neighbor_v2(&nbr.into()).await?;
    Ok(())
}

async fn read_nbr(asn: u32, addr: IpAddr, c: Client) -> Result<()> {
    let nbr = c.read_neighbor_v2(&addr, asn).await?.into_inner();
    println!("{nbr:#?}");
    Ok(())
}

async fn update_nbr(nbr: Neighbor, c: Client) -> Result<()> {
    c.update_neighbor_v2(&nbr.into()).await?;
    Ok(())
}

async fn delete_nbr(asn: u32, addr: IpAddr, c: Client) -> Result<()> {
    c.delete_neighbor_v2(&addr, asn).await?;
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
    c.bgp_apply_v2(&request).await?;
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

async fn get_fsm_history(
    c: Client,
    asn: u32,
    peer: Option<IpAddr>,
    buffer: &str,
    limit_str: &str,
    wide: bool,
) -> Result<()> {
    // Parse buffer type for server-side filtering
    let buffer_type = match buffer {
        "all" => Some(types::FsmEventBuffer::All),
        _ => Some(types::FsmEventBuffer::Major), // Default to major
    };

    let buffer_name = match buffer {
        "all" => "All Events",
        _ => "Major Events",
    };

    let result = c
        .fsm_history(&types::FsmHistoryRequest {
            asn,
            peer,
            buffer: buffer_type,
        })
        .await?
        .into_inner();

    if result.by_peer.is_empty() {
        if let Some(peer_addr) = peer {
            println!("No FSM history found for peer {}", peer_addr);
        } else {
            println!("No FSM history found for ASN {}", asn);
        }
        return Ok(());
    }

    // Parse limit ("all" or "0" means unlimited)
    let limit = if limit_str == "all" {
        usize::MAX
    } else {
        match limit_str.parse::<usize>() {
            Ok(0) => usize::MAX,
            Ok(n) => n,
            Err(_) => 20,
        }
    };

    // Display FSM history in tabular format
    for (peer_addr, events) in result.by_peer.iter() {
        if events.is_empty() {
            println!(
                "\n{}",
                format!(
                    "FSM Event History - Peer: {} - {} (empty)",
                    peer_addr, buffer_name
                )
                .dimmed()
            );
            continue;
        }

        println!(
            "\n{}",
            format!(
                "FSM Event History - Peer: {} - {}",
                peer_addr, buffer_name
            )
            .dimmed()
        );
        println!("{}", "=".repeat(100).dimmed());
        println!(
            "Showing {} of {} events\n",
            events.len().min(limit),
            events.len()
        );

        let mut tw = TabWriter::new(stdout());
        writeln!(
            &mut tw,
            "{}\t{}\t{}\t{}\t{}\t{}",
            "Timestamp".dimmed(),
            "Category".dimmed(),
            "Event".dimmed(),
            "State".dimmed(),
            "Transition".dimmed(),
            "Details".dimmed(),
        )?;

        for event in events.iter().take(limit) {
            let timestamp = event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f");
            let category = format!("{:?}", event.event_category);
            let transition = if let Some(prev) = &event.previous_state {
                format!("{:?} → {:?}", prev, event.current_state)
            } else {
                format!("{:?}", event.current_state)
            };
            let details = event.details.as_deref().unwrap_or("-");

            // Truncate unless wide mode
            let details_display = if !wide && details.len() > 50 {
                format!("{}...", &details[..47])
            } else {
                details.to_string()
            };

            writeln!(
                &mut tw,
                "{}\t{}\t{}\t{:?}\t{}\t{}",
                timestamp,
                category,
                event.event_type,
                event.current_state,
                transition,
                details_display,
            )?;
        }
        tw.flush()?;

        if events.len() > limit {
            println!(
                "\n... ({} more events not shown, use --limit all to see everything)",
                events.len() - limit
            );
        }
    }

    Ok(())
}

async fn get_message_history(
    c: Client,
    asn: u32,
    peer: IpAddr,
    direction: &str,
    limit_str: &str,
    wide: bool,
) -> Result<()> {
    // Parse direction filter
    let dir = match direction {
        "sent" => Some(types::MessageDirection::Sent),
        "received" => Some(types::MessageDirection::Received),
        _ => None, // "both" or any other value means no filter
    };

    // Parse limit ("all" or "0" means unlimited)
    let limit = if limit_str == "all" {
        usize::MAX
    } else {
        match limit_str.parse::<usize>() {
            Ok(0) => usize::MAX,
            Ok(n) => n,
            Err(_) => 20,
        }
    };

    let result = c
        .message_history_v2(&types::MessageHistoryRequest {
            asn,
            peer: Some(peer),
            direction: dir,
        })
        .await?
        .into_inner();

    if result.by_peer.is_empty() {
        println!("No message history found for ASN {} peer {}", asn, peer);
        return Ok(());
    }

    // Should only have one peer since we filtered by peer
    // Note: by_peer uses String keys (from JSON serialization)
    let history = result.by_peer.get(&peer.to_string()).ok_or_else(|| {
        anyhow::anyhow!("Peer {} not found in message history", peer)
    })?;

    // Combine sent and received messages with their direction
    let mut all_messages = Vec::new();

    for entry in &history.received {
        all_messages.push((
            entry.timestamp,
            "RX",
            &entry.connection_id,
            &entry.message,
        ));
    }

    for entry in &history.sent {
        all_messages.push((
            entry.timestamp,
            "TX",
            &entry.connection_id,
            &entry.message,
        ));
    }

    // Sort by timestamp (oldest first)
    all_messages.sort_by_key(|(ts, _, _, _)| *ts);

    // Apply limit
    let messages_to_show =
        all_messages.iter().rev().take(limit).collect::<Vec<_>>();
    let total_count = all_messages.len();

    println!(
        "\n{}",
        format!("BGP Message History - Peer: {}", peer).dimmed()
    );
    println!("{}", "=".repeat(80).dimmed());
    println!(
        "Showing {} of {} messages ({} RX, {} TX)\n",
        messages_to_show.len(),
        total_count,
        history.received.len(),
        history.sent.len()
    );

    // Display messages in reverse chronological order (newest first)
    for (timestamp, direction, conn_id, message) in
        messages_to_show.iter().rev()
    {
        let ts_str = timestamp.format("%Y-%m-%d %H:%M:%S%.3f");
        let uuid_str = conn_id.uuid.to_string();
        let conn_short =
            format!("{}...{}", &uuid_str[..8], &uuid_str[uuid_str.len() - 4..]);

        // Use Debug formatting for full message content
        // (client-generated types don't implement Display)
        let msg_content = format!("{:?}", message);

        // Apply truncation unless wide mode
        let msg_display = if !wide && msg_content.len() > 100 {
            format!("{}...", &msg_content[..97])
        } else {
            msg_content
        };

        println!(
            "{} {} [{}] {}",
            ts_str.to_string().dimmed(),
            if *direction == "RX" {
                "←".green()
            } else {
                "→".blue()
            },
            conn_short.dimmed(),
            msg_display
        );
    }

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
