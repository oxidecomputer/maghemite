// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::Parser;
use colored::*;
use ddm_admin_client::{Client, types};
use mg_common::cli::oxide_cli_style;
use oxnet::{IpNet, Ipv6Net};
use slog::{Drain, Logger};
use std::io::{Write, stdout};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tabwriter::TabWriter;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None, styles = oxide_cli_style())]
struct Arg {
    /// Address of the router's admin API.
    #[arg(short, long, default_value_t = Ipv6Addr::UNSPECIFIED.into())]
    address: IpAddr,

    /// Admin API TCP port.
    #[arg(short, long, default_value_t = 8000)]
    port: u16,

    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Debug, Parser)]
enum SubCommand {
    /// Get a DDM router's peers.
    GetPeers,

    /// Expire a peer.
    ExpirePeer(Peer),

    /// Get the prefixes a DDM router knows about.
    GetPrefixes,

    /// Get the prefixes a DDM router has originated.
    GetOriginated,

    /// Advertise prefixes from a DDM router.
    AdvertisePrefixes(Prefixes),

    /// Withdraw prefixes from a DDM router.
    WithdrawPrefixes(Prefixes),

    /// Get the tunnel endpoints a DDM router knows about.
    TunnelImported,

    /// Get the tunnel endpoints a DDM router has originated.
    TunnelOriginated,

    /// Advertise prefixes from a DDM router.
    TunnelAdvertise(TunnelEndpoint),

    /// Withdraw prefixes from a DDM router.
    TunnelWithdraw(TunnelEndpoint),

    /// Get multicast groups imported from DDM peers.
    MulticastImported,

    /// Get locally originated multicast groups.
    MulticastOriginated,

    /// Advertise multicast groups from this router.
    MulticastAdvertise(MulticastGroup),

    /// Withdraw multicast groups from this router.
    MulticastWithdraw(MulticastGroup),

    /// Sync prefix information from peers.
    Sync,
}

#[derive(Debug, Parser)]
struct Prefixes {
    prefixes: Vec<Ipv6Net>,
}

#[derive(Debug, Parser)]
struct TunnelEndpoint {
    #[arg(short, long)]
    pub overlay_prefix: IpNet,

    #[arg(short, long)]
    pub boundary_addr: Ipv6Addr,

    #[arg(short, long)]
    pub vni: u32,

    #[arg(short, long)]
    pub metric: u64,
}

#[derive(Debug, Parser)]
struct MulticastGroup {
    /// Overlay multicast group address (e.g. 233.252.0.1 or ff0e::1).
    #[arg(short = 'g', long)]
    pub overlay_group: IpAddr,

    /// Underlay multicast address (ff04::/64 admin-local scope).
    #[arg(short = 'u', long)]
    pub underlay_group: Ipv6Addr,

    /// Virtual Network Identifier.
    #[arg(short, long)]
    pub vni: u32,

    /// Path metric.
    #[arg(short, long, default_value_t = 0)]
    pub metric: u64,

    /// Source address for (S,G) routes (omit for (*,G)).
    #[arg(short, long)]
    pub source: Option<IpAddr>,
}

#[derive(Debug, Parser)]
struct Peer {
    addr: Ipv6Addr,
}

fn main() -> Result<()> {
    oxide_tokio_rt::run(run())
}

async fn run() -> Result<()> {
    let arg = Arg::parse();
    let sa: SocketAddr = match arg.address {
        IpAddr::V4(a) => SocketAddrV4::new(a, arg.port).into(),
        IpAddr::V6(a) => SocketAddrV6::new(a, arg.port, 0, 0).into(),
    };
    let endpoint = format!("http://{}", sa);
    let log = init_logger();
    let client = Client::new(&endpoint, log.clone());

    match arg.subcmd {
        SubCommand::GetPeers => {
            let msg = client.get_peers().await?;
            let mut tw = TabWriter::new(stdout());
            writeln!(
                &mut tw,
                "{}\t{}\t{}\t{}\t{}",
                "Interface".dimmed(),
                "Host".dimmed(),
                "Address".dimmed(),
                "Kind".dimmed(),
                "Status".dimmed(),
            )?;
            for (index, info) in &msg.into_inner() {
                writeln!(
                    &mut tw,
                    "{}\t{}\t{}\t{}\t{:?}",
                    index,
                    info.host,
                    info.addr,
                    match *info.kind {
                        0 => "Server",
                        1 => "Transit",
                        _ => "?",
                    },
                    info.status,
                )?;
            }
            tw.flush()?;
        }
        SubCommand::ExpirePeer(peer) => {
            client.expire_peer(&peer.addr).await?;
        }
        SubCommand::GetPrefixes => {
            let msg = client.get_prefixes().await?;
            let mut tw = TabWriter::new(stdout());
            writeln!(
                &mut tw,
                "{}\t{}\t{}",
                "Destination".dimmed(),
                "Next Hop".dimmed(),
                "Path".dimmed(),
            )?;
            for (nexthop, mut destinations) in msg.into_inner() {
                for pv in &mut destinations {
                    // show path from perspective of this node, e.g. nearest node
                    // first
                    pv.path.reverse();
                    let strpath = pv.path.join(" ");
                    writeln!(
                        &mut tw,
                        "{}\t{}\t{}",
                        &pv.destination, nexthop, strpath,
                    )?;
                }
            }
            tw.flush()?;
        }
        SubCommand::GetOriginated => {
            let msg = client.get_originated().await?;
            let mut tw = TabWriter::new(stdout());
            writeln!(&mut tw, "{}", "Prefix".dimmed(),)?;
            for prefix in msg.into_inner() {
                writeln!(&mut tw, "{}", &prefix)?;
            }
            tw.flush()?;
        }
        SubCommand::AdvertisePrefixes(ac) => {
            client.advertise_prefixes(&ac.prefixes).await?;
        }
        SubCommand::WithdrawPrefixes(ac) => {
            client.withdraw_prefixes(&ac.prefixes).await?;
        }
        SubCommand::TunnelImported => {
            let msg = client.get_tunnel_endpoints().await?;
            let mut tw = TabWriter::new(stdout());
            writeln!(
                &mut tw,
                "{}\t{}\t{}\t{}",
                "Overlay Prefix".dimmed(),
                "Boundary Address".dimmed(),
                "VNI".dimmed(),
                "Metric".dimmed(),
            )?;
            for endpoint in msg.into_inner() {
                writeln!(
                    &mut tw,
                    "{}\t{}\t{}\t{}",
                    &endpoint.origin.overlay_prefix,
                    endpoint.origin.boundary_addr,
                    endpoint.origin.vni,
                    endpoint.origin.metric,
                )?;
            }
            tw.flush()?;
        }
        SubCommand::TunnelOriginated => {
            let msg = client.get_originated_tunnel_endpoints().await?;
            let mut tw = TabWriter::new(stdout());
            writeln!(
                &mut tw,
                "{}\t{}\t{}\t{}",
                "Overlay Prefix".dimmed(),
                "Boundary Address".dimmed(),
                "VNI".dimmed(),
                "Metric".dimmed(),
            )?;
            for endpoint in msg.into_inner() {
                writeln!(
                    &mut tw,
                    "{}\t{}\t{}\t{}",
                    &endpoint.overlay_prefix,
                    endpoint.boundary_addr,
                    endpoint.vni,
                    endpoint.metric,
                )?;
            }
            tw.flush()?;
        }
        SubCommand::TunnelAdvertise(ep) => {
            client
                .advertise_tunnel_endpoints(&vec![types::TunnelOrigin {
                    overlay_prefix: ep.overlay_prefix,
                    boundary_addr: ep.boundary_addr,
                    vni: ep.vni,
                    metric: ep.metric,
                }])
                .await?;
        }
        SubCommand::TunnelWithdraw(ep) => {
            client
                .withdraw_tunnel_endpoints(&vec![types::TunnelOrigin {
                    overlay_prefix: ep.overlay_prefix,
                    boundary_addr: ep.boundary_addr,
                    vni: ep.vni,
                    metric: ep.metric,
                }])
                .await?;
        }
        SubCommand::MulticastImported => {
            let msg = client.get_multicast_groups().await?;
            let mut routes: Vec<_> = msg.into_inner().into_iter().collect();
            routes.sort_by(|a, b| {
                a.origin
                    .overlay_group
                    .cmp(&b.origin.overlay_group)
                    .then_with(|| a.origin.source.cmp(&b.origin.source))
            });
            let mut tw = TabWriter::new(stdout());
            writeln!(
                &mut tw,
                "{}\t{}\t{}\t{}\t{}\t{}",
                "Overlay Group".dimmed(),
                "Underlay Group".dimmed(),
                "VNI".dimmed(),
                "Metric".dimmed(),
                "Source".dimmed(),
                "Path".dimmed(),
            )?;
            for route in &routes {
                let source = match &route.origin.source {
                    Some(s) => s.to_string(),
                    None => "(*,G)".to_string(),
                };
                let path: Vec<_> = route
                    .path
                    .iter()
                    .rev()
                    .map(|h| h.router_id.clone())
                    .collect();
                writeln!(
                    &mut tw,
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    route.origin.overlay_group,
                    route.origin.underlay_group,
                    route.origin.vni,
                    route.origin.metric,
                    source,
                    path.join(" "),
                )?;
            }
            tw.flush()?;
        }
        SubCommand::MulticastOriginated => {
            let msg = client.get_originated_multicast_groups().await?;
            let mut origins: Vec<_> = msg.into_inner().into_iter().collect();
            origins.sort_by(|a, b| {
                a.overlay_group
                    .cmp(&b.overlay_group)
                    .then_with(|| a.source.cmp(&b.source))
            });
            let mut tw = TabWriter::new(stdout());
            writeln!(
                &mut tw,
                "{}\t{}\t{}\t{}\t{}",
                "Overlay Group".dimmed(),
                "Underlay Group".dimmed(),
                "VNI".dimmed(),
                "Metric".dimmed(),
                "Source".dimmed(),
            )?;
            for origin in &origins {
                let source = match &origin.source {
                    Some(s) => s.to_string(),
                    None => "(*,G)".to_string(),
                };
                writeln!(
                    &mut tw,
                    "{}\t{}\t{}\t{}\t{}",
                    origin.overlay_group,
                    origin.underlay_group,
                    origin.vni,
                    origin.metric,
                    source,
                )?;
            }
            tw.flush()?;
        }
        SubCommand::MulticastAdvertise(mg) => {
            client
                .advertise_multicast_groups(&vec![types::MulticastOrigin {
                    overlay_group: mg.overlay_group,
                    underlay_group: mg.underlay_group,
                    vni: types::Vni(mg.vni),
                    metric: mg.metric,
                    source: mg.source,
                }])
                .await?;
        }
        SubCommand::MulticastWithdraw(mg) => {
            client
                .withdraw_multicast_groups(&vec![types::MulticastOrigin {
                    overlay_group: mg.overlay_group,
                    underlay_group: mg.underlay_group,
                    vni: types::Vni(mg.vni),
                    metric: mg.metric,
                    source: mg.source,
                }])
                .await?;
        }
        SubCommand::Sync => {
            client.sync().await?;
        }
    }

    Ok(())
}

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, slog::o!())
}
