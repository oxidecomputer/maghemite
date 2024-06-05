// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::Parser;
use colored::*;
use ddm_admin_client::{types, Client};
use mg_common::cli::oxide_cli_style;
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
use slog::{Drain, Logger};
use std::io::{stdout, Write};
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
struct Peer {
    addr: Ipv6Addr,
}

#[tokio::main]
async fn main() -> Result<()> {
    run().await
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

// fn to_ipv6_prefix(x: &types::Ipv6Net) -> Ipv6Net {
//     Ipv6Net {
//         addr: x.addr,
//         len: x.len,
//     }
// }

// fn to_ipv4_prefix(x: &types::Ipv4Net) -> Ipv4Net {
//     Ipv4Net {
//         addr: x.addr,
//         len: x.len,
//     }
// }

// fn to_ip_prefix(x: &types::IpNet) -> IpNet {
//     match x {
//         types::IpNet::V4(p) => IpNet::V4(to_ipv4_prefix(p)),
//         types::IpNet::V6(p) => IpNet::V6(to_ipv6_prefix(p)),
//     }
// }

// fn to_types_ipv6_prefix(x: &Ipv6Net) -> types::Ipv6Net {
//     types::Ipv6Net {
//         addr: x.addr,
//         len: x.len,
//     }
// }

// fn to_types_ipv4_prefix(x: &Ipv4Net) -> types::Ipv4Net {
//     types::Ipv4Net {
//         addr: x.addr,
//         len: x.len,
//     }
// }

// fn to_types_ip_prefix(x: &IpNet) -> types::IpNet {
//     match x {
//         IpNet::V4(p) => types::IpNet::V4(to_types_ipv4_prefix(p)),
//         IpNet::V6(p) => types::IpNet::V6(to_types_ipv6_prefix(p)),
//     }
// }
