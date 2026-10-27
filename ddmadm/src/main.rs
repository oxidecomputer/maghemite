// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::Parser;
use client_common::println_nopipe;
use colored::*;
use ddm_admin_client::Client;
use ddm_api_types_versions::latest::db::{PeerStats, PeerStatus, RouterKind};
use ddm_api_types_versions::latest::external_peers::ExternalPeers;
use ddm_api_types_versions::latest::net as types;
use mg_common::cli::oxide_cli_style;
use mg_common::format_duration_human;
use oxnet::{IpNet, Ipv6Net};
use slog::{Drain, Logger};
use std::collections::BTreeMap;
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
    /// Get the routing session on each address object, and its peer.
    GetPeers,

    /// Get the counters of each routing session, or of one.
    PeerStats {
        /// Address object of the session to show. Shows every session if
        /// omitted.
        aobj_name: Option<String>,
    },

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

    /// Set external peers as a list of address objects.
    SetExternalPeers {
        addr_obj: Vec<String>,
    },

    // Get external peers
    GetExternalPeers,

    /// Get the rack prefixes a DDM transit router has originated.
    RackOriginated,

    /// Advertise rack prefixes from a DDM transit router.
    RackAdvertise(RackPrefixes),

    /// Withdraw rack prefixes from a DDM transit router.
    RackWithdraw(Prefixes),

    /// Get the rack prefixes a DDM router has learned from its peers.
    RackImported,
}

#[derive(Debug, Parser)]
struct Prefixes {
    prefixes: Vec<Ipv6Net>,
}

#[derive(Debug, Parser)]
struct RackPrefixes {
    prefixes: Vec<Ipv6Net>,

    /// Multi-rack join address to associate with the prefixes.
    #[arg(short, long)]
    join_addr: Option<SocketAddrV6>,
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

fn main() -> Result<()> {
    match oxide_tokio_rt::run(run()) {
        Ok(()) => Ok(()),
        Err(e) => {
            if mg_common::is_broken_pipe(&e) {
                std::process::exit(0);
            }
            Err(e)
        }
    }
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
                "{}\t{}\t{}\t{}\t{}\t{}",
                "Address Object".dimmed(),
                "Host".dimmed(),
                "Address".dimmed(),
                "Kind".dimmed(),
                "Status".dimmed(),
                "Duration".dimmed(),
            )?;
            let peers: BTreeMap<_, _> = msg.into_inner().into_iter().collect();
            for (aobj, info) in &peers {
                let (state, duration) = match &info.status {
                    PeerStatus::Init(d) => ("Init", d),
                    PeerStatus::Solicit(d) => ("Solicit", d),
                    PeerStatus::Exchange(d) => ("Exchange", d),
                    PeerStatus::Expired(d) => ("Expired", d),
                };
                let (host, addr, kind) = match &info.peer {
                    Some(p) => (
                        p.host.clone(),
                        p.addr.to_string(),
                        match p.kind {
                            RouterKind::Server => "Server",
                            RouterKind::Transit => "Transit",
                        },
                    ),
                    None => ("-".into(), "-".into(), "-"),
                };
                writeln!(
                    &mut tw,
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    aobj,
                    host,
                    addr,
                    kind,
                    state,
                    format_duration_human(*duration),
                )?;
            }
            tw.flush()?;
        }
        SubCommand::PeerStats { aobj_name } => {
            let stats: BTreeMap<String, PeerStats> = match aobj_name {
                Some(aobj) => {
                    let s = client.get_peer_stats(&aobj).await?.into_inner();
                    [(aobj, s)].into()
                }
                None => client
                    .get_peers_stats()
                    .await?
                    .into_inner()
                    .into_iter()
                    .collect(),
            };
            let mut tw = TabWriter::new(stdout());
            for (aobj, s) in &stats {
                writeln!(&mut tw, "{}", aobj.bold())?;
                for (name, value) in peer_stats_rows(s) {
                    writeln!(&mut tw, "  {}\t{}", name.dimmed(), value)?;
                }
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
                    if let Some(p) = pv.path.pop() {
                        writeln!(
                            &mut tw,
                            "{}\t{}\t{}",
                            pv.destination, nexthop, p,
                        )?;
                    }
                    for p in &pv.path {
                        writeln!(&mut tw, "\t\t{}", p,)?;
                    }
                }
            }
            tw.flush()?;
        }
        SubCommand::GetOriginated => {
            let msg = client.get_originated().await?;
            let mut tw = TabWriter::new(stdout());
            writeln!(&mut tw, "{}", "Prefix".dimmed(),)?;
            for prefix in msg.into_inner() {
                writeln!(&mut tw, "{}", prefix)?;
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
                    endpoint.origin.overlay_prefix,
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
                    endpoint.overlay_prefix,
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
        SubCommand::SetExternalPeers { addr_obj } => {
            client
                .set_external_peers(&ExternalPeers {
                    address_objects: addr_obj.iter().cloned().collect(),
                })
                .await?;
        }
        SubCommand::GetExternalPeers => {
            let peers = client.get_external_peers().await?.into_inner();
            for p in peers.address_objects {
                println_nopipe!("{p}");
            }
        }
        SubCommand::RackOriginated => {
            let msg = client.get_originated_rack_prefixes().await?;
            let mut tw = TabWriter::new(stdout());
            writeln!(
                &mut tw,
                "{}\t{}",
                "Prefix".dimmed(),
                "Join Address".dimmed(),
            )?;
            for (prefix, info) in msg.into_inner() {
                let join_addr = info
                    .multi_rack_join_addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "-".into());
                writeln!(&mut tw, "{}\t{}", prefix, join_addr)?;
            }
            tw.flush()?;
        }
        SubCommand::RackAdvertise(ac) => {
            let info = types::RackPrefixInfo {
                multi_rack_join_addr: ac.join_addr.map(Into::into),
            };
            let prefixes = ac
                .prefixes
                .iter()
                .map(|p| (p.to_string(), info.clone()))
                .collect();
            client.advertise_rack_prefixes(&prefixes).await?;
        }
        SubCommand::RackWithdraw(ac) => {
            client.withdraw_rack_prefixes(&ac.prefixes).await?;
        }
        SubCommand::RackImported => {
            let msg = client.get_rack_prefixes().await?;
            let mut tw = TabWriter::new(stdout());
            writeln!(
                &mut tw,
                "{}\t{}",
                "Prefix".dimmed(),
                "Join Addresses".dimmed(),
            )?;
            for (prefix, join_addrs) in msg.into_inner() {
                let join_addrs = if join_addrs.is_empty() {
                    "-".to_string()
                } else {
                    join_addrs
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                writeln!(&mut tw, "{}\t{}", prefix, join_addrs)?;
            }
            tw.flush()?;
        }
    }

    Ok(())
}

fn peer_stats_rows(s: &PeerStats) -> [(&'static str, u64); 13] {
    // compilation barrier. a new counter must be shown here.
    let PeerStats {
        solicitations_sent,
        solicitations_received,
        advertisements_sent,
        advertisements_received,
        peer_expirations,
        peer_address_changes,
        peer_established,
        updates_sent,
        updates_received,
        update_send_fail,
        imported_underlay_prefixes,
        imported_tunnel_endpoints,
        imported_rack_prefixes,
    } = *s;
    [
        ("Solicitations sent", solicitations_sent),
        ("Solicitations received", solicitations_received),
        ("Advertisements sent", advertisements_sent),
        ("Advertisements received", advertisements_received),
        ("Peer expirations", peer_expirations),
        ("Peer address changes", peer_address_changes),
        ("Peer sessions established", peer_established),
        ("Updates sent", updates_sent),
        ("Updates received", updates_received),
        ("Update send failures", update_send_fail),
        ("Imported underlay prefixes", imported_underlay_prefixes),
        ("Imported tunnel endpoints", imported_tunnel_endpoints),
        ("Imported rack prefixes", imported_rack_prefixes),
    ]
}

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, slog::o!())
}
