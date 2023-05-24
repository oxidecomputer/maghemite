use anyhow::Result;
use clap::Parser;
use colored::*;
use ddm::db::Ipv6Prefix;
use ddm_admin_client::types;
use ddm_admin_client::Client;
use slog::{Drain, Logger};
use std::io::{stdout, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tabwriter::TabWriter;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None, styles = get_styles())]
struct Arg {
    #[arg(short, long, default_value_t = Ipv6Addr::UNSPECIFIED.into())]
    address: IpAddr,

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

    /// Sync prefix information from peers.
    Sync,
}

#[derive(Debug, Parser)]
struct Prefixes {
    prefixes: Vec<Ipv6Prefix>,
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
                        "{}/{}\t{}\t{}",
                        pv.destination.addr,
                        pv.destination.len,
                        nexthop,
                        strpath,
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
                writeln!(&mut tw, "{}/{}", prefix.addr, prefix.len,)?;
            }
            tw.flush()?;
        }
        SubCommand::AdvertisePrefixes(ac) => {
            let mut prefixes: Vec<types::Ipv6Prefix> = Vec::new();
            for p in ac.prefixes {
                prefixes.push(types::Ipv6Prefix {
                    addr: p.addr,
                    len: p.len,
                });
            }
            client.advertise_prefixes(&prefixes).await?;
        }
        SubCommand::WithdrawPrefixes(ac) => {
            let mut prefixes: Vec<types::Ipv6Prefix> = Vec::new();
            for p in ac.prefixes {
                prefixes.push(types::Ipv6Prefix {
                    addr: p.addr,
                    len: p.len,
                });
            }
            client.withdraw_prefixes(&prefixes).await?;
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

pub fn get_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .header(anstyle::Style::new().bold().underline().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(245, 207, 101)),
        )))
        .literal(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(72, 213, 151)),
        )))
        .invalid(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(72, 213, 151)),
        )))
        .valid(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(72, 213, 151)),
        )))
        .usage(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(245, 207, 101)),
        )))
        .error(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(232, 104, 134)),
        )))
}
