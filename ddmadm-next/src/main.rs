use anyhow::Result;
use clap::Parser;
use colored::*;
use ddm_next::db::Ipv6Prefix;
use ddm_next_admin_client::types;
use ddm_next_admin_client::Client;
use slog::{Drain, Logger};
use std::io::{stdout, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tabwriter::TabWriter;

#[derive(Debug, Parser)]
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
    /// Get a DDM router's peers
    GetPeers,

    /// Get the prefixes a DDM router knows about.
    GetPrefixes,

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
        SubCommand::GetPrefixes => {
            let msg = client.get_prefixes().await?;
            let mut tw = TabWriter::new(stdout());
            writeln!(
                &mut tw,
                "{}\t{}",
                "Destination".dimmed(),
                "Next Hop".dimmed(),
            )?;
            for (nexthop, destinations) in msg.into_inner() {
                for dest in &destinations {
                    writeln!(
                        &mut tw,
                        "{}/{}\t{}",
                        dest.addr, dest.len, nexthop,
                    )?;
                }
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
