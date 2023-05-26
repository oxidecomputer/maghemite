use anyhow::Result;
use bfd_client::{types::AddPeerRequest, Client};
use clap::Parser;
use colored::Colorize;
use slog::{Drain, Logger};
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use tabwriter::TabWriter;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None, styles = get_styles())]
struct Cli {
    /// Address of the daemon's admin API.
    #[arg(short, long, default_value_t = Ipv6Addr::UNSPECIFIED.into())]
    address: IpAddr,

    /// Admin API TCP port.
    #[arg(short, long, default_value_t = 8001)]
    port: u16,

    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Debug, Parser)]
enum SubCommand {
    /// Get the list of configured peers.
    GetPeers,

    /// Add a peer.
    AddPeer {
        /// Address of the peer.
        peer: IpAddr,
        /// Address to listen on.
        listen: IpAddr,
        /// Acceptable time between control messages in microseconds.
        required_rx: u64,
        /// Detection threshold for connectivity as a multipler to required_rx
        detection_threshold: u8,
    },

    /// Remove a peer.
    RemovePeer {
        /// Address of the peer.
        peer: IpAddr,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let sa = SocketAddr::new(cli.address, cli.port);
    let endpoint = format!("http://{}", sa);
    let log = init_logger();
    let client = Client::new(&endpoint, log.clone());

    match cli.subcmd {
        SubCommand::GetPeers => {
            let msg = client.get_peers().await?;
            let mut tw = TabWriter::new(std::io::stdout());
            writeln!(
                &mut tw,
                "{}\t{}",
                "Addresss".dimmed(),
                "Status".dimmed(),
            )?;
            for (addr, status) in &msg.into_inner() {
                writeln!(&mut tw, "{}\t{:?}", addr, status,)?;
            }
            tw.flush()?;
        }
        SubCommand::AddPeer {
            peer,
            listen,
            required_rx,
            detection_threshold,
        } => {
            client
                .add_peer(&AddPeerRequest {
                    peer,
                    listen,
                    required_rx,
                    detection_threshold,
                })
                .await?;
        }
        SubCommand::RemovePeer { peer } => {
            client.remove_peer(&peer).await?;
        }
    }

    Ok(())
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

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, slog::o!())
}
