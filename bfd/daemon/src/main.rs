use anyhow::Result;
use bfd::Daemon;
use clap::Parser;
use slog::{Drain, Logger};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

mod admin;
mod udp;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, styles = get_styles())]
pub struct Cli {
    /// Management server TCP port.
    #[arg(long, default_value_t = 8001)]
    port: u16,

    /// Management server address.
    #[arg(long, default_value = "::")]
    addr: IpAddr,

    /// Dump the OpenAPI 3 management spec and exit.
    #[arg(long)]
    dump_api: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let log = init_logger();

    if cli.dump_api {
        admin::dump_spec();
        return Ok(());
    }

    let daemon = Arc::new(Mutex::new(Daemon::new(log.clone())));

    admin::handler(daemon, cli.addr, cli.port, log)?;

    std::thread::park();

    Ok(())
}

/// Oxide themed CLI ;)
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

/// Create a bunyan style logger.
fn init_logger() -> Logger {
    let drain = slog_bunyan::new(std::io::stdout()).build().fuse();
    let drain = slog_async::Async::new(drain)
        .chan_size(0x8000)
        .build()
        .fuse();
    slog::Logger::root(drain, slog::o!())
}
