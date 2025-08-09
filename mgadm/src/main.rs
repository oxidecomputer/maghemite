// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(clippy::large_enum_variant)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use mg_admin_client::Client;
use mg_common::cli::oxide_cli_style;
use slog::Drain;
use slog::Logger;
use std::net::{IpAddr, SocketAddr};

mod bfd;
mod bgp;
mod rib;
mod static_routing;

#[derive(Parser, Debug)]
#[command(
    version,
    about,
    long_about = None,
    styles = oxide_cli_style(),
    infer_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Address of admin interface
    #[arg(short, env, long, default_value = "::1")]
    address: IpAddr,

    /// TCP port for admin interface
    #[arg(short, long, default_value_t = 4676)]
    port: u16,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// BGP management commands.
    #[command(subcommand)]
    Bgp(bgp::Commands),

    /// Static routing management commands.
    #[command(subcommand)]
    Static(static_routing::Commands),

    /// Bidirectional forwarding detection protocol management
    #[command(subcommand)]
    Bfd(bfd::Commands),

    /// RIB configuration commands.
    #[command(subcommand)]
    Rib(rib::Commands),
}

fn main() -> Result<()> {
    oxide_tokio_rt::run(run())
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let log = init_logger();

    let endpoint =
        format!("http://{}", SocketAddr::new(cli.address, cli.port),);

    let client = Client::new(&endpoint, log.clone());

    match cli.command {
        Commands::Bgp(command) => bgp::commands(command, client).await?,
        Commands::Static(command) => {
            static_routing::commands(command, client).await?
        }
        Commands::Bfd(command) => bfd::commands(command, client).await?,
        Commands::Rib(command) => rib::commands(command, client).await?,
    }
    Ok(())
}

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain)
        .chan_size(0x2000)
        .build()
        .fuse();
    slog::Logger::root(drain, slog::o!())
}
