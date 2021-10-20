// Copyright 2021 Oxide Computer Company

#![feature(ip)]
#![feature(maybe_uninit_slice)]

use rift::{
    Rift, 
    config::{Config, RackRouterConfig},
};
use rift_protocol::{Level, net::Ipv6Prefix};
use slog;
use slog_term;
use slog_async;
use std::sync::Arc;
use tokio::sync::Mutex;
use slog::Drain;
use clap::{AppSettings, Clap};
use slog::{warn, error};

mod platform;
mod link;
mod topology;


#[derive(Clap)]
#[clap(
    version = "0.1", 
    author = "Ryan Goodfellow <ryan.goodfellow@oxide.computer>"
)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Opts {
    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,

    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::InferSubcommands)]
struct ComputeRouter {
    id: u64,
    level: Level,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::InferSubcommands)]
struct RackRouter {
    id: u64,
    level: Level,
    rack_id: u8,
    prefix: Ipv6Prefix,
}

#[derive(Clap)]
enum SubCommand {
    #[clap(about = "run as a rack router")]
    Rack(RackRouter),
    #[clap(about = "run as a compute host router")]
    Compute(ComputeRouter),
}


#[tokio::main]
async fn main() -> Result<(), String> {

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, slog::o!());
    let ilu = Arc::new(Mutex::new(crate::platform::Illumos{log: log.clone()}));

    let opts: Opts = Opts::parse();

    let mut riftp = match opts.subcmd {
        SubCommand::Rack(r) => {
            Rift::new(ilu, log.clone(), Config{
                id: r.id,
                level: r.level,
                rack_router: Some(RackRouterConfig{
                    prefix: r.prefix,
                    rack_id: r.rack_id,
                }),
            })
        }
        SubCommand::Compute(c) => {
            Rift::new(ilu, log.clone(), Config{
                id: c.id,
                level: c.level,
                rack_router: None,
            })
        }
    };

    match riftp.run().await {
        Ok(()) => warn!(log, "early exit?"),
        Err(e) => error!(log, "rift: {}", e),
    };

    Ok(())

}
