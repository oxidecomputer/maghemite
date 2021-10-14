// Copyright 2021 Oxide Computer Company

#![feature(ip)]
#![feature(maybe_uninit_slice)]

use rift::Rift;
use rift::config::Config;
use rift_protocol::Level;
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
    id: u64,
    level: Level,
}


#[tokio::main]
async fn main() -> Result<(), String> {

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, slog::o!());

    let opts: Opts = Opts::parse();

    let ilu = Arc::new(Mutex::new(crate::platform::Illumos{log: log.clone()}));
    let mut riftp = Rift::new(ilu, log.clone(), Config{
        id: opts.id,
        level: opts.level,
    });
    match riftp.run().await {
        Ok(()) => warn!(log, "early exit?"),
        Err(e) => error!(log, "rift: {}", e),
    };

    Ok(())

}
