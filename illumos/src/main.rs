// Copyright 2021 Oxide Computer Company

#![feature(ip)]
#![feature(maybe_uninit_slice)]

use rift::Rift;
use rift::config::Config;
use slog;
use slog_term;
use slog_async;
use std::sync::Arc;
use tokio::sync::Mutex;
use slog::Drain;
use clap::{AppSettings, Clap};

mod platform;
mod link;

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
    let mut riftp = Rift::new(ilu, log.clone(), Config{id: opts.id});
    match riftp.run().await {
        Ok(()) => slog::warn!(log, "early exit?"),
        Err(e) => slog::error!(log, "rift: {}", e),
    };

    Ok(())

}
