// Copyright 2021 Oxide Computer Company

use rift::Rift;
use slog;
use slog_term;
use slog_async;
use std::sync::{Arc, Mutex};

mod platform;
mod illumos;
mod link;

use slog::Drain;

#[tokio::main]
async fn main() -> Result<(), String> {

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, slog::o!());

    let ilu = Arc::new(Mutex::new(crate::platform::Illumos{log: log.clone()}));
    let mut riftp = Rift::new(ilu, log.clone());
    match riftp.run() {
        Ok(()) => slog::warn!(log, "early exit?"),
        Err(e) => slog::error!(log, "rift: {}", e),
    };

    Ok(())

}
