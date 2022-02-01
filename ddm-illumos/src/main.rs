use std::sync::Arc;

use tokio::sync::Mutex;
use slog::{info, warn, error, Logger, Drain};
use structopt::StructOpt;
use structopt::clap::AppSettings::*;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "ddm-illumos",
    about = "illumos ddm control plane",
    global_setting(ColorAuto),
    global_setting(ColoredHelp)
)]
struct Opt {
    #[structopt(subcommand)]
    subcommand: SubCommand
}
#[derive(Debug, StructOpt)]
enum SubCommand {
    Server,
    Transit,
}

#[tokio::main]
async fn main() -> Result<(), String> {

    let opt = Opt::from_args();

    let log = init_logger();
    info!(log, "starting illumos ddm control plane");

    let kind = match opt.subcommand {
        SubCommand::Server => ddm::protocol::RouterKind::Server,
        SubCommand::Transit=> ddm::protocol::RouterKind::Transit,
    };

    let p = Arc::new(Mutex::new(ddm::illumos::Platform::new(log.clone())));
    let r = Arc::new(ddm::router::Router::new(
        hostname::get().unwrap().into_string().unwrap(),
        kind,
    ));

    let config = ddm::config::Config{
        admin_port: 1947,
    };

    match ddm::router::Router::run_sync(r, p, config, log.clone()).await {
        Ok(_) => warn!(log, "early exit?"),
        Err(e) => error!(log, "ddm: {}", e),
    };


    Ok(())

}

fn init_logger() -> Logger {

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).chan_size(0x2000).build().fuse();
    slog::Logger::root(drain, slog::o!())

}