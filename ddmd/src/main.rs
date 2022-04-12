use std::sync::Arc;
use std::net::Ipv6Addr;

use structopt::StructOpt;
use structopt::clap::AppSettings::*;
use slog::{info, warn, error, Logger, Drain};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "ddm-illumos",
    about = "illumos ddm control plane",
    global_setting(ColorAuto),
    global_setting(ColoredHelp)
)]
struct Opt {
    /// Port to use for admin server
    admin_port: u16,

    admin_address: Option<Ipv6Addr>,

    #[structopt(subcommand)]
    subcommand: SubCommand
}
#[derive(Debug, StructOpt)]
enum SubCommand {
    Server,
    Transit(Transit),
}

#[derive(Debug, StructOpt)]
struct Transit {
    #[structopt(long)]
    dendrite: bool,
    #[structopt(long)]
    protod_host: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    println!("hi");

    let opt = Opt::from_args();

    let log = init_logger();
    info!(log, "starting illumos ddm control plane");

    let (kind, dendrite, protod) = match opt.subcommand {
        SubCommand::Server => (
            ddm2::protocol::RouterKind::Server,
            false,
            "".into(),
        ),
        SubCommand::Transit(t) => (
            ddm2::protocol::RouterKind::Transit,
            t.dendrite,
            t.protod_host.unwrap_or("localhost".into()),
        ),
    };

    let config = ddm2::router::Config{
        name: hostname::get().unwrap().into_string().unwrap(),
        router_kind: kind,
        ..Default::default()
    };

    let mut r = ddm2::router::Router::new(
            log.clone(),
            config,
    ).expect("new router");
    r.run().await.expect("run router");

    let addr = match opt.admin_address {
        Some(addr) => addr,
        None => Ipv6Addr::LOCALHOST,
    };

    match ddm2::admin::start_server(
        log.clone(),
        addr,
        opt.admin_port,
        Arc::new(r),
    ) {
        Ok(_) => warn!(log, "early exit?"),
        Err(e) => error!(log, "run ddm admin server: {}", e),
    }

    Ok(())
}

fn init_logger() -> Logger {

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).chan_size(0x2000).build().fuse();
    slog::Logger::root(drain, slog::o!())

}
