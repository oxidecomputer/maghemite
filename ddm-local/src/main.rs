use std::sync::Arc;

use tokio::{
    select,
    signal::unix::{signal, SignalKind},
    sync::Mutex,
};
use slog::{info, warn, error, Logger, Drain};
use structopt::StructOpt;
use structopt::clap::AppSettings::*;
use libnet::{
    connect_simnet_peers,
    delete_link,
    delete_ipaddr,
    LinkHandle,
    LinkFlags,
};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "ddm-local",
    about = "A DDM control plane router that runs locally for testing purposes",
    global_setting(ColorAuto),
    global_setting(ColoredHelp)
)]
struct Opt {
    /// Id of this router
    id: u16,

    /// Port to use for admin server
    admin_port: u16,

    #[structopt(subcommand)]
    subcommand: SubCommand
}
#[derive(Debug, StructOpt)]
enum SubCommand {
    Server(ServerCommand),
    Transit(TransitCommand),
}

#[derive(Debug, StructOpt)]
struct TransitCommand {
    /// Radix of this router
    radix: u16,
}

#[derive(Debug)]
struct PortRef {
    id: u16,
    port: u16,
}

impl std::str::FromStr for PortRef {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(":").collect();
        Ok(PortRef{
            id: parts[0].parse::<u16>()?,
            port: parts[1].parse::<u16>()?,
        })
    }

}

#[derive(Debug, StructOpt)]
struct ServerCommand {
    /// List of transit router ports to connect to in form of <id>:<port-num>
    ports: Vec<PortRef>
}

#[tokio::main]
async fn main() -> Result<(), String> {

    let opt = Opt::from_args();

    let log = init_logger();
    info!(log, "starting local ddm control plane");

    let (radix, kind) = match opt.subcommand {
        SubCommand::Server(ref s) => {
            (s.ports.len() as u16, ddm::protocol::RouterKind::Server)
        }
        SubCommand::Transit(ref t) => {
            (t.radix, ddm::protocol::RouterKind::Transit)
        }
    };

    let p = ddm::local::Platform::new(
        log.clone(),
        opt.id,
        radix,
    ).map_err(|e| format!("new platform: {}", e))?;

    match opt.subcommand {
        SubCommand::Server(ref s) => {
            for (i, p) in s.ports.iter().enumerate() {
                connect_simnet_peers(
                    &LinkHandle::Name(format!("mg{}_sim{}", opt.id, i)),
                    &LinkHandle::Name(format!("mg{}_sim{}", p.id, p.port)),
                ).map_err(|e| { format!("connect simnet: {}", e.to_string()) })?;
            }
        }
        _ => {}
    }

    let p = Arc::new(Mutex::new(p));
    let r = Arc::new(ddm::router::Router::new(
        hostname::get().unwrap().into_string().unwrap(),
        kind,
    ));

    let config = ddm::config::Config{
        admin_port: opt.admin_port,
    };

    ddm::router::Router::run(r, p, config, log.clone())
        .map_err(|e| e.to_string())?;

    info!(log, "waiting for shutdown");

    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| e.to_string())?;

    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|e| e.to_string())?;

    select! {
        _ = sigterm.recv() => warn!(log, "caught SIGTERM, shutting down"),
        _ = sigint.recv() => warn!(log, "caught SIGINT, shutting down"),
    };

    cleanup(&log, &opt);

    drop(log);

    Ok(())

}

fn cleanup(log: &Logger, opt: &Opt) {
    let radix = match opt.subcommand {
        SubCommand::Transit(ref t) => t.radix.into(),
        SubCommand::Server(ref s) => s.ports.len(),
    };
    for i in 0..radix {
        let link = format!("mg{}_sim{}", opt.id, i);
        let addr = format!("{}/v6", link);

        // delete address
        match delete_ipaddr(&addr) {
            Ok(()) => {}
            Err(e) => error!(log, "delete addr {}: {}", addr, e)
        };

        // delete interface
        match delete_link(&LinkHandle::Name(link.clone()), LinkFlags::Active) {
            Ok(()) => {}
            Err(e) => error!(log, "delete link {}: {}", link, e)
        };
    }
}

fn init_logger() -> Logger {

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).chan_size(0x2000).build().fuse();
    slog::Logger::root(drain, slog::o!())

}
