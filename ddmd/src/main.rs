use std::net::Ipv6Addr;
use std::sync::Arc;

use slog::error;
use slog::info;
use slog::warn;
use slog::Drain;
use slog::Logger;
use structopt::clap::AppSettings::*;
use structopt::StructOpt;

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

    /// Admin address to listen on
    admin_address: Option<Ipv6Addr>,

    /// Interfaces to route over.
    ifx: Vec<String>,

    #[structopt(subcommand)]
    subcommand: SubCommand,
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
    #[structopt(long)]
    protod_port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    println!("hi");

    let opt = Opt::from_args();

    let log = init_logger();
    info!(log, "starting illumos ddm control plane");

    let name = hostname::get().unwrap().into_string().unwrap();

    let config = match opt.subcommand {
        SubCommand::Server => ddm::router::Config {
            name,
            interfaces: opt.ifx,
            router_kind: ddm::protocol::RouterKind::Server,
            ..Default::default()
        },
        SubCommand::Transit(t) => {
            let protod = if t.dendrite {
                Some(ddm::router::ProtodConfig {
                    host: t.protod_host.unwrap_or("localhost".into()),
                    port: t.protod_port.unwrap_or(protod_api::default_port()),
                })
            } else {
                None
            };
            ddm::router::Config {
                name,
                interfaces: opt.ifx,
                protod,
                router_kind: ddm::protocol::RouterKind::Transit,
                ..Default::default()
            }
        }
    };

    let mut r =
        ddm::router::Router::new(log.clone(), config).expect("new router");
    r.run().await.expect("run router");

    let addr = match opt.admin_address {
        Some(addr) => addr,
        None => Ipv6Addr::LOCALHOST,
    };

    match ddm::admin::start_server(
        log.clone(),
        addr,
        opt.admin_port,
        Arc::new(r),
    ) {
        Ok(handle) => match handle.await {
            Ok(_) => warn!(log, "early exit?"),
            Err(e) => error!(log, "admin join error: {}", e),
        },
        Err(e) => error!(log, "run ddm admin server: {}", e),
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
