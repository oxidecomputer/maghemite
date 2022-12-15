use clap::Parser;
use slog::error;
use slog::info;
use slog::warn;
use slog::Drain;
use slog::Logger;
use std::net::Ipv6Addr;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[clap(name = "ddmd", about = "ddm control plane daemon")]
struct Opt {
    /// Port to use for admin server
    #[arg(long, default_value_t = 8000)]
    admin_port: u16,

    /// Admin address to listen on
    #[arg(long, default_value_t = Ipv6Addr::UNSPECIFIED)]
    admin_address: Ipv6Addr,

    /// Address objects to route over.
    #[arg(short, long = "addr", name = "addr")]
    addresses: Vec<String>,

    /// Milliseconds between peer hails.
    #[arg(long, default_value_t = 50)]
    pub hail_interval: u64,

    /// Milliseconds between router solicitations.
    #[arg(long, default_value_t = 50)]
    pub discovery_interval: u64,

    /// Milliseconds to wait for hail response
    #[arg(long, default_value_t = 250)]
    pub hail_timeout: u64,

    #[clap(subcommand)]
    subcommand: SubCommand,
}
#[derive(Debug, Parser)]
enum SubCommand {
    Server,
    Transit(Transit),
}

#[derive(Debug, Parser)]
struct Transit {
    #[arg(long)]
    dendrite: bool,
    #[arg(long, default_value = "localhost")]
    dpd_host: String,
    #[arg(long, default_value_t = dpd_api::default_port())]
    dpd_port: u16,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let opt = Opt::parse();

    let log = init_logger();
    info!(log, "starting illumos ddm control plane");

    let name = hostname::get().unwrap().into_string().unwrap();

    let config = match opt.subcommand {
        SubCommand::Server => ddm::router::Config {
            name,
            interfaces: opt.addresses,
            router_kind: ddm::protocol::RouterKind::Server,
            peer_interval: opt.hail_interval,
            peer_timeout: opt.hail_timeout,
            discovery_interval: opt.discovery_interval,
            ..Default::default()
        },
        SubCommand::Transit(t) => {
            let dpd = if t.dendrite {
                Some(ddm::router::DpdConfig {
                    host: t.dpd_host,
                    port: t.dpd_port,
                })
            } else {
                None
            };
            ddm::router::Config {
                name,
                interfaces: opt.addresses,
                dpd,
                router_kind: ddm::protocol::RouterKind::Transit,
                peer_interval: opt.hail_interval,
                peer_timeout: opt.hail_timeout,
                discovery_interval: opt.discovery_interval,
                ..Default::default()
            }
        }
    };

    let mut r =
        ddm::router::Router::new(log.clone(), config).expect("new router");
    r.run().await.expect("run router");

    match ddm::admin::start_server(
        log.clone(),
        opt.admin_address,
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
