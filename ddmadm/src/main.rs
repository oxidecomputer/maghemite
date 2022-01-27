use structopt::{
    StructOpt,
    clap::AppSettings::*,
};
use anyhow::Result;
use ddm::net::Ipv6Prefix;
use slog::{info, error, Logger, Drain};
use ddm_admin_client::{Client, types};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "ddmadm",
    about = "A DDM router administration CLI",
    global_setting(ColorAuto),
    global_setting(ColoredHelp)
)]
struct Opt {
    /// Address of the router, defaults to localhost
    #[structopt(short, long)]
    address: Option<String>,

    /// Port to use, defaults to 8000
    #[structopt(short, long)]
    port: Option<usize>,

    #[structopt(subcommand)]
    subcommand: SubCommand
}

#[derive(Debug, StructOpt)]
enum SubCommand {
    /// Ping a DDM router.
    Ping,

    /// Get a DDM router's peers
    GetPeers,

    /// Get the prefixes a DDM router knows about.
    GetPrefixes,

    /// Get the set of active DDM routes on a router.
    GetRoutes,

    /// Advertise a prefix from a DDM router.
    AdvertisePrefix(AdvertiseCommand)
}

#[derive(Debug, StructOpt)]
struct AdvertiseCommand {
    /// IPv6 Prefix to advertise
    prefixes: Vec::<Ipv6Prefix>,
}

#[tokio::main]
async fn main() -> Result<()> {

    let opt = Opt::from_args();
    let log = init_logger();

    let addr = match opt.address {
        Some(a) => a,
        None => "localhost".into(),
    };
    let port = match opt.port {
        Some(p) => p,
        None => 8000,
    };

    let endpoint = format!("http://{}:{}", addr, port);
    let client = Client::new(&endpoint, log.clone());

    match opt.subcommand {
        SubCommand::Ping => {
            match client.adm_ping().await {
                Ok(msg) => info!(log, "{}", msg),
                Err(e) => error!(log, "{}", e),
            };
        }

        SubCommand::GetPeers => {
            match client.get_peers().await {
                Ok(msg) => info!(log, "{:#?}", msg),
                Err(e) => error!(log, "{}", e),
            };
        }

        SubCommand::GetPrefixes => {
            match client.get_prefixes().await {
                Ok(msg) => info!(log, "{:#?}", msg),
                Err(e) => error!(log, "{}", e),
            };
        }

        SubCommand::GetRoutes => {
            match client.get_routes().await {
                Ok(msg) => info!(log, "{:#?}", msg),
                Err(e) => error!(log, "{}", e),
            };
        }

        SubCommand::AdvertisePrefix(ac) => {
            // TODO a better way to deal with translating the client type back
            // into the type it was derived from in the first place?
            let mut prefixes: Vec::<types::Ipv6Prefix> = Vec::new();
            for p in ac.prefixes {
                prefixes.push(types::Ipv6Prefix{
                    addr: p.addr,
                    mask: p.mask,
                });
            }
            match client.advertise_prefix(&prefixes).await {
                Ok(msg) => info!(log, "{:#?}", msg),
                Err(e) => error!(log, "{}", e),
            };
        }
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
