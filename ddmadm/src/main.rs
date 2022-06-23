use anyhow::Result;
use ddm::net::Ipv6Prefix;
use ddm_admin_client::types;
use ddm_admin_client::Client;
use slog::error;
use slog::info;
use slog::Drain;
use slog::Logger;
use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use structopt::clap::AppSettings::*;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "ddmadm",
    about = "A DDM router administration CLI",
    global_setting(ColorAuto),
    global_setting(ColoredHelp)
)]
struct Opt {
    /// Address of the router
    #[structopt(short, long, default_value = "::1")]
    address: Ipv6Addr,

    /// Port to use
    #[structopt(short, long, default_value = "8000")]
    port: u16,

    #[structopt(subcommand)]
    subcommand: SubCommand,
}

#[derive(Debug, StructOpt)]
enum SubCommand {
    /// Get a DDM router's peers
    GetPeers,

    /// Get the prefixes a DDM router knows about.
    GetPrefixes,

    /// Get the set of active DDM routes on a router.
    //TODO GetRoutes,

    /// Advertise a prefix from a DDM router.
    AdvertisePrefix(AdvertiseCommand),
}

#[derive(Debug, StructOpt)]
struct AdvertiseCommand {
    /// IPv6 Prefix to advertise
    prefixes: Vec<Ipv6Prefix>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();
    let log = init_logger();

    let endpoint =
        format!("http://{}", SocketAddrV6::new(opt.address, opt.port, 0, 0));
    let client = Client::new(&endpoint, log.clone());

    match opt.subcommand {
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

        /* TODO
        SubCommand::GetRoutes => {
            match client.get_routes().await {
                Ok(msg) => info!(log, "{:#?}", msg),
                Err(e) => error!(log, "{}", e),
            };
        }
        */
        SubCommand::AdvertisePrefix(ac) => {
            // TODO a better way to deal with translating the client type back
            // into the type it was derived from in the first place?
            let mut prefixes: Vec<types::Ipv6Prefix> = Vec::new();
            for p in ac.prefixes {
                prefixes.push(types::Ipv6Prefix {
                    addr: p.addr,
                    mask: p.mask,
                });
            }
            match client.advertise_prefixes(&prefixes).await {
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
    let drain = slog_async::Async::new(drain)
        .chan_size(0x2000)
        .build()
        .fuse();
    slog::Logger::root(drain, slog::o!())
}
