// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::Parser;
use ddm::db::{Db, RouterKind};
use ddm::sm::{DpdConfig, SmContext, StateMachine};
use ddm::sys::Route;
use slog::{Drain, Logger};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::mpsc::channel;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None, styles = get_styles())]
struct Arg {
    /// Address objects to route over.
    #[arg(short, long = "addr", name = "addr")]
    addresses: Vec<String>,

    /// How long to wait between solicitations (milliseconds).
    #[arg(long, default_value_t = 2000)]
    solicit_interval: u64,

    /// How long to wait without a solicitation response before expiring a peer
    /// (milliseconds).
    #[arg(long, default_value_t = 5000)]
    expire_threshold: u64,

    /// How often to check for link failure while waiting for discovery messges
    /// (milliseconds).
    #[arg(long, default_value_t = 1000)]
    discovery_read_timeout: u64,

    /// How long to wait between attempts to get an IP address for a specified
    /// address object (milliseconds).
    #[arg(long, default_value_t = 1000)]
    ip_addr_wait: u64,

    /// How long to wait for a response to exchange messages.
    #[arg(long, default_value_t = 3000)]
    pub exchange_timeout: u64,

    /// Address to listen on for the admin API.
    #[arg(long, default_value_t = Ipv6Addr::UNSPECIFIED.into())]
    admin_addr: IpAddr,

    /// Port to listen on for the admin API.
    #[arg(long, default_value_t = 8000)]
    admin_port: u16,

    /// Kind of router to run.
    #[arg(long, default_value_t = RouterKind::Server)]
    kind: RouterKind,

    /// The tcp port to listen on for exchange messages.
    #[arg(long, default_value_t = 0xdddd)]
    exchange_port: u16,

    /// Whether or not to use Dendrite as the underlying routing and forwarding
    /// platform.
    #[arg(long, default_value_t = false)]
    dendrite: bool,

    /// Hostname for the Dendrite dpd server.
    #[arg(long, default_value_t = String::from("localhost"))]
    dpd_host: String,

    /// Listening port for the Dendrite dpd server.
    #[arg(long, default_value_t = dpd_client::default_port())]
    dpd_port: u16,
}

#[derive(Debug, Parser, Clone)]
struct Dendrite {
    host: String,
    port: u16,
}

#[tokio::main]
async fn main() {
    let arg = Arg::parse();

    let mut event_channels = Vec::new();
    let db = Db::default();
    let log = init_logger();

    let mut sms = Vec::new();

    let dpd = match arg.dendrite {
        true => Some(DpdConfig {
            host: arg.dpd_host.clone(),
            port: arg.dpd_port,
        }),
        false => None,
    };

    let rt = Arc::new(tokio::runtime::Handle::current());
    let hostname = hostname::get()
        .expect("failed to get hostname")
        .to_string_lossy()
        .to_string();

    for name in arg.addresses {
        let (tx, rx) = channel();
        let config = ddm::sm::Config {
            solicit_interval: arg.solicit_interval,
            expire_threshold: arg.expire_threshold,
            discovery_read_timeout: arg.discovery_read_timeout,
            ip_addr_wait: arg.ip_addr_wait,
            exchange_timeout: arg.exchange_timeout,
            exchange_port: arg.exchange_port,
            aobj_name: name.clone(),
            if_name: String::new(),
            if_index: 0,
            kind: arg.kind,
            dpd: dpd.clone(),
            addr: Ipv6Addr::UNSPECIFIED,
        };
        let ctx = SmContext {
            config,
            db: db.clone(),
            event_channels: Vec::new(),
            tx: tx.clone(),
            log: log.clone(),
            hostname: hostname.clone(),
            rt: rt.clone(),
        };
        let sm = StateMachine { ctx, rx: Some(rx) };
        sms.push(sm);
        event_channels.push(tx);
    }

    // Add an event channel sender for each state machine to every other state
    // machine.
    for (i, sm) in sms.iter_mut().enumerate() {
        for (j, e) in event_channels.iter().enumerate() {
            // dont give a state machine an event sender to itself.
            if i == j {
                continue;
            }
            sm.ctx.event_channels.push(e.clone());
        }
    }

    for sm in &mut sms {
        sm.run().unwrap();
    }

    termination_handler(db.clone(), dpd, rt, log.clone());

    ddm::admin::handler(
        arg.admin_addr,
        arg.admin_port,
        event_channels,
        db,
        log,
    )
    .unwrap();

    std::thread::park();
}

fn termination_handler(
    db: Db,
    dendrite: Option<DpdConfig>,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) {
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("error setting termination handler");
        const SIGTERM_EXIT: i32 = 130;
        let imported = db.imported();
        let routes: Vec<Route> =
            imported.iter().map(|x| (x.clone()).into()).collect();
        ddm::sys::remove_routes(&log, "shutdown-all", &dendrite, routes, &rt);
        std::process::exit(SIGTERM_EXIT);
    });
}

pub(crate) fn init_logger() -> Logger {
    let drain = slog_bunyan::new(std::io::stdout()).build().fuse();
    let drain = slog_async::Async::new(drain)
        .chan_size(0x8000)
        .build()
        .fuse();
    slog::Logger::root(drain, slog::o!())
}

pub fn get_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .header(anstyle::Style::new().bold().underline().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(245, 207, 101)),
        )))
        .literal(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(72, 213, 151)),
        )))
        .invalid(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(72, 213, 151)),
        )))
        .valid(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(72, 213, 151)),
        )))
        .usage(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(245, 207, 101)),
        )))
        .error(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(232, 104, 134)),
        )))
}
