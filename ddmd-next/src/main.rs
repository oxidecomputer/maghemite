use clap::Parser;
use ddm_next::db::{Db, RouterKind};
use ddm_next::sm::{DpdConfig, SmContext, StateMachine};
use ddm_next::sys::Route;
use libnet::get_ipaddr_info;
use slog::{Drain, Logger};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::mpsc::channel;
use std::sync::Arc;

#[derive(Debug, Parser)]
struct Arg {
    /// Address objects to route over.
    #[arg(short, long = "addr", name = "addr")]
    addresses: Vec<String>,

    #[arg(long, default_value_t = 1701)]
    solicit_interval: u64,

    #[arg(long, default_value_t = 0x1701)]
    expire_threshold: u64,

    #[arg(long, default_value_t = Ipv6Addr::UNSPECIFIED.into())]
    admin_addr: IpAddr,

    #[arg(long, default_value_t = 8000)]
    admin_port: u16,

    #[arg(long, default_value_t = RouterKind::Server)]
    kind: RouterKind,

    #[arg(long, default_value_t = 0xdddd)]
    exchange_port: u16,

    #[arg(long, default_value_t = false)]
    dendrite: bool,

    #[arg(long, default_value_t = String::from("localhost"))]
    dpd_host: String,

    #[arg(long, default_value_t = dpd_api::default_port())]
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

    for name in arg.addresses {
        let info = get_ipaddr_info(&name).unwrap();
        let addr = match info.addr {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => panic!("{} is not an ipv6 address", name),
        };
        let (tx, rx) = channel();
        let config = ddm_next::sm::Config {
            solicit_interval: arg.solicit_interval,
            expire_threshold: arg.expire_threshold,
            exchange_port: arg.exchange_port,
            if_name: info.ifname.clone(),
            if_index: info.index as u32,
            kind: arg.kind,
            dpd: dpd.clone(),
            addr,
        };
        let rt = Arc::new(tokio::runtime::Handle::current());
        let ctx = SmContext {
            config,
            db: db.clone(),
            event_channels: Vec::new(),
            tx: tx.clone(),
            log: log.clone(),
            rt,
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

    termination_handler(db.clone(), dpd, log.clone());

    ddm_next::admin::handler(
        arg.admin_addr,
        arg.admin_port,
        event_channels,
        db,
        log,
    )
    .unwrap();

    std::thread::park();
}

fn termination_handler(db: Db, dendrite: Option<DpdConfig>, log: Logger) {
    ctrlc::set_handler(move || {
        const SIGTERM_EXIT: i32 = 130;
        let imported = db.imported();
        let routes: Vec<Route> = imported.iter().map(|x| (*x).into()).collect();
        ddm_next::sys::remove_routes(&log, &dendrite, routes)
            .expect("route removal on termination");
        std::process::exit(SIGTERM_EXIT);
    })
    .expect("error setting termination handler");
}

pub(crate) fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, slog::o!())
}
