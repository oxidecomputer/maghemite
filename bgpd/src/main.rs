use bgp::session::Asn;
use bgp::router::Dispatcher;
use clap::Parser;
use slog::{Drain, Logger};
use std::net::Ipv6Addr;
use crate::admin::RouterConfig;
use std::sync::Arc;

mod admin;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Autonomous system number for this router
    asn: u32,

    /// Id for this router
    id: u32,

    /// Listening address <addr>:<port>
    #[arg(short, long, default_value = "0.0.0.0:179")]
    listen: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let disp = Arc::new(Dispatcher::new(args.listen));
    let d = disp.clone();
    tokio::spawn(async move {
        d.run().await;
    });

    let j = admin::start_server(
        init_logger(),
        Ipv6Addr::UNSPECIFIED,
        8000,
        RouterConfig {
            asn: Asn::FourOctet(args.asn),
            id: args.id,
        },
        disp,
    );

    j.unwrap().await.unwrap();

    /*
    let args = Args::parse();

    //XXX just hacking in a session for now

    let session = Session::new(
        Duration::from_secs(30), // idle hold time
        Duration::from_secs(10), // delay open time
    );

    let (to_session_tx, to_session_rx) = channel(64);
    let (from_session_tx, from_session_rx) = channel(64);

    let log = init_logger();

    let bgp_state = Arc::new(Mutex::new(BgpState::default()));

    let neighbor = NeighborInfo {
        name: "atrea-iv".to_owned(),
        host: args.peer,
    };

    let mut runner = SessionRunner::new(
        Duration::from_secs(5),  // connect retry time
        Duration::from_secs(20), // keepalive time
        Duration::from_secs(30), // hold time
        session,
        to_session_rx,
        from_session_tx,
        bgp_state,
        neighbor.clone(),
        Asn::FourOctet(47),
        0x1de, // id
        "0.0.0.0:179".to_string(),
        log.clone(),
    );

    let j = tokio::spawn(async move {
        runner.start().await;
    });

    let lg = log.clone();
    tokio::spawn(async move {
        let mut rx = from_session_rx;
        loop {
            match rx.recv().await.unwrap() {

                FsmEvent::Transition(from, to) => {
                    info!(lg, 
                        "{} {} {} {} {}", 
                        format!("[{}]", neighbor.name).dimmed(),
                        "transition".blue(),
                        from, 
                        "->".dimmed(),
                        to,
                    );
                }

                FsmEvent::Message(m) => {
                    if m == Message::KeepAlive {
                        debug!(lg,
                            "{} {} {:#?}",
                            format!("[{}]", neighbor.name).dimmed(),
                            "message".blue(),
                            m,
                        );
                    } else {
                        info!(lg,
                            "{} {} {:#?}",
                            format!("[{}]", neighbor.name).dimmed(),
                            "message".blue(),
                            m,
                        );
                    }
                }

                eve => {
                    info!(lg, "event: {:#?}", eve);
                }
            };
        }
    });

    to_session_tx.send(FsmEvent::ManualStart).await.unwrap();

    j.await.unwrap();
    */
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
