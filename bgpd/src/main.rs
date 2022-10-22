use bgp::session::{Asn, FsmEvent, Session, SessionRunner};
use bgp::state::BgpState;
use clap::Parser;
use slog::{info, Drain, Logger};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Peer to connect to <addr>:<port>
    peer: String,

    /// Listening address <addr>:<port>
    #[arg(short, long, default_value = "0.0.0.0:179")]
    listen: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    //XXX just hacking in a session for now

    let session = Session::new(
        Duration::from_secs(30), // idle hold time
        Duration::from_secs(10), // delay open time
    );

    let (to_session_tx, to_session_rx) = channel(64);
    let (from_session_tx, mut from_session_rx) = channel(64);

    let log = init_logger();

    let bgp_state = Arc::new(Mutex::new(BgpState::default()));

    let mut runner = SessionRunner::new(
        Duration::from_secs(5),  // connect retry time
        Duration::from_secs(20), // keepalive time
        Duration::from_secs(30), // hold time
        session,
        to_session_rx,
        from_session_tx,
        bgp_state,
        args.peer,
        //Asn::FourOctet(395849),
        Asn::FourOctet(47),
        0x1de,
        "0.0.0.0:179".to_string(),
        log.clone(),
    );

    let j = tokio::spawn(async move {
        runner.start().await;
    });

    let lg = log.clone();
    tokio::spawn(async move {
        let eve = from_session_rx.recv().await;
        info!(lg, "event from session: {:#?}", eve);
    });

    to_session_tx.send(FsmEvent::ManualStart).await.unwrap();

    j.await.unwrap();
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
