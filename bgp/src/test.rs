use crate::config::{PeerConfig, RouterConfig};
use crate::connection::test::{BgpConnectionChannel, BgpListenerChannel};
use crate::session::{Asn, FsmStateKind, NeighborInfo, Session};
use crate::state::BgpState;
use slog::Logger;
use std::net::SocketAddr;
use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use std::time::Duration;

type Router = crate::router::Router<BgpConnectionChannel>;
type FsmEvent = crate::session::FsmEvent<BgpConnectionChannel>;
type SessionRunner = crate::session::SessionRunner<BgpConnectionChannel>;

#[test]
fn test_basic_peering() {
    let log = crate::log::init_file_logger("r1.basic_peering.log");

    // Router 1 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    let (event_tx, event_rx) = channel();
    let r1 = Arc::new(Router::new(
        "1.0.0.1:179".into(),
        RouterConfig {
            asn: Asn::FourOctet(4200000001),
            id: 1,
        },
        log.clone(),
    ));

    let rtr = r1.clone();
    let tx = event_tx.clone();
    spawn(move || {
        rtr.run::<BgpListenerChannel>(tx);
    });

    let r1_session = new_session(
        log.clone(),
        PeerConfig {
            name: "r2".into(),
            host: "2.0.0.1:179".parse().unwrap(),
            hold_time: 6,
            idle_hold_time: 6,
            delay_open: 0,
            connect_retry: 1,
            keepalive: 3,
            resolution: 100,
        },
        r1.clone(),
        "1.0.0.1:179".parse().unwrap(),
        event_tx,
        event_rx,
    );

    // Router 2 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    let log = crate::log::init_file_logger("r2.basic_peering.log");

    let (event_tx, event_rx) = channel();

    let r2 = Arc::new(Router::new(
        "2.0.0.1:179".into(),
        RouterConfig {
            asn: Asn::FourOctet(4200000002),
            id: 2,
        },
        log.clone(),
    ));

    let rtr = r2.clone();
    let tx = event_tx.clone();
    spawn(move || {
        rtr.run::<BgpListenerChannel>(tx);
    });

    let r2_session = new_session(
        log.clone(),
        PeerConfig {
            name: "r1".into(),
            host: "1.0.0.1:179".parse().unwrap(),
            hold_time: 6,
            idle_hold_time: 6,
            delay_open: 0,
            connect_retry: 1,
            keepalive: 3,
            resolution: 100,
        },
        r2.clone(),
        "2.0.0.1:179".parse().unwrap(),
        event_tx.clone(),
        event_rx,
    );

    std::thread::sleep(Duration::from_secs(1));

    assert_eq!(*r1_session.state.lock().unwrap(), FsmStateKind::Established);
    assert_eq!(*r2_session.state.lock().unwrap(), FsmStateKind::Established);

    r2.shutdown();
    r2_session.shutdown();

    std::thread::sleep(Duration::from_secs(10));
    assert_eq!(*r1_session.state.lock().unwrap(), FsmStateKind::Connect);
    assert_eq!(*r2_session.state.lock().unwrap(), FsmStateKind::Idle);

    let rtr = r2.clone();
    let tx = event_tx.clone();
    spawn(move || {
        rtr.run::<BgpListenerChannel>(tx);
    });
    let r = r2_session.clone();
    spawn(move || {
        r.start();
    });
    event_tx.send(FsmEvent::ManualStart).unwrap();

    std::thread::sleep(Duration::from_secs(5));

    assert_eq!(*r1_session.state.lock().unwrap(), FsmStateKind::Established);
    assert_eq!(*r2_session.state.lock().unwrap(), FsmStateKind::Established);
}

fn new_session(
    log: Logger,
    peer: PeerConfig,
    r: Arc<Router>,
    bind_addr: SocketAddr,
    event_tx: Sender<FsmEvent>,
    event_rx: Receiver<FsmEvent>,
) -> Arc<SessionRunner> {
    let session = Session::new();
    let bgp_state = Arc::new(Mutex::new(BgpState::default()));

    r.add_session(peer.host.ip(), event_tx.clone());

    let neighbor = NeighborInfo {
        name: peer.name.clone(),
        host: peer.host,
    };

    let runner = Arc::new(SessionRunner::new(
        Duration::from_secs(peer.connect_retry),
        Duration::from_secs(peer.keepalive),
        Duration::from_secs(peer.hold_time),
        Duration::from_secs(peer.idle_hold_time),
        Duration::from_secs(peer.delay_open),
        session,
        event_rx,
        event_tx.clone(),
        bgp_state,
        neighbor.clone(),
        r.config.asn,
        r.config.id,
        Duration::from_millis(peer.resolution),
        Some(bind_addr),
        log.clone(),
    ));

    let r = runner.clone();
    spawn(move || {
        r.start();
    });

    event_tx.send(FsmEvent::ManualStart).unwrap();

    runner
}
