use crate::config::{PeerConfig, RouterConfig};
use crate::connection_channel::{BgpConnectionChannel, BgpListenerChannel};
use crate::session::FsmStateKind;
use rdb::{Asn, Prefix4};
use std::collections::BTreeMap;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::thread::spawn;
use std::time::Duration;

type Router = crate::router::Router<BgpConnectionChannel>;
type Dispatcher = crate::dispatcher::Dispatcher<BgpConnectionChannel>;
type FsmEvent = crate::session::FsmEvent<BgpConnectionChannel>;

macro_rules! wait_for_eq {
    ($lhs:expr, $rhs:expr, $period:expr, $count:expr) => {
        let mut ok = false;
        for _ in 0..$count {
            if $lhs == $rhs {
                ok = true;
                break;
            }
            sleep(Duration::from_secs($period));
        }
        if !ok {
            assert_eq!($lhs, $rhs);
        }
    };
    ($lhs:expr, $rhs:expr) => {
        wait_for_eq!($lhs, $rhs, 1, 10);
    };
}

macro_rules! parse {
    ($x:expr, $err:expr) => {
        $x.parse().expect($err)
    };
}
macro_rules! ip {
    ($x:expr) => {
        parse!($x, "ip address")
    };
}

macro_rules! cidr {
    ($x:expr) => {
        parse!($x, "ip cidr")
    };
}

macro_rules! sockaddr {
    ($x:expr) => {
        parse!($x, "socket address")
    };
}

#[test]
fn test_basic_peering() {
    let (r1, _d1, r2, d2) = two_router_test_setup("basic_peering");

    let r1_session = r1.get_session(ip!("2.0.0.1")).expect("get session one");
    let r2_session = r2.get_session(ip!("1.0.0.1")).expect("get session two");

    // Give peer sessions a few seconds and ensure we have reached the
    // established state on both sides.

    wait_for_eq!(r1_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_session.state(), FsmStateKind::Established);

    // Shut down r2 and ensure that r2's peer session has gone back to idle.
    // Ensure that r1's peer session to r2 has gone back to connect.
    r2.shutdown();
    d2.shutdown();
    wait_for_eq!(r1_session.state(), FsmStateKind::Connect);
    wait_for_eq!(r2_session.state(), FsmStateKind::Idle);

    r2.run();
    spawn(move || {
        d2.run::<BgpListenerChannel>();
    });
    r2.send_event(FsmEvent::ManualStart)
        .expect("manual start session two");

    wait_for_eq!(r1_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_session.state(), FsmStateKind::Established);
}

#[test]
fn test_basic_update() {
    let (r1, d1, r2, _d2) = two_router_test_setup("basic_update");

    // originate a prefix
    r1.originate4(ip!("1.0.0.1"), vec![ip!("1.2.3.0/24")])
        .expect("originate");

    // once we reach established the originated routes should have propagated
    let r1_session = r1.get_session(ip!("2.0.0.1")).expect("get session one");
    let r2_session = r2.get_session(ip!("1.0.0.1")).expect("get session two");
    wait_for_eq!(r1_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_session.state(), FsmStateKind::Established);

    let prefix: Prefix4 = cidr!("1.2.3.0/24");

    wait_for_eq!(r2.db.get_nexthop4(&prefix).is_empty(), false);

    // shut down r1 and ensure that the prefixes are withdrawn from r2 on
    // session timeout.
    r1.shutdown();
    d1.shutdown();
    wait_for_eq!(r2_session.state(), FsmStateKind::Connect);
    wait_for_eq!(r1_session.state(), FsmStateKind::Idle);
    wait_for_eq!(r2.db.get_nexthop4(&prefix).is_empty(), true);
}

fn two_router_test_setup(
    name: &str,
) -> (Arc<Router>, Arc<Dispatcher>, Arc<Router>, Arc<Dispatcher>) {
    let log = crate::log::init_file_logger(&format!("r1.{name}.log"));

    std::fs::create_dir_all("/tmp").expect("create tmp dir");

    // Router 1 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    let db_path = format!("/tmp/r1.{name}.db");
    let _ = std::fs::remove_dir_all(&db_path);
    let db = rdb::Db::new(&db_path, log.clone()).expect("create db");

    let a2s1 = Arc::new(Mutex::new(BTreeMap::new()));
    let d1 =
        Arc::new(crate::dispatcher::Dispatcher::<BgpConnectionChannel>::new(
            a2s1.clone(),
            "1.0.0.1:179".into(),
            log.clone(),
        ));

    let (r1_event_tx, event_rx) = channel();
    let r1 = Arc::new(Router::new(
        RouterConfig {
            asn: Asn::FourOctet(4200000001),
            id: 1,
        },
        log.clone(),
        db.clone(),
        a2s1.clone(),
    ));

    r1.run();
    let d = d1.clone();
    spawn(move || {
        d.run::<BgpListenerChannel>();
    });

    r1.new_session(
        PeerConfig {
            name: "r2".into(),
            host: sockaddr!("2.0.0.1:179"),
            hold_time: 6,
            idle_hold_time: 6,
            delay_open: 0,
            connect_retry: 1,
            keepalive: 3,
            resolution: 100,
        },
        sockaddr!("1.0.0.1:179"),
        r1_event_tx.clone(),
        event_rx,
    )
    .expect("new session on router one");

    r1_event_tx
        .send(FsmEvent::ManualStart)
        .expect("session manual start on router one");

    // Router 2 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    let log = crate::log::init_file_logger(&format!("r2.{name}.log"));

    let db_path = format!("/tmp/r2.{name}.db");
    let _ = std::fs::remove_dir_all(&db_path);
    let db = rdb::Db::new(&db_path, log.clone())
        .expect("create datastore for router 2");

    let a2s2 = Arc::new(Mutex::new(BTreeMap::new()));
    let d2 =
        Arc::new(crate::dispatcher::Dispatcher::<BgpConnectionChannel>::new(
            a2s2.clone(),
            "2.0.0.1:179".into(),
            log.clone(),
        ));

    let (r2_event_tx, event_rx) = channel();

    let r2 = Arc::new(Router::new(
        RouterConfig {
            asn: Asn::FourOctet(4200000002),
            id: 2,
        },
        log.clone(),
        db.clone(),
        a2s1.clone(),
    ));

    r2.run();
    let d = d2.clone();
    spawn(move || {
        d.run::<BgpListenerChannel>();
    });

    r2.new_session(
        PeerConfig {
            name: "r1".into(),
            host: sockaddr!("1.0.0.1:179"),
            hold_time: 6,
            idle_hold_time: 6,
            delay_open: 0,
            connect_retry: 1,
            keepalive: 3,
            resolution: 100,
        },
        sockaddr!("2.0.0.1:179"),
        r2_event_tx.clone(),
        event_rx,
    )
    .expect("new session on router two");

    r2_event_tx
        .send(FsmEvent::ManualStart)
        .expect("start session on router two");

    (r1, d1, r2, d2)
}
