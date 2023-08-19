use crate::config::{PeerConfig, RouterConfig};
use crate::connection::test::{BgpConnectionChannel, BgpListenerChannel};
use crate::messages::{
    PathAttribute, PathAttributeType, PathAttributeTypeCode,
    PathAttributeValue, UpdateMessage,
};
use crate::session::{Asn, FsmStateKind};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread::spawn;
use std::time::Duration;

type Router = crate::router::Router<BgpConnectionChannel>;
type FsmEvent = crate::session::FsmEvent<BgpConnectionChannel>;

#[allow(clippy::type_complexity)]
fn two_router_test_setup(name: &str) -> (Arc<Router>, Arc<Router>) {
    let log = crate::log::init_file_logger(&format!("r1.{name}.log"));

    // Router 1 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    let db = rdb::Db::new(&format!("/tmp/r1.{name}.db")).unwrap();

    let (r1_event_tx, event_rx) = channel();
    let r1 = Arc::new(Router::new(
        "1.0.0.1:179".into(),
        RouterConfig {
            asn: Asn::FourOctet(4200000001),
            id: 1,
        },
        log.clone(),
        db.clone(),
    ));

    let rtr = r1.clone();
    let tx = r1_event_tx.clone();
    spawn(move || {
        rtr.run::<BgpListenerChannel>(tx);
    });

    r1.new_session(
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
        "1.0.0.1:179".parse().unwrap(),
        r1_event_tx.clone(),
        event_rx,
        db.clone(),
    );
    r1_event_tx.send(FsmEvent::ManualStart).unwrap();

    // Router 2 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    let log = crate::log::init_file_logger(&format!("r2.{name}.log"));
    let db = rdb::Db::new(&format!("/tmp/r2.{name}.db")).unwrap();

    let (r2_event_tx, event_rx) = channel();

    let r2 = Arc::new(Router::new(
        "2.0.0.1:179".into(),
        RouterConfig {
            asn: Asn::FourOctet(4200000002),
            id: 2,
        },
        log.clone(),
        db.clone(),
    ));

    let rtr = r2.clone();
    let tx = r2_event_tx.clone();
    spawn(move || {
        rtr.run::<BgpListenerChannel>(tx);
    });

    r2.new_session(
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
        "2.0.0.1:179".parse().unwrap(),
        r2_event_tx.clone(),
        event_rx,
        db.clone(),
    );
    r2_event_tx.send(FsmEvent::ManualStart).unwrap();

    (r1, r2)
}

#[test]
fn test_basic_peering() {
    let (r1, r2) = two_router_test_setup("basic_peering");

    let r1_session = &r1.sessions.lock().unwrap()[0];
    let r2_session = &r2.sessions.lock().unwrap()[0];
    let r2_event_tx = r2_session.event_tx.clone();

    std::thread::sleep(Duration::from_secs(1));

    assert_eq!(*r1_session.state.lock().unwrap(), FsmStateKind::Established);
    assert_eq!(*r2_session.state.lock().unwrap(), FsmStateKind::Established);

    r2.shutdown();
    r2_session.shutdown();

    std::thread::sleep(Duration::from_secs(10));
    assert_eq!(*r1_session.state.lock().unwrap(), FsmStateKind::Connect);
    assert_eq!(*r2_session.state.lock().unwrap(), FsmStateKind::Idle);

    let rtr = r2.clone();
    let tx = r2_event_tx.clone();
    spawn(move || {
        rtr.run::<BgpListenerChannel>(tx);
    });
    let r = r2_session.clone();
    spawn(move || {
        r.start();
    });
    r2_event_tx.send(FsmEvent::ManualStart).unwrap();

    std::thread::sleep(Duration::from_secs(5));

    assert_eq!(*r1_session.state.lock().unwrap(), FsmStateKind::Established);
    assert_eq!(*r2_session.state.lock().unwrap(), FsmStateKind::Established);
}

#[test]
fn test_basic_update() {
    let (r1, r2) = two_router_test_setup("basic_update");

    let r1_session = &r1.sessions.lock().unwrap()[0];
    let r1_event_tx = r1_session.event_tx.clone();

    let update = UpdateMessage {
        withdrawn: vec![],
        path_attributes: vec![PathAttribute {
            typ: PathAttributeType {
                flags: 0,
                type_code: PathAttributeTypeCode::NextHop,
            },
            value: PathAttributeValue::NextHop("1.2.3.1".parse().unwrap()),
        }],
        nlri: vec!["1.2.3.0/24".parse().unwrap()],
    };

    std::thread::sleep(Duration::from_secs(1));

    r1_event_tx.send(FsmEvent::Announce(update)).unwrap();

    std::thread::sleep(Duration::from_secs(1));

    let advertised = r2
        .db
        .get_nexthop4(rdb::Route4Key {
            prefix: rdb::Prefix4 {
                value: "1.2.3.0".parse().unwrap(),
                length: 24,
            },
            nexthop: "1.2.3.1".parse().unwrap(),
        })
        .unwrap();

    assert!(advertised)
}
