// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::config::{PeerConfig, RouterConfig};
use crate::connection_channel::{BgpConnectionChannel, BgpListenerChannel};
use crate::session::{FsmStateKind, SessionInfo};
use mg_common::{
    cidr, ip, parse, sockaddr, wait_for, wait_for_eq, wait_for_neq,
};
use rdb::{Asn, Prefix};
use std::collections::BTreeMap;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread::spawn;

type Router = crate::router::Router<BgpConnectionChannel>;
type Dispatcher = crate::dispatcher::Dispatcher<BgpConnectionChannel>;
type FsmEvent = crate::session::FsmEvent<BgpConnectionChannel>;

// This test effectively does the following:
// 1. Sets up a basic pair of routers, r1 and r2
//    - r1 either uses active or passive tcp establishment
// 2. Brings up a BGP session between r1 and r2
// 3. Ensures the BGP FSM moves into Established on both r1 and r2
// 4. Shuts down r2
// 5. Ensures r2's BGP FSM moves into Idle
// 6. Ensures r1's BGP FSM moves into Active (passive tcp establishment)
//    or Connect (active tcp establishment)
// 7. Restarts r2
// 8. Ensures the BGP session between r1 and r2 moves back into Established
fn basic_peering_helper(passive: bool) {
    let test_str = match passive {
        true => "basic_peering_passive",
        false => "basic_peering_active",
    };

    let (r1, d1, r2, d2) = two_router_test_setup(
        test_str,
        Some(SessionInfo {
            passive_tcp_establishment: passive,
            ..Default::default()
        }),
        None,
    );

    let r1_session = r1.get_session(ip!("2.0.0.1")).expect("get session one");
    let r2_session = r2.get_session(ip!("1.0.0.1")).expect("get session two");

    // Give peer sessions a few seconds and ensure we have reached the
    // established state on both sides.

    wait_for_eq!(r1_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_session.state(), FsmStateKind::Established);

    // Shut down r2 and ensure that r2's peer session has gone back to idle.
    r2.shutdown();
    d2.shutdown();
    wait_for_eq!(
        r2_session.state(),
        FsmStateKind::Idle,
        "r2 state should be Idle after being shutdown"
    );

    // Ensure r1's FSM moves through the correct states after the session drops.
    // (r1 should see the Hold Time expire after r2 shuts down)
    if passive {
        // passive means wait for connections, i.e. the FSM moves from
        // Idle -> Active when the IdleHoldTimer expires
        wait_for_eq!(
            r1_session.state(),
            FsmStateKind::Active,
            "r1 state should move into Active when session uses passive tcp establishment"
        );
    } else {
        // active (!passive) means actively attempt to open a connection, i.e.
        // the FSM moves from Idle -> Connect when the IdleHoldTimer expires
        wait_for_eq!(
            r1_session.state(),
            FsmStateKind::Connect,
            "r1 state should move into Connect when session uses active tcp establishment"
        );
    }

    r2.run();
    let d2_clone = d2.clone();
    spawn(move || {
        d2_clone.run::<BgpListenerChannel>();
    });
    r2.send_event(FsmEvent::ManualStart)
        .expect("manual start session two");

    wait_for_eq!(
        r1_session.state(),
        FsmStateKind::Established,
        "r1 state should move to Established after manual start of r2"
    );
    wait_for_eq!(
        r2_session.state(),
        FsmStateKind::Established,
        "r2 state should move to Established after manual start"
    );

    // Clean up properly
    r1.shutdown();
    d1.shutdown();
}

#[test]
fn test_basic_peering_passive() {
    basic_peering_helper(true);
}

#[test]
fn test_basic_peering_active() {
    basic_peering_helper(false);
}

// This test does the following:
// 1. Sets up a basic pair of routers
// 2. Configures r1 to originate an IPv4 Unicast prefix
// 3. Brings up a BGP session between r1 and r2
// 4. Ensures the BGP FSM moves into Established on both r1 and r2
// 5. Ensures r2 has succesfully received and installed the prefix
// 6. Shuts down r1
// 7. Ensures the BGP FSM moves out of Established on both r1 and r2
// 8. Ensures r2 has successfully uninstalled the implicitly withdrawn prefix
#[test]
fn test_basic_update() {
    let (r1, d1, r2, d2) = two_router_test_setup("basic_update", None, None);

    // originate a prefix
    r1.create_origin4(vec![ip!("1.2.3.0/24")])
        .expect("originate");

    // once we reach established the originated routes should have propagated
    let r1_session = r1.get_session(ip!("2.0.0.1")).expect("get session one");
    let r2_session = r2.get_session(ip!("1.0.0.1")).expect("get session two");
    wait_for_eq!(r1_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_session.state(), FsmStateKind::Established);

    let prefix = Prefix::V4(cidr!("1.2.3.0/24"));

    wait_for_eq!(r2.db.get_prefix_paths(&prefix).is_empty(), false);

    // shut down r1 and ensure that the prefixes are withdrawn from r2 on
    // session timeout.
    r1.shutdown();
    d1.shutdown();
    wait_for_neq!(
        r1_session.state(),
        FsmStateKind::Established,
        "r2 state should NOT be established after shutdown of r1"
    );
    wait_for_neq!(
        r2_session.state(),
        FsmStateKind::Established,
        "r1 state should NOT be established after being shutdown"
    );
    wait_for_eq!(r2.db.get_prefix_paths(&prefix).is_empty(), true);

    // Clean up properly
    r2.shutdown();
    d2.shutdown();
}

fn two_router_test_setup(
    name: &str,
    r1_info: Option<SessionInfo>,
    r2_info: Option<SessionInfo>,
) -> (Arc<Router>, Arc<Dispatcher>, Arc<Router>, Arc<Dispatcher>) {
    let log = mg_common::log::init_file_logger(&format!("r1.{name}.log"));

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
        r1_info.unwrap_or_default(),
    )
    .expect("new session on router one");

    r1_event_tx
        .send(FsmEvent::ManualStart)
        .expect("session manual start on router one");

    // Router 2 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    let log = mg_common::log::init_file_logger(&format!("r2.{name}.log"));

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
        a2s2.clone(),
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
        r2_info.unwrap_or_default(),
    )
    .expect("new session on router two");

    r2_event_tx
        .send(FsmEvent::ManualStart)
        .expect("start session on router two");

    (r1, d1, r2, d2)
}
