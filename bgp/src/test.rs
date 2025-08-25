// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    config::{PeerConfig, RouterConfig},
    connection::{BgpConnection, BgpListener},
    connection_channel::{BgpConnectionChannel, BgpListenerChannel},
    connection_tcp::{BgpConnectionTcp, BgpListenerTcp},
    dispatcher::Dispatcher,
    router::Router,
    session::{FsmStateKind, SessionInfo},
};
use mg_common::*;
use rdb::{Asn, Prefix};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{mpsc::channel, Arc, Mutex},
    thread::spawn,
};

struct TestRouter<Cnx: BgpConnection> {
    router: Arc<Router<Cnx>>,
    dispatcher: Arc<Dispatcher<Cnx>>,
}

impl<Cnx: BgpConnection + 'static> TestRouter<Cnx> {
    fn shutdown(&self) {
        self.router.shutdown();
        self.dispatcher.shutdown();
    }

    fn run<Listener: BgpListener<Cnx> + 'static>(&self) {
        self.router.run();
        let d = self.dispatcher.clone();
        spawn(move || {
            d.run::<Listener>();
        });
    }
}

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
fn basic_peering<
    Cnx: BgpConnection + 'static,
    Listener: BgpListener<Cnx> + 'static,
>(
    passive: bool,
    r1_addr: SocketAddr,
    r2_addr: SocketAddr,
    r1_peer: SocketAddr,
    r2_peer: SocketAddr,
) {
    let is_tcp = std::any::type_name::<Cnx>().contains("Tcp");
    let test_str = match (passive, is_tcp) {
        (true, true) => "basic_peering_passive_tcp",
        (false, true) => "basic_peering_active_tcp",
        (true, false) => "basic_peering_passive",
        (false, false) => "basic_peering_active",
    };

    let (r1, r2) = two_router_test_setup::<Cnx, Listener>(
        test_str,
        Some(SessionInfo {
            passive_tcp_establishment: passive,
            ..Default::default()
        }),
        None,
        r1_addr,
        r2_addr,
        r1_peer,
        r2_peer,
    );

    // Generate consistent IPs based on the addresses we used for session lookup
    let (r1_peer_ip, r2_peer_ip) = if is_tcp {
        (ip!("127.0.0.1"), ip!("127.0.0.1")) // TCP can use same IP with different ports
    } else {
        // Channel-based: extract IPs from the peer host addresses we used
        (r1_peer.ip(), r2_peer.ip()) // r1 looks for r2, r2 looks for r1
    };

    let r1_session =
        r1.router.get_session(r1_peer_ip).expect("get session one");
    let r2_session =
        r2.router.get_session(r2_peer_ip).expect("get session two");

    // Give peer sessions a few seconds and ensure we have reached the
    // established state on both sides.
    wait_for_eq!(r1_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_session.state(), FsmStateKind::Established);

    // Shut down r2 and ensure that r2's peer session has gone back to idle.
    r2.shutdown();
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

    r2.run::<Listener>();
    r2.router
        .send_event(crate::session::FsmEvent::ManualStart)
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
    r2.shutdown();
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
fn basic_update<
    Cnx: BgpConnection + 'static,
    Listener: BgpListener<Cnx> + 'static,
>(
    r1_addr: SocketAddr,
    r2_addr: SocketAddr,
    r1_peer: SocketAddr,
    r2_peer: SocketAddr,
) {
    let is_tcp = std::any::type_name::<Cnx>().contains("Tcp");
    let test_name = if is_tcp {
        "basic_update_tcp"
    } else {
        "basic_update"
    };
    let (r1, r2) = two_router_test_setup::<Cnx, Listener>(
        test_name, None, None, r1_addr, r2_addr, r1_peer, r2_peer,
    );

    // originate a prefix
    r1.router
        .create_origin4(vec![ip!("1.2.3.0/24")])
        .expect("originate");

    // Generate consistent IPs based on the addresses we used for session lookup
    let (r1_peer_ip, r2_peer_ip) = if is_tcp {
        (ip!("127.0.0.1"), ip!("127.0.0.1")) // TCP can use same IP with different ports
    } else {
        // Channel-based: extract IPs from the peer host addresses we used
        (r1_peer.ip(), r2_peer.ip()) // r1 looks for r2, r2 looks for r1
    };

    // once we reach established the originated routes should have propagated
    let r1_session =
        r1.router.get_session(r1_peer_ip).expect("get session one");
    let r2_session =
        r2.router.get_session(r2_peer_ip).expect("get session two");
    wait_for_eq!(r1_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_session.state(), FsmStateKind::Established);

    let prefix = Prefix::V4(cidr!("1.2.3.0/24"));

    wait_for_eq!(r2.router.db.get_prefix_paths(&prefix).is_empty(), false);

    // shut down r1 and ensure that the prefixes are withdrawn from r2 on
    // session timeout.
    r1.shutdown();
    wait_for_neq!(
        r1_session.state(),
        FsmStateKind::Established,
        "r1 state should NOT be established after being shutdown"
    );
    wait_for_neq!(
        r2_session.state(),
        FsmStateKind::Established,
        "r2 state should NOT be established after shutdown of r1"
    );
    wait_for_eq!(r2.router.db.get_prefix_paths(&prefix).is_empty(), true);

    // Clean up properly
    r2.shutdown();
}

fn two_router_test_setup<
    Cnx: BgpConnection + 'static,
    Listener: BgpListener<Cnx> + 'static,
>(
    name: &str,
    r1_info: Option<SessionInfo>,
    r2_info: Option<SessionInfo>,
    r1_addr: SocketAddr,
    r2_addr: SocketAddr,
    r1_peer: SocketAddr,
    r2_peer: SocketAddr,
) -> (TestRouter<Cnx>, TestRouter<Cnx>)
where
    Cnx: Clone + Send,
{
    let log = mg_common::log::init_file_logger(&format!("r1.{name}.log"));

    std::fs::create_dir_all("/tmp").expect("create tmp dir");

    // Router 1 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    let db_path = format!("/tmp/r1.{name}.db");
    let _ = std::fs::remove_dir_all(&db_path);
    let db = rdb::Db::new(&db_path, log.clone()).expect("create db");

    let a2s1 = Arc::new(Mutex::new(BTreeMap::new()));
    let d1 = Arc::new(Dispatcher::<Cnx>::new(
        a2s1.clone(),
        r1_addr.to_string(),
        log.clone(),
    ));

    let (r1_event_tx, event_rx) = channel();
    let r1_router = Arc::new(Router::<Cnx>::new(
        RouterConfig {
            asn: Asn::FourOctet(4200000001),
            id: 1,
        },
        log.clone(),
        db.clone(),
        a2s1.clone(),
    ));

    r1_router.run();
    let d = d1.clone();
    spawn(move || {
        d.run::<Listener>();
    });

    r1_router
        .new_session(
            PeerConfig {
                name: "r2".into(),
                host: r1_peer,
                hold_time: 6,
                idle_hold_time: 6,
                delay_open: 0,
                connect_retry: 1,
                keepalive: 3,
                resolution: 100,
            },
            r1_addr,
            r1_event_tx.clone(),
            event_rx,
            r1_info.unwrap_or_default(),
        )
        .expect("new session on router one");

    r1_event_tx
        .send(crate::session::FsmEvent::ManualStart)
        .expect("session manual start on router one");

    let r1 = TestRouter {
        router: r1_router,
        dispatcher: d1,
    };

    // Router 2 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    let log = mg_common::log::init_file_logger(&format!("r2.{name}.log"));

    let db_path = format!("/tmp/r2.{name}.db");
    let _ = std::fs::remove_dir_all(&db_path);
    let db = rdb::Db::new(&db_path, log.clone())
        .expect("create datastore for router 2");

    let a2s2 = Arc::new(Mutex::new(BTreeMap::new()));
    let d2 = Arc::new(Dispatcher::<Cnx>::new(
        a2s2.clone(),
        r2_addr.to_string(),
        log.clone(),
    ));

    let (r2_event_tx, event_rx) = channel();

    let r2_router = Arc::new(Router::<Cnx>::new(
        RouterConfig {
            asn: Asn::FourOctet(4200000002),
            id: 2,
        },
        log.clone(),
        db.clone(),
        a2s2.clone(),
    ));

    r2_router.run();
    let d = d2.clone();
    spawn(move || {
        d.run::<Listener>();
    });

    r2_router
        .new_session(
            PeerConfig {
                name: "r1".into(),
                host: r2_peer,
                hold_time: 6,
                idle_hold_time: 6,
                delay_open: 0,
                connect_retry: 1,
                keepalive: 3,
                resolution: 100,
            },
            r2_addr,
            r2_event_tx.clone(),
            event_rx,
            r2_info.unwrap_or_default(),
        )
        .expect("new session on router two");

    r2_event_tx
        .send(crate::session::FsmEvent::ManualStart)
        .expect("start session on router two");

    let r2 = TestRouter {
        router: r2_router,
        dispatcher: d2,
    };

    (r1, r2)
}

// In order to facilitate test cases being run in parallel, sockaddrs must
// be unique, although the reasoning is different for Channels and TCP.
//
// Channels:
// The current BgpConnectionChannel implementation does not have a single
// listener that splits off individual connections as they are accept()'d. It
// uses the Listener's SocketAddr as the key in a HashMap to coordinate the
// exchange of the local and remote halves of a duplex channel, therefore a
// Listener is implicitly coupled to a single channel. Given this, each
// Channel-based test case will supply unique IPs. The port provided here is
// pinned to 179 (BGP) as a convention, but is not strictly necessary.
//
// TCP:
// A single TcpListener can accept() multiple connections, as you'd expect from
// a typical OS TCP/IP implementation.  However, since the test has multiple
// logical routers making use of the same TCP/IP stack, each listener must
// bind() to a different port to avoid collisions (i.e. EADDRINUSE). To avoid
// the need for IP management, we use the unspecified address (0.0.0.0) as the
// local listener, and the loopback address (127.0.0.1) as the remote peer.
// Port numbers supplied here must be unique per logical router.

#[test]
fn test_basic_peering_passive() {
    basic_peering::<BgpConnectionChannel, BgpListenerChannel>(
        true,
        sockaddr!("10.0.0.1:179"),
        sockaddr!("10.0.0.2:179"),
        sockaddr!("10.0.0.2:179"),
        sockaddr!("10.0.0.1:179"),
    )
}

#[test]
fn test_basic_peering_active() {
    basic_peering::<BgpConnectionChannel, BgpListenerChannel>(
        false,
        sockaddr!("11.0.0.1:179"),
        sockaddr!("11.0.0.2:179"),
        sockaddr!("11.0.0.2:179"),
        sockaddr!("11.0.0.1:179"),
    )
}

#[test]
fn test_basic_peering_passive_tcp() {
    basic_peering::<BgpConnectionTcp, BgpListenerTcp>(
        true,
        sockaddr!("0.0.0.0:20000"),
        sockaddr!("0.0.0.0:20001"),
        sockaddr!("127.0.0.1:20001"),
        sockaddr!("127.0.0.1:20000"),
    )
}

#[test]
fn test_basic_peering_active_tcp() {
    basic_peering::<BgpConnectionTcp, BgpListenerTcp>(
        false,
        sockaddr!("0.0.0.0:20010"),
        sockaddr!("0.0.0.0:20011"),
        sockaddr!("127.0.0.1:20011"),
        sockaddr!("127.0.0.1:20010"),
    )
}

#[test]
fn test_basic_update() {
    basic_update::<BgpConnectionChannel, BgpListenerChannel>(
        sockaddr!("12.0.0.1:179"),
        sockaddr!("12.0.0.2:179"),
        sockaddr!("12.0.0.2:179"),
        sockaddr!("12.0.0.1:179"),
    )
}

#[test]
fn test_basic_update_tcp() {
    basic_update::<BgpConnectionTcp, BgpListenerTcp>(
        sockaddr!("0.0.0.0:20020"),
        sockaddr!("0.0.0.0:20021"),
        sockaddr!("127.0.0.1:20021"),
        sockaddr!("127.0.0.1:20020"),
    )
}
