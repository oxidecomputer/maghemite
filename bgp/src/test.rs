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
use lazy_static::lazy_static;
use mg_common::log::init_file_logger;
use mg_common::test::{IpAllocation, LoopbackIpManager};
use mg_common::*;
use rdb::{Asn, Prefix};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::{mpsc::channel, Arc, Mutex},
    thread::spawn,
};

// Use non-standard port outside the privileged range to avoid needing privs
const TEST_BGP_PORT: u16 = 10179;

lazy_static! {
    static ref LOOPBACK_MANAGER: Arc<Mutex<LoopbackIpManager>> = {
        let ifname = if cfg!(target_os = "macos") || cfg!(target_os = "illumos")
        {
            "lo0"
        } else if cfg!(target_os = "linux") {
            "lo"
        } else {
            panic!("unsupported platform");
        };

        let log = init_file_logger("loopback-manager.log");

        Arc::new(Mutex::new(LoopbackIpManager::new(ifname, log)))
    };
}

/// Ensure test IP addresses are available for TCP tests
/// Returns a guard that will clean up the IPs when dropped
fn ensure_loop_ips(addresses: &[IpAddr]) -> IpAllocation {
    lazy_static::initialize(&LOOPBACK_MANAGER);

    mg_common::test::LoopbackIpManager::allocate(
        LOOPBACK_MANAGER.clone(),
        addresses,
    )
    .expect("failed to create loopback manager")
}

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

struct LogicalRouter {
    name: String,
    asn: Asn,
    id: u32,
    listen_addr: SocketAddr,
    neighbors: Vec<Neighbor>,
}

struct Neighbor {
    peer_config: PeerConfig,
    session_info: Option<SessionInfo>,
}

fn test_setup<Cnx, Listener>(
    test_name: &str,
    routers: &[LogicalRouter],
) -> (Vec<TestRouter<Cnx>>, Option<IpAllocation>)
where
    Cnx: BgpConnection + Clone + Send + 'static,
    Listener: BgpListener<Cnx> + 'static,
{
    std::fs::create_dir_all("/tmp").expect("create tmp dir");

    let mut test_routers = Vec::with_capacity(routers.len());
    let mut session_senders = Vec::new();
    let mut ip_addresses = Vec::new();

    // Manage local addresses for TCP tests
    let ip_guard = if std::any::type_name::<Cnx>().contains("Tcp") {
        routers
            .iter()
            .for_each(|lr| ip_addresses.push(lr.listen_addr.ip()));
        Some(ensure_loop_ips(&ip_addresses))
    } else {
        None
    };

    // Create all routers first
    for logical_router in routers.iter() {
        let log = init_file_logger(&format!(
            "{}.{test_name}.log",
            logical_router.name
        ));

        // Create database
        let db_path = format!("/tmp/{}.{test_name}.db", logical_router.name);
        let _ = std::fs::remove_dir_all(&db_path);
        let db = rdb::Db::new(&db_path, log.clone()).expect("create db");

        // Create dispatcher
        let addr_to_session = Arc::new(Mutex::new(BTreeMap::new()));
        let dispatcher = Arc::new(Dispatcher::new(
            addr_to_session.clone(),
            logical_router.listen_addr.to_string(),
            log.clone(),
        ));

        // Create router
        let router = Arc::new(Router::new(
            RouterConfig {
                asn: logical_router.asn,
                id: logical_router.id,
            },
            log.clone(),
            db.clone(),
            addr_to_session.clone(),
        ));

        // Start router and dispatcher
        router.run();
        let d = dispatcher.clone();
        spawn(move || {
            d.run::<Listener>();
        });

        // Set up all peer sessions for this router
        for neighbor in &logical_router.neighbors {
            // Each session gets its own channel pair for FsmEvents
            let (event_tx, event_rx) = channel();
            let peer_config = neighbor.peer_config.clone();

            router
                .new_session(
                    peer_config,
                    logical_router.listen_addr,
                    event_tx.clone(),
                    event_rx,
                    neighbor.session_info.clone().unwrap_or_default(),
                )
                .unwrap_or_else(|_| {
                    panic!("new session on router {}", logical_router.name)
                });

            // Store the sender so we can send ManualStart later
            session_senders.push(event_tx);
        }

        // Store components
        test_routers.push(TestRouter {
            router: router.clone(),
            dispatcher,
        });
    }

    // Start all sessions
    for session_tx in session_senders {
        session_tx
            .send(crate::session::FsmEvent::ManualStart)
            .expect("send manual start event");
    }

    (test_routers, ip_guard)
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
fn basic_peering_helper<
    Cnx: BgpConnection + 'static,
    Listener: BgpListener<Cnx> + 'static,
>(
    passive: bool,
    r1_addr: SocketAddr,
    r2_addr: SocketAddr,
) {
    let is_tcp = std::any::type_name::<Cnx>().contains("Tcp");
    let test_str = match (passive, is_tcp) {
        (true, true) => "basic_peering_passive_tcp",
        (false, true) => "basic_peering_active_tcp",
        (true, false) => "basic_peering_passive",
        (false, false) => "basic_peering_active",
    };

    let routers = vec![
        LogicalRouter {
            name: "r1".to_string(),
            asn: Asn::FourOctet(4200000001),
            id: 1,
            listen_addr: r1_addr,
            neighbors: vec![Neighbor {
                peer_config: PeerConfig {
                    name: "r2".into(),
                    host: r2_addr,
                    hold_time: 6,
                    idle_hold_time: 6,
                    delay_open: 0,
                    connect_retry: 1,
                    keepalive: 3,
                    resolution: 100,
                },
                session_info: Some(SessionInfo {
                    passive_tcp_establishment: passive,
                    ..Default::default()
                }),
            }],
        },
        LogicalRouter {
            name: "r2".to_string(),
            asn: Asn::FourOctet(4200000002),
            id: 2,
            listen_addr: r2_addr,
            neighbors: vec![Neighbor {
                peer_config: PeerConfig {
                    name: "r1".into(),
                    host: r1_addr,
                    hold_time: 6,
                    idle_hold_time: 6,
                    delay_open: 0,
                    connect_retry: 1,
                    keepalive: 3,
                    resolution: 100,
                },
                session_info: None,
            }],
        },
    ];

    let (test_routers, _ip_guard) =
        test_setup::<Cnx, Listener>(test_str, &routers);

    let r1 = &test_routers[0];
    let r2 = &test_routers[1];

    let r1_session = r1
        .router
        .get_session(r2_addr.ip())
        .expect("get session one");
    let r2_session = r2
        .router
        .get_session(r1_addr.ip())
        .expect("get session two");

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
fn basic_update_helper<
    Cnx: BgpConnection + 'static,
    Listener: BgpListener<Cnx> + 'static,
>(
    r1_addr: SocketAddr,
    r2_addr: SocketAddr,
) {
    let is_tcp = std::any::type_name::<Cnx>().contains("Tcp");
    let test_name = if is_tcp {
        "basic_update_tcp"
    } else {
        "basic_update"
    };

    let routers = vec![
        LogicalRouter {
            name: "r1".to_string(),
            asn: Asn::FourOctet(4200000001),
            id: 1,
            listen_addr: r1_addr,
            neighbors: vec![Neighbor {
                peer_config: PeerConfig {
                    name: "r2".into(),
                    host: r2_addr,
                    hold_time: 6,
                    idle_hold_time: 6,
                    delay_open: 0,
                    connect_retry: 1,
                    keepalive: 3,
                    resolution: 100,
                },
                session_info: None,
            }],
        },
        LogicalRouter {
            name: "r2".to_string(),
            asn: Asn::FourOctet(4200000002),
            id: 2,
            listen_addr: r2_addr,
            neighbors: vec![Neighbor {
                peer_config: PeerConfig {
                    name: "r1".into(),
                    host: r1_addr,
                    hold_time: 6,
                    idle_hold_time: 6,
                    delay_open: 0,
                    connect_retry: 1,
                    keepalive: 3,
                    resolution: 100,
                },
                session_info: None,
            }],
        },
    ];

    let (test_routers, _ip_guard) =
        test_setup::<Cnx, Listener>(test_name, &routers);

    let r1 = &test_routers[0];
    let r2 = &test_routers[1];

    // originate a prefix
    r1.router
        .create_origin4(vec![ip!("1.2.3.0/24")])
        .expect("originate");

    // once we reach established the originated routes should have propagated
    let r1_session = r1
        .router
        .get_session(r2_addr.ip())
        .expect("get session one");
    let r2_session = r2
        .router
        .get_session(r1_addr.ip())
        .expect("get session two");
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

// Channels vs TCP:
// ================
//
// Channels:
// The current BgpConnectionChannel implementation does not have a listener
// that is capable of splitting off individual connections as they are
// accept()'d. It instead uses the Listener's SocketAddr as the key in a HashMap
// to coordinate the exchange of the local and remote halves of a duplex
// channel, meaning a Listener is inherently coupled to a single channel. Given
// this, each Channel-based logical router can only support a single peer.
//
// TCP:
// Contrary to Channels, the BgpConnectionTcp implementation makes use of a
// TcpListener that can accept() multiple connections, as you'd expect from a
// typical OS TCP/IP implementation. Since the test has multiple logical routers
// making use of the same TCP/IP stack, each listener must bind() to a unique
// (ip:port) to avoid collisions (i.e. EADDRINUSE). While the TCP stack can
// support connections to multiple peers with the same address and unique
// ports, the `addr_to_session` data structure is keyed by IP address not
// sockaddr and thus cannot distinguish between two ports on the same IP, e.g.
// 127.0.0.1:10179 and 127.0.0.1:20179. It is therefore necessary to have
// unique addresses on the system in order to facilitate the use of multiple
// logical routers.
//
// Impact on tests:
// ================
//
// Each tests must provide unique sockaddr to be used for the BGP session.
// For TCP tests, loopback addresses (within 127.0.0.0/8) are preferred.

//
// Channel-based tests
//
#[test]
fn test_basic_update() {
    basic_update_helper::<BgpConnectionChannel, BgpListenerChannel>(
        sockaddr!(&format!("10.0.0.1:{TEST_BGP_PORT}")),
        sockaddr!(&format!("10.0.0.2:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_basic_peering_passive() {
    basic_peering_helper::<BgpConnectionChannel, BgpListenerChannel>(
        true,
        sockaddr!(&format!("11.0.0.1:{TEST_BGP_PORT}")),
        sockaddr!(&format!("11.0.0.2:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_basic_peering_active() {
    basic_peering_helper::<BgpConnectionChannel, BgpListenerChannel>(
        false,
        sockaddr!(&format!("12.0.0.1:{TEST_BGP_PORT}")),
        sockaddr!(&format!("12.0.0.2:{TEST_BGP_PORT}")),
    )
}

//
// TCP-based tests
//
#[test]
fn test_basic_peering_passive_tcp() {
    basic_peering_helper::<BgpConnectionTcp, BgpListenerTcp>(
        true,
        sockaddr!(&format!("127.0.0.1:{TEST_BGP_PORT}")),
        sockaddr!(&format!("127.0.0.2:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_basic_peering_active_tcp() {
    basic_peering_helper::<BgpConnectionTcp, BgpListenerTcp>(
        false,
        sockaddr!(&format!("127.0.0.3:{TEST_BGP_PORT}")),
        sockaddr!(&format!("127.0.0.4:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_basic_update_tcp() {
    basic_update_helper::<BgpConnectionTcp, BgpListenerTcp>(
        sockaddr!(&format!("127.0.0.5:{TEST_BGP_PORT}")),
        sockaddr!(&format!("127.0.0.6:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_three_router_chain_tcp() {
    let r1_addr = "127.0.0.7";
    let r2_addr = "127.0.0.8";
    let r3_addr = "127.0.0.9";

    // Ensure additional loopback IPs are available for this test
    let _ip_guard =
        ensure_loop_ips(&[ip!(r1_addr), ip!(r2_addr), ip!(r3_addr)]);

    // Set up 3 routers in a chain topology: r1 <-> r2 <-> r3
    // This validates that the BgpListener can handle multiple connections
    let routers = vec![
        LogicalRouter {
            name: "r1".to_string(),
            asn: Asn::FourOctet(4200000001),
            id: 1,
            listen_addr: sockaddr!(&format!("{r1_addr}:{TEST_BGP_PORT}")),
            neighbors: vec![Neighbor {
                peer_config: PeerConfig {
                    name: "r2".into(),
                    host: sockaddr!(&format!("{r2_addr}:{TEST_BGP_PORT}")),
                    hold_time: 6,
                    idle_hold_time: 6,
                    delay_open: 0,
                    connect_retry: 1,
                    keepalive: 3,
                    resolution: 100,
                },
                session_info: None,
            }],
        },
        LogicalRouter {
            name: "r2".to_string(),
            asn: Asn::FourOctet(4200000002),
            id: 2,
            listen_addr: sockaddr!(&format!("{r2_addr}:{TEST_BGP_PORT}")),
            neighbors: vec![
                Neighbor {
                    peer_config: PeerConfig {
                        name: "r1".into(),
                        host: sockaddr!(&format!("{r1_addr}:{TEST_BGP_PORT}")),
                        hold_time: 6,
                        idle_hold_time: 6,
                        delay_open: 0,
                        connect_retry: 1,
                        keepalive: 3,
                        resolution: 100,
                    },
                    session_info: None,
                },
                Neighbor {
                    peer_config: PeerConfig {
                        name: "r3".into(),
                        host: sockaddr!(&format!("{r3_addr}:{TEST_BGP_PORT}")),
                        hold_time: 6,
                        idle_hold_time: 6,
                        delay_open: 0,
                        connect_retry: 1,
                        keepalive: 3,
                        resolution: 100,
                    },
                    session_info: None,
                },
            ],
        },
        LogicalRouter {
            name: "r3".to_string(),
            asn: Asn::FourOctet(4200000003),
            id: 3,
            listen_addr: sockaddr!(&format!("{r3_addr}:{TEST_BGP_PORT}")),
            neighbors: vec![Neighbor {
                peer_config: PeerConfig {
                    name: "r2".into(),
                    host: sockaddr!(&format!("{r2_addr}:{TEST_BGP_PORT}")),
                    hold_time: 6,
                    idle_hold_time: 6,
                    delay_open: 0,
                    connect_retry: 1,
                    keepalive: 3,
                    resolution: 100,
                },
                session_info: None,
            }],
        },
    ];

    let (test_routers, _ip_guard2) = test_setup::<
        BgpConnectionTcp,
        BgpListenerTcp,
    >("three_router_chain_tcp", &routers);

    // Verify BGP sessions reach Established state
    // This test validates that the BgpListener can handle multiple connections

    // Get sessions from each router
    let r1_r2_session = test_routers[0]
        .router
        .get_session(ip!(r2_addr))
        .expect("get r1->r2 session");
    let r2_r1_session = test_routers[1]
        .router
        .get_session(ip!(r1_addr))
        .expect("get r2->r1 session");
    let r2_r3_session = test_routers[1]
        .router
        .get_session(ip!(r3_addr))
        .expect("get r2->r3 session");
    let r3_r2_session = test_routers[2]
        .router
        .get_session(ip!(r2_addr))
        .expect("get r3->r2 session");

    wait_for_eq!(r1_r2_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_r1_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_r3_session.state(), FsmStateKind::Established);
    wait_for_eq!(r3_r2_session.state(), FsmStateKind::Established);

    // Clean up
    for router in test_routers.iter() {
        router.shutdown();
    }
}
