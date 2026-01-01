// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    config::{PeerConfig, RouterConfig},
    connection::{BgpConnection, BgpListener},
    connection_channel::{BgpConnectionChannel, BgpListenerChannel},
    connection_tcp::{BgpConnectionTcp, BgpListenerTcp},
    dispatcher::Dispatcher,
    params::{Ipv4UnicastConfig, Ipv6UnicastConfig, JitterRange},
    router::Router,
    session::{
        AdminEvent, ConnectionKind, FsmEvent, FsmStateKind, SessionEndpoint,
        SessionInfo,
    },
};
use lazy_static::lazy_static;
use mg_common::log::init_file_logger;
use mg_common::test::{IpAllocation, LoopbackIpManager};
use mg_common::*;
use rdb::{Asn, ImportExportPolicy4, ImportExportPolicy6, Prefix, Prefix4};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, mpsc::channel},
    time::Duration,
};

// Use non-standard port outside the privileged range to avoid needing privs
const TEST_BGP_PORT: u16 = 10179;

// XXX: add an iBGP option for the tests
// XXX: Add test impl of BgpConnection (and Clock?) for FSM tests.
//      The DUT will still have a SessionRunner & timers, but the test peer will
//      be simulated by test code + will inject different events into the DUT's
//      FSM event queue so we can test all events in each state. We should have
//      explicit expectations for how every possible event is handled in every
//      FSM state. Test each state like there's a `match` for events.
//      We also need to add tests for IdleHoldTimer and DampPeerOscillations.

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

struct TestRouter<Cnx: BgpConnection + 'static> {
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
        let listen_addr = self.dispatcher.listen_addr().to_string();
        let listen_addr_for_log = listen_addr.clone();
        eprintln!("Spawning Dispatcher thread for {}", listen_addr);
        std::thread::Builder::new()
            .name(format!("bgp-listener-{}", listen_addr))
            .spawn(move || {
                d.run::<Listener>();
                eprintln!(
                    "Dispatcher thread for {} exiting",
                    listen_addr_for_log
                );
            })
            .expect("failed to spawn dispatcher thread");
    }
}

/// Test-specific enum describing which route address families are exchanged
/// in a BGP session. This is independent of the TCP/IP connection address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteExchange {
    Ipv4 {
        nexthop: Option<IpAddr>,
    },
    Ipv6 {
        nexthop: Option<IpAddr>,
    },
    DualStack {
        ipv4_nexthop: Option<IpAddr>,
        ipv6_nexthop: Option<IpAddr>,
    },
}

struct LogicalRouter {
    name: String,
    asn: Asn,
    id: u32,
    listen_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    neighbors: Vec<NeighborConfig>,
}

struct NeighborConfig {
    peer_name: String,
    remote_host: SocketAddr,
    session_info: SessionInfo,
}

/// Create SessionInfo for tests with fixed timer values and route exchange configuration.
/// This constructs SessionInfo directly without using PeerConfig.
///
/// # Arguments
/// * `route_exchange` - Which route address families to exchange
/// * `local_addr` - Local bind address for this session
/// * `remote_addr` - Remote peer address (for nexthop defaults)
/// * `passive` - Whether to use passive TCP establishment
fn create_test_session_info(
    route_exchange: RouteExchange,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    passive: bool,
) -> SessionInfo {
    // Derive AF configuration from route_exchange
    // Use remote_addr for nexthop defaults (what this router advertises)
    let (ipv4_unicast, ipv6_unicast) = match route_exchange {
        RouteExchange::Ipv4 { nexthop } => {
            let ipv4_cfg = Ipv4UnicastConfig {
                nexthop: nexthop.or_else(|| {
                    if remote_addr.is_ipv4() {
                        Some(remote_addr.ip())
                    } else {
                        None
                    }
                }),
                import_policy: ImportExportPolicy4::default(),
                export_policy: ImportExportPolicy4::default(),
            };
            (Some(ipv4_cfg), None)
        }
        RouteExchange::Ipv6 { nexthop } => {
            let ipv6_cfg = Ipv6UnicastConfig {
                nexthop: nexthop.or_else(|| {
                    if remote_addr.is_ipv6() {
                        Some(remote_addr.ip())
                    } else {
                        None
                    }
                }),
                import_policy: ImportExportPolicy6::NoFiltering,
                export_policy: ImportExportPolicy6::NoFiltering,
            };
            (None, Some(ipv6_cfg))
        }
        RouteExchange::DualStack {
            ipv4_nexthop,
            ipv6_nexthop,
        } => {
            let ipv4_cfg = Ipv4UnicastConfig {
                nexthop: ipv4_nexthop.or_else(|| {
                    if remote_addr.is_ipv4() {
                        Some(remote_addr.ip())
                    } else {
                        None
                    }
                }),
                import_policy: ImportExportPolicy4::default(),
                export_policy: ImportExportPolicy4::default(),
            };
            let ipv6_cfg = Ipv6UnicastConfig {
                nexthop: ipv6_nexthop.or_else(|| {
                    if remote_addr.is_ipv6() {
                        Some(remote_addr.ip())
                    } else {
                        None
                    }
                }),
                import_policy: ImportExportPolicy6::NoFiltering,
                export_policy: ImportExportPolicy6::NoFiltering,
            };
            (Some(ipv4_cfg), Some(ipv6_cfg))
        }
    };

    // Construct SessionInfo directly with fixed test values
    SessionInfo {
        passive_tcp_establishment: passive,
        remote_asn: None,
        remote_id: None,
        bind_addr: Some(local_addr),
        min_ttl: None,
        md5_auth_key: None,
        multi_exit_discriminator: None,
        communities: BTreeSet::new(),
        local_pref: None,
        enforce_first_as: false,
        ipv4_unicast,
        ipv6_unicast,
        vlan_id: None,
        // Fixed test timer values
        connect_retry_time: Duration::from_secs(1),
        keepalive_time: Duration::from_secs(3),
        hold_time: Duration::from_secs(6),
        idle_hold_time: Duration::from_secs(0),
        delay_open_time: Duration::from_secs(0),
        resolution: Duration::from_millis(100),
        connect_retry_jitter: None,
        idle_hold_jitter: Some(JitterRange {
            min: 0.75,
            max: 1.0,
        }),
        deterministic_collision_resolution: false,
    }
}

fn test_setup<Cnx, Listener>(
    test_name: &str,
    routers: &[LogicalRouter],
) -> (Vec<TestRouter<Cnx>>, Option<IpAllocation>)
where
    Cnx: BgpConnection + Send + 'static,
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
        let addr_to_session: Arc<
            Mutex<BTreeMap<IpAddr, SessionEndpoint<Cnx>>>,
        > = Arc::new(Mutex::new(BTreeMap::new()));
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
        let listen_addr = dispatcher.listen_addr().to_string();
        let listen_addr_for_log = listen_addr.clone();
        eprintln!("Spawning Dispatcher thread for {}", listen_addr);
        std::thread::Builder::new()
            .name(format!("bgp-listener-{}", listen_addr))
            .spawn(move || {
                d.run::<Listener>();
                eprintln!(
                    "Dispatcher thread for {} exiting",
                    listen_addr_for_log
                );
            })
            .expect("failed to spawn dispatcher thread");

        // Set up all peer sessions for this router
        for neighbor in &logical_router.neighbors {
            // Each session gets its own channel pair for FsmEvents
            let (event_tx, event_rx) = channel();

            // Create PeerConfig from neighbor's configuration for compatibility with new_session
            let peer_config = PeerConfig {
                name: neighbor.peer_name.clone(),
                host: neighbor.remote_host,
                hold_time: 6,
                idle_hold_time: 0,
                delay_open: 0,
                connect_retry: 1,
                keepalive: 3,
                resolution: 100,
            };

            // Use bind_addr from LogicalRouter if specified, otherwise use listen_addr
            let bind_addr = logical_router
                .bind_addr
                .unwrap_or(logical_router.listen_addr);

            let session_info = neighbor.session_info.clone();

            let session_runner = router
                .new_session(
                    peer_config,
                    Some(bind_addr),
                    event_tx.clone(),
                    event_rx,
                    session_info,
                )
                .unwrap_or_else(|_| {
                    panic!("new session on router {}", logical_router.name)
                });

            // If LogicalRouter.bind_addr is None, clear the bind_addr
            // that was just set by new_session (at router.rs:212)
            if logical_router.bind_addr.is_none() {
                let mut info = lock!(session_runner.session);
                info.bind_addr = None;
            }

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
            .send(FsmEvent::Admin(AdminEvent::ManualStart))
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
    route_exchange: RouteExchange,
    r1_addr: SocketAddr,
    r2_addr: SocketAddr,
) {
    let is_tcp = std::any::type_name::<Cnx>().contains("Tcp");
    let is_ipv6 = r1_addr.ip().is_ipv6();
    let test_str = match (passive, is_tcp, is_ipv6) {
        (true, true, true) => "basic_peering_passive_tcp_ipv6",
        (false, true, true) => "basic_peering_active_tcp_ipv6",
        (true, false, true) => "basic_peering_passive_ipv6",
        (false, false, true) => "basic_peering_active_ipv6",
        (true, true, false) => "basic_peering_passive_tcp",
        (false, true, false) => "basic_peering_active_tcp",
        (true, false, false) => "basic_peering_passive",
        (false, false, false) => "basic_peering_active",
    };

    let routers = vec![
        LogicalRouter {
            name: "r1".to_string(),
            asn: Asn::FourOctet(4200000001),
            id: 1,
            listen_addr: r1_addr,
            bind_addr: Some(r1_addr),
            neighbors: vec![NeighborConfig {
                peer_name: "r2".to_string(),
                remote_host: r2_addr,
                session_info: create_test_session_info(
                    route_exchange,
                    r1_addr,
                    r2_addr,
                    passive,
                ),
            }],
        },
        LogicalRouter {
            name: "r2".to_string(),
            asn: Asn::FourOctet(4200000002),
            id: 2,
            listen_addr: r2_addr,
            bind_addr: Some(r2_addr),
            neighbors: vec![NeighborConfig {
                peer_name: "r1".to_string(),
                remote_host: r1_addr,
                session_info: create_test_session_info(
                    route_exchange,
                    r2_addr,
                    r1_addr,
                    !passive,
                ),
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

    // Verify Arc-based connection query API
    // Both sessions should report exactly 1 active connection
    assert_eq!(
        r1_session.connection_count(),
        1,
        "r1 should have 1 active connection"
    );

    assert_eq!(
        r2_session.connection_count(),
        1,
        "r2 should have 1 active connection"
    );

    // Verify primary connection exists and directions are opposite
    let r1_primary = r1_session.primary_connection();
    assert!(r1_primary.is_some(), "r1 should have primary connection");
    let r1_dir = match &r1_primary.unwrap() {
        ConnectionKind::Full(pc) => pc.conn.direction(),
        ConnectionKind::Partial(c) => c.direction(),
    };

    let r2_primary = r2_session.primary_connection();
    assert!(r2_primary.is_some(), "r2 should have primary connection");
    let r2_dir = match &r2_primary.unwrap() {
        ConnectionKind::Full(pc) => pc.conn.direction(),
        ConnectionKind::Partial(c) => c.direction(),
    };

    // One should be Outbound and one Inbound (they're using same physical connection)
    assert_ne!(r1_dir, r2_dir, "Connection directions should be opposite");

    // Verify all_connections contains single connection in both sessions
    assert_eq!(
        r1_session.connection_count(),
        1,
        "r1 should have exactly 1 connection"
    );
    assert_eq!(
        r2_session.connection_count(),
        1,
        "r2 should have exactly 1 connection"
    );

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
        .send_admin_event(AdminEvent::ManualStart)
        .expect("manual start session two");

    wait_for_eq!(
        {
            let state = r1_session.state();
            println!("r1_session.state(): {state}");
            state
        },
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
// 2. Configures r1 to originate prefix(es) based on route_exchange
// 3. Brings up a BGP session between r1 and r2
// 4. Ensures the BGP FSM moves into Established on both r1 and r2
// 5. Ensures r2 has succesfully received and installed the prefix(es)
// 6. Shuts down r1
// 7. Ensures the BGP FSM moves out of Established on both r1 and r2
// 8. Ensures r2 has successfully uninstalled the implicitly withdrawn prefix(es)
fn basic_update_helper<
    Cnx: BgpConnection + 'static,
    Listener: BgpListener<Cnx> + 'static,
>(
    route_exchange: RouteExchange,
    r1_addr: SocketAddr,
    r2_addr: SocketAddr,
) {
    let is_tcp = std::any::type_name::<Cnx>().contains("Tcp");
    let is_ipv6 = r1_addr.ip().is_ipv6();
    let test_name = match (is_tcp, is_ipv6) {
        (true, true) => "basic_update_ipv6_tcp",
        (true, false) => "basic_update_tcp",
        (false, true) => "basic_update_ipv6",
        (false, false) => "basic_update",
    };

    let routers = vec![
        LogicalRouter {
            name: "r1".to_string(),
            asn: Asn::FourOctet(4200000001),
            id: 1,
            listen_addr: r1_addr,
            bind_addr: Some(r1_addr),
            neighbors: vec![NeighborConfig {
                peer_name: "r2".to_string(),
                remote_host: r2_addr,
                session_info: create_test_session_info(
                    route_exchange,
                    r1_addr,
                    r2_addr,
                    false,
                ),
            }],
        },
        LogicalRouter {
            name: "r2".to_string(),
            asn: Asn::FourOctet(4200000002),
            id: 2,
            listen_addr: r2_addr,
            bind_addr: Some(r2_addr),
            neighbors: vec![NeighborConfig {
                peer_name: "r1".to_string(),
                remote_host: r1_addr,
                session_info: create_test_session_info(
                    route_exchange,
                    r2_addr,
                    r1_addr,
                    false,
                ),
            }],
        },
    ];

    let (test_routers, _ip_guard) =
        test_setup::<Cnx, Listener>(test_name, &routers);

    let r1 = &test_routers[0];
    let r2 = &test_routers[1];

    // let the session get into established state
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

    // Originate and verify routes based on route_exchange variant
    match route_exchange {
        RouteExchange::Ipv4 { .. } => {
            // IPv4-only: originate and verify IPv4 prefix
            r1.router
                .create_origin4(vec![cidr!("1.2.3.0/24")])
                .expect("originate IPv4");

            let prefix_rdb = Prefix::V4(cidr!("1.2.3.0/24"));
            wait_for!(!r2.router.db.get_prefix_paths(&prefix_rdb).is_empty());

            // Shut down r1 and verify withdrawal
            r1.shutdown();
            wait_for_neq!(r1_session.state(), FsmStateKind::Established);
            wait_for_neq!(r2_session.state(), FsmStateKind::Established);
            wait_for!(r2.router.db.get_prefix_paths(&prefix_rdb).is_empty());
        }
        RouteExchange::Ipv6 { .. } => {
            // IPv6-only: originate and verify IPv6 prefix
            r1.router
                .create_origin6(vec![cidr!("3fff:db8::/32")])
                .expect("originate IPv6");

            let prefix_rdb = Prefix::V6(cidr!("3fff:db8::/32"));
            wait_for!(!r2.router.db.get_prefix_paths(&prefix_rdb).is_empty());

            // Shut down r1 and verify withdrawal
            r1.shutdown();
            wait_for_neq!(r1_session.state(), FsmStateKind::Established);
            wait_for_neq!(r2_session.state(), FsmStateKind::Established);
            wait_for!(r2.router.db.get_prefix_paths(&prefix_rdb).is_empty());
        }
        RouteExchange::DualStack { .. } => {
            // Dual-stack: originate and verify both IPv4 and IPv6 prefixes
            r1.router
                .create_origin4(vec![cidr!("1.2.3.0/24")])
                .expect("originate IPv4");
            r1.router
                .create_origin6(vec![cidr!("3fff:db8::/32")])
                .expect("originate IPv6");

            let prefix4_rdb = Prefix::V4(cidr!("1.2.3.0/24"));
            let prefix6_rdb = Prefix::V6(cidr!("3fff:db8::/32"));

            wait_for!(!r2.router.db.get_prefix_paths(&prefix4_rdb).is_empty());
            wait_for!(!r2.router.db.get_prefix_paths(&prefix6_rdb).is_empty());

            // Shut down r1 and verify withdrawal of both
            r1.shutdown();
            wait_for_neq!(r1_session.state(), FsmStateKind::Established);
            wait_for_neq!(r2_session.state(), FsmStateKind::Established);
            wait_for!(r2.router.db.get_prefix_paths(&prefix4_rdb).is_empty());
            wait_for!(r2.router.db.get_prefix_paths(&prefix6_rdb).is_empty());
        }
    }

    // Clean up properly
    r2.shutdown();
}

/// Helper for testing 3-router chain topology: r1 <-> r2 <-> r3
/// This validates that the BgpListener can handle multiple connections.
fn three_router_chain_helper<
    Cnx: BgpConnection + 'static,
    Listener: BgpListener<Cnx> + 'static,
>(
    r1_addr: SocketAddr,
    r2_addr: SocketAddr,
    r3_addr: SocketAddr,
) {
    let is_tcp = std::any::type_name::<Cnx>().contains("Tcp");
    let is_ipv6 = r1_addr.ip().is_ipv6();
    let test_str = match (is_tcp, is_ipv6) {
        (true, true) => "three_router_chain_tcp_ipv6",
        (true, false) => "three_router_chain_tcp",
        (false, true) => "three_router_chain_ipv6",
        (false, false) => "three_router_chain",
    };

    // Set up 3 routers in a chain topology: r1 <-> r2 <-> r3
    let routers = vec![
        LogicalRouter {
            name: "r1".to_string(),
            asn: Asn::FourOctet(4200000001),
            id: 1,
            listen_addr: r1_addr,
            bind_addr: Some(r1_addr),
            neighbors: vec![NeighborConfig {
                peer_name: "r2".to_string(),
                remote_host: r2_addr,
                session_info: SessionInfo::from_peer_config(&PeerConfig {
                    name: "r2".into(),
                    host: r2_addr,
                    hold_time: 6,
                    idle_hold_time: 0,
                    delay_open: 0,
                    connect_retry: 1,
                    keepalive: 3,
                    resolution: 100,
                }),
            }],
        },
        LogicalRouter {
            name: "r2".to_string(),
            asn: Asn::FourOctet(4200000002),
            id: 2,
            listen_addr: r2_addr,
            bind_addr: Some(r2_addr),
            neighbors: vec![
                NeighborConfig {
                    peer_name: "r1".to_string(),
                    remote_host: r1_addr,
                    session_info: SessionInfo::from_peer_config(&PeerConfig {
                        name: "r1".into(),
                        host: r1_addr,
                        hold_time: 6,
                        idle_hold_time: 0,
                        delay_open: 0,
                        connect_retry: 1,
                        keepalive: 3,
                        resolution: 100,
                    }),
                },
                NeighborConfig {
                    peer_name: "r3".to_string(),
                    remote_host: r3_addr,
                    session_info: SessionInfo::from_peer_config(&PeerConfig {
                        name: "r3".into(),
                        host: r3_addr,
                        hold_time: 6,
                        idle_hold_time: 0,
                        delay_open: 0,
                        connect_retry: 1,
                        keepalive: 3,
                        resolution: 100,
                    }),
                },
            ],
        },
        LogicalRouter {
            name: "r3".to_string(),
            asn: Asn::FourOctet(4200000003),
            id: 3,
            listen_addr: r3_addr,
            bind_addr: Some(r3_addr),
            neighbors: vec![NeighborConfig {
                peer_name: "r2".to_string(),
                remote_host: r2_addr,
                session_info: SessionInfo::from_peer_config(&PeerConfig {
                    name: "r2".into(),
                    host: r2_addr,
                    hold_time: 6,
                    idle_hold_time: 0,
                    delay_open: 0,
                    connect_retry: 1,
                    keepalive: 3,
                    resolution: 100,
                }),
            }],
        },
    ];

    let (test_routers, _ip_guard) =
        test_setup::<Cnx, Listener>(test_str, &routers);

    let r1 = &test_routers[0];
    let r2 = &test_routers[1];
    let r3 = &test_routers[2];

    // Get sessions from each router
    let r1_r2_session = r1
        .router
        .get_session(r2_addr.ip())
        .expect("get r1->r2 session");
    let r2_r1_session = r2
        .router
        .get_session(r1_addr.ip())
        .expect("get r2->r1 session");
    let r2_r3_session = r2
        .router
        .get_session(r3_addr.ip())
        .expect("get r2->r3 session");
    let r3_r2_session = r3
        .router
        .get_session(r2_addr.ip())
        .expect("get r3->r2 session");

    // Verify all sessions reach Established state
    wait_for_eq!(r1_r2_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_r1_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_r3_session.state(), FsmStateKind::Established);
    wait_for_eq!(r3_r2_session.state(), FsmStateKind::Established);

    // Clean up
    for router in test_routers.iter() {
        router.shutdown();
    }
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
        RouteExchange::Ipv4 { nexthop: None },
        sockaddr!(&format!("10.0.0.1:{TEST_BGP_PORT}")),
        sockaddr!(&format!("10.0.0.2:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_basic_peering_passive() {
    basic_peering_helper::<BgpConnectionChannel, BgpListenerChannel>(
        true,
        RouteExchange::Ipv4 { nexthop: None },
        sockaddr!(&format!("11.0.0.1:{TEST_BGP_PORT}")),
        sockaddr!(&format!("11.0.0.2:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_basic_peering_active() {
    basic_peering_helper::<BgpConnectionChannel, BgpListenerChannel>(
        false,
        RouteExchange::Ipv4 { nexthop: None },
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
        RouteExchange::Ipv4 { nexthop: None },
        sockaddr!(&format!("127.0.0.1:{TEST_BGP_PORT}")),
        sockaddr!(&format!("127.0.0.2:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_basic_peering_active_tcp() {
    basic_peering_helper::<BgpConnectionTcp, BgpListenerTcp>(
        false,
        RouteExchange::Ipv4 { nexthop: None },
        sockaddr!(&format!("127.0.0.3:{TEST_BGP_PORT}")),
        sockaddr!(&format!("127.0.0.4:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_basic_update_tcp() {
    basic_update_helper::<BgpConnectionTcp, BgpListenerTcp>(
        RouteExchange::Ipv4 { nexthop: None },
        sockaddr!(&format!("127.0.0.5:{TEST_BGP_PORT}")),
        sockaddr!(&format!("127.0.0.6:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_three_router_chain_tcp() {
    let r1_addr: SocketAddr = sockaddr!(&format!("127.0.0.7:{TEST_BGP_PORT}"));
    let r2_addr: SocketAddr = sockaddr!(&format!("127.0.0.8:{TEST_BGP_PORT}"));
    let r3_addr: SocketAddr = sockaddr!(&format!("127.0.0.9:{TEST_BGP_PORT}"));

    // Ensure loopback IPs are available for this test
    let _ip_guard =
        ensure_loop_ips(&[r1_addr.ip(), r2_addr.ip(), r3_addr.ip()]);

    three_router_chain_helper::<BgpConnectionTcp, BgpListenerTcp>(
        r1_addr, r2_addr, r3_addr,
    )
}

#[test]
fn test_three_router_chain_tcp_ipv6() {
    let r1_addr: SocketAddr = sockaddr!(&format!("[3fff::c]:{TEST_BGP_PORT}"));
    let r2_addr: SocketAddr = sockaddr!(&format!("[3fff::d]:{TEST_BGP_PORT}"));
    let r3_addr: SocketAddr = sockaddr!(&format!("[3fff::e]:{TEST_BGP_PORT}"));

    three_router_chain_helper::<BgpConnectionTcp, BgpListenerTcp>(
        r1_addr, r2_addr, r3_addr,
    )
}

/// Test that threads are properly cleaned up throughout the neighbor lifecycle.
/// This test verifies that no threads leak when:
/// 1. A neighbor is created and established
/// 2. The neighbor is reset (hard) and re-established
/// 3. The neighbor is deleted
#[test]
#[serial_test::serial]
fn test_neighbor_thread_lifecycle_no_leaks() {
    let r1_addr = sockaddr!(&format!("127.0.0.10:{TEST_BGP_PORT}"));
    let r2_addr = sockaddr!(&format!("127.0.0.11:{TEST_BGP_PORT}"));

    // Wait for baseline BGP thread count to reach 0
    // This handles the case where previous tests' threads are still being cleaned up by the OS.
    // We count only threads with names starting with "bgp-" to exclude
    // dependency threads (slog-async, rdb reapers, etc.)
    wait_for!(
        {
            let count = mg_common::test::count_threads_with_prefix("bgp-")
                .expect("couldn't collect thread count");
            if count > 0 {
                eprintln!(
                    "Waiting for baseline to stabilize (current: {count})"
                );
            }
            count == 0
        },
        "Baseline BGP thread count should reach 0"
    );
    let baseline = 0;
    eprintln!("=== Baseline BGP thread count: {baseline} ===");

    let r1_peer_config = PeerConfig {
        name: "r2".into(),
        host: r2_addr,
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 3,
        resolution: 100,
    };

    let r2_peer_config = PeerConfig {
        name: "r1".into(),
        host: r1_addr,
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 3,
        resolution: 100,
    };

    let routers = vec![
        LogicalRouter {
            name: "r1".to_string(),
            asn: Asn::FourOctet(4200000001),
            id: 1,
            listen_addr: r1_addr,
            bind_addr: Some(r1_addr),
            neighbors: vec![NeighborConfig {
                peer_name: "r2".to_string(),
                remote_host: r2_addr,
                session_info: SessionInfo::from_peer_config(&r1_peer_config),
            }],
        },
        LogicalRouter {
            name: "r2".to_string(),
            asn: Asn::FourOctet(4200000002),
            id: 2,
            listen_addr: r2_addr,
            bind_addr: Some(r2_addr),
            neighbors: vec![NeighborConfig {
                peer_name: "r1".to_string(),
                remote_host: r1_addr,
                session_info: SessionInfo::from_peer_config(&r2_peer_config),
            }],
        },
    ];

    let (test_routers, _ip_guard) = test_setup::<
        BgpConnectionTcp,
        BgpListenerTcp,
    >("neighbor_thread_lifecycle", &routers);

    let r1 = &test_routers[0];
    let r2 = &test_routers[1];

    // Stage 1: Wait for establishment
    let r1_session = r1
        .router
        .get_session(r2_addr.ip())
        .expect("Failed to get r1->r2 session");
    let r2_session = r2
        .router
        .get_session(r1_addr.ip())
        .expect("Failed to get r2->r1 session");

    wait_for_eq!(r1_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_session.state(), FsmStateKind::Established);

    let after_establish = mg_common::test::count_threads_with_prefix("bgp-")
        .expect("couldn't collect thread count");
    eprintln!(
        "=== After establishment BGP thread count: {after_establish} (baseline: {baseline}, delta: +{}) ===",
        after_establish - baseline
    );
    let delta = after_establish - baseline;

    // Stage 2: Reset neighbor and wait for re-establishment
    r1_session
        .event_tx
        .send(FsmEvent::Admin(AdminEvent::Reset))
        .expect("reset r1");

    // Wait for it to go through Idle and back to Established
    wait_for_eq!(r1_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_session.state(), FsmStateKind::Established);

    // Wait for thread count to stabilize back to established delta
    wait_for!(
        {
            let after_reset =
                mg_common::test::count_threads_with_prefix("bgp-")
                    .expect("couldn't collect thread count");
            after_reset == baseline + delta
        },
        "Thread count should stabilize after reset+re-establish"
    );

    // Stage 3: Delete the session/neighbor by shutting down routers
    // First drop session references to release channels
    drop(r1_session);
    drop(r2_session);

    r1.shutdown();
    r2.shutdown();

    // Drop the routers to trigger cleanup
    drop(test_routers);

    // Wait for thread count to return to baseline
    wait_for!(
        {
            let after_shutdown =
                mg_common::test::count_threads_with_prefix("bgp-")
                    .expect("couldn't get bgp thread count");
            if after_shutdown != baseline {
                eprintln!(
                    "BGP thread count after shutdown ({after_shutdown} != baseline {baseline})"
                );

                // Dump detailed thread stacks
                match mg_common::test::dump_thread_stacks() {
                    Ok(stacks) => {
                        eprintln!("=== Thread stack traces ===");
                        eprintln!("{stacks}");
                    }
                    Err(e) => {
                        eprintln!("Could not dump thread stacks: {e}");
                    }
                }
            }
            after_shutdown == baseline
        },
        "BGP thread count should return to baseline after delete"
    );
}

/// Test import/export policy filtering.
///
/// This test verifies that:
/// 1. Export policy on the sender filters prefixes before transmission
/// 2. Import policy on the receiver filters prefixes after reception
/// 3. Removing export policy allows filtered prefixes through
/// 4. Removing import policy allows filtered prefixes through
/// 5. Path attributes are correctly preserved through filtering
#[test]
fn test_import_export_policy_filtering() {
    use rdb::ImportExportPolicy4;
    use std::collections::BTreeSet;

    let r1_addr: SocketAddr = sockaddr!(&format!("127.0.0.12:{TEST_BGP_PORT}"));
    let r2_addr: SocketAddr = sockaddr!(&format!("127.0.0.13:{TEST_BGP_PORT}"));

    // Ensure loopback IPs are available for this test
    let _ip_guard = ensure_loop_ips(&[r1_addr.ip(), r2_addr.ip()]);

    // Define our test prefixes
    let prefix_a = ip!("10.1.0.0/24"); // Will pass both export and import
    let prefix_b = ip!("10.2.0.0/24"); // Will be filtered by export, passes import
    let prefix_c = ip!("10.3.0.0/24"); // Will pass export but filtered by import

    // Build export policy for r1: allow prefix_a and prefix_c, deny prefix_b
    let export_allow: BTreeSet<Prefix4> =
        [cidr!("10.1.0.0/24"), cidr!("10.3.0.0/24")]
            .into_iter()
            .collect();

    // Build import policy for r2: allow prefix_a and prefix_b, deny prefix_c
    let import_allow: BTreeSet<Prefix4> =
        [cidr!("10.1.0.0/24"), cidr!("10.2.0.0/24")]
            .into_iter()
            .collect();

    // Configure r1 with export policy
    let r1_peer_config = PeerConfig {
        name: "r2".into(),
        host: r2_addr,
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 3,
        resolution: 100,
    };
    let r1_session_info = {
        let mut info = SessionInfo::from_peer_config(&r1_peer_config);
        if let Some(ref mut cfg) = info.ipv4_unicast {
            cfg.export_policy =
                ImportExportPolicy4::Allow(export_allow.clone());
        }
        info
    };

    // Configure r2 with import policy
    let r2_peer_config = PeerConfig {
        name: "r1".into(),
        host: r1_addr,
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 3,
        resolution: 100,
    };
    let r2_session_info = {
        let mut info = SessionInfo::from_peer_config(&r2_peer_config);
        if let Some(ref mut cfg) = info.ipv4_unicast {
            cfg.import_policy =
                ImportExportPolicy4::Allow(import_allow.clone());
        }
        info
    };

    let routers = vec![
        LogicalRouter {
            name: "r1".to_string(),
            asn: Asn::FourOctet(4200000001),
            id: 1,
            listen_addr: r1_addr,
            bind_addr: Some(r1_addr),
            neighbors: vec![NeighborConfig {
                peer_name: "r2".to_string(),
                remote_host: r2_addr,
                session_info: r1_session_info,
            }],
        },
        LogicalRouter {
            name: "r2".to_string(),
            asn: Asn::FourOctet(4200000002),
            id: 2,
            listen_addr: r2_addr,
            bind_addr: Some(r2_addr),
            neighbors: vec![NeighborConfig {
                peer_name: "r1".to_string(),
                remote_host: r1_addr,
                session_info: r2_session_info,
            }],
        },
    ];

    let (test_routers, _ip_guard2) = test_setup::<
        BgpConnectionTcp,
        BgpListenerTcp,
    >("import_export_policy", &routers);

    let r1 = &test_routers[0];
    let r2 = &test_routers[1];

    // Wait for session establishment
    let r1_session = r1
        .router
        .get_session(r2_addr.ip())
        .expect("get r1->r2 session");
    let r2_session = r2
        .router
        .get_session(r1_addr.ip())
        .expect("get r2->r1 session");
    wait_for_eq!(r1_session.state(), FsmStateKind::Established);
    wait_for_eq!(r2_session.state(), FsmStateKind::Established);

    // Originate all 3 prefixes from r1
    r1.router
        .create_origin4(vec![prefix_a, prefix_b, prefix_c])
        .expect("originate prefixes");

    // Wait for routes to propagate - r2 should only see prefix_a
    // (prefix_b filtered by export, prefix_c filtered by import)
    let prefix_a_rdb = Prefix::V4(cidr!("10.1.0.0/24"));
    let prefix_b_rdb = Prefix::V4(cidr!("10.2.0.0/24"));
    let prefix_c_rdb = Prefix::V4(cidr!("10.3.0.0/24"));

    wait_for!(
        !r2.router.db.get_prefix_paths(&prefix_a_rdb).is_empty(),
        "r2 should receive prefix_a"
    );

    // Verify r2's RIB state with policies active
    // prefix_a: should be present (passes both export and import)
    let paths_a = r2.router.db.get_prefix_paths(&prefix_a_rdb);
    assert_eq!(paths_a.len(), 1, "prefix_a should have exactly one path");
    let path_a = &paths_a[0];
    assert_eq!(path_a.nexthop, r1_addr.ip(), "nexthop should be r1");
    let bgp_props_a = path_a.bgp.as_ref().expect("should have BGP properties");
    assert_eq!(
        bgp_props_a.origin_as, 4200000001,
        "origin AS should be r1's ASN"
    );
    assert_eq!(
        bgp_props_a.as_path,
        vec![4200000001],
        "AS path should contain r1's ASN"
    );

    // prefix_b: should NOT be present (filtered by r1's export policy)
    let paths_b = r2.router.db.get_prefix_paths(&prefix_b_rdb);
    assert!(
        paths_b.is_empty(),
        "prefix_b should be filtered by export policy"
    );

    // prefix_c: should NOT be present (filtered by r2's import policy)
    let paths_c = r2.router.db.get_prefix_paths(&prefix_c_rdb);
    assert!(
        paths_c.is_empty(),
        "prefix_c should be filtered by import policy"
    );

    // Remove r1's export policy - prefix_b should now be sent to r2
    // The ExportPolicy4Changed handler will automatically send the newly-allowed
    // prefix without requiring manual re-origination.
    assert_eq!(
        r1_session.state(),
        FsmStateKind::Established,
        "r1 session should be in Established state before policy update"
    );
    let r1_session_info_no_export = {
        let mut info = SessionInfo::from_peer_config(&r1_peer_config);
        if let Some(ref mut cfg) = info.ipv4_unicast {
            cfg.export_policy = ImportExportPolicy4::NoFiltering;
        }
        info
    };
    r1.router
        .update_session(r1_peer_config.clone(), r1_session_info_no_export)
        .expect("update r1 session to remove export policy");

    // prefix_b should now appear (was filtered by export, now allowed)
    // but prefix_c is still filtered by r2's import policy
    wait_for!(
        !r2.router.db.get_prefix_paths(&prefix_b_rdb).is_empty(),
        "r2 should receive prefix_b after removing export policy"
    );

    // Verify prefix_b arrived with correct attributes
    let paths_b = r2.router.db.get_prefix_paths(&prefix_b_rdb);
    assert_eq!(
        paths_b.len(),
        1,
        "prefix_b should have exactly one path after export policy removal"
    );
    let path_b = &paths_b[0];
    assert_eq!(
        path_b.nexthop,
        r1_addr.ip(),
        "prefix_b nexthop should be r1"
    );
    let bgp_props_b = path_b.bgp.as_ref().expect("should have BGP properties");
    assert_eq!(
        bgp_props_b.origin_as, 4200000001,
        "prefix_b origin AS should be r1's ASN"
    );

    // prefix_c should still be filtered by r2's import policy
    let paths_c = r2.router.db.get_prefix_paths(&prefix_c_rdb);
    assert!(
        paths_c.is_empty(),
        "prefix_c should still be filtered by import policy"
    );

    // Now remove r2's import policy - prefix_c should appear via route-refresh
    let r2_session_info_no_import = {
        let mut info = SessionInfo::from_peer_config(&r2_peer_config);
        if let Some(ref mut cfg) = info.ipv4_unicast {
            cfg.import_policy = ImportExportPolicy4::NoFiltering;
        }
        info
    };
    r2.router
        .update_session(r2_peer_config.clone(), r2_session_info_no_import)
        .expect("update r2 session to remove import policy");

    // Wait for prefix_c to appear after import policy removal
    // The import policy change triggers a route-refresh request to r1
    wait_for!(
        !r2.router.db.get_prefix_paths(&prefix_c_rdb).is_empty(),
        "r2 should receive prefix_c after removing import policy"
    );

    // Final verification: all 3 prefixes present with correct attributes
    for (prefix_name, prefix_rdb) in [
        ("prefix_a", &prefix_a_rdb),
        ("prefix_b", &prefix_b_rdb),
        ("prefix_c", &prefix_c_rdb),
    ] {
        let paths = r2.router.db.get_prefix_paths(prefix_rdb);
        assert_eq!(
            paths.len(),
            1,
            "{prefix_name} should have exactly one path after policy removal"
        );
        let path = &paths[0];
        assert_eq!(
            path.nexthop,
            r1_addr.ip(),
            "{prefix_name} nexthop should be r1"
        );
        let bgp_props = path.bgp.as_ref().expect("should have BGP properties");
        assert_eq!(
            bgp_props.origin_as, 4200000001,
            "{prefix_name} origin AS should be r1's ASN"
        );
        assert_eq!(
            bgp_props.as_path,
            vec![4200000001],
            "{prefix_name} AS path should contain r1's ASN"
        );
    }

    // Clean up
    r1.shutdown();
    r2.shutdown();
}

// IPv6-only tests added via basic_update and basic_peering helpers
// Tests with IPv6 addresses will have IPv6-only config automatically applied

#[test]
fn test_basic_update_ipv6() {
    basic_update_helper::<BgpConnectionChannel, BgpListenerChannel>(
        RouteExchange::Ipv6 { nexthop: None },
        sockaddr!(&format!("[3fff::]:{TEST_BGP_PORT}")),
        sockaddr!(&format!("[3fff::1]:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_basic_update_ipv6_tcp() {
    basic_update_helper::<BgpConnectionTcp, BgpListenerTcp>(
        RouteExchange::Ipv6 { nexthop: None },
        sockaddr!(&format!("[3fff::a]:{TEST_BGP_PORT}")),
        sockaddr!(&format!("[3fff::b]:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_ipv6_basic_peering_passive() {
    basic_peering_helper::<BgpConnectionChannel, BgpListenerChannel>(
        true,
        RouteExchange::Ipv6 { nexthop: None },
        sockaddr!(&format!("[3fff::2]:{TEST_BGP_PORT}")),
        sockaddr!(&format!("[3fff::3]:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_ipv6_basic_peering_active() {
    basic_peering_helper::<BgpConnectionChannel, BgpListenerChannel>(
        false,
        RouteExchange::Ipv6 { nexthop: None },
        sockaddr!(&format!("[3fff::4]:{TEST_BGP_PORT}")),
        sockaddr!(&format!("[3fff::5]:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_ipv6_basic_peering_passive_tcp() {
    basic_peering_helper::<BgpConnectionTcp, BgpListenerTcp>(
        true,
        RouteExchange::Ipv6 { nexthop: None },
        sockaddr!(&format!("[3fff::6]:{TEST_BGP_PORT}")),
        sockaddr!(&format!("[3fff::7]:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_ipv6_basic_peering_active_tcp() {
    basic_peering_helper::<BgpConnectionTcp, BgpListenerTcp>(
        false,
        RouteExchange::Ipv6 { nexthop: None },
        sockaddr!(&format!("[3fff::8]:{TEST_BGP_PORT}")),
        sockaddr!(&format!("[3fff::9]:{TEST_BGP_PORT}")),
    )
}

// =========================================================================
// Cross-Address-Family Nexthop Tests
// =========================================================================
// These tests verify that derive_nexthop() correctly handles configured
// nexthops for cross-AF scenarios (e.g., IPv4 routes over IPv6 connections).

#[test]
fn test_dual_stack_routes_ipv4_peer_success() {
    // IPv4 connection with dual-stack routes
    basic_update_helper::<BgpConnectionTcp, BgpListenerTcp>(
        RouteExchange::DualStack {
            ipv4_nexthop: Some(ip!("10.0.1.1")),
            ipv6_nexthop: Some(ip!("3fff:db8:1::1")),
        },
        sockaddr!(&format!("10.0.1.1:{TEST_BGP_PORT}")),
        sockaddr!(&format!("10.0.1.2:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_dual_stack_routes_ipv6_peer_success() {
    // IPv6 connection with dual-stack routes
    basic_update_helper::<BgpConnectionTcp, BgpListenerTcp>(
        RouteExchange::DualStack {
            ipv4_nexthop: Some(ip!("10.0.2.1")),
            ipv6_nexthop: Some(ip!("3fff:db8:2::1")),
        },
        sockaddr!(&format!("[3fff::f]:{TEST_BGP_PORT}")),
        sockaddr!(&format!("[3fff::10]:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_ipv4_routes_ipv6_peer_success() {
    // IPv6 connection with IPv4-only routes
    basic_update_helper::<BgpConnectionTcp, BgpListenerTcp>(
        RouteExchange::Ipv4 {
            nexthop: Some(ip!("10.0.3.1")),
        },
        sockaddr!(&format!("[3fff::11]:{TEST_BGP_PORT}")),
        sockaddr!(&format!("[3fff::12]:{TEST_BGP_PORT}")),
    )
}

#[test]
fn test_ipv6_routes_ipv4_peer_success() {
    // IPv4 connection with IPv6-only routes
    basic_update_helper::<BgpConnectionTcp, BgpListenerTcp>(
        RouteExchange::Ipv6 {
            nexthop: Some(ip!("3fff:db8:4::1")),
        },
        sockaddr!(&format!("10.0.4.1:{TEST_BGP_PORT}")),
        sockaddr!(&format!("10.0.4.2:{TEST_BGP_PORT}")),
    )
}
