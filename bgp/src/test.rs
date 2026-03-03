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
    router::{EnsureSessionResult, Router},
    session::{
        AdminEvent, ConnectionKind, FsmEvent, FsmStateKind, PeerId,
        SessionEndpoint, SessionInfo, SessionRunner,
    },
    unnumbered::UnnumberedManager,
    unnumbered_mock::UnnumberedManagerMock,
};
use lazy_static::lazy_static;
use mg_common::log::init_file_logger;
use mg_common::test::{IpAllocation, LoopbackIpManager};
use mg_common::*;
use rdb::{Asn, ImportExportPolicy4, ImportExportPolicy6, Prefix, Prefix4};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
        mpsc::channel,
    },
    thread::{Builder, sleep},
    time::{Duration, Instant},
};

// Use non-standard port outside the privileged range to avoid needing privs
const TEST_BGP_PORT: u16 = 10179;

// =============================================================================
// Test timer configuration
// =============================================================================
// All tests use these same BGP timer values. Verification durations are derived
// from these to ensure tests wait long enough without excessive duration.

/// Standard connect_retry timer used by all tests
const TEST_CONNECT_RETRY_SECS: u64 = 1;

/// Standard hold_time used by all tests
const TEST_HOLD_TIME_SECS: u64 = 6;

/// Duration to verify sessions don't establish when they shouldn't.
/// Waits for 3 connect_retry cycles - if FSM was going to incorrectly
/// attempt a connection, it would have done so by now.
const CONNECT_RETRY_VERIFICATION: Duration =
    Duration::from_secs(TEST_CONNECT_RETRY_SECS * 3);

/// Duration to verify established sessions stay established.
/// Waits slightly longer than hold_time to ensure keepalives are being
/// exchanged properly and the session doesn't timeout.
const ESTABLISHED_VERIFICATION: Duration =
    Duration::from_secs(TEST_HOLD_TIME_SECS + 2);

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

        // Extract test name from thread name for per-test log files.
        // With cargo nextest, each test runs in its own process, so this
        // will be unique per test process.
        let thread_name = std::thread::current();
        let test_name = thread_name
            .name()
            .and_then(|name| name.split("::").last())
            .unwrap_or("unknown");
        let log_filename = format!("loopback-manager.{}.log", test_name);

        let log = init_file_logger(&log_filename);

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
        Builder::new()
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

    // Extract the actual test function name from the thread name.
    // The Rust test harness names threads like "test::test_function_name".
    // This ensures each test function gets its own database, even if helpers
    // are called with identical parameters by different tests.
    let thread_name = std::thread::current();
    let actual_test_name = thread_name
        .name()
        .and_then(|name| name.split("::").last())
        .map(|s| s.to_string())
        .unwrap_or_else(|| test_name.to_string());

    // Create all routers first
    for logical_router in routers.iter() {
        let log = init_file_logger(&format!(
            "{}.{actual_test_name}.log",
            logical_router.name
        ));

        // Create database with unique path per test function
        let db_path =
            format!("/tmp/{}.{actual_test_name}.db", logical_router.name);
        let _ = std::fs::remove_dir_all(&db_path);
        let db = rdb::Db::new(&db_path, log.clone()).expect("create db");

        // Create dispatcher
        // Phase 4: Use PeerId instead of IpAddr
        let peer_to_session: Arc<
            Mutex<BTreeMap<PeerId, SessionEndpoint<Cnx>>>,
        > = Arc::new(Mutex::new(BTreeMap::new()));
        let dispatcher = Arc::new(Dispatcher::new(
            peer_to_session.clone(),
            logical_router.listen_addr.to_string(),
            log.clone(),
            None, // No unnumbered manager for tests
        ));

        // Create router
        let router = Arc::new(Router::new(
            RouterConfig {
                asn: logical_router.asn,
                id: logical_router.id,
            },
            log.clone(),
            db.clone(),
            peer_to_session.clone(),
        ));

        // Start router and dispatcher
        router.run();
        let d = dispatcher.clone();
        let listen_addr = dispatcher.listen_addr().to_string();
        let listen_addr_for_log = listen_addr.clone();
        eprintln!("Spawning Dispatcher thread for {}", listen_addr);
        Builder::new()
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
                group: String::new(),
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
        RouteExchange::Ipv4 {
            nexthop: initial_nexthop,
        } => {
            // IPv4-only: originate and verify IPv4 prefix
            r1.router
                .create_origin4(vec![cidr!("1.2.3.0/24")])
                .expect("originate IPv4");

            let prefix_rdb = Prefix::V4(cidr!("1.2.3.0/24"));
            wait_for!(!r2.router.db.get_prefix_paths(&prefix_rdb).is_empty());

            // Verify initial nexthop if one was configured and test override change
            let paths = r2.router.db.get_prefix_paths(&prefix_rdb);
            assert_eq!(paths.len(), 1);
            if let Some(initial_nh) = initial_nexthop {
                assert_eq!(paths[0].nexthop, initial_nh);

                // Test nexthop override change
                let new_nexthop = match initial_nh {
                    IpAddr::V4(_) => ip!("10.255.255.254"),
                    IpAddr::V6(_) => unreachable!(),
                };

                let peer_config = PeerConfig {
                    name: "r2".into(),
                    group: String::new(),
                    host: r2_addr,
                    hold_time: 6,
                    idle_hold_time: 0,
                    delay_open: 0,
                    connect_retry: 1,
                    keepalive: 3,
                    resolution: 100,
                };
                let mut session_info = create_test_session_info(
                    route_exchange,
                    r1_addr,
                    r2_addr,
                    false,
                );
                session_info.ipv4_unicast.as_mut().unwrap().nexthop =
                    Some(new_nexthop);

                r1.router
                    .update_session(peer_config, session_info)
                    .expect("update nexthop");

                // Verify nexthop change is reflected in re-advertised route
                wait_for!(
                    {
                        let paths = r2.router.db.get_prefix_paths(&prefix_rdb);
                        !paths.is_empty() && paths[0].nexthop == new_nexthop
                    },
                    "nexthop should be updated"
                );
            }

            // Shut down r1 and verify withdrawal
            r1.shutdown();
            wait_for_neq!(r1_session.state(), FsmStateKind::Established);
            wait_for_neq!(r2_session.state(), FsmStateKind::Established);
            wait_for!(r2.router.db.get_prefix_paths(&prefix_rdb).is_empty());
        }
        RouteExchange::Ipv6 {
            nexthop: initial_nexthop,
        } => {
            // IPv6-only: originate and verify IPv6 prefix
            r1.router
                .create_origin6(vec![cidr!("3fff:db8::/32")])
                .expect("originate IPv6");

            let prefix_rdb = Prefix::V6(cidr!("3fff:db8::/32"));
            wait_for!(!r2.router.db.get_prefix_paths(&prefix_rdb).is_empty());

            // Verify initial nexthop if one was configured and test override change
            let paths = r2.router.db.get_prefix_paths(&prefix_rdb);
            assert_eq!(paths.len(), 1);
            if let Some(initial_nh) = initial_nexthop {
                assert_eq!(paths[0].nexthop, initial_nh);

                // Test nexthop override change
                let new_nexthop = match initial_nh {
                    IpAddr::V6(_) => ip!("3fff:ffff:ffff:ffff::ffff:fffe"),
                    IpAddr::V4(_) => unreachable!(),
                };

                let peer_config = PeerConfig {
                    name: "r2".into(),
                    group: String::new(),
                    host: r2_addr,
                    hold_time: 6,
                    idle_hold_time: 0,
                    delay_open: 0,
                    connect_retry: 1,
                    keepalive: 3,
                    resolution: 100,
                };
                let mut session_info = create_test_session_info(
                    route_exchange,
                    r1_addr,
                    r2_addr,
                    false,
                );
                session_info.ipv6_unicast.as_mut().unwrap().nexthop =
                    Some(new_nexthop);

                r1.router
                    .update_session(peer_config, session_info)
                    .expect("update nexthop");

                // Verify nexthop change is reflected in re-advertised route
                wait_for!(
                    {
                        let paths = r2.router.db.get_prefix_paths(&prefix_rdb);
                        !paths.is_empty() && paths[0].nexthop == new_nexthop
                    },
                    "nexthop should be updated"
                );
            }

            // Shut down r1 and verify withdrawal
            r1.shutdown();
            wait_for_neq!(r1_session.state(), FsmStateKind::Established);
            wait_for_neq!(r2_session.state(), FsmStateKind::Established);
            wait_for!(r2.router.db.get_prefix_paths(&prefix_rdb).is_empty());
        }
        RouteExchange::DualStack {
            ipv4_nexthop,
            ipv6_nexthop,
        } => {
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

            // Verify initial nexthops if configured
            let paths4 = r2.router.db.get_prefix_paths(&prefix4_rdb);
            assert_eq!(paths4.len(), 1);
            if let Some(expected_nexthop) = ipv4_nexthop {
                assert_eq!(paths4[0].nexthop, expected_nexthop);
            }

            let paths6 = r2.router.db.get_prefix_paths(&prefix6_rdb);
            assert_eq!(paths6.len(), 1);
            if let Some(expected_nexthop) = ipv6_nexthop {
                assert_eq!(paths6[0].nexthop, expected_nexthop);
            }

            // Test nexthop override changes if any were configured
            if ipv4_nexthop.is_some() || ipv6_nexthop.is_some() {
                let new_ipv4_nexthop =
                    ipv4_nexthop.map(|_| ip!("10.255.255.254"));
                let new_ipv6_nexthop =
                    ipv6_nexthop.map(|_| ip!("3fff:ffff:ffff:ffff::ffff:fffe"));

                let peer_config = PeerConfig {
                    name: "r2".into(),
                    group: String::new(),
                    host: r2_addr,
                    hold_time: 6,
                    idle_hold_time: 0,
                    delay_open: 0,
                    connect_retry: 1,
                    keepalive: 3,
                    resolution: 100,
                };
                let mut session_info = create_test_session_info(
                    route_exchange,
                    r1_addr,
                    r2_addr,
                    false,
                );
                if let Some(nexthop) = new_ipv4_nexthop {
                    session_info.ipv4_unicast.as_mut().unwrap().nexthop =
                        Some(nexthop);
                }
                if let Some(nexthop) = new_ipv6_nexthop {
                    session_info.ipv6_unicast.as_mut().unwrap().nexthop =
                        Some(nexthop);
                }

                r1.router
                    .update_session(peer_config, session_info)
                    .expect("update nexthop");

                // Verify IPv4 nexthop change if applicable
                if let Some(new_nh) = new_ipv4_nexthop {
                    wait_for!(
                        {
                            let paths =
                                r2.router.db.get_prefix_paths(&prefix4_rdb);
                            !paths.is_empty() && paths[0].nexthop == new_nh
                        },
                        "IPv4 nexthop should be updated"
                    );
                }

                // Verify IPv6 nexthop change if applicable
                if let Some(new_nh) = new_ipv6_nexthop {
                    wait_for!(
                        {
                            let paths =
                                r2.router.db.get_prefix_paths(&prefix6_rdb);
                            !paths.is_empty() && paths[0].nexthop == new_nh
                        },
                        "IPv6 nexthop should be updated"
                    );
                }
            }

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
                    group: String::new(),
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
                        group: String::new(),
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
                        group: String::new(),
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
                    group: String::new(),
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
// ports, the `peer_to_session` data structure is keyed by IP address not
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
        group: String::new(),
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
        group: String::new(),
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
        group: String::new(),
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
        group: String::new(),
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

/// Helper to set up two routers with unnumbered BGP sessions.
///
/// This creates a realistic unnumbered BGP setup where:
/// - Router 1 and Router 2 each have one or more interfaces
/// - Each interface has a corresponding unnumbered BGP session
/// - NDP mock managers simulate neighbor discovery
/// - Sessions can actually establish and reach Established state
///
/// Returns: (Router1, Mock1, Sessions1, Router2, Mock2, Sessions2)
#[allow(clippy::type_complexity)]
fn unnumbered_peering_helper(
    test_name: &str,
    interfaces: Vec<(String, u32)>, // (interface_name, scope_id)
    route_exchange: RouteExchange,
) -> (
    Arc<Router<BgpConnectionChannel>>,
    Arc<UnnumberedManagerMock>,
    Vec<Arc<SessionRunner<BgpConnectionChannel>>>,
    Arc<Router<BgpConnectionChannel>>,
    Arc<UnnumberedManagerMock>,
    Vec<Arc<SessionRunner<BgpConnectionChannel>>>,
) {
    let log = init_file_logger(&format!("{}.log", test_name));

    // Create databases
    let db1 = rdb::test::get_test_db(&format!("{}_r1", test_name), log.clone())
        .expect("create db1");
    let db2 = rdb::test::get_test_db(&format!("{}_r2", test_name), log.clone())
        .expect("create db2");

    // Create mock NDP managers
    let mock_ndp1 = UnnumberedManagerMock::new();
    let mock_ndp2 = UnnumberedManagerMock::new();

    // Register all interfaces in both mocks
    for (iface, scope_id) in &interfaces {
        mock_ndp1.register_interface(iface.clone(), *scope_id);
        mock_ndp2.register_interface(iface.clone(), *scope_id);
    }

    // Create session maps
    let p2s1: Arc<
        Mutex<BTreeMap<PeerId, SessionEndpoint<BgpConnectionChannel>>>,
    > = Arc::new(Mutex::new(BTreeMap::new()));
    let p2s2: Arc<
        Mutex<BTreeMap<PeerId, SessionEndpoint<BgpConnectionChannel>>>,
    > = Arc::new(Mutex::new(BTreeMap::new()));

    // Create one Dispatcher per interface for each router.
    // Each Dispatcher binds to a unique link-local address with its interface's scope_id,
    // and runs its own accept loop thread. All Dispatchers share the same peer_to_session map.
    let mut dispatchers1 = Vec::new();
    let mut dispatchers2 = Vec::new();

    for (iface, scope_id) in &interfaces {
        // Router 1 dispatcher for this interface
        let r1_addr = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            TEST_BGP_PORT,
            0,
            *scope_id,
        ));
        let disp1 = Arc::new(Dispatcher::new(
            p2s1.clone(),
            r1_addr.to_string(),
            log.clone(),
            Some(mock_ndp1.clone()),
        ));

        let d1 = disp1.clone();
        let iface_name = iface.clone();
        Builder::new()
            .name(format!("bgp-listener-r1-{}", iface_name))
            .spawn(move || {
                d1.run::<BgpListenerChannel>();
            })
            .expect("spawn dispatcher1");

        dispatchers1.push(disp1);

        // Router 2 dispatcher for this interface
        let r2_addr = SocketAddr::V6(SocketAddrV6::new(
            "fe80::2".parse().unwrap(),
            TEST_BGP_PORT,
            0,
            *scope_id,
        ));
        let disp2 = Arc::new(Dispatcher::new(
            p2s2.clone(),
            r2_addr.to_string(),
            log.clone(),
            Some(mock_ndp2.clone()),
        ));

        let d2 = disp2.clone();
        let iface_name = iface.clone();
        Builder::new()
            .name(format!("bgp-listener-r2-{}", iface_name))
            .spawn(move || {
                d2.run::<BgpListenerChannel>();
            })
            .expect("spawn dispatcher2");

        dispatchers2.push(disp2);
    }

    // Create routers
    let router1 = Arc::new(Router::new(
        RouterConfig {
            asn: Asn::FourOctet(64512),
            id: 1,
        },
        log.clone(),
        db1.db().clone(),
        p2s1.clone(),
    ));
    let router2 = Arc::new(Router::new(
        RouterConfig {
            asn: Asn::FourOctet(64513),
            id: 2,
        },
        log.clone(),
        db2.db().clone(),
        p2s2.clone(),
    ));

    router1.run();
    router2.run();

    // Create sessions for each interface
    let mut sessions1 = Vec::new();
    let mut sessions2 = Vec::new();

    for (iface, scope_id) in &interfaces {
        // Router 1 session
        let (event_tx1, event_rx1) = channel();
        let bind_addr1 = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            TEST_BGP_PORT,
            0,
            *scope_id,
        ));
        let session_info1 = create_test_session_info(
            route_exchange,
            bind_addr1,
            SocketAddr::V6(SocketAddrV6::new(
                "fe80::2".parse().unwrap(),
                TEST_BGP_PORT,
                0,
                *scope_id,
            )),
            false,
        );

        let peer_config1 = PeerConfig {
            name: format!("peer_{}", iface),
            group: String::new(),
            host: sockaddr!(&format!("[fe80::2]:{TEST_BGP_PORT}")),
            hold_time: 6,
            idle_hold_time: 0,
            delay_open: 0,
            connect_retry: 1,
            keepalive: 3,
            resolution: 100,
        };

        let result1 = router1
            .ensure_unnumbered_session(
                iface.clone(),
                peer_config1,
                Some(bind_addr1),
                event_tx1.clone(),
                event_rx1,
                session_info1,
                mock_ndp1.clone(),
            )
            .expect("create session1");

        let session1 = match result1 {
            EnsureSessionResult::New(s) => s,
            EnsureSessionResult::Updated(s) => s,
        };

        sessions1.push(session1);

        // Router 2 session
        let (event_tx2, event_rx2) = channel();
        let bind_addr2 = SocketAddr::V6(SocketAddrV6::new(
            "fe80::2".parse().unwrap(),
            TEST_BGP_PORT,
            0,
            *scope_id,
        ));
        let session_info2 = create_test_session_info(
            route_exchange,
            bind_addr2,
            SocketAddr::V6(SocketAddrV6::new(
                "fe80::1".parse().unwrap(),
                TEST_BGP_PORT,
                0,
                *scope_id,
            )),
            false,
        );

        let peer_config2 = PeerConfig {
            name: format!("peer_{}", iface),
            group: String::new(),
            host: sockaddr!(&format!("[fe80::1]:{TEST_BGP_PORT}")),
            hold_time: 6,
            idle_hold_time: 0,
            delay_open: 0,
            connect_retry: 1,
            keepalive: 3,
            resolution: 100,
        };

        let result2 = router2
            .ensure_unnumbered_session(
                iface.clone(),
                peer_config2,
                Some(bind_addr2),
                event_tx2.clone(),
                event_rx2,
                session_info2,
                mock_ndp2.clone(),
            )
            .expect("create session2");

        let session2 = match result2 {
            EnsureSessionResult::New(s) => s,
            EnsureSessionResult::Updated(s) => s,
        };

        sessions2.push(session2);

        // Discover peers via NDP BEFORE starting sessions
        let peer1_addr: Ipv6Addr = "fe80::1".parse().unwrap();
        let peer2_addr: Ipv6Addr = "fe80::2".parse().unwrap();

        mock_ndp1.discover_peer(iface, peer2_addr).unwrap();
        mock_ndp2.discover_peer(iface, peer1_addr).unwrap();

        // NOW start the sessions after NDP discovery
        event_tx1
            .send(FsmEvent::Admin(AdminEvent::ManualStart))
            .expect("start session1");

        event_tx2
            .send(FsmEvent::Admin(AdminEvent::ManualStart))
            .expect("start session2");
    }

    (router1, mock_ndp1, sessions1, router2, mock_ndp2, sessions2)
}

/// Test: Session survives NDP neighbor changes and reconnects via new neighbor after reset.
///
/// Expected behavior:
/// - Two routers establish BGP session via unnumbered interface
/// - Session reaches Established
/// - Router 1's NDP updates to point to a different peer address
/// - Session STAYS Established (NDP change doesn't affect FSM)
/// - After AdminEvent::Reset, session reconnects using new NDP neighbor
#[test]
fn test_unnumbered_session_survives_peer_change() {
    let (router1, mock_ndp1, sessions1, router2, _mock_ndp2, sessions2) =
        unnumbered_peering_helper(
            "unnumbered_peer_change",
            vec![("eth0".to_string(), 2)],
            RouteExchange::Ipv4 { nexthop: None },
        );

    let session1 = &sessions1[0];
    let session2 = &sessions2[0];

    // Debug: check what's happening
    sleep(Duration::from_secs(5));
    eprintln!("Session1 state: {:?}", session1.state());
    eprintln!("Session2 state: {:?}", session2.state());
    eprintln!("Session1 peer addr: {:?}", session1.get_peer_socket_addr());
    eprintln!("Session2 peer addr: {:?}", session2.get_peer_socket_addr());
    eprintln!("Session1 is_unnumbered: {}", session1.is_unnumbered());
    eprintln!("Session2 is_unnumbered: {}", session2.is_unnumbered());

    // Wait for both sessions to reach Established
    wait_for_eq!(session1.state(), FsmStateKind::Established);
    wait_for_eq!(session2.state(), FsmStateKind::Established);

    // Verify initial peer addresses
    let peer2_addr = SocketAddr::V6(SocketAddrV6::new(
        "fe80::2".parse().unwrap(),
        TEST_BGP_PORT,
        0,
        2,
    ));
    assert_eq!(session1.get_peer_socket_addr(), Some(peer2_addr));

    // Simulate cable swap: Router 1's interface now sees a different peer
    let new_peer_ip: Ipv6Addr = "fe80::99".parse().unwrap();
    mock_ndp1.discover_peer("eth0", new_peer_ip).unwrap();

    // Router 1's query now returns the new peer
    let new_peer_addr =
        SocketAddr::V6(SocketAddrV6::new(new_peer_ip, TEST_BGP_PORT, 0, 2));
    wait_for!(session1.get_peer_socket_addr() == Some(new_peer_addr));

    // CRITICAL: Session must stay Established (NDP change doesn't affect FSM)
    assert_eq!(
        session1.state(),
        FsmStateKind::Established,
        "Session must stay Established when NDP neighbor changes"
    );
    assert_eq!(
        session2.state(),
        FsmStateKind::Established,
        "Remote session should also stay Established"
    );

    // Manually reset session1
    session1
        .event_tx
        .send(FsmEvent::Admin(AdminEvent::Reset))
        .expect("send reset");

    // Session should re-establish
    wait_for_eq!(session1.state(), FsmStateKind::Established);

    // After reset, session1 still queries the new peer address
    assert_eq!(session1.get_peer_socket_addr(), Some(new_peer_addr));

    // Clean up
    router1.shutdown();
    router2.shutdown();
}

/// Test: Session handles peer expiry and rediscovery.
///
/// Expected behavior:
/// - Session established between two routers
/// - Router 1's NDP peer expires (no neighbor)
/// - Session STAYS Established (NDP expiry doesn't trigger FSM transitions)
/// - Peer rediscovered
/// - Session remains Established throughout
#[test]
fn test_unnumbered_peer_expiry_and_rediscovery() {
    let (router1, mock_ndp1, sessions1, router2, _mock_ndp2, sessions2) =
        unnumbered_peering_helper(
            "unnumbered_expiry",
            vec![("eth0".to_string(), 2)],
            RouteExchange::Ipv4 { nexthop: None },
        );

    let session1 = &sessions1[0];
    let session2 = &sessions2[0];

    // Wait for both sessions to reach Established
    wait_for_eq!(session1.state(), FsmStateKind::Established);
    wait_for_eq!(session2.state(), FsmStateKind::Established);

    // Expire Router 1's NDP neighbor
    mock_ndp1.expire_peer("eth0").unwrap();

    // Router 1's query now returns None
    wait_for!(session1.get_peer_socket_addr().is_none());

    // CRITICAL: Session must STAY Established despite NDP expiry
    // Verify for longer than hold_time to ensure keepalives are exchanged
    let start = Instant::now();
    while start.elapsed() < ESTABLISHED_VERIFICATION {
        assert_eq!(
            session1.state(),
            FsmStateKind::Established,
            "Session must stay Established despite NDP peer expiry"
        );
        assert_eq!(
            session2.state(),
            FsmStateKind::Established,
            "Remote session should also stay Established"
        );
        sleep(Duration::from_millis(100));
    }

    // Rediscover peer
    let peer2_ip: Ipv6Addr = "fe80::2".parse().unwrap();
    mock_ndp1.discover_peer("eth0", peer2_ip).unwrap();

    // Router 1's query returns the peer again
    let peer2_addr =
        SocketAddr::V6(SocketAddrV6::new(peer2_ip, TEST_BGP_PORT, 0, 2));
    wait_for!(session1.get_peer_socket_addr() == Some(peer2_addr));

    // Sessions should still be Established
    assert_eq!(session1.state(), FsmStateKind::Established);
    assert_eq!(session2.state(), FsmStateKind::Established);

    // Clean up
    router1.shutdown();
    router2.shutdown();
}

/// Test: Multiple unnumbered sessions on different interfaces work independently.
///
/// Expected behavior:
/// - Two routers with two unnumbered sessions each (eth0 and eth1)
/// - All sessions establish independently
/// - NDP changes on eth0 don't affect eth1
/// - Both sessions stay Established when eth0's NDP changes
#[test]
fn test_multiple_unnumbered_sessions() {
    let (router1, mock_ndp1, sessions1, router2, _mock_ndp2, sessions2) =
        unnumbered_peering_helper(
            "multiple_unnumbered",
            vec![("eth0".to_string(), 2), ("eth1".to_string(), 3)],
            RouteExchange::Ipv4 { nexthop: None },
        );

    let session1_eth0 = &sessions1[0];
    let session1_eth1 = &sessions1[1];
    let session2_eth0 = &sessions2[0];
    let session2_eth1 = &sessions2[1];

    // Wait for all sessions to reach Established
    wait_for_eq!(session1_eth0.state(), FsmStateKind::Established);
    wait_for_eq!(session1_eth1.state(), FsmStateKind::Established);
    wait_for_eq!(session2_eth0.state(), FsmStateKind::Established);
    wait_for_eq!(session2_eth1.state(), FsmStateKind::Established);

    // Change Router 1's eth0 NDP neighbor
    let new_peer_ip: Ipv6Addr = "fe80::99".parse().unwrap();
    mock_ndp1.discover_peer("eth0", new_peer_ip).unwrap();
    let new_peer =
        SocketAddr::V6(SocketAddrV6::new(new_peer_ip, TEST_BGP_PORT, 0, 2));
    wait_for!(session1_eth0.get_peer_socket_addr() == Some(new_peer));

    // CRITICAL: All sessions must stay Established
    assert_eq!(
        session1_eth0.state(),
        FsmStateKind::Established,
        "eth0 session must stay Established when NDP changes"
    );
    assert_eq!(
        session1_eth1.state(),
        FsmStateKind::Established,
        "eth1 session must stay Established (unaffected by eth0 NDP change)"
    );
    assert_eq!(
        session2_eth0.state(),
        FsmStateKind::Established,
        "Remote eth0 session should stay Established"
    );
    assert_eq!(
        session2_eth1.state(),
        FsmStateKind::Established,
        "Remote eth1 session should stay Established"
    );

    // Verify eth1 peer address unchanged
    let peer2_eth1 = SocketAddr::V6(SocketAddrV6::new(
        "fe80::2".parse().unwrap(),
        TEST_BGP_PORT,
        0,
        3,
    ));
    assert_eq!(
        session1_eth1.get_peer_socket_addr(),
        Some(peer2_eth1),
        "eth1 peer should be unchanged"
    );

    // Clean up
    router1.shutdown();
    router2.shutdown();
}

/// Test: Same link-local address on multiple interfaces.
///
/// Topology:
/// ```text
///         eth0 (scope 2)                    eth0 (scope 2)
///        ┌─────────────┐                   ┌─────────────┐
///        │  fe80::1%2  │◄─────────────────►│  fe80::2%2  │
///        │             │      link 0       │             │
///        │   Router1   │                   │   Router2   │
///        │             │      link 1       │             │
///        │  fe80::1%3  │◄─────────────────►│  fe80::2%3  │
///        └─────────────┘                   └─────────────┘
///         eth1 (scope 3)                    eth1 (scope 3)
/// ```
///
/// NDP discovery (what each router sees as its peer):
/// ```text
/// R1's view:  eth0 -> fe80::2%2,  eth1 -> fe80::2%3  (both point to R2)
/// R2's view:  eth0 -> fe80::1%2,  eth1 -> fe80::1%3  (both point to R1)
/// ```
///
/// Expected behavior:
/// - Two routers, each with two interfaces (eth0 and eth1)
/// - Both interfaces discover the same peer link-local (fe80::2 from R1's view)
/// - scope_id differentiates the interfaces (2 for eth0, 3 for eth1)
/// - Both sessions establish independently
/// - NDP changes on one interface don't affect the other
///
/// This tests that when NDP discovers the same IP on multiple interfaces,
/// each interface's scope_id correctly identifies which physical link to use.
#[test]
fn test_same_linklocal_multiple_interfaces() {
    let (router1, mock_ndp1, sessions1, router2, _mock_ndp2, sessions2) =
        unnumbered_peering_helper(
            "same_linklocal",
            vec![("eth0".to_string(), 2), ("eth1".to_string(), 3)],
            RouteExchange::Ipv4 { nexthop: None },
        );

    // The helper already discovers fe80::2 on both interfaces of mock_ndp1.
    // The point of this test is to verify that the same peer IP (fe80::2) on
    // multiple interfaces is correctly differentiated by scope_id.
    let peer_ip: Ipv6Addr = "fe80::2".parse().unwrap();

    // Expected SocketAddrs - same IP but different scope_id per interface
    let peer_eth0 = SocketAddr::V6(SocketAddrV6::new(
        peer_ip,
        TEST_BGP_PORT,
        0,
        2, // scope_id 2 for eth0
    ));
    let peer_eth1 = SocketAddr::V6(SocketAddrV6::new(
        peer_ip, // SAME IP as eth0
        TEST_BGP_PORT,
        0,
        3, // scope_id 3 for eth1
    ));

    let session1_eth0 = &sessions1[0];
    let session1_eth1 = &sessions1[1];
    let session2_eth0 = &sessions2[0];
    let session2_eth1 = &sessions2[1];

    // Wait for all sessions to reach Established
    wait_for_eq!(session1_eth0.state(), FsmStateKind::Established);
    wait_for_eq!(session1_eth1.state(), FsmStateKind::Established);
    wait_for_eq!(session2_eth0.state(), FsmStateKind::Established);
    wait_for_eq!(session2_eth1.state(), FsmStateKind::Established);

    // Verify both sessions see the same IP but different scope_id
    // This is the core of the test: same peer IP (fe80::2) is correctly
    // distinguished by scope_id (2 for eth0, 3 for eth1)
    assert_eq!(session1_eth0.get_peer_socket_addr(), Some(peer_eth0));
    assert_eq!(session1_eth1.get_peer_socket_addr(), Some(peer_eth1));

    // Verify they're truly independent: change eth0's peer
    let new_peer_ip: Ipv6Addr = "fe80::99".parse().unwrap();
    mock_ndp1.discover_peer("eth0", new_peer_ip).unwrap();
    let new_peer_eth0 =
        SocketAddr::V6(SocketAddrV6::new(new_peer_ip, TEST_BGP_PORT, 0, 2));
    wait_for!(session1_eth0.get_peer_socket_addr() == Some(new_peer_eth0));

    // eth1 should still see fe80::2 with scope 3
    assert_eq!(
        session1_eth1.get_peer_socket_addr(),
        Some(peer_eth1),
        "eth1 should still see fe80::2 with its own scope_id"
    );

    // CRITICAL: All sessions must stay Established
    assert_eq!(session1_eth0.state(), FsmStateKind::Established);
    assert_eq!(session1_eth1.state(), FsmStateKind::Established);
    assert_eq!(session2_eth0.state(), FsmStateKind::Established);
    assert_eq!(session2_eth1.state(), FsmStateKind::Established);

    // Clean up
    router1.shutdown();
    router2.shutdown();
}

// =========================================================================
// Unnumbered BGP Test Infrastructure
// =========================================================================

/// Global scope_id counter for allocating unique scope IDs in tests.
static SCOPE_ID_COUNTER: AtomicU32 = AtomicU32::new(100);

/// Allocate a new unique scope_id for test topologies.
fn next_scope_id() -> u32 {
    SCOPE_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Handle to an unnumbered router instance in a test topology.
struct UnnumberedRouterHandle {
    router: Arc<Router<BgpConnectionChannel>>,
    dispatchers: Vec<Arc<Dispatcher<BgpConnectionChannel>>>,
    mock_ndp: Arc<UnnumberedManagerMock>,
    sessions: Vec<Arc<SessionRunner<BgpConnectionChannel>>>,
    _db_guard: rdb::test::TestDb,
}

impl UnnumberedRouterHandle {
    fn shutdown(&self) {
        self.router.shutdown();
        for dispatcher in &self.dispatchers {
            dispatcher.shutdown();
        }
    }
}

/// Test topology containing multiple unnumbered routers.
struct UnnumberedTopology {
    routers: Vec<UnnumberedRouterHandle>,
}

impl Drop for UnnumberedTopology {
    fn drop(&mut self) {
        for router in &self.routers {
            router.shutdown();
        }
    }
}

/// Create SessionInfo for unnumbered BGP sessions.
///
/// Forces nexthops to None so that BGP automatically uses the local link-local address.
fn create_unnumbered_session_info(
    route_exchange: RouteExchange,
    passive: bool,
) -> SessionInfo {
    let (ipv4_unicast, ipv6_unicast) = match route_exchange {
        RouteExchange::Ipv4 { .. } => {
            let ipv4_cfg = Ipv4UnicastConfig {
                nexthop: None, // Let BGP use local link-local address
                import_policy: ImportExportPolicy4::default(),
                export_policy: ImportExportPolicy4::default(),
            };
            (Some(ipv4_cfg), None)
        }
        RouteExchange::Ipv6 { .. } => {
            let ipv6_cfg = Ipv6UnicastConfig {
                nexthop: None, // Let BGP use local link-local address
                import_policy: ImportExportPolicy6::NoFiltering,
                export_policy: ImportExportPolicy6::NoFiltering,
            };
            (None, Some(ipv6_cfg))
        }
        RouteExchange::DualStack { .. } => {
            let ipv4_cfg = Ipv4UnicastConfig {
                nexthop: None, // Let BGP use local link-local address
                import_policy: ImportExportPolicy4::default(),
                export_policy: ImportExportPolicy4::default(),
            };
            let ipv6_cfg = Ipv6UnicastConfig {
                nexthop: None, // Let BGP use local link-local address
                import_policy: ImportExportPolicy6::NoFiltering,
                export_policy: ImportExportPolicy6::NoFiltering,
            };
            (Some(ipv4_cfg), Some(ipv6_cfg))
        }
    };

    SessionInfo {
        passive_tcp_establishment: passive,
        remote_asn: None,
        remote_id: None,
        bind_addr: None, // Unnumbered sessions don't use bind_addr
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
        idle_hold_jitter: None,
        deterministic_collision_resolution: false,
    }
}

/// Create a pair of routers with unnumbered BGP sessions.
///
/// # Arguments
/// * `test_name` - Name of the test (used for log files and database paths)
/// * `interface_name` - Interface name for the unnumbered session
/// * `scope_id` - Scope ID for the link-local addresses
/// * `route_exchange` - Route exchange configuration
///
/// # Returns
/// Topology with two routers and established unnumbered sessions.
fn unnumbered_pair(
    test_name: &str,
    interface_name: &str,
    scope_id: u32,
    route_exchange: RouteExchange,
) -> UnnumberedTopology {
    let log = init_file_logger(&format!("{}.log", test_name));

    // Create databases with unique paths
    let db1 = rdb::test::get_test_db(&format!("{}_r1", test_name), log.clone())
        .expect("create db1");
    let db2 = rdb::test::get_test_db(&format!("{}_r2", test_name), log.clone())
        .expect("create db2");

    // Create mock NDP managers
    let mock_ndp1 = UnnumberedManagerMock::new();
    let mock_ndp2 = UnnumberedManagerMock::new();

    // Register interface in both mocks
    mock_ndp1.register_interface(interface_name.to_string(), scope_id);
    mock_ndp2.register_interface(interface_name.to_string(), scope_id);

    // Allocate link-local addresses with scope_id
    let r1_ip: Ipv6Addr = "fe80::1".parse().unwrap();
    let r2_ip: Ipv6Addr = "fe80::2".parse().unwrap();
    let r1_addr =
        SocketAddr::V6(SocketAddrV6::new(r1_ip, TEST_BGP_PORT, 0, scope_id));
    let r2_addr =
        SocketAddr::V6(SocketAddrV6::new(r2_ip, TEST_BGP_PORT, 0, scope_id));

    // Create session maps
    let p2s1: Arc<
        Mutex<BTreeMap<PeerId, SessionEndpoint<BgpConnectionChannel>>>,
    > = Arc::new(Mutex::new(BTreeMap::new()));
    let p2s2: Arc<
        Mutex<BTreeMap<PeerId, SessionEndpoint<BgpConnectionChannel>>>,
    > = Arc::new(Mutex::new(BTreeMap::new()));

    // Create dispatchers
    let dispatcher1 = Arc::new(Dispatcher::new(
        p2s1.clone(),
        r1_addr.to_string(),
        log.clone(),
        Some(mock_ndp1.clone()),
    ));
    let dispatcher2 = Arc::new(Dispatcher::new(
        p2s2.clone(),
        r2_addr.to_string(),
        log.clone(),
        Some(mock_ndp2.clone()),
    ));

    // Start dispatchers in background threads
    let d1 = dispatcher1.clone();
    Builder::new()
        .name(format!("bgp-listener-{}-r1", test_name))
        .spawn(move || {
            d1.run::<BgpListenerChannel>();
        })
        .expect("spawn dispatcher1");

    let d2 = dispatcher2.clone();
    Builder::new()
        .name(format!("bgp-listener-{}-r2", test_name))
        .spawn(move || {
            d2.run::<BgpListenerChannel>();
        })
        .expect("spawn dispatcher2");

    // Create routers
    let router1 = Arc::new(Router::new(
        RouterConfig {
            asn: Asn::FourOctet(64512),
            id: 1,
        },
        log.clone(),
        db1.db().clone(),
        p2s1.clone(),
    ));
    let router2 = Arc::new(Router::new(
        RouterConfig {
            asn: Asn::FourOctet(64513),
            id: 2,
        },
        log.clone(),
        db2.db().clone(),
        p2s2.clone(),
    ));

    router1.run();
    router2.run();

    // Create sessions
    let (event_tx1, event_rx1) = channel();
    let session_info1 = create_unnumbered_session_info(route_exchange, false);

    let peer_config1 = PeerConfig {
        name: format!("peer_{}", interface_name),
        group: String::new(),
        host: r2_addr,
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 3,
        resolution: 100,
    };

    let result1 = router1
        .ensure_unnumbered_session(
            interface_name.to_string(),
            peer_config1,
            Some(r1_addr),
            event_tx1.clone(),
            event_rx1,
            session_info1,
            mock_ndp1.clone(),
        )
        .expect("create session1");

    let session1 = match result1 {
        EnsureSessionResult::New(s) => s,
        EnsureSessionResult::Updated(s) => s,
    };

    let (event_tx2, event_rx2) = channel();
    let session_info2 = create_unnumbered_session_info(route_exchange, false);

    let peer_config2 = PeerConfig {
        name: format!("peer_{}", interface_name),
        group: String::new(),
        host: r1_addr,
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 3,
        resolution: 100,
    };

    let result2 = router2
        .ensure_unnumbered_session(
            interface_name.to_string(),
            peer_config2,
            Some(r2_addr),
            event_tx2.clone(),
            event_rx2,
            session_info2,
            mock_ndp2.clone(),
        )
        .expect("create session2");

    let session2 = match result2 {
        EnsureSessionResult::New(s) => s,
        EnsureSessionResult::Updated(s) => s,
    };

    // Discover peers via NDP
    mock_ndp1
        .discover_peer(interface_name, r2_ip)
        .expect("discover peer on r1");
    mock_ndp2
        .discover_peer(interface_name, r1_ip)
        .expect("discover peer on r2");

    // Start sessions
    event_tx1
        .send(FsmEvent::Admin(AdminEvent::ManualStart))
        .expect("start session1");
    event_tx2
        .send(FsmEvent::Admin(AdminEvent::ManualStart))
        .expect("start session2");

    // Build topology
    UnnumberedTopology {
        routers: vec![
            UnnumberedRouterHandle {
                router: router1,
                dispatchers: vec![dispatcher1],
                mock_ndp: mock_ndp1,
                sessions: vec![session1],
                _db_guard: db1,
            },
            UnnumberedRouterHandle {
                router: router2,
                dispatchers: vec![dispatcher2],
                mock_ndp: mock_ndp2,
                sessions: vec![session2],
                _db_guard: db2,
            },
        ],
    }
}

/// Create a three-router chain topology with unnumbered BGP sessions.
///
/// Topology: R1 <--r1_r2_interface--> R2 <--r2_r3_interface--> R3
///
/// This topology demonstrates:
/// - R2 as a transit router with two unnumbered interfaces
/// - Same link-local IP (fe80::2) on R2 with different scope_ids
/// - Scope isolation: NDP changes on one interface don't affect the other
///
/// # Link-Local Addresses
/// - R1: fe80::1%r1_r2_scope_id (single interface)
/// - R2: fe80::2%r1_r2_scope_id (r1_r2_interface) + fe80::2%r2_r3_scope_id (r2_r3_interface)
/// - R3: fe80::3%r2_r3_scope_id (single interface)
fn unnumbered_three_router_chain(
    test_name: &str,
    r1_r2_interface: &str,
    r1_r2_scope_id: u32,
    r2_r3_interface: &str,
    r2_r3_scope_id: u32,
    route_exchange: RouteExchange,
) -> UnnumberedTopology {
    let log = init_file_logger(&format!("{}.log", test_name));

    // Create databases with unique paths
    let db1 = rdb::test::get_test_db(&format!("{}_r1", test_name), log.clone())
        .expect("create db1");
    let db2 = rdb::test::get_test_db(&format!("{}_r2", test_name), log.clone())
        .expect("create db2");
    let db3 = rdb::test::get_test_db(&format!("{}_r3", test_name), log.clone())
        .expect("create db3");

    // Create mock NDP managers
    let mock_ndp1 = UnnumberedManagerMock::new();
    let mock_ndp2 = UnnumberedManagerMock::new();
    let mock_ndp3 = UnnumberedManagerMock::new();

    // Register interfaces with scope_ids
    mock_ndp1.register_interface(r1_r2_interface.to_string(), r1_r2_scope_id);
    mock_ndp2.register_interface(r1_r2_interface.to_string(), r1_r2_scope_id);
    mock_ndp2.register_interface(r2_r3_interface.to_string(), r2_r3_scope_id);
    mock_ndp3.register_interface(r2_r3_interface.to_string(), r2_r3_scope_id);

    // Link-local addresses for each router
    // IMPORTANT: R1 and R3 both use fe80::1 to test peer isolation bug
    // In real unnumbered BGP, different routers can use the same link-local
    // address because they're on different interfaces (different scope_ids)
    let r1_ip: Ipv6Addr = "fe80::1".parse().unwrap();
    let r2_ip: Ipv6Addr = "fe80::2".parse().unwrap();
    let r3_ip: Ipv6Addr = "fe80::1".parse().unwrap(); // Same as R1, different scope_id
    let r1_addr = SocketAddr::V6(SocketAddrV6::new(
        r1_ip,
        TEST_BGP_PORT,
        0,
        r1_r2_scope_id,
    ));
    let r2_eth0_addr = SocketAddr::V6(SocketAddrV6::new(
        r2_ip,
        TEST_BGP_PORT,
        0,
        r1_r2_scope_id,
    ));
    let r2_eth1_addr = SocketAddr::V6(SocketAddrV6::new(
        r2_ip,
        TEST_BGP_PORT,
        0,
        r2_r3_scope_id,
    ));
    let r3_addr = SocketAddr::V6(SocketAddrV6::new(
        r3_ip,
        TEST_BGP_PORT,
        0,
        r2_r3_scope_id,
    ));

    // Create session maps
    let p2s1: Arc<
        Mutex<BTreeMap<PeerId, SessionEndpoint<BgpConnectionChannel>>>,
    > = Arc::new(Mutex::new(BTreeMap::new()));
    let p2s2: Arc<
        Mutex<BTreeMap<PeerId, SessionEndpoint<BgpConnectionChannel>>>,
    > = Arc::new(Mutex::new(BTreeMap::new()));
    let p2s3: Arc<
        Mutex<BTreeMap<PeerId, SessionEndpoint<BgpConnectionChannel>>>,
    > = Arc::new(Mutex::new(BTreeMap::new()));

    // Create Dispatcher for R1 (single interface)
    let disp1 = Arc::new(Dispatcher::new(
        p2s1.clone(),
        r1_addr.to_string(),
        log.clone(),
        Some(mock_ndp1.clone()),
    ));
    Builder::new()
        .name(format!("bgp-listener-r1-{}", r1_r2_interface))
        .spawn({
            let d = disp1.clone();
            move || d.run::<BgpListenerChannel>()
        })
        .expect("spawn r1 dispatcher");

    // Create Dispatchers for R2 (two interfaces)
    let disp2_eth0 = Arc::new(Dispatcher::new(
        p2s2.clone(),
        r2_eth0_addr.to_string(),
        log.clone(),
        Some(mock_ndp2.clone()),
    ));
    Builder::new()
        .name(format!("bgp-listener-r2-{}", r1_r2_interface))
        .spawn({
            let d = disp2_eth0.clone();
            move || d.run::<BgpListenerChannel>()
        })
        .expect("spawn r2 eth0 dispatcher");

    let disp2_eth1 = Arc::new(Dispatcher::new(
        p2s2.clone(),
        r2_eth1_addr.to_string(),
        log.clone(),
        Some(mock_ndp2.clone()),
    ));
    Builder::new()
        .name(format!("bgp-listener-r2-{}", r2_r3_interface))
        .spawn({
            let d = disp2_eth1.clone();
            move || d.run::<BgpListenerChannel>()
        })
        .expect("spawn r2 eth1 dispatcher");

    // Create Dispatcher for R3 (single interface)
    let disp3 = Arc::new(Dispatcher::new(
        p2s3.clone(),
        r3_addr.to_string(),
        log.clone(),
        Some(mock_ndp3.clone()),
    ));
    Builder::new()
        .name(format!("bgp-listener-r3-{}", r2_r3_interface))
        .spawn({
            let d = disp3.clone();
            move || d.run::<BgpListenerChannel>()
        })
        .expect("spawn r3 dispatcher");

    // Create routers
    let router1 = Arc::new(Router::new(
        RouterConfig {
            asn: Asn::FourOctet(65001),
            id: 1,
        },
        log.clone(),
        db1.db().clone(),
        p2s1.clone(),
    ));
    let router2 = Arc::new(Router::new(
        RouterConfig {
            asn: Asn::FourOctet(65002),
            id: 2,
        },
        log.clone(),
        db2.db().clone(),
        p2s2.clone(),
    ));
    let router3 = Arc::new(Router::new(
        RouterConfig {
            asn: Asn::FourOctet(65003),
            id: 3,
        },
        log.clone(),
        db3.db().clone(),
        p2s3.clone(),
    ));

    router1.run();
    router2.run();
    router3.run();

    // Create sessions

    // R1 session to R2
    let (event_tx1, event_rx1) = channel();
    let session_info1 = create_unnumbered_session_info(route_exchange, false);
    let peer_config1 = PeerConfig {
        name: format!("r1_to_r2_{}", r1_r2_interface),
        group: String::new(),
        host: r2_eth0_addr,
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 3,
        resolution: 100,
    };
    let result1 = router1
        .ensure_unnumbered_session(
            r1_r2_interface.to_string(),
            peer_config1,
            Some(r1_addr),
            event_tx1.clone(),
            event_rx1,
            session_info1,
            mock_ndp1.clone(),
        )
        .expect("create r1 session");
    let session1 = match result1 {
        EnsureSessionResult::New(s) => s,
        EnsureSessionResult::Updated(s) => s,
    };

    // R2 session to R1 (eth0)
    let (event_tx2_r1, event_rx2_r1) = channel();
    let session_info2_r1 =
        create_unnumbered_session_info(route_exchange, false);
    let peer_config2_r1 = PeerConfig {
        name: format!("r2_to_r1_{}", r1_r2_interface),
        group: String::new(),
        host: r1_addr,
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 3,
        resolution: 100,
    };
    let result2_r1 = router2
        .ensure_unnumbered_session(
            r1_r2_interface.to_string(),
            peer_config2_r1,
            Some(r2_eth0_addr),
            event_tx2_r1.clone(),
            event_rx2_r1,
            session_info2_r1,
            mock_ndp2.clone(),
        )
        .expect("create r2-r1 session");
    let session2_r1 = match result2_r1 {
        EnsureSessionResult::New(s) => s,
        EnsureSessionResult::Updated(s) => s,
    };

    // R2 session to R3 (eth1)
    let (event_tx2_r3, event_rx2_r3) = channel();
    let session_info2_r3 =
        create_unnumbered_session_info(route_exchange, false);
    let peer_config2_r3 = PeerConfig {
        name: format!("r2_to_r3_{}", r2_r3_interface),
        group: String::new(),
        host: r3_addr,
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 3,
        resolution: 100,
    };
    let result2_r3 = router2
        .ensure_unnumbered_session(
            r2_r3_interface.to_string(),
            peer_config2_r3,
            Some(r2_eth1_addr),
            event_tx2_r3.clone(),
            event_rx2_r3,
            session_info2_r3,
            mock_ndp2.clone(),
        )
        .expect("create r2-r3 session");
    let session2_r3 = match result2_r3 {
        EnsureSessionResult::New(s) => s,
        EnsureSessionResult::Updated(s) => s,
    };

    // R3 session to R2
    let (event_tx3, event_rx3) = channel();
    let session_info3 = create_unnumbered_session_info(route_exchange, false);
    let peer_config3 = PeerConfig {
        name: format!("r3_to_r2_{}", r2_r3_interface),
        group: String::new(),
        host: r2_eth1_addr,
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 3,
        resolution: 100,
    };
    let result3 = router3
        .ensure_unnumbered_session(
            r2_r3_interface.to_string(),
            peer_config3,
            Some(r3_addr),
            event_tx3.clone(),
            event_rx3,
            session_info3,
            mock_ndp3.clone(),
        )
        .expect("create r3 session");
    let session3 = match result3 {
        EnsureSessionResult::New(s) => s,
        EnsureSessionResult::Updated(s) => s,
    };

    // Discover peers via NDP
    mock_ndp1
        .discover_peer(r1_r2_interface, r2_ip)
        .expect("r1 discovers r2");
    mock_ndp2
        .discover_peer(r1_r2_interface, r1_ip)
        .expect("r2 discovers r1 on eth0");
    mock_ndp2
        .discover_peer(r2_r3_interface, r3_ip)
        .expect("r2 discovers r3 on eth1");
    mock_ndp3
        .discover_peer(r2_r3_interface, r2_ip)
        .expect("r3 discovers r2");

    // Start all sessions
    event_tx1
        .send(FsmEvent::Admin(AdminEvent::ManualStart))
        .expect("start r1 session");
    event_tx2_r1
        .send(FsmEvent::Admin(AdminEvent::ManualStart))
        .expect("start r2-r1 session");
    event_tx2_r3
        .send(FsmEvent::Admin(AdminEvent::ManualStart))
        .expect("start r2-r3 session");
    event_tx3
        .send(FsmEvent::Admin(AdminEvent::ManualStart))
        .expect("start r3 session");

    // Build topology
    UnnumberedTopology {
        routers: vec![
            UnnumberedRouterHandle {
                router: router1,
                dispatchers: vec![disp1],
                mock_ndp: mock_ndp1,
                sessions: vec![session1],
                _db_guard: db1,
            },
            UnnumberedRouterHandle {
                router: router2,
                dispatchers: vec![disp2_eth0, disp2_eth1],
                mock_ndp: mock_ndp2,
                sessions: vec![session2_r1, session2_r3],
                _db_guard: db2,
            },
            UnnumberedRouterHandle {
                router: router3,
                dispatchers: vec![disp3],
                mock_ndp: mock_ndp3,
                sessions: vec![session3],
                _db_guard: db3,
            },
        ],
    }
}

// =========================================================================
// Unnumbered BGP Test Cases
// =========================================================================

/// Test: Session survives NDP changes without FSM state transitions.
///
/// This test verifies that:
/// 1. Sessions establish normally with initial NDP neighbors
/// 2. Updating NDP neighbor to new IP doesn't affect FSM state
/// 3. get_peer_addr() reflects the new NDP neighbor
/// 4. Sessions stay Established throughout NDP changes
/// 5. Expiring NDP neighbor (get_peer_addr() -> None) doesn't affect FSM
/// 6. Rediscovering original peer works correctly
#[test]
fn test_unnumbered_unaffected_by_ndp() {
    let scope_id = next_scope_id();
    let topo = unnumbered_pair(
        "ndp_changes",
        "eth0",
        scope_id,
        RouteExchange::Ipv4 { nexthop: None },
    );

    let r1 = &topo.routers[0];
    let r2 = &topo.routers[1];
    let session1 = &r1.sessions[0];
    let session2 = &r2.sessions[0];

    // Step 1: Wait for Established state on both sessions
    wait_for_eq!(
        session1.state(),
        FsmStateKind::Established,
        "R1 session should reach Established"
    );
    wait_for_eq!(
        session2.state(),
        FsmStateKind::Established,
        "R2 session should reach Established"
    );

    // Verify initial peer addresses
    let initial_r2_ip: Ipv6Addr = "fe80::2".parse().unwrap();
    let initial_r1_ip: Ipv6Addr = "fe80::1".parse().unwrap();
    let initial_r2_addr = SocketAddr::V6(SocketAddrV6::new(
        initial_r2_ip,
        TEST_BGP_PORT,
        0,
        scope_id,
    ));
    let initial_r1_addr = SocketAddr::V6(SocketAddrV6::new(
        initial_r1_ip,
        TEST_BGP_PORT,
        0,
        scope_id,
    ));
    assert_eq!(
        session1.get_peer_socket_addr(),
        Some(initial_r2_addr),
        "R1 should see R2's address initially"
    );
    assert_eq!(
        session2.get_peer_socket_addr(),
        Some(initial_r1_addr),
        "R2 should see R1's address initially"
    );

    // Step 2: Update NDP neighbor to new IP on R1
    let new_peer_ip: Ipv6Addr = "fe80::99".parse().unwrap();
    r1.mock_ndp
        .discover_peer("eth0", new_peer_ip)
        .expect("update peer on R1");

    // Step 3: Verify get_peer_addr() returns new IP
    let new_peer_addr = SocketAddr::V6(SocketAddrV6::new(
        new_peer_ip,
        TEST_BGP_PORT,
        0,
        scope_id,
    ));
    wait_for!(
        session1.get_peer_socket_addr() == Some(new_peer_addr),
        "R1 should see new peer address"
    );

    // Step 4: Assert sessions stay Established
    assert_eq!(
        session1.state(),
        FsmStateKind::Established,
        "R1 session must stay Established after NDP update"
    );
    assert_eq!(
        session2.state(),
        FsmStateKind::Established,
        "R2 session must stay Established after R1's NDP update"
    );

    // Verify connection still active
    assert_eq!(
        session1.connection_count(),
        1,
        "R1 should still have active connection"
    );
    assert_eq!(
        session2.connection_count(),
        1,
        "R2 should still have active connection"
    );

    // Step 5: Expire NDP neighbor on R1
    r1.mock_ndp.expire_peer("eth0").expect("expire peer on R1");

    // Step 6: Verify get_peer_addr() returns None
    wait_for!(
        session1.get_peer_socket_addr().is_none(),
        "R1 should see no peer after expiry"
    );

    // Step 7: Assert sessions still stay Established
    // Verify for longer than hold_time to ensure keepalives are exchanged
    let start = Instant::now();
    while start.elapsed() < ESTABLISHED_VERIFICATION {
        assert_eq!(
            session1.state(),
            FsmStateKind::Established,
            "R1 session must stay Established despite NDP expiry"
        );
        assert_eq!(
            session2.state(),
            FsmStateKind::Established,
            "R2 session must stay Established despite R1's NDP expiry"
        );
        sleep(Duration::from_millis(100));
    }

    // Step 8: Rediscover original peer
    r1.mock_ndp
        .discover_peer("eth0", initial_r2_ip)
        .expect("rediscover peer on R1");

    // Step 9: Verify get_peer_addr() returns original peer
    wait_for!(
        session1.get_peer_socket_addr() == Some(initial_r2_addr),
        "R1 should see original peer after rediscovery"
    );

    // Step 10: Assert sessions remain Established throughout
    assert_eq!(
        session1.state(),
        FsmStateKind::Established,
        "R1 session should still be Established"
    );
    assert_eq!(
        session2.state(),
        FsmStateKind::Established,
        "R2 session should still be Established"
    );

    // Topology cleanup happens via Drop
}

/// Test: Session reconnects with new peer address after AdminEvent::Reset.
///
/// This test verifies that:
/// 1. Sessions establish normally with initial NDP neighbors
/// 2. Updating NDP neighbor to new IP doesn't affect FSM state (session stays Established)
/// 3. After AdminEvent::Reset, session tears down and re-establishes
/// 4. Reconnection uses the current NDP neighbor (new IP), not the original
#[test]
fn test_unnumbered_ndp_change() {
    let scope_id = next_scope_id();
    let topo = unnumbered_pair(
        "ndp_change_reset",
        "eth0",
        scope_id,
        RouteExchange::Ipv4 { nexthop: None },
    );

    let r1 = &topo.routers[0];
    let r2 = &topo.routers[1];
    let session1 = &r1.sessions[0];
    let session2 = &r2.sessions[0];

    // Step 1: Wait for Established state on both sessions
    wait_for_eq!(
        session1.state(),
        FsmStateKind::Established,
        "R1 session should reach Established"
    );
    wait_for_eq!(
        session2.state(),
        FsmStateKind::Established,
        "R2 session should reach Established"
    );

    // Verify initial peer addresses
    let initial_r2_addr = SocketAddr::V6(SocketAddrV6::new(
        "fe80::2".parse().unwrap(),
        TEST_BGP_PORT,
        0,
        scope_id,
    ));
    assert_eq!(
        session1.get_peer_socket_addr(),
        Some(initial_r2_addr),
        "R1 should see R2's initial address"
    );

    // Step 2: Change NDP neighbor to new IP on R1
    let new_peer_ip: Ipv6Addr = "fe80::88".parse().unwrap();
    r1.mock_ndp
        .discover_peer("eth0", new_peer_ip)
        .expect("update peer on R1");

    // Step 3: Verify get_peer_addr() returns new IP
    let new_peer_addr = SocketAddr::V6(SocketAddrV6::new(
        new_peer_ip,
        TEST_BGP_PORT,
        0,
        scope_id,
    ));
    wait_for!(
        session1.get_peer_socket_addr() == Some(new_peer_addr),
        "R1 should see new peer address"
    );

    // Step 4: Verify session stays Established despite NDP change
    assert_eq!(
        session1.state(),
        FsmStateKind::Established,
        "R1 session must stay Established after NDP update"
    );
    assert_eq!(
        session2.state(),
        FsmStateKind::Established,
        "R2 session must stay Established after R1's NDP update"
    );

    // Step 5: Send AdminEvent::Reset to R1's session
    session1
        .event_tx
        .send(FsmEvent::Admin(AdminEvent::Reset))
        .expect("send reset to R1 session");

    // Step 6 & 7: Wait for sessions to re-establish
    // The session will tear down and reconnect using the current NDP neighbor (new IP).
    // The FSM transitions through Idle very quickly, so we wait directly for re-establishment.
    wait_for_eq!(
        session1.state(),
        FsmStateKind::Established,
        "R1 session should re-establish after reset"
    );
    wait_for_eq!(
        session2.state(),
        FsmStateKind::Established,
        "R2 session should re-establish after R1's reset"
    );

    // Step 8: Verify reconnection used the new peer address
    assert_eq!(
        session1.get_peer_socket_addr(),
        Some(new_peer_addr),
        "R1 should still see new peer address after reconnection"
    );

    // Verify connections are active
    assert_eq!(
        session1.connection_count(),
        1,
        "R1 should have active connection"
    );
    assert_eq!(
        session2.connection_count(),
        1,
        "R2 should have active connection"
    );

    // Topology cleanup happens via Drop
}

/// Test: Three-router chain with same link-local IP on different interfaces.
///
/// This test verifies:
/// 1. R2 can run two unnumbered sessions using the same link-local IP (fe80::2)
///    on different interfaces with different scope_ids
/// 2. All sessions establish correctly
/// 3. NDP changes on one interface (eth0) don't affect the other (eth1)
/// 4. Sessions remain Established despite NDP changes on one interface
/// 5. scope_id properly isolates sessions
#[test]
fn test_three_router_chain_unnumbered() {
    let r1_r2_scope_id = next_scope_id();
    let r2_r3_scope_id = next_scope_id();

    let topo = unnumbered_three_router_chain(
        "three_chain",
        "eth0",
        r1_r2_scope_id,
        "eth1",
        r2_r3_scope_id,
        RouteExchange::Ipv4 { nexthop: None },
    );

    let r1 = &topo.routers[0];
    let r2 = &topo.routers[1];
    let r3 = &topo.routers[2];

    // Step 1: Verify session counts
    assert_eq!(r1.sessions.len(), 1, "R1 should have 1 session");
    assert_eq!(r2.sessions.len(), 2, "R2 should have 2 sessions");
    assert_eq!(r3.sessions.len(), 1, "R3 should have 1 session");

    let r1_session = &r1.sessions[0];
    let r2_eth0_session = &r2.sessions[0]; // R2 to R1
    let r2_eth1_session = &r2.sessions[1]; // R2 to R3
    let r3_session = &r3.sessions[0];

    // Step 2: Wait for all sessions to reach Established
    wait_for_eq!(
        r1_session.state(),
        FsmStateKind::Established,
        "R1 session should reach Established"
    );
    wait_for_eq!(
        r2_eth0_session.state(),
        FsmStateKind::Established,
        "R2 eth0 session should reach Established"
    );
    wait_for_eq!(
        r2_eth1_session.state(),
        FsmStateKind::Established,
        "R2 eth1 session should reach Established"
    );
    wait_for_eq!(
        r3_session.state(),
        FsmStateKind::Established,
        "R3 session should reach Established"
    );

    // Step 3: Verify R2's two sessions use different scope_ids
    let r2_eth0_peer = r2_eth0_session
        .get_peer_socket_addr()
        .expect("R2 eth0 should have peer");
    let r2_eth1_peer = r2_eth1_session
        .get_peer_socket_addr()
        .expect("R2 eth1 should have peer");

    // Extract scope_ids from peer addresses
    let eth0_scope = if let SocketAddr::V6(v6) = r2_eth0_peer {
        v6.scope_id()
    } else {
        panic!("R2 eth0 peer should be IPv6");
    };
    let eth1_scope = if let SocketAddr::V6(v6) = r2_eth1_peer {
        v6.scope_id()
    } else {
        panic!("R2 eth1 peer should be IPv6");
    };

    assert_eq!(
        eth0_scope, r1_r2_scope_id,
        "R2 eth0 should use r1_r2_scope_id"
    );
    assert_eq!(
        eth1_scope, r2_r3_scope_id,
        "R2 eth1 should use r2_r3_scope_id"
    );
    assert_ne!(
        eth0_scope, eth1_scope,
        "R2's two sessions should have different scope_ids"
    );

    // Step 4: Change NDP on R2's eth0 interface to a new peer
    let new_eth0_ip: Ipv6Addr = "fe80::99".parse().unwrap();
    r2.mock_ndp
        .discover_peer("eth0", new_eth0_ip)
        .expect("update eth0 peer on R2");

    // Step 5: Verify only eth0 session's get_peer_addr() changes
    let new_eth0_peer = SocketAddr::V6(SocketAddrV6::new(
        new_eth0_ip,
        TEST_BGP_PORT,
        0,
        r1_r2_scope_id,
    ));
    wait_for!(
        r2_eth0_session.get_peer_socket_addr() == Some(new_eth0_peer),
        "R2 eth0 session should see new peer address"
    );

    // Step 6: Verify eth1 session unaffected
    assert_eq!(
        r2_eth1_session.get_peer_socket_addr(),
        Some(r2_eth1_peer),
        "R2 eth1 session should still have original peer"
    );

    // Step 7: Assert both R2 sessions stay Established
    assert_eq!(
        r2_eth0_session.state(),
        FsmStateKind::Established,
        "R2 eth0 session should stay Established after NDP change"
    );
    assert_eq!(
        r2_eth1_session.state(),
        FsmStateKind::Established,
        "R2 eth1 session should stay Established"
    );

    // Verify all other sessions also stayed Established
    assert_eq!(
        r1_session.state(),
        FsmStateKind::Established,
        "R1 session should stay Established"
    );
    assert_eq!(
        r3_session.state(),
        FsmStateKind::Established,
        "R3 session should stay Established"
    );

    // Verify all connections are active
    assert_eq!(
        r1_session.connection_count(),
        1,
        "R1 should have active connection"
    );
    assert_eq!(
        r2_eth0_session.connection_count(),
        1,
        "R2 eth0 should have active connection"
    );
    assert_eq!(
        r2_eth1_session.connection_count(),
        1,
        "R2 eth1 should have active connection"
    );
    assert_eq!(
        r3_session.connection_count(),
        1,
        "R3 should have active connection"
    );

    // Step 8: Test route exchange and cleanup with peer isolation
    // This tests that route cleanup properly distinguishes between unnumbered
    // peers that may share the same link-local IP but have different scope_ids.

    // Step 8a: Originate routes from R1 and R3
    r1.router
        .create_origin4(vec![cidr!("10.1.0.0/24")])
        .expect("originate IPv4 route on R1");
    r3.router
        .create_origin4(vec![cidr!("10.3.0.0/24")])
        .expect("originate IPv4 route on R3");

    // Step 8b: Verify R2 receives both routes
    let r1_prefix = Prefix::V4(cidr!("10.1.0.0/24"));
    let r3_prefix = Prefix::V4(cidr!("10.3.0.0/24"));

    wait_for!(
        !r2.router.db.get_prefix_paths(&r1_prefix).is_empty(),
        "R2 should receive route from R1"
    );
    wait_for!(
        !r2.router.db.get_prefix_paths(&r3_prefix).is_empty(),
        "R2 should receive route from R3"
    );

    let r1_paths = r2.router.db.get_prefix_paths(&r1_prefix);
    let r3_paths = r2.router.db.get_prefix_paths(&r3_prefix);
    assert_eq!(r1_paths.len(), 1, "Should have exactly one path from R1");
    assert_eq!(r3_paths.len(), 1, "Should have exactly one path from R3");

    // Step 8c: Shutdown R1 to bring down the BGP session to R2
    r1.shutdown();

    // Step 8d: Wait for R1's session to tear down
    wait_for_neq!(
        r1_session.state(),
        FsmStateKind::Established,
        "R1 session should tear down after shutdown"
    );
    wait_for_neq!(
        r2_eth0_session.state(),
        FsmStateKind::Established,
        "R2 eth0 session should tear down after R1 shutdown"
    );

    // Step 8e: Verify R1's routes are withdrawn
    wait_for!(
        r2.router.db.get_prefix_paths(&r1_prefix).is_empty(),
        "R2 should withdraw R1's routes after session teardown"
    );

    // Step 8f: Verify R3's routes are still present
    // This assertion is expected to FAIL if the bug exists:
    // BgpPathProperties.peer is an IpAddr (doesn't include scope_id).
    // When R1's session tears down, remove_bgp_prefixes_from_peer() is called
    // with R1's link-local address (fe80::1). If R3 also uses a link-local
    // address without scope_id differentiation, the cleanup might incorrectly
    // match and remove R3's routes too.
    let r3_paths_after = r2.router.db.get_prefix_paths(&r3_prefix);
    assert_eq!(
        r3_paths_after.len(),
        1,
        "R2 should still have R3's routes after R1 shutdown. \
         BUG: peer tracking uses IpAddr without scope_id, causing \
         incorrect route removal when unnumbered peers share link-local IPs"
    );

    // Verify R2-R3 session is still Established
    assert_eq!(
        r2_eth1_session.state(),
        FsmStateKind::Established,
        "R2 eth1 session to R3 should stay Established"
    );
    assert_eq!(
        r3_session.state(),
        FsmStateKind::Established,
        "R3 session should stay Established"
    );

    // Topology cleanup happens via Drop
}

/// Test: Dual-stack route exchange over unnumbered BGP session.
///
/// This test verifies:
/// 1. IPv4 routes can be originated and received over unnumbered sessions
/// 2. IPv6 routes can be originated and received over unnumbered sessions
/// 3. Nexthops are set to the peer's link-local IPv6 address
/// 4. Routes are properly withdrawn when session goes down
#[test]
fn test_unnumbered_dualstack_route_exchange() {
    let scope_id = next_scope_id();
    let topo = unnumbered_pair(
        "dualstack_routes",
        "eth0",
        scope_id,
        RouteExchange::DualStack {
            ipv4_nexthop: None,
            ipv6_nexthop: None,
        },
    );

    let r1 = &topo.routers[0];
    let r2 = &topo.routers[1];
    let session1 = &r1.sessions[0];
    let session2 = &r2.sessions[0];

    // Wait for Established state on both sessions
    wait_for_eq!(
        session1.state(),
        FsmStateKind::Established,
        "R1 session should reach Established"
    );
    wait_for_eq!(
        session2.state(),
        FsmStateKind::Established,
        "R2 session should reach Established"
    );

    // Define the expected nexthop (R1's link-local address)
    let r1_linklocal: IpAddr = ip!("fe80::1");
    let r2_linklocal: IpAddr = ip!("fe80::2");

    // Step 1: Originate IPv4 route from R1
    r1.router
        .create_origin4(vec![cidr!("10.1.0.0/24")])
        .expect("originate IPv4 route on R1");

    // Step 2: Verify R2 receives IPv4 route with link-local nexthop
    let ipv4_prefix = Prefix::V4(cidr!("10.1.0.0/24"));
    wait_for!(
        !r2.router.db.get_prefix_paths(&ipv4_prefix).is_empty(),
        "R2 should receive IPv4 route from R1"
    );

    let ipv4_paths = r2.router.db.get_prefix_paths(&ipv4_prefix);
    assert_eq!(ipv4_paths.len(), 1, "Should have exactly one path for IPv4");
    assert_eq!(
        ipv4_paths[0].nexthop, r1_linklocal,
        "IPv4 route nexthop should be R1's link-local address"
    );

    // Step 3: Originate IPv6 route from R1
    r1.router
        .create_origin6(vec![cidr!("2001:db8:1::/48")])
        .expect("originate IPv6 route on R1");

    // Step 4: Verify R2 receives IPv6 route with link-local nexthop
    let ipv6_prefix = Prefix::V6(cidr!("2001:db8:1::/48"));
    wait_for!(
        !r2.router.db.get_prefix_paths(&ipv6_prefix).is_empty(),
        "R2 should receive IPv6 route from R1"
    );

    let ipv6_paths = r2.router.db.get_prefix_paths(&ipv6_prefix);
    assert_eq!(ipv6_paths.len(), 1, "Should have exactly one path for IPv6");
    assert_eq!(
        ipv6_paths[0].nexthop, r1_linklocal,
        "IPv6 route nexthop should be R1's link-local address"
    );

    // Step 5: Originate routes from R2 in the opposite direction
    r2.router
        .create_origin4(vec![cidr!("10.2.0.0/24")])
        .expect("originate IPv4 route on R2");
    r2.router
        .create_origin6(vec![cidr!("2001:db8:2::/48")])
        .expect("originate IPv6 route on R2");

    // Step 6: Verify R1 receives both routes with R2's link-local nexthop
    let r2_ipv4_prefix = Prefix::V4(cidr!("10.2.0.0/24"));
    wait_for!(
        !r1.router.db.get_prefix_paths(&r2_ipv4_prefix).is_empty(),
        "R1 should receive IPv4 route from R2"
    );

    let r2_ipv4_paths = r1.router.db.get_prefix_paths(&r2_ipv4_prefix);
    assert_eq!(
        r2_ipv4_paths.len(),
        1,
        "Should have exactly one path for R2's IPv4"
    );
    assert_eq!(
        r2_ipv4_paths[0].nexthop, r2_linklocal,
        "R2's IPv4 route nexthop should be R2's link-local address"
    );

    let r2_ipv6_prefix = Prefix::V6(cidr!("2001:db8:2::/48"));
    wait_for!(
        !r1.router.db.get_prefix_paths(&r2_ipv6_prefix).is_empty(),
        "R1 should receive IPv6 route from R2"
    );

    let r2_ipv6_paths = r1.router.db.get_prefix_paths(&r2_ipv6_prefix);
    assert_eq!(
        r2_ipv6_paths.len(),
        1,
        "Should have exactly one path for R2's IPv6"
    );
    assert_eq!(
        r2_ipv6_paths[0].nexthop, r2_linklocal,
        "R2's IPv6 route nexthop should be R2's link-local address"
    );

    // Step 7: Shutdown R1 and verify routes are withdrawn
    r1.shutdown();

    // Wait for sessions to tear down
    wait_for_neq!(
        session1.state(),
        FsmStateKind::Established,
        "R1 session should tear down"
    );
    wait_for_neq!(
        session2.state(),
        FsmStateKind::Established,
        "R2 session should tear down"
    );

    // Verify R1's routes are withdrawn from R2
    wait_for!(
        r2.router.db.get_prefix_paths(&ipv4_prefix).is_empty(),
        "R1's IPv4 route should be withdrawn from R2"
    );
    wait_for!(
        r2.router.db.get_prefix_paths(&ipv6_prefix).is_empty(),
        "R1's IPv6 route should be withdrawn from R2"
    );

    // Topology cleanup happens via Drop
}

/// Test: Complete interface availability lifecycle for unnumbered BGP.
///
/// Validates FSM behavior through the full interface lifecycle:
/// - Stage 1: Sessions configured before interfaces exist on system
/// - Stage 2: Interfaces appear, sessions establish
/// - Stage 3: Interface removed on one side, sessions stay Established
/// - Stage 4: Sessions reset while interfaces inactive, cannot establish until interfaces return
#[test]
fn test_unnumbered_interface_lifecycle() {
    let log = init_file_logger("unnumbered_interface_lifecycle.log");

    // =========================================================================
    // Setup: Two routers with interface CONFIGURED but NOT on system
    // =========================================================================

    let db1 = rdb::test::get_test_db("unnumbered_lifecycle_r1", log.clone())
        .expect("create db1");
    let db2 = rdb::test::get_test_db("unnumbered_lifecycle_r2", log.clone())
        .expect("create db2");

    let mock_ndp1 = UnnumberedManagerMock::new();
    let mock_ndp2 = UnnumberedManagerMock::new();

    let scope_id = 2u32;

    // ONLY configure interface mapping - do NOT add to system yet
    mock_ndp1.configure_interface("eth0".to_string(), scope_id);
    mock_ndp2.configure_interface("eth0".to_string(), scope_id);

    // Create session maps
    let p2s1: Arc<
        Mutex<BTreeMap<PeerId, SessionEndpoint<BgpConnectionChannel>>>,
    > = Arc::new(Mutex::new(BTreeMap::new()));
    let p2s2: Arc<
        Mutex<BTreeMap<PeerId, SessionEndpoint<BgpConnectionChannel>>>,
    > = Arc::new(Mutex::new(BTreeMap::new()));

    // Create dispatchers (needed for inbound connections)
    let r1_ip: Ipv6Addr = "fe80::1".parse().unwrap();
    let r2_ip: Ipv6Addr = "fe80::2".parse().unwrap();
    let r1_addr =
        SocketAddr::V6(SocketAddrV6::new(r1_ip, TEST_BGP_PORT, 0, scope_id));
    let r2_addr =
        SocketAddr::V6(SocketAddrV6::new(r2_ip, TEST_BGP_PORT, 0, scope_id));

    let disp1 = Arc::new(Dispatcher::new(
        p2s1.clone(),
        r1_addr.to_string(),
        log.clone(),
        Some(mock_ndp1.clone()),
    ));
    let disp2 = Arc::new(Dispatcher::new(
        p2s2.clone(),
        r2_addr.to_string(),
        log.clone(),
        Some(mock_ndp2.clone()),
    ));

    let d1 = disp1.clone();
    Builder::new()
        .name("bgp-listener-r1".to_string())
        .spawn(move || d1.run::<BgpListenerChannel>())
        .expect("spawn dispatcher1");

    let d2 = disp2.clone();
    Builder::new()
        .name("bgp-listener-r2".to_string())
        .spawn(move || d2.run::<BgpListenerChannel>())
        .expect("spawn dispatcher2");

    // Create routers
    let router1 = Arc::new(Router::new(
        RouterConfig {
            asn: Asn::FourOctet(64512),
            id: 1,
        },
        log.clone(),
        db1.db().clone(),
        p2s1.clone(),
    ));
    let router2 = Arc::new(Router::new(
        RouterConfig {
            asn: Asn::FourOctet(64513),
            id: 2,
        },
        log.clone(),
        db2.db().clone(),
        p2s2.clone(),
    ));

    router1.run();
    router2.run();

    // Create sessions
    let (event_tx1, event_rx1) = channel();
    let session_info1 = create_test_session_info(
        RouteExchange::Ipv4 { nexthop: None },
        r1_addr,
        r2_addr,
        false,
    );
    let peer_config1 = PeerConfig {
        name: "peer_eth0".to_string(),
        group: String::new(),
        host: r2_addr,
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 3,
        resolution: 100,
    };

    let result1 = router1
        .ensure_unnumbered_session(
            "eth0".to_string(),
            peer_config1,
            Some(r1_addr),
            event_tx1.clone(),
            event_rx1,
            session_info1,
            mock_ndp1.clone(),
        )
        .expect("create session1");

    let session1 = match result1 {
        EnsureSessionResult::New(s) => s,
        EnsureSessionResult::Updated(s) => s,
    };

    let (event_tx2, event_rx2) = channel();
    let session_info2 = create_test_session_info(
        RouteExchange::Ipv4 { nexthop: None },
        r2_addr,
        r1_addr,
        false,
    );
    let peer_config2 = PeerConfig {
        name: "peer_eth0".to_string(),
        group: String::new(),
        host: r1_addr,
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 3,
        resolution: 100,
    };

    let result2 = router2
        .ensure_unnumbered_session(
            "eth0".to_string(),
            peer_config2,
            Some(r2_addr),
            event_tx2.clone(),
            event_rx2,
            session_info2,
            mock_ndp2.clone(),
        )
        .expect("create session2");

    let session2 = match result2 {
        EnsureSessionResult::New(s) => s,
        EnsureSessionResult::Updated(s) => s,
    };

    // Start sessions
    event_tx1
        .send(FsmEvent::Admin(AdminEvent::ManualStart))
        .expect("start session1");
    event_tx2
        .send(FsmEvent::Admin(AdminEvent::ManualStart))
        .expect("start session2");

    // =========================================================================
    // Stage 1: Interface not present - sessions cannot establish
    // =========================================================================

    // Wait for FSM to reach Connect or Active state
    wait_for!(
        session1.state() == FsmStateKind::Connect
            || session1.state() == FsmStateKind::Active,
        "Stage 1: Session1 should reach Connect or Active"
    );
    wait_for!(
        session2.state() == FsmStateKind::Connect
            || session2.state() == FsmStateKind::Active,
        "Stage 1: Session2 should reach Connect or Active"
    );

    // Wait for multiple connect_retry cycles to verify sessions don't establish
    sleep(CONNECT_RETRY_VERIFICATION);

    // Verify sessions are still not Established
    wait_for!(
        session1.state() != FsmStateKind::Established,
        "Stage 1: Session1 must not reach Established when interface missing"
    );
    wait_for!(
        session2.state() != FsmStateKind::Established,
        "Stage 1: Session2 must not reach Established when interface missing"
    );

    // =========================================================================
    // Stage 2: Interface appears - sessions establish
    // =========================================================================

    // Simulate interfaces appearing on the system
    mock_ndp1.add_system_interface("eth0");
    mock_ndp2.add_system_interface("eth0");

    // Verify interface_is_active() now returns true
    assert!(
        mock_ndp1.interface_is_active("eth0"),
        "Stage 2: interface_is_active should return true after add_system_interface"
    );
    assert!(
        mock_ndp2.interface_is_active("eth0"),
        "Stage 2: interface_is_active should return true after add_system_interface"
    );

    // Simulate monitor thread detecting interfaces and activating NDP
    // This is what UnnumberedManagerNdp::activate_interface() does
    mock_ndp1
        .activate_ndp("eth0")
        .expect("Stage 2: activate_ndp should succeed");
    mock_ndp2
        .activate_ndp("eth0")
        .expect("Stage 2: activate_ndp should succeed");

    // Discover peers via NDP (now possible since NDP is activated)
    mock_ndp1.discover_peer("eth0", r2_ip).unwrap();
    mock_ndp2.discover_peer("eth0", r1_ip).unwrap();

    // Sessions should now establish
    wait_for_eq!(
        session1.state(),
        FsmStateKind::Established,
        "Stage 2: Session1 should reach Established after interface appears"
    );
    wait_for_eq!(
        session2.state(),
        FsmStateKind::Established,
        "Stage 2: Session2 should reach Established after interface appears"
    );

    // =========================================================================
    // Stage 3: Interface removed - sessions stay Established
    // =========================================================================

    // Remove interface from system on Router 1 (but keep configuration)
    mock_ndp1.remove_system_interface("eth0");

    // Verify interface_is_active() now returns false
    assert!(
        !mock_ndp1.interface_is_active("eth0"),
        "Stage 3: interface_is_active should return false after removal"
    );

    // Sessions must STAY Established - verify for longer than hold_time to
    // ensure keepalives are being exchanged properly
    let start = Instant::now();
    while start.elapsed() < ESTABLISHED_VERIFICATION {
        wait_for_eq!(
            session1.state(),
            FsmStateKind::Established,
            "Stage 3: Session1 must stay Established despite interface removal"
        );
        wait_for_eq!(
            session2.state(),
            FsmStateKind::Established,
            "Stage 3: Session2 must stay Established (interface still present on remote)"
        );
        sleep(Duration::from_millis(500));
    }

    // =========================================================================
    // Stage 4: Session reset while interface inactive, then re-establishes
    // =========================================================================

    // Remove interface on both sides to simulate link failure scenario
    mock_ndp2.remove_system_interface("eth0");

    // Verify both interfaces are now inactive
    assert!(
        !mock_ndp1.interface_is_active("eth0"),
        "Stage 4: R1 interface should still be inactive from Stage 3"
    );
    assert!(
        !mock_ndp2.interface_is_active("eth0"),
        "Stage 4: R2 interface should now be inactive"
    );

    // Reset sessions via admin event (simulates operator intervention or
    // external trigger after detecting link issues)
    event_tx1
        .send(FsmEvent::Admin(AdminEvent::Reset))
        .expect("reset session1");
    event_tx2
        .send(FsmEvent::Admin(AdminEvent::Reset))
        .expect("reset session2");

    // Wait for sessions to leave Established state after Reset
    wait_for!(
        session1.state() != FsmStateKind::Established,
        "Stage 4: Session1 should leave Established after Reset"
    );
    wait_for!(
        session2.state() != FsmStateKind::Established,
        "Stage 4: Session2 should leave Established after Reset"
    );

    // Sessions should cycle in Connect/Active but not re-establish
    // (interface_is_active returns false, blocking connection attempts)
    // Verify for multiple connect_retry cycles
    let start = Instant::now();
    while start.elapsed() < CONNECT_RETRY_VERIFICATION {
        assert_ne!(
            session1.state(),
            FsmStateKind::Established,
            "Stage 4: Session1 must not re-establish while interface inactive"
        );
        assert_ne!(
            session2.state(),
            FsmStateKind::Established,
            "Stage 4: Session2 must not re-establish while interface inactive"
        );
        sleep(Duration::from_millis(500));
    }

    // Now bring interfaces back on both sides
    mock_ndp1.add_system_interface("eth0");
    mock_ndp2.add_system_interface("eth0");

    // Verify interface_is_active() returns true again
    assert!(
        mock_ndp1.interface_is_active("eth0"),
        "Stage 4: R1 interface_is_active should return true after re-add"
    );
    assert!(
        mock_ndp2.interface_is_active("eth0"),
        "Stage 4: R2 interface_is_active should return true after re-add"
    );

    // Simulate monitor thread detecting interfaces and re-activating NDP
    // (remove_system_interface clears NDP state, so must re-activate)
    mock_ndp1
        .activate_ndp("eth0")
        .expect("Stage 4: activate_ndp should succeed after re-add");
    mock_ndp2
        .activate_ndp("eth0")
        .expect("Stage 4: activate_ndp should succeed after re-add");

    // Rediscover peers (NDP state was cleared when interface was removed)
    mock_ndp1.discover_peer("eth0", r2_ip).unwrap();
    mock_ndp2.discover_peer("eth0", r1_ip).unwrap();

    // Sessions should now re-establish
    wait_for_eq!(
        session1.state(),
        FsmStateKind::Established,
        "Stage 4: Session1 should re-establish after interface returns"
    );
    wait_for_eq!(
        session2.state(),
        FsmStateKind::Established,
        "Stage 4: Session2 should re-establish after interface returns"
    );

    // =========================================================================
    // Cleanup
    // =========================================================================

    router1.shutdown();
    router2.shutdown();
    disp1.shutdown();
    disp2.shutdown();
}
