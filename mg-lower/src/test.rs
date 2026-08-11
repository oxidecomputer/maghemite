use std::{
    collections::HashMap,
    net::Ipv6Addr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use ddm_api_types_versions::latest::net::TunnelOrigin;
use dpd_client::types::{
    Ipv4Route, Ipv6Route, LinkId, LinkState, PortId, PortMedia, PortPrbsMode,
    PortSpeed, Route,
};
use mg_api_types::rdb::path::Path;
use mg_common::stats::MgLowerStats;
use oxnet::{IpNet, Ipv4Net};
use rdb::types::{RouterId, RouterInfo};
use rdb::{Rib, StaticRouteKey};

use crate::dendrite::get_routes_for_prefix;
use crate::platform::test::{TestDdm, TestDpd, TestSwitchZone};

#[tokio::test]
async fn sync_prefix_test() {
    let rt = Arc::new(tokio::runtime::Handle::current());
    let (tx, done) = std::sync::mpsc::channel::<()>();

    std::thread::spawn(move || {
        let dpd = TestDpd::default();
        let ddm = TestDdm::default();
        let sw = TestSwitchZone {
            routes: HashMap::default(),
            default_ifname: Some(String::from("tfportqsfp0_0")),
            default_gw: "1.2.3.4".parse().unwrap(),
        };
        let tep: Ipv6Addr = "fd00:a:b:c::d".parse().unwrap();

        let mut rib = Rib::default();

        let router = RouterId::new_random();
        test_setup(router, tep, &dpd, &ddm, &mut rib);

        // extra prefix should get picked up by tunnel routing
        rib.insert(
            "4.0.0.0/24".parse::<Ipv4Net>().unwrap().into(),
            vec![Path {
                nexthop: "3.0.0.1".parse().unwrap(),
                nexthop_interface: None,
                shutdown: false,
                rib_priority: 10,
                bgp: None,
                vlan_id: None,
            }]
            .into_iter()
            .collect(),
        );

        let log = util::test::logger();

        crate::sync_prefix(
            router,
            tep,
            &rib,
            &"4.0.0.0/24".parse::<Ipv4Net>().unwrap().into(),
            &dpd,
            &ddm,
            &sw,
            &log,
            &rt,
        )
        .expect("sync prefix run");

        // There are four lights!
        assert_eq!(ddm.tunnel_originated.lock().unwrap().len(), 4);
        assert_eq!(dpd.v4_routes.lock().unwrap().len(), 4);

        // Every dpd route call must carry this router's id.
        let routers_seen = dpd.route_call_routers.lock().unwrap();
        assert!(!routers_seen.is_empty());
        assert!(routers_seen.iter().all(|x| *x == router));

        tx.send(()).unwrap();
    });

    done.recv().unwrap();
}

#[tokio::test]
async fn sync_link_down_test() {
    let rt = Arc::new(tokio::runtime::Handle::current());
    let (tx, done) = std::sync::mpsc::channel::<()>();

    std::thread::spawn(move || {
        let dpd = TestDpd::default();
        let ddm = TestDdm::default();
        let sw = TestSwitchZone {
            routes: vec![(
                "3.0.0.1/32".parse().unwrap(),
                (
                    Some(String::from("tfportqsfp1_0")),
                    "3.0.0.254".parse().unwrap(),
                ),
            )]
            .into_iter()
            .collect(),
            default_ifname: Some(String::from("tfportqsfp0_0")),
            default_gw: "1.2.3.4".parse().unwrap(),
        };
        let tep: Ipv6Addr = "fd00:a:b:c::d".parse().unwrap();

        let log = util::test::logger();
        let mut rib = Rib::default();

        let router = RouterId::new_random();
        test_setup(router, tep, &dpd, &ddm, &mut rib);

        let do_sync = || {
            crate::sync_prefix(
                router,
                tep,
                &rib,
                &"3.0.0.0/24".parse::<Ipv4Net>().unwrap().into(),
                &dpd,
                &ddm,
                &sw,
                &log,
                &rt,
            )
            .expect("sync prefix run");
        };

        // Should be 3 routes with all links up
        do_sync();
        assert_eq!(ddm.tunnel_originated.lock().unwrap().len(), 3);
        assert_eq!(dpd.v4_routes.lock().unwrap().len(), 3);

        // Take down a link and sync
        // One route should be gone with a link down
        dpd.links.lock().unwrap().get_mut(1).unwrap().link_state =
            LinkState::Down;
        do_sync();
        assert_eq!(ddm.tunnel_originated.lock().unwrap().len(), 2);
        assert_eq!(dpd.v4_routes.lock().unwrap().len(), 2);

        // Bring link back up and sync
        // One route should be back to 3 routes
        dpd.links.lock().unwrap().get_mut(1).unwrap().link_state =
            LinkState::Up;
        do_sync();
        assert_eq!(ddm.tunnel_originated.lock().unwrap().len(), 3);
        assert_eq!(dpd.v4_routes.lock().unwrap().len(), 3);

        tx.send(()).unwrap();
    });

    // There are two lights?
    done.recv().unwrap();
}

fn test_setup(
    router: RouterId,
    tep: Ipv6Addr,
    dpd: &TestDpd,
    ddm: &TestDdm,
    rib: &mut Rib,
) {
    // Set up dpd links
    dpd.links.lock().unwrap().push(dpd_client::types::Link {
        address: dpd_client::types::MacAddr {
            a: [1, 1, 1, 1, 1, 1],
        },
        asic_id: 3,
        autoneg: false,
        enabled: true,
        fec: None,
        fsm_state: String::default(),
        ipv6_enabled: false,
        kr: false,
        link_id: LinkId(0),
        link_state: LinkState::Up,
        media: PortMedia::Optical,
        port_id: PortId::Qsfp("qsfp0".parse().unwrap()),
        prbs: PortPrbsMode::Mission,
        presence: true,
        speed: PortSpeed::Speed100G,
        tofino_connector: 5,
    });
    dpd.links.lock().unwrap().push(dpd_client::types::Link {
        address: dpd_client::types::MacAddr {
            a: [2, 2, 2, 2, 2, 2],
        },
        asic_id: 4,
        autoneg: false,
        enabled: true,
        fec: None,
        fsm_state: String::default(),
        ipv6_enabled: false,
        kr: false,
        link_id: LinkId(0),
        link_state: LinkState::Up,
        media: PortMedia::Optical,
        port_id: PortId::Qsfp("qsfp1".parse().unwrap()),
        prbs: PortPrbsMode::Mission,
        presence: true,
        speed: PortSpeed::Speed100G,
        tofino_connector: 6,
    });

    // Add three initial prefixes to dpd
    dpd.v4_routes.lock().unwrap().insert(
        "1.0.0.0/24".parse().unwrap(),
        vec![dpd_client::types::Route::V4(Ipv4Route {
            link_id: LinkId(0),
            port_id: PortId::Qsfp("qsfp0".parse().unwrap()),
            tag: String::from("mg_lower_test"),
            tgt_ip: "1.0.0.1".parse().unwrap(),
            vlan_id: None,
        })],
    );
    dpd.v4_routes.lock().unwrap().insert(
        "2.0.0.0/24".parse().unwrap(),
        vec![dpd_client::types::Route::V4(Ipv4Route {
            link_id: LinkId(0),
            port_id: PortId::Qsfp("qsfp0".parse().unwrap()),
            tag: String::from("mg_lower_test"),
            tgt_ip: "2.0.0.1".parse().unwrap(),
            vlan_id: None,
        })],
    );
    dpd.v4_routes.lock().unwrap().insert(
        "3.0.0.0/24".parse().unwrap(),
        vec![dpd_client::types::Route::V4(Ipv4Route {
            link_id: LinkId(0),
            port_id: PortId::Qsfp("qsfp1".parse().unwrap()),
            tag: String::from("mg_lower_test"),
            tgt_ip: "3.0.0.1".parse().unwrap(),
            vlan_id: None,
        })],
    );

    // Add three initial prefixes to ddm
    ddm.tunnel_originated.lock().unwrap().push(TunnelOrigin {
        boundary_addr: tep,
        metric: 0,
        overlay_prefix: "1.0.0.0/24".parse().unwrap(),
        vni: 1701,
        router_id: Some(router.0),
    });
    ddm.tunnel_originated.lock().unwrap().push(TunnelOrigin {
        boundary_addr: tep,
        metric: 0,
        overlay_prefix: "2.0.0.0/24".parse().unwrap(),
        vni: 1701,
        router_id: Some(router.0),
    });
    ddm.tunnel_originated.lock().unwrap().push(TunnelOrigin {
        boundary_addr: tep,
        metric: 0,
        overlay_prefix: "3.0.0.0/24".parse().unwrap(),
        vni: 1701,
        router_id: Some(router.0),
    });

    // Add three initial prefixes to rib
    rib.insert(
        "1.0.0.0/24".parse::<Ipv4Net>().unwrap().into(),
        vec![Path {
            nexthop: "1.0.0.1".parse().unwrap(),
            nexthop_interface: None,
            shutdown: false,
            rib_priority: 10,
            bgp: None,
            vlan_id: None,
        }]
        .into_iter()
        .collect(),
    );
    rib.insert(
        "2.0.0.0/24".parse::<Ipv4Net>().unwrap().into(),
        vec![Path {
            nexthop: "2.0.0.1".parse().unwrap(),
            nexthop_interface: None,
            shutdown: false,
            rib_priority: 10,
            bgp: None,
            vlan_id: None,
        }]
        .into_iter()
        .collect(),
    );
    rib.insert(
        "3.0.0.0/24".parse::<Ipv4Net>().unwrap().into(),
        vec![Path {
            nexthop: "3.0.0.1".parse().unwrap(),
            nexthop_interface: None,
            shutdown: false,
            rib_priority: 10,
            bgp: None,
            vlan_id: None,
        }]
        .into_iter()
        .collect(),
    );
}

/// Set up the minimal link state that v4-over-v6 tests need.
/// All tests use qsfp0/link 0 as the port backing the v6 nexthop.
fn v4_over_v6_link_setup(dpd: &TestDpd) {
    dpd.links.lock().unwrap().push(dpd_client::types::Link {
        address: dpd_client::types::MacAddr {
            a: [1, 1, 1, 1, 1, 1],
        },
        asic_id: 3,
        autoneg: false,
        enabled: true,
        fec: None,
        fsm_state: String::default(),
        ipv6_enabled: false,
        kr: false,
        link_id: LinkId(0),
        link_state: LinkState::Up,
        media: PortMedia::Optical,
        port_id: PortId::Qsfp("qsfp0".parse().unwrap()),
        prbs: PortPrbsMode::Mission,
        presence: true,
        speed: PortSpeed::Speed100G,
        tofino_connector: 5,
    });
}

/// Bug 1 + Bug 2: `get_routes_for_prefix` drops `Route::V6` entries that
/// are stored under an IPv4 prefix, so the caller never sees v4-over-v6
/// routes that are actually installed on the ASIC.
#[tokio::test]
async fn sync_v4_over_v6_readback() {
    let rt = Arc::new(tokio::runtime::Handle::current());
    let (tx, done) = std::sync::mpsc::channel::<()>();

    std::thread::spawn(move || {
        let dpd = TestDpd::default();
        v4_over_v6_link_setup(&dpd);

        // Pre-populate dpd with a Route::V6 entry for an IPv4 prefix,
        // exactly as `route_ipv4_over_ipv6_add` would store it.
        dpd.v4_routes.lock().unwrap().insert(
            "5.0.0.0/24".parse().unwrap(),
            vec![Route::V6(Ipv6Route {
                link_id: LinkId(0),
                port_id: PortId::Qsfp("qsfp0".parse().unwrap()),
                tag: String::from("mg-lower"),
                tgt_ip: "fe80::1".parse().unwrap(),
                vlan_id: None,
            })],
        );

        let log = util::test::logger();
        let prefix: IpNet = "5.0.0.0/24".parse::<Ipv4Net>().unwrap().into();

        let result = get_routes_for_prefix(
            RouterId::new_random(),
            &dpd,
            &prefix,
            rt.clone(),
            log.clone(),
        )
        .expect("get_routes_for_prefix should not error");

        // The route we just inserted must be visible.  With the current
        // bugs the result is empty because Route::V6 is dropped.
        assert_eq!(
            result.len(),
            1,
            "v4-over-v6 route should appear in dpd_current, got {} entries",
            result.len()
        );

        tx.send(()).unwrap();
    });

    done.recv().unwrap();
}

/// Symptom of Bug 1 + 2: because `get_routes_for_prefix` never returns the
/// v4-over-v6 route, every `sync_prefix` call sees it as missing and adds
/// it again, causing the ASIC route count to grow without bound.
#[tokio::test]
async fn sync_v4_over_v6_idempotent() {
    let rt = Arc::new(tokio::runtime::Handle::current());
    let (tx, done) = std::sync::mpsc::channel::<()>();

    std::thread::spawn(move || {
        let dpd = TestDpd::default();
        let ddm = TestDdm::default();
        let sw = TestSwitchZone {
            routes: HashMap::default(),
            default_ifname: Some(String::from("tfportqsfp0_0")),
            default_gw: "1.2.3.4".parse().unwrap(),
        };
        let tep: Ipv6Addr = "fd00:a:b:c::d".parse().unwrap();
        v4_over_v6_link_setup(&dpd);

        // RIB contains one v4-over-v6 path for 5.0.0.0/24.
        let mut rib = Rib::default();
        rib.insert(
            "5.0.0.0/24".parse::<Ipv4Net>().unwrap().into(),
            vec![Path {
                nexthop: "fe80::1".parse().unwrap(),
                nexthop_interface: Some(String::from("tfportqsfp0_0")),
                shutdown: false,
                rib_priority: 10,
                bgp: None,
                vlan_id: None,
            }]
            .into_iter()
            .collect(),
        );

        let router = RouterId::new_random();

        // Need a ddm tunnel entry so the overlay bookkeeping is satisfied.
        ddm.tunnel_originated.lock().unwrap().push(TunnelOrigin {
            boundary_addr: tep,
            metric: 0,
            overlay_prefix: "5.0.0.0/24".parse().unwrap(),
            vni: 1701,
            router_id: Some(router.0),
        });

        let log = util::test::logger();
        let prefix: IpNet = "5.0.0.0/24".parse::<Ipv4Net>().unwrap().into();

        // First sync — installs the route.
        crate::sync_prefix(
            router, tep, &rib, &prefix, &dpd, &ddm, &sw, &log, &rt,
        )
        .expect("first sync_prefix");

        let count_after_first = dpd
            .v4_routes
            .lock()
            .unwrap()
            .get(&"5.0.0.0/24".parse().unwrap())
            .map(|v| v.len())
            .unwrap_or(0);
        assert_eq!(count_after_first, 1, "first sync should install 1 route");

        // Second sync — should be a no-op; route is already on the ASIC.
        crate::sync_prefix(
            router, tep, &rib, &prefix, &dpd, &ddm, &sw, &log, &rt,
        )
        .expect("second sync_prefix");

        let count_after_second = dpd
            .v4_routes
            .lock()
            .unwrap()
            .get(&"5.0.0.0/24".parse().unwrap())
            .map(|v| v.len())
            .unwrap_or(0);
        assert_eq!(
            count_after_second, 1,
            "second sync should not add a duplicate; got {} routes",
            count_after_second
        );

        tx.send(()).unwrap();
    });

    done.recv().unwrap();
}

/// Bug 3 (compounded by Bug 1): a v4-over-v6 route that is no longer in
/// the RIB should be deleted from the ASIC.  The current code cannot
/// delete it because (a) `get_routes_for_prefix` never reads it back, so
/// it never appears in `dpd_current`, and (b) even if it did, the delete
/// loop in `update_dendrite` skips `IpAddr::V6` nexthops.
#[tokio::test]
async fn sync_v4_over_v6_removal() {
    let rt = Arc::new(tokio::runtime::Handle::current());
    let (tx, done) = std::sync::mpsc::channel::<()>();

    std::thread::spawn(move || {
        let dpd = TestDpd::default();
        let ddm = TestDdm::default();
        let sw = TestSwitchZone {
            routes: HashMap::default(),
            default_ifname: Some(String::from("tfportqsfp0_0")),
            default_gw: "1.2.3.4".parse().unwrap(),
        };
        let tep: Ipv6Addr = "fd00:a:b:c::d".parse().unwrap();
        v4_over_v6_link_setup(&dpd);

        // Pre-populate dpd with a v4-over-v6 route (as if a prior sync
        // installed it).
        dpd.v4_routes.lock().unwrap().insert(
            "5.0.0.0/24".parse().unwrap(),
            vec![Route::V6(Ipv6Route {
                link_id: LinkId(0),
                port_id: PortId::Qsfp("qsfp0".parse().unwrap()),
                tag: String::from("mg-lower"),
                tgt_ip: "fe80::1".parse().unwrap(),
                vlan_id: None,
            })],
        );

        // RIB is empty for this prefix — the route should be withdrawn.
        let rib = Rib::default();

        let log = util::test::logger();
        let prefix: IpNet = "5.0.0.0/24".parse::<Ipv4Net>().unwrap().into();

        crate::sync_prefix(
            RouterId::new_random(),
            tep,
            &rib,
            &prefix,
            &dpd,
            &ddm,
            &sw,
            &log,
            &rt,
        )
        .expect("sync_prefix");

        // The v4-over-v6 route should have been removed.
        let remaining = dpd
            .v4_routes
            .lock()
            .unwrap()
            .get(&"5.0.0.0/24".parse().unwrap())
            .map(|v| v.len())
            .unwrap_or(0);
        assert_eq!(
            remaining, 0,
            "stale v4-over-v6 route should be deleted, but {} remain",
            remaining
        );

        tx.send(()).unwrap();
    });

    done.recv().unwrap();
}

/// Mixed-AF test: a prefix has both a standard v4 route and a v4-over-v6
/// route, both present in the RIB.  After `sync_prefix` the ASIC should
/// hold exactly 2 routes — one V4, one V6.  The v4-over-v6 bugs must not
/// cause extra additions or corrupt the standard v4 route.
#[tokio::test]
async fn sync_mixed_v4_and_v4_over_v6() {
    let rt = Arc::new(tokio::runtime::Handle::current());
    let (tx, done) = std::sync::mpsc::channel::<()>();

    std::thread::spawn(move || {
        let dpd = TestDpd::default();
        let ddm = TestDdm::default();
        let sw = TestSwitchZone {
            routes: HashMap::default(),
            default_ifname: Some(String::from("tfportqsfp0_0")),
            default_gw: "1.2.3.4".parse().unwrap(),
        };
        let tep: Ipv6Addr = "fd00:a:b:c::d".parse().unwrap();
        v4_over_v6_link_setup(&dpd);

        // Pre-populate dpd with both a V4 and a V6 route under the same
        // IPv4 prefix.
        dpd.v4_routes.lock().unwrap().insert(
            "5.0.0.0/24".parse().unwrap(),
            vec![
                Route::V4(Ipv4Route {
                    link_id: LinkId(0),
                    port_id: PortId::Qsfp("qsfp0".parse().unwrap()),
                    tag: String::from("mg-lower"),
                    tgt_ip: "10.0.0.1".parse().unwrap(),
                    vlan_id: None,
                }),
                Route::V6(Ipv6Route {
                    link_id: LinkId(0),
                    port_id: PortId::Qsfp("qsfp0".parse().unwrap()),
                    tag: String::from("mg-lower"),
                    tgt_ip: "fe80::1".parse().unwrap(),
                    vlan_id: None,
                }),
            ],
        );

        // RIB has matching paths for both routes.
        let mut rib = Rib::default();
        rib.insert(
            "5.0.0.0/24".parse::<Ipv4Net>().unwrap().into(),
            vec![
                Path {
                    nexthop: "10.0.0.1".parse().unwrap(),
                    nexthop_interface: None,
                    shutdown: false,
                    rib_priority: 10,
                    bgp: None,
                    vlan_id: None,
                },
                Path {
                    nexthop: "fe80::1".parse().unwrap(),
                    nexthop_interface: Some(String::from("tfportqsfp0_0")),
                    shutdown: false,
                    rib_priority: 10,
                    bgp: None,
                    vlan_id: None,
                },
            ]
            .into_iter()
            .collect(),
        );

        let router = RouterId::new_random();

        // DDM tunnel entry for the prefix.
        ddm.tunnel_originated.lock().unwrap().push(TunnelOrigin {
            boundary_addr: tep,
            metric: 0,
            overlay_prefix: "5.0.0.0/24".parse().unwrap(),
            vni: 1701,
            router_id: Some(router.0),
        });

        let log = util::test::logger();
        let prefix: IpNet = "5.0.0.0/24".parse::<Ipv4Net>().unwrap().into();

        crate::sync_prefix(
            router,
            tep,
            &rib,
            &prefix,
            &dpd,
            &ddm,
            &sw,
            &log,
            &rt,
        )
        .expect("sync_prefix");

        // Should still be exactly 2 routes — one V4, one V6.
        let count = dpd
            .v4_routes
            .lock()
            .unwrap()
            .get(&"5.0.0.0/24".parse().unwrap())
            .map(|v| v.len())
            .unwrap_or(0);
        assert_eq!(
            count, 2,
            "mixed prefix should have exactly 2 routes after sync, got {}",
            count
        );

        tx.send(()).unwrap();
    });

    done.recv().unwrap();
}

fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !cond() {
        if Instant::now() > deadline {
            panic!("timed out waiting for {what}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Two routers, each with its own mg-lower `run` loop against a shared
/// platform: routes land with each router's own id and tep, and shutting one
/// router down withdraws only its platform state.
#[tokio::test]
async fn two_router_lifecycle() {
    let rt = Arc::new(tokio::runtime::Handle::current());
    let (tx, done) = std::sync::mpsc::channel::<()>();

    std::thread::spawn(move || {
        let log = util::test::logger();
        // dpd/ddm are shared across routers, like the real platform.
        let dpd = Arc::new(TestDpd::default());
        v4_over_v6_link_setup(&dpd);
        let ddm = Arc::new(TestDdm::default());

        let db = rdb::test::get_test_db("mg_lower_two_router", log.clone())
            .expect("create test db");
        let tep1: Ipv6Addr = "fd00::1".parse().unwrap();
        let tep2: Ipv6Addr = "fd00::2".parse().unwrap();
        let mk_router = |name: &str, tep| {
            db.db()
                .create_router(RouterInfo {
                    id: RouterId::new_random(),
                    name: name.to_string(),
                    tep,
                })
                .expect("create router")
        };
        let r1 = mk_router("r1", tep1);
        let r2 = mk_router("r2", tep2);

        // One static route per router, populated before the run loops start
        // so the initial full_sync picks them up.
        let mk_route = |prefix: &str, nexthop: &str| StaticRouteKey {
            prefix: prefix.parse().unwrap(),
            nexthop: nexthop.parse().unwrap(),
            vlan_id: None,
            rib_priority: 10,
        };
        r1.add_static_routes(&[mk_route("1.0.0.0/24", "1.0.0.1")])
            .expect("add r1 static route");
        r2.add_static_routes(&[mk_route("2.0.0.0/24", "2.0.0.1")])
            .expect("add r2 static route");

        let spawn_lower = |rdb: rdb::RouterDb, tep, flag: Arc<AtomicBool>| {
            let dpd = dpd.clone();
            let ddm = ddm.clone();
            let log = log.clone();
            let rt = rt.clone();
            std::thread::spawn(move || {
                let sw = TestSwitchZone {
                    routes: HashMap::default(),
                    default_ifname: Some(String::from("tfportqsfp0_0")),
                    default_gw: "1.2.3.4".parse().unwrap(),
                };
                crate::run(
                    tep,
                    rdb,
                    log,
                    Arc::new(MgLowerStats::default()),
                    rt,
                    flag,
                    &*dpd,
                    &*ddm,
                    &sw,
                );
            })
        };
        let shut1 = Arc::new(AtomicBool::new(false));
        let shut2 = Arc::new(AtomicBool::new(false));
        let j1 = spawn_lower(r1.clone(), tep1, shut1.clone());
        let j2 = spawn_lower(r2.clone(), tep2, shut2.clone());

        wait_until("both routers' routes to sync", || {
            dpd.v4_routes.lock().unwrap().len() == 2
                && ddm.tunnel_originated.lock().unwrap().len() == 2
        });

        // Each tunnel origin carries its own router's tep.
        {
            let origins = ddm.tunnel_originated.lock().unwrap();
            let tep_for = |prefix: &str| {
                origins
                    .iter()
                    .find(|x| {
                        x.overlay_prefix == prefix.parse::<IpNet>().unwrap()
                    })
                    .expect("tunnel origin for prefix")
                    .boundary_addr
            };
            assert_eq!(tep_for("1.0.0.0/24"), tep1);
            assert_eq!(tep_for("2.0.0.0/24"), tep2);
        }

        // Every dpd route call carried one of the two router ids, and both
        // routers made calls.
        {
            let seen = dpd.route_call_routers.lock().unwrap();
            assert!(
                seen.iter().all(|x| *x == r1.id() || *x == r2.id()),
                "dpd route call with unknown router id"
            );
            assert!(seen.contains(&r1.id()));
            assert!(seen.contains(&r2.id()));
        }

        // Shut down r1: its ASIC routes and tunnel origins are withdrawn,
        // r2's are untouched.
        shut1.store(true, Ordering::Relaxed);
        j1.join().expect("join r1 mg-lower");
        {
            let routes = dpd.v4_routes.lock().unwrap();
            assert_eq!(routes.len(), 1);
            assert!(routes.contains_key(&"2.0.0.0/24".parse().unwrap()));
            let origins = ddm.tunnel_originated.lock().unwrap();
            assert_eq!(origins.len(), 1);
            assert!(origins.iter().all(|x| x.boundary_addr == tep2));
        }

        shut2.store(true, Ordering::Relaxed);
        j2.join().expect("join r2 mg-lower");
        assert!(dpd.v4_routes.lock().unwrap().is_empty());
        assert!(ddm.tunnel_originated.lock().unwrap().is_empty());

        tx.send(()).unwrap();
    });

    done.recv().unwrap();
}
