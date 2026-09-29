use std::{
    collections::{BTreeSet, HashMap},
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

/// The router used by tests that call the sync functions directly.
const TABLE: RouterId = RouterId(uuid::Uuid::from_u128(1));

#[tokio::test]
async fn sync_prefix_test() {
    let rt = Arc::new(tokio::runtime::Handle::current());
    let (tx, done) = std::sync::mpsc::channel::<()>();

    std::thread::spawn(move || {
        let dpd = TestDpd::default();
        dpd.routers.lock().unwrap().insert(TABLE);
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
            TABLE,
            Some(router.0),
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
        assert_eq!(dpd.v4_count(), 4);

        // Every dpd route call must carry this router's id.
        let routers_seen = dpd.route_call_routers.lock().unwrap();
        assert!(!routers_seen.is_empty());
        assert!(routers_seen.iter().all(|x| *x == TABLE));

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
        dpd.routers.lock().unwrap().insert(TABLE);
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
                TABLE,
                Some(router.0),
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
        assert_eq!(dpd.v4_count(), 3);

        // Take down a link and sync
        // One route should be gone with a link down
        dpd.links.lock().unwrap().get_mut(1).unwrap().link_state =
            LinkState::Down;
        do_sync();
        assert_eq!(ddm.tunnel_originated.lock().unwrap().len(), 2);
        assert_eq!(dpd.v4_count(), 2);

        // Bring link back up and sync
        // One route should be back to 3 routes
        dpd.links.lock().unwrap().get_mut(1).unwrap().link_state =
            LinkState::Up;
        do_sync();
        assert_eq!(ddm.tunnel_originated.lock().unwrap().len(), 3);
        assert_eq!(dpd.v4_count(), 3);

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
    dpd.insert_v4(
        TABLE,
        "1.0.0.0/24".parse().unwrap(),
        vec![dpd_client::types::Route::V4(Ipv4Route {
            link_id: LinkId(0),
            port_id: PortId::Qsfp("qsfp0".parse().unwrap()),
            tag: String::from("mg_lower_test"),
            tgt_ip: "1.0.0.1".parse().unwrap(),
            vlan_id: None,
        })],
    );
    dpd.insert_v4(
        TABLE,
        "2.0.0.0/24".parse().unwrap(),
        vec![dpd_client::types::Route::V4(Ipv4Route {
            link_id: LinkId(0),
            port_id: PortId::Qsfp("qsfp0".parse().unwrap()),
            tag: String::from("mg_lower_test"),
            tgt_ip: "2.0.0.1".parse().unwrap(),
            vlan_id: None,
        })],
    );
    dpd.insert_v4(
        TABLE,
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
        dpd.routers.lock().unwrap().insert(TABLE);
        v4_over_v6_link_setup(&dpd);

        // Pre-populate dpd with a Route::V6 entry for an IPv4 prefix,
        // exactly as `route_ipv4_over_ipv6_add` would store it.
        dpd.insert_v4(
            TABLE,
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
            TABLE,
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
        dpd.routers.lock().unwrap().insert(TABLE);
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
            TABLE,
            Some(router.0),
            tep,
            &rib,
            &prefix,
            &dpd,
            &ddm,
            &sw,
            &log,
            &rt,
        )
        .expect("first sync_prefix");

        let count_after_first =
            dpd.v4_targets(TABLE, &"5.0.0.0/24".parse().unwrap()).len();
        assert_eq!(count_after_first, 1, "first sync should install 1 route");

        // Second sync — should be a no-op; route is already on the ASIC.
        crate::sync_prefix(
            TABLE,
            Some(router.0),
            tep,
            &rib,
            &prefix,
            &dpd,
            &ddm,
            &sw,
            &log,
            &rt,
        )
        .expect("second sync_prefix");

        let count_after_second =
            dpd.v4_targets(TABLE, &"5.0.0.0/24".parse().unwrap()).len();
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
        dpd.routers.lock().unwrap().insert(TABLE);
        let ddm = TestDdm::default();
        let sw = TestSwitchZone {
            routes: HashMap::default(),
            default_ifname: Some(String::from("tfportqsfp0_0")),
            default_gw: "1.2.3.4".parse().unwrap(),
        };
        let tep: Ipv6Addr = "fd00:a:b:c::d".parse().unwrap();
        v4_over_v6_link_setup(&dpd);

        let router = RouterId::new_random();

        // Pre-populate dpd with a v4-over-v6 route (as if a prior sync
        // installed it).
        dpd.insert_v4(
            TABLE,
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
            TABLE,
            Some(router.0),
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
        let remaining =
            dpd.v4_targets(TABLE, &"5.0.0.0/24".parse().unwrap()).len();
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
        dpd.routers.lock().unwrap().insert(TABLE);
        let ddm = TestDdm::default();
        let sw = TestSwitchZone {
            routes: HashMap::default(),
            default_ifname: Some(String::from("tfportqsfp0_0")),
            default_gw: "1.2.3.4".parse().unwrap(),
        };
        let tep: Ipv6Addr = "fd00:a:b:c::d".parse().unwrap();
        v4_over_v6_link_setup(&dpd);

        let router = RouterId::new_random();

        // Pre-populate dpd with both a V4 and a V6 route under the same
        // IPv4 prefix.
        dpd.insert_v4(
            TABLE,
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
            TABLE,
            Some(router.0),
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
        let count = dpd.v4_targets(TABLE, &"5.0.0.0/24".parse().unwrap()).len();
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

        let lower = |rdb: &rdb::RouterDb, tep| {
            let (dpd, ddm, rt) = (dpd.clone(), ddm.clone(), rt.clone());
            start_lower(rdb.clone(), tep, dpd, ddm, rt)
        };
        let (shut1, j1) = lower(&r1, tep1);
        let (shut2, j2) = lower(&r2, tep2);

        wait_until("both routers' routes to sync", || {
            dpd.v4_count() == 2
                && ddm.tunnel_originated.lock().unwrap().len() == 2
        });

        // Both routers' TEPs are claimed on the ASIC, each on its own table.
        assert_eq!(dpd.loopbacks(r1.id()), vec![tep1]);
        assert_eq!(dpd.loopbacks(r2.id()), vec![tep2]);

        // ...and each TEP's underlay /64 is originated into ddm.
        let tep_net = |tep: Ipv6Addr| oxnet::Ipv6Net::new(tep, 64).unwrap();
        {
            let originated = ddm.originated.lock().unwrap();
            assert_eq!(originated.len(), 2, "{originated:?}");
            assert!(originated.contains(&tep_net(tep1)));
            assert!(originated.contains(&tep_net(tep2)));
        }

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
            let (t1, t2) = (r1.id(), r2.id());
            assert!(
                seen.iter().all(|x| *x == t1 || *x == t2),
                "dpd route call with unknown router id"
            );
            assert!(seen.contains(&t1));
            assert!(seen.contains(&t2));
        }

        // Shut down r1: it is deleted from dpd, its tunnel origins are
        // withdrawn, and r2's state is untouched.
        shut1.store(true, Ordering::Relaxed);
        j1.join().expect("join r1 mg-lower");
        {
            assert_eq!(
                *dpd.routers.lock().unwrap(),
                BTreeSet::from([rdb::DEFAULT_ROUTER_ID, r2.id()])
            );
            assert_eq!(dpd.v4_count(), 1);
            assert_eq!(
                dpd.v4_targets(r2.id(), &"2.0.0.0/24".parse().unwrap())
                    .len(),
                1
            );
            let origins = ddm.tunnel_originated.lock().unwrap();
            assert_eq!(origins.len(), 1);
            assert!(origins.iter().all(|x| x.boundary_addr == tep2));
            assert!(dpd.loopbacks(r1.id()).is_empty());
            assert_eq!(dpd.loopbacks(r2.id()), vec![tep2]);
            // r1's TEP underlay /64 is withdrawn from ddm; r2's stays.
            let originated = ddm.originated.lock().unwrap();
            assert_eq!(*originated, vec![tep_net(tep2)]);
        }

        shut2.store(true, Ordering::Relaxed);
        j2.join().expect("join r2 mg-lower");
        assert_eq!(dpd.v4_count(), 0);
        assert!(ddm.tunnel_originated.lock().unwrap().is_empty());
        assert!(dpd.loopbacks(r2.id()).is_empty());
        assert!(ddm.originated.lock().unwrap().is_empty());

        tx.send(()).unwrap();
    });

    done.recv().unwrap();
}

/// A ddm failure while withdrawing the TEP underlay /64 at teardown is
/// logged and leaves the prefix in place; it does not abort the rest of the
/// withdraw (the ASIC state is still cleaned). Documented limitation: the
/// stale /64 is not retried.
#[tokio::test]
async fn tep_underlay_withdraw_failure_is_tolerated() {
    let rt = Arc::new(tokio::runtime::Handle::current());
    let (tx, done) = std::sync::mpsc::channel::<()>();

    std::thread::spawn(move || {
        let log = util::test::logger();
        let dpd = Arc::new(TestDpd::default());
        v4_over_v6_link_setup(&dpd);
        let ddm = Arc::new(TestDdm::default());

        let db = rdb::test::get_test_db(
            "mg_lower_tep_underlay_withdraw_failure",
            log.clone(),
        )
        .expect("create test db");
        let tep: Ipv6Addr = "fd00::1".parse().unwrap();
        let r1 = db
            .db()
            .create_router(RouterInfo {
                id: RouterId::new_random(),
                name: "r1".to_string(),
                tep,
            })
            .expect("create router");
        r1.add_static_routes(&[StaticRouteKey {
            prefix: "1.0.0.0/24".parse().unwrap(),
            nexthop: "1.0.0.1".parse().unwrap(),
            vlan_id: None,
            rib_priority: 10,
        }])
        .expect("add static route");

        let (shut, j) =
            start_lower(r1.clone(), tep, dpd.clone(), ddm.clone(), rt.clone());

        let tep_net = oxnet::Ipv6Net::new(tep, 64).unwrap();
        wait_until("route and TEP /64 to sync", || {
            dpd.v4_count() == 1
                && ddm.originated.lock().unwrap().contains(&tep_net)
        });

        // Inject one ddm failure for the underlay withdraw, then shut down.
        *ddm.fail_withdraw_prefixes.lock().unwrap() = 1;
        shut.store(true, Ordering::Relaxed);
        j.join().expect("join mg-lower");

        // ASIC state is fully withdrawn; the /64 whose withdraw failed is
        // still originated.
        assert_eq!(dpd.v4_count(), 0);
        assert!(dpd.loopbacks(r1.id()).is_empty());
        assert!(ddm.tunnel_originated.lock().unwrap().is_empty());
        assert_eq!(*ddm.originated.lock().unwrap(), vec![tep_net]);
        assert_eq!(*ddm.fail_withdraw_prefixes.lock().unwrap(), 0);

        tx.send(()).unwrap();
    });

    done.recv().unwrap();
}

/// Start `crate::run` for one router on its own thread. Returns the
/// shutdown flag and the thread's join handle.
fn start_lower(
    rdb: rdb::RouterDb,
    tep: Ipv6Addr,
    dpd: Arc<TestDpd>,
    ddm: Arc<TestDdm>,
    rt: Arc<tokio::runtime::Handle>,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let shut = Arc::new(AtomicBool::new(false));
    let flag = shut.clone();
    let j = std::thread::spawn(move || {
        let sw = TestSwitchZone {
            routes: HashMap::default(),
            default_ifname: Some(String::from("tfportqsfp0_0")),
            default_gw: "1.2.3.4".parse().unwrap(),
        };
        crate::run(
            tep,
            rdb,
            util::test::logger(),
            Arc::new(MgLowerStats::default()),
            rt,
            flag,
            &*dpd,
            &*ddm,
            &sw,
        );
    });
    (shut, j)
}

/// Shutting down the default router withdraws its routes one by one and
/// leaves the router itself in dpd.
#[tokio::test]
async fn default_router_is_never_deleted_from_dpd() {
    let rt = Arc::new(tokio::runtime::Handle::current());
    let (tx, done) = std::sync::mpsc::channel::<()>();

    std::thread::spawn(move || {
        let log = util::test::logger();
        let dpd = Arc::new(TestDpd::default());
        v4_over_v6_link_setup(&dpd);
        let ddm = Arc::new(TestDdm::default());

        let db = rdb::test::get_test_db("mg_lower_default_router", log)
            .expect("create test db");
        let default = db.router().clone();
        default
            .add_static_routes(&[StaticRouteKey {
                prefix: "1.0.0.0/24".parse().unwrap(),
                nexthop: "1.0.0.1".parse().unwrap(),
                vlan_id: None,
                rib_priority: 10,
            }])
            .expect("add static route");

        let tep: Ipv6Addr = "fd00::1".parse().unwrap();
        let (shut, j) =
            start_lower(default, tep, dpd.clone(), ddm.clone(), rt.clone());
        wait_until("the default router's route", || dpd.v4_count() == 1);

        shut.store(true, Ordering::Relaxed);
        j.join().expect("join mg-lower");
        assert_eq!(dpd.v4_count(), 0);
        assert!(dpd.loopbacks(rdb::DEFAULT_ROUTER_ID).is_empty());
        assert!(
            dpd.routers
                .lock()
                .unwrap()
                .contains(&rdb::DEFAULT_ROUTER_ID)
        );

        tx.send(()).unwrap();
    });

    done.recv().unwrap();
}
