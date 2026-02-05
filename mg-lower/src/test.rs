use std::{collections::HashMap, net::Ipv6Addr, sync::Arc};

use ddm_admin_client::types::TunnelOrigin;
use dpd_client::types::{
    Ipv4Route, Ipv6Route, LinkId, LinkState, PortId, PortMedia, PortPrbsMode,
    PortSpeed, Route,
};
use rdb::{Path, Prefix4, db::Rib};

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

        test_setup(tep, &dpd, &ddm, &mut rib);

        // extra prefix should get picked up by tunnel routing
        rib.insert(
            "4.0.0.0/24".parse::<Prefix4>().unwrap().into(),
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
            tep,
            &rib,
            &"4.0.0.0/24".parse::<Prefix4>().unwrap().into(),
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

        test_setup(tep, &dpd, &ddm, &mut rib);

        let do_sync = || {
            crate::sync_prefix(
                tep,
                &rib,
                &"3.0.0.0/24".parse::<Prefix4>().unwrap().into(),
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

fn test_setup(tep: Ipv6Addr, dpd: &TestDpd, ddm: &TestDdm, rib: &mut Rib) {
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
    });
    ddm.tunnel_originated.lock().unwrap().push(TunnelOrigin {
        boundary_addr: tep,
        metric: 0,
        overlay_prefix: "2.0.0.0/24".parse().unwrap(),
        vni: 1701,
    });
    ddm.tunnel_originated.lock().unwrap().push(TunnelOrigin {
        boundary_addr: tep,
        metric: 0,
        overlay_prefix: "3.0.0.0/24".parse().unwrap(),
        vni: 1701,
    });

    // Add three initial prefixes to rib
    rib.insert(
        "1.0.0.0/24".parse::<Prefix4>().unwrap().into(),
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
        "2.0.0.0/24".parse::<Prefix4>().unwrap().into(),
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
        "3.0.0.0/24".parse::<Prefix4>().unwrap().into(),
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
        let prefix: rdb::Prefix =
            "5.0.0.0/24".parse::<Prefix4>().unwrap().into();

        let result =
            get_routes_for_prefix(&dpd, &prefix, rt.clone(), log.clone())
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
            "5.0.0.0/24".parse::<Prefix4>().unwrap().into(),
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

        // Need a ddm tunnel entry so the overlay bookkeeping is satisfied.
        ddm.tunnel_originated.lock().unwrap().push(TunnelOrigin {
            boundary_addr: tep,
            metric: 0,
            overlay_prefix: "5.0.0.0/24".parse().unwrap(),
            vni: 1701,
        });

        let log = util::test::logger();
        let prefix: rdb::Prefix =
            "5.0.0.0/24".parse::<Prefix4>().unwrap().into();

        // First sync — installs the route.
        crate::sync_prefix(tep, &rib, &prefix, &dpd, &ddm, &sw, &log, &rt)
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
        crate::sync_prefix(tep, &rib, &prefix, &dpd, &ddm, &sw, &log, &rt)
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
        let prefix: rdb::Prefix =
            "5.0.0.0/24".parse::<Prefix4>().unwrap().into();

        crate::sync_prefix(tep, &rib, &prefix, &dpd, &ddm, &sw, &log, &rt)
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
            "5.0.0.0/24".parse::<Prefix4>().unwrap().into(),
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
        });

        let log = util::test::logger();
        let prefix: rdb::Prefix =
            "5.0.0.0/24".parse::<Prefix4>().unwrap().into();

        crate::sync_prefix(tep, &rib, &prefix, &dpd, &ddm, &sw, &log, &rt)
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
