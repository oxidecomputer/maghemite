use std::{collections::HashMap, net::Ipv6Addr, sync::Arc};

use ddm_admin_client::types::TunnelOrigin;
use dpd_client::types::{
    Ipv4Route, LinkId, LinkState, PortId, PortMedia, PortPrbsMode, PortSpeed,
};
use rdb::{db::Rib, Path, Prefix4};

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
        vec![Ipv4Route {
            link_id: LinkId(0),
            port_id: PortId::Qsfp("qsfp0".parse().unwrap()),
            tag: String::from("mg_lower_test"),
            tgt_ip: "1.0.0.1".parse().unwrap(),
            vlan_id: None,
        }],
    );
    dpd.v4_routes.lock().unwrap().insert(
        "2.0.0.0/24".parse().unwrap(),
        vec![Ipv4Route {
            link_id: LinkId(0),
            port_id: PortId::Qsfp("qsfp0".parse().unwrap()),
            tag: String::from("mg_lower_test"),
            tgt_ip: "2.0.0.1".parse().unwrap(),
            vlan_id: None,
        }],
    );
    dpd.v4_routes.lock().unwrap().insert(
        "3.0.0.0/24".parse().unwrap(),
        vec![Ipv4Route {
            link_id: LinkId(0),
            port_id: PortId::Qsfp("qsfp1".parse().unwrap()),
            tag: String::from("mg_lower_test"),
            tgt_ip: "3.0.0.1".parse().unwrap(),
            vlan_id: None,
        }],
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
            shutdown: false,
            rib_priority: 10,
            bgp: None,
            vlan_id: None,
        }]
        .into_iter()
        .collect(),
    );
}
