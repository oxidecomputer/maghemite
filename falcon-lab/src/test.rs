//! Tests

#![allow(clippy::iter_nth_zero)]

use crate::{
    bgp::basic_unnumbered_neighbor,
    dendrite::{softnpu_link_create, wait_for_dpd},
    eos::EosNode,
    frr::FrrNode,
    mgd::{MgdNode, wait_for_mgd},
    topo::{Trio, trio},
    wait_for_eq,
};
use anyhow::{Context, Result};
use dpd_client::{
    Client as DpdClient,
    types::{Ipv4Entry, Ipv6Entry, LinkId, PortId},
};
use libfalcon::Runner;
use mg_admin_client::{
    Client as MgdClient,
    types::{
        AddStaticRoute4Request, AddStaticRoute6Request, BestpathFanoutRequest,
        BfdPeerConfig, BfdPeerState, FsmStateKind, Origin4, Origin6, Router,
        SessionMode, StaticRoute4, StaticRoute4List, StaticRoute6,
        StaticRoute6List,
    },
};
use oxnet::{Ipv4Net, Ipv6Net};
use rdb_types::{AddressFamily, Prefix4, Prefix6};
use slog::info;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

const TRIO_UNNUMBERED_TOPO_NAME: &str = "mgtriou";
const TRIO_BFD_STATIC_TOPO_NAME: &str = "mgtriobfd";
const OP_TIMEOUT: Duration = Duration::from_secs(10);

// BFD-static test addressing. `OX_*` addresses are configured on the helios
// side of each softnpu link; `CR*` addresses are configured on the peer.
const OX_CR1_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const CR1_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const OX_CR2_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 1);
const CR2_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);
const OX_CR1_V4_CIDR: &str = "10.0.0.1/24";
const OX_CR2_V4_CIDR: &str = "10.0.1.1/24";
const CR1_V4_CIDR: &str = "10.0.0.2/24";
const CR2_V4_CIDR: &str = "10.0.1.2/24";

const OX_CR1_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1); // fd00:1::1
const CR1_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 2); // fd00:1::2
const OX_CR2_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 2, 0, 0, 0, 0, 0, 1); // fd00:2::1
const CR2_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 2, 0, 0, 0, 0, 0, 2); // fd00:2::2
const OX_CR1_V6_CIDR: &str = "fd00:1::1/64";
const OX_CR2_V6_CIDR: &str = "fd00:2::1/64";
const CR1_V6_CIDR: &str = "fd00:1::2/64";
const CR2_V6_CIDR: &str = "fd00:2::2/64";

/// Destination prefixes with nexthops via both cr1 and cr2.
const TEST_PREFIX_V4: &str = "192.168.100.0/24";
const TEST_PREFIX_V6: &str = "fd01::/64";

/// BFD detection time: 300ms * 3 = 900ms.
const BFD_REQUIRED_RX_US: u64 = 300_000;
const BFD_DETECTION_MULT: u8 = 3;

/// Output of `boot_trio`: the running topology plus clients ready for
/// test-specific configuration.
struct BootedTrio {
    ad: Arc<Runner>,
    ox: MgdNode,
    cr1: FrrNode,
    cr2: EosNode,
    mgd: MgdClient,
    dpd: DpdClient,
    #[allow(dead_code)]
    mgmt_addr: IpAddr,
}

/// Launch the trio topology and complete the work shared by every trio-based
/// test: dhcp mgmt, concurrent peer install + npuvm setup, dpd startup,
/// softnpu link creation, and tfport readiness. The caller supplies a closure
/// that populates a `JoinSet` with per-peer setup futures so that they run
/// concurrently with the npuvm install.
async fn boot_trio<F>(
    topo_name: &str,
    persistent: bool,
    npuvm_commit: String,
    dendrite_commit: Option<String>,
    sidecar_lite_commit: Option<String>,
    spawn_peer_setups: F,
) -> Result<BootedTrio>
where
    F: FnOnce(
        FrrNode,
        EosNode,
        Arc<Runner>,
    ) -> tokio::task::JoinSet<Result<()>>,
{
    let Trio {
        mut d,
        ox,
        cr1,
        cr2,
    } = trio(topo_name)?;
    d.persistent = persistent;
    d.launch().await.context("launch failed")?;
    let ad = Arc::new(d);

    let mgmt_addr = ox.illumos().dhcp(&ad, "vioif1/dhcp").await?;

    let mut js = spawn_peer_setups(cr1, cr2, ad.clone());
    js.spawn(ox.dendrite().npuvm(
        ad.clone(),
        2,
        0,
        npuvm_commit,
        dendrite_commit,
        sidecar_lite_commit,
    ));
    for result in js.join_all().await.into_iter() {
        result?;
    }

    let mgd = ox.client(&ad, mgmt_addr).await?;
    let dpd = ox.dendrite().client(&ad, mgmt_addr).await?;
    wait_for_dpd(&dpd, OP_TIMEOUT, &ad.log).await?;

    for link in ["qsfp0", "qsfp1"] {
        softnpu_link_create(&dpd, link)
            .await
            .context(format!("create {link}"))?;
    }
    for link in ["tfportqsfp0_0", "tfportqsfp1_0"] {
        ox.illumos().wait_for_link(&ad, link, OP_TIMEOUT).await?;
    }

    Ok(BootedTrio {
        ad,
        ox,
        cr1,
        cr2,
        mgd,
        dpd,
        mgmt_addr,
    })
}

pub async fn cleanup_unnumbered_test() -> Result<()> {
    // dropping this with out persistent set will destroy
    // the topo
    let _topo = trio(TRIO_UNNUMBERED_TOPO_NAME)?;
    Ok(())
}

pub async fn run_trio_unnumbered_test(
    persistent: bool,
    npuvm_commit: String,
    dendrite_commit: Option<String>,
    sidecar_lite_commit: Option<String>,
) -> Result<()> {
    let BootedTrio {
        ad,
        ox,
        cr1,
        cr2,
        mgd,
        dpd,
        ..
    } = boot_trio(
        TRIO_UNNUMBERED_TOPO_NAME,
        persistent,
        npuvm_commit,
        dendrite_commit,
        sidecar_lite_commit,
        |cr1, cr2, ad| {
            let mut js = tokio::task::JoinSet::new();
            js.spawn(frr_setup(cr1, ad.clone()));
            js.spawn(eos_setup(cr2, ad.clone()));
            js
        },
    )
    .await?;

    for link in ["tfportqsfp0_0", "tfportqsfp1_0"] {
        let addr = format!("{link}/ll");
        ox.illumos()
            .addrconf(&ad, &addr)
            .await
            .context(format!("create {addr}"))?;
    }

    ox.run_mgd(&ad).await?;
    ox.ddm().run_ddm(&ad).await?;
    wait_for_mgd(&mgd, OP_TIMEOUT, &ad.log).await?;

    // Fanout of 2 so both peer paths survive best-path selection and we can
    // validate ECMP in loc_rib and dpd.
    mgd.update_bestpath_fanout(&BestpathFanoutRequest {
        fanout: std::num::NonZeroU8::new(2).expect("fanout > 0"),
    })
    .await
    .context("mgd: set bestpath fanout")?;

    let local_asn: u32 = 33;

    info!(ad.log, "adding BGP router to mgd");

    mgd.create_router(&Router {
        asn: local_asn,
        graceful_shutdown: false,
        id: 33,
        listen: "[::]:179".to_owned(),
    })
    .await
    .context("mgd: create router")?;

    mgd.create_unnumbered_neighbor_v2(&basic_unnumbered_neighbor(
        "cr1",
        "test",
        "tfportqsfp0_0",
        33,
        0,
    ))
    .await
    .context("mgd: create cr1 unnumbered neighbor")?;

    mgd.create_unnumbered_neighbor_v2(&basic_unnumbered_neighbor(
        "cr2",
        "test",
        "tfportqsfp1_0",
        33,
        1800,
    ))
    .await
    .context("mgd: create cr2 unnumbered neighbor")?;

    mgd.create_origin4(&Origin4 {
        asn: 33,
        prefixes: vec!["4.5.6.0/24".parse().expect("parse ipv4 origin")],
    })
    .await
    .context("announce v4 prefix")?;

    mgd.create_origin6(&Origin6 {
        asn: 33,
        prefixes: vec!["fdee::/64".parse().expect("parse ipv6 origin")],
    })
    .await
    .context("announce v6 prefix")?;

    // Prefixes announced by the two peers back to ox, and by ox back to them.
    const CR_V4_PREFIX: &str = "1.2.3.0/24";
    const CR_V6_PREFIX: &str = "fd99::/64";
    const OX_V4_ORIGIN: &str = "4.5.6.0/24";
    const OX_V6_ORIGIN: &str = "fdee::/64";

    wait_for_eq!(
        mgd.get_neighbors(local_asn)
            .await
            .map(|x| x.into_inner().len())
            .unwrap_or(0),
        2,
        "mgd neighbor count"
    );

    for name in ["cr1", "cr2"] {
        let desc = format!("mgd bgp {name} established");
        wait_for_eq!(
            neighbor_fsm_state(&mgd, local_asn, name).await,
            Some(FsmStateKind::Established),
            &desc
        );
    }

    // Both peers advertise the same prefix, so mgd should see a single
    // imported entry per family with two paths, and — with fanout=2 — the
    // same two paths should survive into the selected (loc) RIB.
    wait_for_eq!(
        mgd_imported_paths(&mgd, AddressFamily::Ipv4, CR_V4_PREFIX).await,
        Some(2),
        "mgd imported paths for 1.2.3.0/24"
    );
    wait_for_eq!(
        mgd_imported_paths(&mgd, AddressFamily::Ipv6, CR_V6_PREFIX).await,
        Some(2),
        "mgd imported paths for fd99::/64"
    );
    wait_for_eq!(
        mgd_selected_paths(&mgd, AddressFamily::Ipv4, CR_V4_PREFIX).await,
        Some(2),
        "mgd selected paths for 1.2.3.0/24"
    );
    wait_for_eq!(
        mgd_selected_paths(&mgd, AddressFamily::Ipv6, CR_V6_PREFIX).await,
        Some(2),
        "mgd selected paths for fd99::/64"
    );

    // dpd should have the specific prefixes, each with two ECMP targets.
    let cr_v4: Prefix4 = CR_V4_PREFIX.parse().expect("parse cr v4 prefix");
    let cr_v6: Prefix6 = CR_V6_PREFIX.parse().expect("parse cr v6 prefix");
    wait_for_eq!(
        dpd_v4_targets(&dpd, &cr_v4).await.len(),
        2,
        "dpd ipv4 targets for 1.2.3.0/24"
    );
    wait_for_eq!(
        dpd_v6_targets(&dpd, &cr_v6).await.len(),
        2,
        "dpd ipv6 targets for fd99::/64"
    );

    // Each peer should have imported ox's originated prefixes.
    let ox_v4: Ipv4Net = OX_V4_ORIGIN.parse().expect("parse ox v4 origin");
    let ox_v6: Ipv6Net = OX_V6_ORIGIN.parse().expect("parse ox v6 origin");
    wait_for_eq!(
        cr1.bgp_ipv4_imported(&ad)
            .await
            .map(|r| r.all().any(|(p, _)| *p == ox_v4))
            .unwrap_or(false),
        true,
        "cr1 imported 4.5.6.0/24"
    );
    wait_for_eq!(
        cr1.bgp_ipv6_imported(&ad)
            .await
            .map(|r| r.all().any(|(p, _)| *p == ox_v6))
            .unwrap_or(false),
        true,
        "cr1 imported fdee::/64"
    );
    wait_for_eq!(
        cr2.bgp_ipv4_imported(&ad)
            .await
            .map(|r| r.all().any(|(p, _)| *p == ox_v4))
            .unwrap_or(false),
        true,
        "cr2 imported 4.5.6.0/24"
    );
    wait_for_eq!(
        cr2.bgp_ipv6_imported(&ad)
            .await
            .map(|r| r.all().any(|(p, _)| *p == ox_v6))
            .unwrap_or(false),
        true,
        "cr2 imported fdee::/64"
    );

    info!(ad.log, "trio bgp unnumbered test passed 🎉");

    Ok(())
}

async fn frr_setup(r: FrrNode, d: Arc<Runner>) -> Result<()> {
    const BASE_CONFIG: &str = "
        configure
        ip forwarding
        ipv6 forwarding
        ip route 1.2.3.0/24 null0
        ipv6 route fd99::/64 null0
        route-map PERMIT-ALL permit 10
        router bgp 44
          timers bgp 2 6
          neighbor enp0s8 interface remote-as external
          neighbor enp0s8 timers connect 1     
          address-family ipv4 unicast
            network 1.2.3.0/24
            neighbor enp0s8 activate
            neighbor enp0s8 route-map PERMIT-ALL out
            neighbor enp0s8 route-map PERMIT-ALL in
          exit-address-family
          address-family ipv6 unicast
            network fd99::/64
            neighbor enp0s8 activate
            neighbor enp0s8 route-map PERMIT-ALL out
            neighbor enp0s8 route-map PERMIT-ALL in
          exit-address-family
        exit
    ";

    r.install(&d).await?;
    r.enable_daemons(&d, &["bgpd"]).await?;
    r.shell(&d, BASE_CONFIG).await?;
    Ok(())
}

async fn eos_setup(r: EosNode, d: Arc<Runner>) -> Result<()> {
    const BASE_CONFIG: &str = "
        enable
        configure
        ipv6 unicast-routing
        ip routing ipv6 interfaces
        ip routing
        ip route 1.2.3.0/24 null0
        ipv6 route fd99::/64 null0
        interface et1
          no switchport
          ipv6 enable

        router bgp 45
          router-id 1.2.3.1
          no bgp default ipv4-unicast
          timers bgp 2 6
          neighbor ebgp peer group
          neighbor ebgp remote-as 33
          neighbor interface Et1 peer-group ebgp
          address-family ipv4
             neighbor ebgp activate
             neighbor ebgp next-hop address-family ipv6 originate
             network 1.2.3.0/24
          exit
          address-family ipv6
             neighbor ebgp activate
             neighbor ebgp next-hop address-family ipv6 originate
             network fd99::/64
          exit
        exit
    ";
    r.wait_for_init(&d).await?;
    r.shell(&d, BASE_CONFIG).await?;
    Ok(())
}

pub async fn cleanup_bfd_static_test() -> Result<()> {
    // dropping this without persistent set will destroy the topo
    let _topo = trio(TRIO_BFD_STATIC_TOPO_NAME)?;
    Ok(())
}

pub async fn run_trio_bfd_static_test(
    persistent: bool,
    npuvm_commit: String,
    dendrite_commit: Option<String>,
    sidecar_lite_commit: Option<String>,
) -> Result<()> {
    let BootedTrio {
        ad,
        ox,
        cr1,
        cr2,
        mgd,
        dpd,
        ..
    } = boot_trio(
        TRIO_BFD_STATIC_TOPO_NAME,
        persistent,
        npuvm_commit,
        dendrite_commit,
        sidecar_lite_commit,
        |cr1, cr2, ad| {
            let mut js = tokio::task::JoinSet::new();
            js.spawn(frr_bfd_setup(cr1, ad.clone()));
            js.spawn(eos_bfd_setup(cr2, ad.clone()));
            js
        },
    )
    .await?;

    // Register each ox-side address with dpd so softnpu punts packets for
    // those destinations to the CPU port. Link-local v6 is handled
    // implicitly by the P4 pipeline, but globally-scoped addresses need an
    // explicit per-link mapping. IPv6 is also disabled by default per-link
    // in the P4 pipeline, so enable it before registering v6 addresses.
    for (qsfp, v4, v6) in [
        ("qsfp0", OX_CR1_V4, OX_CR1_V6),
        ("qsfp1", OX_CR2_V4, OX_CR2_V6),
    ] {
        let port = PortId::Qsfp(qsfp.parse().expect("parse qsfp port"));
        let link = LinkId(0);
        dpd.link_ipv4_create(
            &port,
            &link,
            &Ipv4Entry {
                addr: v4,
                tag: "falcon-lab".into(),
            },
        )
        .await
        .context(format!("dpd: program {v4} on {qsfp}/0"))?;
        dpd.link_ipv6_enabled_set(&port, &link, true)
            .await
            .context(format!("dpd: enable ipv6 on {qsfp}/0"))?;
        dpd.link_ipv6_create(
            &port,
            &link,
            &Ipv6Entry {
                addr: v6,
                tag: "falcon-lab".into(),
            },
        )
        .await
        .context(format!("dpd: program {v6} on {qsfp}/0"))?;
    }

    // Configure numbered v4 + v6 addresses on the ox side of each softnpu
    // link so static-route nexthops resolve. illumos requires a v6 link-local
    // (via addrconf) on an interface before a static global v6 address can
    // be added, so do addrconf first.
    for (link, v4_cidr, v6_cidr) in [
        ("tfportqsfp0_0", OX_CR1_V4_CIDR, OX_CR1_V6_CIDR),
        ("tfportqsfp1_0", OX_CR2_V4_CIDR, OX_CR2_V6_CIDR),
    ] {
        let ll = format!("{link}/ll");
        ox.illumos()
            .addrconf(&ad, &ll)
            .await
            .context(format!("addrconf {ll}"))?;
        for (suffix, cidr) in [("v4", v4_cidr), ("v6", v6_cidr)] {
            let addrobj = format!("{link}/{suffix}");
            ox.illumos()
                .staticaddr(&ad, &addrobj, cidr)
                .await
                .context(format!("assign {cidr} to {link}"))?;
        }
    }

    ox.run_mgd(&ad).await?;
    // mg-lower's sync loop queries ddm on every prefix change and bails the
    // whole sync when ddm is unreachable. We don't exercise DDM here, but
    // ddmd has to be up for static routes to lower into dpd.
    ox.ddm().run_ddm(&ad).await?;
    wait_for_mgd(&mgd, OP_TIMEOUT, &ad.log).await?;

    // Default fanout is 1, which collapses the two static paths into a single
    // selected nexthop. Bump to 2 so both paths propagate through best-path
    // selection and land in dpd as ECMP.
    mgd.update_bestpath_fanout(&BestpathFanoutRequest {
        fanout: std::num::NonZeroU8::new(2).expect("fanout > 0"),
    })
    .await
    .context("mgd: set bestpath fanout")?;

    let prefix_v4: Prefix4 =
        TEST_PREFIX_V4.parse().expect("parse v4 test prefix");
    let prefix_v6: Prefix6 =
        TEST_PREFIX_V6.parse().expect("parse v6 test prefix");

    info!(ad.log, "installing static v4 route {TEST_PREFIX_V4}");
    mgd.static_add_v4_route(&AddStaticRoute4Request {
        routes: StaticRoute4List {
            list: [CR1_V4, CR2_V4]
                .into_iter()
                .map(|nh| StaticRoute4 {
                    prefix: prefix_v4,
                    nexthop: nh,
                    vlan_id: None,
                    rib_priority: 0,
                })
                .collect(),
        },
    })
    .await
    .context("mgd: add v4 static route")?;

    info!(ad.log, "installing static v6 route {TEST_PREFIX_V6}");
    mgd.static_add_v6_route(&AddStaticRoute6Request {
        routes: StaticRoute6List {
            list: [CR1_V6, CR2_V6]
                .into_iter()
                .map(|nh| StaticRoute6 {
                    prefix: prefix_v6,
                    nexthop: nh,
                    vlan_id: None,
                    rib_priority: 0,
                })
                .collect(),
        },
    })
    .await
    .context("mgd: add v6 static route")?;

    info!(ad.log, "adding BFD peers for cr1 and cr2 (dual-stack)");
    for (peer, listen) in [
        (IpAddr::V4(CR1_V4), IpAddr::V4(OX_CR1_V4)),
        (IpAddr::V4(CR2_V4), IpAddr::V4(OX_CR2_V4)),
        (IpAddr::V6(CR1_V6), IpAddr::V6(OX_CR1_V6)),
        (IpAddr::V6(CR2_V6), IpAddr::V6(OX_CR2_V6)),
    ] {
        mgd.add_bfd_peer(&BfdPeerConfig {
            peer,
            listen,
            required_rx: BFD_REQUIRED_RX_US,
            detection_threshold: BFD_DETECTION_MULT,
            mode: SessionMode::SingleHop,
        })
        .await
        .context(format!("mgd: add bfd peer {peer}"))?;
    }

    use BfdPeerState::{Down, Up};

    info!(ad.log, "phase 1: both peers up");
    expect_bfd(&mgd, cr1, cr2, &ad, Up, Up).await?;
    expect_route(&dpd, &prefix_v4, &prefix_v6, true, true, "phase 1").await?;

    info!(ad.log, "phase 2: pause bfdd on cr1");
    cr1.pause_bfdd(&ad).await?;
    expect_bfd(&mgd, cr1, cr2, &ad, Down, Up).await?;
    expect_route(&dpd, &prefix_v4, &prefix_v6, false, true, "phase 2").await?;

    info!(ad.log, "phase 3: pause ceos on cr2");
    cr2.pause(&ad).await?;
    expect_bfd(&mgd, cr1, cr2, &ad, Down, Down).await?;
    // With every nexthop shutdown, all shutdown nexthops are reinstated.
    expect_route(&dpd, &prefix_v4, &prefix_v6, true, true, "phase 3").await?;

    info!(ad.log, "phase 4: resume bfdd on cr1");
    cr1.resume_bfdd(&ad).await?;
    expect_bfd(&mgd, cr1, cr2, &ad, Up, Down).await?;
    expect_route(&dpd, &prefix_v4, &prefix_v6, true, false, "phase 4").await?;

    info!(ad.log, "phase 5: unpause ceos on cr2");
    cr2.unpause(&ad).await?;
    expect_bfd(&mgd, cr1, cr2, &ad, Up, Up).await?;
    expect_route(&dpd, &prefix_v4, &prefix_v6, true, true, "phase 5").await?;

    info!(ad.log, "trio bfd static routing test passed 🎉");

    Ok(())
}

async fn frr_bfd_setup(r: FrrNode, d: Arc<Runner>) -> Result<()> {
    // Address the softnpu-facing link (v4 + v6) and bring up passive BFD peers
    // for each family. Once mgd initiates BFD to these addresses the sessions
    // establish bidirectionally.
    let rx_ms = BFD_REQUIRED_RX_US / 1000;
    let config = format!(
        "
        configure
        interface enp0s8
          ip address {cr_v4_cidr}
          ipv6 address {cr_v6_cidr}
          no shutdown
        exit
        bfd
          peer {ox_v4} local-address {cr_v4}
            detect-multiplier {mult}
            receive-interval {rx_ms}
            transmit-interval {rx_ms}
            no shutdown
          exit
          peer {ox_v6} local-address {cr_v6}
            detect-multiplier {mult}
            receive-interval {rx_ms}
            transmit-interval {rx_ms}
            no shutdown
          exit
        exit
        ",
        cr_v4_cidr = CR1_V4_CIDR,
        cr_v6_cidr = CR1_V6_CIDR,
        ox_v4 = OX_CR1_V4,
        ox_v6 = OX_CR1_V6,
        cr_v4 = CR1_V4,
        cr_v6 = CR1_V6,
        mult = BFD_DETECTION_MULT,
    );

    r.install(&d).await?;
    r.enable_daemons(&d, &["bfdd"]).await?;
    r.shell(&d, &config).await?;
    Ok(())
}

async fn eos_bfd_setup(r: EosNode, d: Arc<Runner>) -> Result<()> {
    // Address the softnpu-facing link (v4 + v6) and install dummy BFD-tracked
    // static routes whose nexthops are the ox side of the link. This is EOS's
    // idiomatic way to bring up BFD sessions without a BGP/OSPF client.
    let rx_ms = BFD_REQUIRED_RX_US / 1000;
    let config = format!(
        "
        enable
        configure
        ip routing
        ipv6 unicast-routing
        interface Ethernet1
          no switchport
          ip address {cr_v4_cidr}
          ipv6 enable
          ipv6 address {cr_v6_cidr}
          bfd interval {rx_ms} min-rx {rx_ms} multiplier {mult}
        exit
        ip route 100.64.0.0/24 {ox_v4} track bfd
        ipv6 route 3fff::/64 {ox_v6} track bfd
        exit
        ",
        cr_v4_cidr = CR2_V4_CIDR,
        cr_v6_cidr = CR2_V6_CIDR,
        ox_v4 = OX_CR2_V4,
        ox_v6 = OX_CR2_V6,
        mult = BFD_DETECTION_MULT,
    );
    r.wait_for_init(&d).await?;
    r.shell(&d, &config).await?;
    Ok(())
}

/// Expect a scalar BFD state per peer. Since failure injection targets the
/// peer daemon as a whole, the v4 and v6 sessions to a given peer always
/// share the same state.
///
/// mgd-side state is always checked. Peer-side state is checked only when
/// the peer is expected `Up`: a paused daemon cannot answer queries, so
/// `Down` phases have no observable peer-side truth.
async fn expect_bfd(
    mgd: &MgdClient,
    cr1: FrrNode,
    cr2: EosNode,
    d: &Runner,
    cr1_state: BfdPeerState,
    cr2_state: BfdPeerState,
) -> Result<()> {
    for (peer, want) in [
        (IpAddr::V4(CR1_V4), cr1_state),
        (IpAddr::V6(CR1_V6), cr1_state),
        (IpAddr::V4(CR2_V4), cr2_state),
        (IpAddr::V6(CR2_V6), cr2_state),
    ] {
        let desc = format!("mgd bfd {peer} -> {want:?}");
        wait_for_eq!(bfd_state(mgd, peer).await, Some(want), &desc);
    }

    if matches!(cr1_state, BfdPeerState::Up) {
        for peer in [IpAddr::V4(OX_CR1_V4), IpAddr::V6(OX_CR1_V6)] {
            let desc = format!("cr1 bfd {peer} -> Up");
            wait_for_eq!(
                cr1.bfd_peer_up(d, peer).await.unwrap_or(false),
                true,
                &desc
            );
        }
    }
    if matches!(cr2_state, BfdPeerState::Up) {
        for peer in [IpAddr::V4(OX_CR2_V4), IpAddr::V6(OX_CR2_V6)] {
            let desc = format!("cr2 bfd {peer} -> Up");
            wait_for_eq!(
                cr2.bfd_peer_up(d, peer).await.unwrap_or(false),
                true,
                &desc
            );
        }
    }
    Ok(())
}

/// Expect the test's v4 + v6 prefixes to resolve to the given subset of cr1 /
/// cr2 as dpd targets.
async fn expect_route(
    dpd: &DpdClient,
    prefix_v4: &Prefix4,
    prefix_v6: &Prefix6,
    cr1_in: bool,
    cr2_in: bool,
    phase: &str,
) -> Result<()> {
    // Push cr1 before cr2 so the list is already in the sorted order that
    // dpd_v*_targets returns.
    let mut want_v4 = Vec::new();
    let mut want_v6 = Vec::new();
    if cr1_in {
        want_v4.push(CR1_V4);
        want_v6.push(CR1_V6);
    }
    if cr2_in {
        want_v4.push(CR2_V4);
        want_v6.push(CR2_V6);
    }

    let desc_v4 = format!("{phase} v4");
    let desc_v6 = format!("{phase} v6");
    wait_for_eq!(
        dpd_v4_targets(dpd, prefix_v4).await,
        want_v4.clone(),
        &desc_v4
    );
    wait_for_eq!(
        dpd_v6_targets(dpd, prefix_v6).await,
        want_v6.clone(),
        &desc_v6
    );
    Ok(())
}

async fn bfd_state(mgd: &MgdClient, peer: IpAddr) -> Option<BfdPeerState> {
    let peers = mgd.get_bfd_peers().await.ok()?.into_inner();
    peers
        .into_iter()
        .find(|p| p.config.peer == peer)
        .map(|p| p.state)
}

/// Look up the FSM state of the neighbor with the given `name`. The
/// `get_neighbors` map is keyed by interface/peer-id which we don't care
/// about here; we iterate values and match on `PeerInfo::name`.
async fn neighbor_fsm_state(
    mgd: &MgdClient,
    local_asn: u32,
    name: &str,
) -> Option<FsmStateKind> {
    mgd.get_neighbors(local_asn)
        .await
        .ok()?
        .into_inner()
        .into_values()
        .find(|p| p.name == name)
        .map(|p| p.fsm_state)
}

/// Number of imported paths in the mgd RIB for a given prefix, or `None`
/// if the prefix is absent. Reflects every path mgd has seen regardless of
/// best-path selection.
async fn mgd_imported_paths(
    mgd: &MgdClient,
    af: AddressFamily,
    prefix: &str,
) -> Option<usize> {
    mgd.get_rib_imported(Some(&af), None)
        .await
        .ok()?
        .into_inner()
        .get(prefix)
        .map(|paths| paths.len())
}

/// Number of selected (loc_rib) paths in the mgd RIB for a given prefix,
/// or `None` if the prefix is absent. Reflects bestpath fanout.
async fn mgd_selected_paths(
    mgd: &MgdClient,
    af: AddressFamily,
    prefix: &str,
) -> Option<usize> {
    mgd.get_rib_selected(Some(&af), None)
        .await
        .ok()?
        .into_inner()
        .get(prefix)
        .map(|paths| paths.len())
}

async fn dpd_v4_targets(dpd: &DpdClient, prefix: &Prefix4) -> Vec<Ipv4Addr> {
    let items = match dpd.route_ipv4_list(None, None).await {
        Ok(r) => r.into_inner().items,
        Err(_) => return Vec::new(),
    };
    let want_cidr = prefix.to_string();
    let mut out: Vec<Ipv4Addr> = items
        .into_iter()
        .filter(|r| r.cidr.to_string() == want_cidr)
        .flat_map(|r| {
            r.targets.into_iter().filter_map(|t| match t {
                dpd_client::types::Route::V4(rt) => Some(rt.tgt_ip),
                _ => None,
            })
        })
        .collect();
    out.sort();
    out
}

async fn dpd_v6_targets(dpd: &DpdClient, prefix: &Prefix6) -> Vec<Ipv6Addr> {
    let items = match dpd.route_ipv6_list(None, None).await {
        Ok(r) => r.into_inner().items,
        Err(_) => return Vec::new(),
    };
    let want_cidr = prefix.to_string();
    let mut out: Vec<Ipv6Addr> = items
        .into_iter()
        .filter(|r| r.cidr.to_string() == want_cidr)
        .flat_map(|r| r.targets.into_iter().map(|t| t.tgt_ip))
        .collect();
    out.sort();
    out
}
