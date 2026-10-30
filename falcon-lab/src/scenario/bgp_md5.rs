//! BGP TCP MD5 interop scenario.

use super::{
    BootedInterop, Interop3LinkScenario, InteropLayout, OP_TIMEOUT,
    boot_interop, run_with_optional_diagnostics,
};
use crate::{
    bird::MD5_KEY, dendrite::NpuvmCommits, diagnostics::ProtocolDiagnostics,
    mgd::wait_for_mgd, wait_for_eq,
};
use anyhow::{Context, Result};
use dpd_client::types::{Ipv4Entry, LinkId, PortId};
use mg_admin_client::{Client as MgdClient, types::Neighbor};
use mg_api_types::bgp::{
    config::{Ipv4UnicastConfig, Origin4, PeerInfo, Router},
    history::Origin6,
    policy::ImportExportPolicy4,
    session::FsmStateKind,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::time::{Instant, sleep, timeout};

const DUT_ASN: u32 = 33;
const PEER_ASN: u32 = 47;
const DUT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 3, 1);
const PEER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 3, 2);
const DUT_LINK: &str = "tfportqsfp9_0";
const PEER_LINK: &str = "vioif0";
const STABILITY_INTERVAL: Duration = Duration::from_secs(13);

pub(super) async fn run(
    scenario: Interop3LinkScenario,
    persistent: bool,
    diag_on_fail: bool,
    commits: NpuvmCommits,
) -> Result<()> {
    let bt = boot_interop(
        InteropLayout::ThreeLinks(scenario),
        persistent,
        diag_on_fail,
        commits,
        ProtocolDiagnostics::Bgp,
        |_cr1, _cr2, _cr3, _bird, _ad| tokio::task::JoinSet::new(),
    )
    .await?;
    run_with_optional_diagnostics(bt, diag_on_fail, body).await
}

async fn body(bt: BootedInterop) -> Result<()> {
    numbered_body(&bt).await?;
    bird_unnumbered_body(&bt).await
}

// The numbered fixture proves session establishment only. Do not reuse it for
// route-installation testing: peers such as FRR may select numbered or
// IPv4-mapped-IPv6 next hops.
async fn numbered_body(bt: &BootedInterop) -> Result<()> {
    let BootedInterop {
        ad,
        ox,
        peer,
        mgd,
        peer_mgd,
        dpd,
        ..
    } = bt;
    let port = PortId::Qsfp("qsfp9".parse().expect("parse qsfp9 port"));
    dpd.link_ipv4_create(
        &port,
        &LinkId(0),
        &Ipv4Entry {
            addr: DUT_ADDR,
            tag: "falcon-lab".into(),
        },
    )
    .await
    .context("dpd: program 10.0.3.1 on qsfp9/0")?;
    ox.illumos()
        .staticaddr(ad, &format!("{DUT_LINK}/v4"), "10.0.3.1/24")
        .await
        .context("assign DUT IPv4 address")?;
    peer.illumos()
        .staticaddr(ad, &format!("{PEER_LINK}/v4"), "10.0.3.2/24")
        .await
        .context("assign peer IPv4 address")?;

    ox.run_mgd(ad).await?;
    wait_for_mgd(mgd, OP_TIMEOUT, &ad.log).await?;
    for (client, asn, id, label) in
        [(mgd, DUT_ASN, 33, "DUT"), (peer_mgd, PEER_ASN, 47, "peer")]
    {
        client
            .create_router(&Router {
                asn,
                graceful_shutdown: false,
                id,
                listen: "[::]:179".to_owned(),
            })
            .await
            .with_context(|| format!("{label}: create router"))?;
    }

    mgd.create_neighbor(&md5_neighbor(
        DUT_ASN, PEER_ASN, "peer", DUT_ADDR, PEER_ADDR, true,
    ))
    .await
    .context("DUT: create passive MD5 neighbor")?;
    peer_mgd
        .create_neighbor(&md5_neighbor(
            PEER_ASN, DUT_ASN, "dut", PEER_ADDR, DUT_ADDR, false,
        ))
        .await
        .context("peer: create active MD5 neighbor")?;

    let (dut, peer) = wait_for_established(mgd, peer_mgd).await?;
    anyhow::ensure!(
        dut.local_tcp_port == 179 && dut.remote_tcp_port != 179,
        "DUT did not accept the inbound BGP connection: local port {}, remote port {}",
        dut.local_tcp_port,
        dut.remote_tcp_port
    );
    anyhow::ensure!(
        peer.local_tcp_port != 179 && peer.remote_tcp_port == 179,
        "peer did not initiate the inbound BGP connection: local port {}, remote port {}",
        peer.local_tcp_port,
        peer.remote_tcp_port
    );

    let dut_transitions = transition_counters(&dut);
    let peer_transitions = transition_counters(&peer);
    let deadline = Instant::now() + STABILITY_INTERVAL;
    while Instant::now() < deadline {
        let dut = peer_info(mgd, DUT_ASN, "peer")
            .await
            .context("DUT PeerInfo disappeared during hold-time observation")?;
        let peer = peer_info(peer_mgd, PEER_ASN, "dut").await.context(
            "peer PeerInfo disappeared during hold-time observation",
        )?;
        assert_stable(&dut, dut_transitions, "DUT")?;
        assert_stable(&peer, peer_transitions, "peer")?;
        sleep(Duration::from_millis(250)).await;
    }

    let dut = peer_info(mgd, DUT_ASN, "peer")
        .await
        .context("DUT PeerInfo disappeared after hold-time observation")?;
    let peer = peer_info(peer_mgd, PEER_ASN, "dut")
        .await
        .context("peer PeerInfo disappeared after hold-time observation")?;
    assert_stable(&dut, dut_transitions, "DUT")?;
    assert_stable(&peer, peer_transitions, "peer")?;
    anyhow::ensure!(
        dut.fsm_state_duration > Duration::from_secs(12),
        "DUT was not continuously Established for two hold-time periods"
    );
    anyhow::ensure!(
        peer.fsm_state_duration > Duration::from_secs(12),
        "peer was not continuously Established for two hold-time periods"
    );
    Ok(())
}

/// Exercise all three BIRD links without weakening the accepted-socket
/// regression above: these are authenticated IPv6 link-local sessions with
/// RFC 8950 IPv4 routes, bidirectional imports, and three-way DUT ECMP.
async fn bird_unnumbered_body(bt: &BootedInterop) -> Result<()> {
    use mg_api_types::{rdb::rib::AddressFamily, rib::BestpathFanoutRequest};
    let BootedInterop {
        ad,
        ox,
        bird,
        mgd,
        dpd,
        layout,
        ..
    } = bt;
    ox.ddm().run_ddm(ad).await?;
    mgd.update_bestpath_fanout(&BestpathFanoutRequest {
        fanout: std::num::NonZeroU8::new(3).unwrap(),
    })
    .await?;
    mgd.create_origin4(&Origin4 {
        asn: DUT_ASN,
        prefixes: vec!["4.5.6.0/24".parse()?],
    })
    .await?;
    mgd.create_origin6(&Origin6 {
        asn: DUT_ASN,
        prefixes: vec!["fdee::/64".parse()?],
    })
    .await?;
    super::setup_bird_bgp(ad, *ox, *bird, mgd, *layout).await?;
    super::expect_bird_bgp(ad, *bird, layout.links_per_peer()).await?;

    wait_for_eq!(
        mgd.get_neighbors(DUT_ASN)
            .await
            .map(|r| r.len())
            .unwrap_or(0),
        4,
        "DUT numbered peer plus three BIRD neighbors"
    );
    for (af, prefix) in [
        (AddressFamily::Ipv4, "1.2.3.0/24"),
        (AddressFamily::Ipv6, "fd99::/64"),
    ] {
        wait_for_eq!(
            super::mgd_imported_paths(mgd, af, prefix).await,
            Some(3),
            &format!("DUT imported three BIRD paths for {prefix}")
        );
        wait_for_eq!(
            super::mgd_selected_paths(mgd, af, prefix).await,
            Some(3),
            &format!("DUT selected three BIRD paths for {prefix}")
        );
    }
    let v4 = "1.2.3.0/24".parse()?;
    let v6 = "fd99::/64".parse()?;
    wait_for_eq!(
        super::dpd_v4_targets(dpd, &v4).await.len(),
        3,
        "BIRD IPv4 ECMP"
    );
    wait_for_eq!(
        super::dpd_v6_targets(dpd, &v6).await.len(),
        3,
        "BIRD IPv6 ECMP"
    );

    let mut counters = Vec::new();
    for index in 0..layout.links_per_peer() {
        let name = format!("bird{index}");
        let info = peer_info(mgd, DUT_ASN, &name)
            .await
            .context("missing BIRD PeerInfo")?;
        anyhow::ensure!(
            info.fsm_state == FsmStateKind::Established,
            "{name} not Established"
        );
        counters.push((name, transition_counters(&info)));
    }
    let deadline = Instant::now() + STABILITY_INTERVAL;
    loop {
        let finished = Instant::now() >= deadline;
        for (index, (name, transitions)) in counters.iter().enumerate() {
            let info = peer_info(mgd, DUT_ASN, name)
                .await
                .context("BIRD PeerInfo disappeared")?;
            assert_stable(&info, *transitions, name)?;
            anyhow::ensure!(
                bird.bgp_established(ad, index).await?,
                "BIRD dut{index} left Established"
            );
            if finished {
                anyhow::ensure!(
                    info.fsm_state_duration > Duration::from_secs(12),
                    "{name} did not stay Established for two hold periods"
                );
            }
        }
        if finished {
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

fn md5_neighbor(
    asn: u32,
    remote_asn: u32,
    name: &str,
    source: Ipv4Addr,
    remote: Ipv4Addr,
    passive: bool,
) -> Neighbor {
    Neighbor {
        asn,
        name: name.to_owned(),
        group: "bgp-md5".to_owned(),
        host: SocketAddr::new(remote.into(), 179),
        hold_time: 6,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 1,
        keepalive: 2,
        resolution: 100,
        passive,
        remote_asn: Some(remote_asn),
        min_ttl: None,
        md5_auth_key: Some(MD5_KEY.to_owned()),
        multi_exit_discriminator: None,
        communities: Vec::new(),
        local_pref: None,
        enforce_first_as: false,
        vlan_id: None,
        ipv4_unicast: Some(Ipv4UnicastConfig {
            import_policy: ImportExportPolicy4::NoFiltering,
            export_policy: ImportExportPolicy4::NoFiltering,
            nexthop: None,
        }),
        ipv6_unicast: None,
        deterministic_collision_resolution: false,
        idle_hold_jitter: None,
        connect_retry_jitter: None,
        src_addr: Some(source.into()),
        src_port: None,
    }
}

async fn wait_for_established(
    dut: &MgdClient,
    peer: &MgdClient,
) -> Result<(PeerInfo, PeerInfo)> {
    timeout(Duration::from_secs(30), async {
        loop {
            if let (Some(dut), Some(peer)) = (
                peer_info(dut, DUT_ASN, "peer").await,
                peer_info(peer, PEER_ASN, "dut").await,
            ) && dut.fsm_state == FsmStateKind::Established
                && peer.fsm_state == FsmStateKind::Established
            {
                return (dut, peer);
            }
            sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .context("timed out waiting for both MD5 peers to become Established")
}

async fn peer_info(mgd: &MgdClient, asn: u32, name: &str) -> Option<PeerInfo> {
    mgd.get_neighbors(asn)
        .await
        .ok()?
        .into_inner()
        .into_values()
        .find(|peer| peer.name == name)
}

fn assert_stable(
    peer: &PeerInfo,
    transitions: [u64; 8],
    label: &str,
) -> Result<()> {
    anyhow::ensure!(
        peer.fsm_state == FsmStateKind::Established,
        "{label} left Established"
    );
    anyhow::ensure!(
        transition_counters(peer) == transitions,
        "{label} FSM transition counters changed"
    );
    Ok(())
}

fn transition_counters(peer: &PeerInfo) -> [u64; 8] {
    let c = &peer.counters;
    [
        c.transitions_to_idle,
        c.transitions_to_connect,
        c.transitions_to_active,
        c.transitions_to_open_sent,
        c.transitions_to_open_confirm,
        c.transitions_to_connection_collision,
        c.transitions_to_session_setup,
        c.transitions_to_established,
    ]
}
