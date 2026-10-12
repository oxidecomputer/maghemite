//! Bidirectional BGP transit through four third-party spines.

use super::{
    HELIOS_MGMT_ADDR, InteropRouters, LAUNCH_TIMEOUT, OP_TIMEOUT,
    ScenarioOptions, SpineLeafScenario, collect_interop_diagnostics,
    mgd_imported_paths, mgd_selected_paths, neighbor_fsm_state,
};
use crate::{
    bgp::basic_unnumbered_neighbor,
    bird::BgpLink,
    dendrite::{NpuvmCommits, softnpu_link_create, wait_for_dpd},
    diagnostics::ProtocolDiagnostics,
    juniper::clear_staged_routing_configs,
    mgd::{MgdNode, wait_for_mgd},
    topo::{SpineLeaf, Topology},
    wait_for_eq,
};
use anyhow::{Context, Result, ensure};
use dpd_client::{
    Client as DpdClient,
    types::{Ipv4Entry, Ipv6Entry, LinkId, PortId, Route},
};
use libfalcon::Runner;
use mg_admin_client::{Client as MgdClient, types::Neighbor};
use mg_api_types::{
    bgp::{
        config::{Origin4, Router},
        history::Origin6,
        session::FsmStateKind,
    },
    rdb::rib::AddressFamily,
    rib::BestpathFanoutRequest,
};
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    num::NonZeroU8,
    sync::Arc,
    time::Duration,
};
use tokio::time::timeout;

mod config;
use config::{LEAF_ASNS, ORIGINS4, ORIGINS6, SPINES, addresses};

impl SpineLeafScenario {
    fn numbered(self) -> bool {
        matches!(self, Self::BgpNumbered)
    }
}

pub(super) async fn run(
    scenario: SpineLeafScenario,
    options: ScenarioOptions,
) -> Result<()> {
    clear_staged_routing_configs().context("clear stale Junos config")?;
    let SpineLeaf {
        mut d,
        leaves,
        frr,
        eos,
        junos,
        bird,
    } = SpineLeaf::build(scenario)?;
    d.persistent = options.persistent;
    timeout(LAUNCH_TIMEOUT, d.launch())
        .await
        .context("launch timed out")?
        .context("launch failed")?;
    let d = Arc::new(d);
    let spines = InteropRouters {
        cr1: frr,
        cr2: eos,
        cr3: junos,
        bird,
    };
    let result = body(&d, leaves, spines, scenario, options.commits).await;
    if let Err(e) = &result {
        slog::warn!(d.log, "{} failed: {e:#}", scenario.name());
        if options.diag_on_fail {
            collect_interop_diagnostics(
                &d,
                leaves[0],
                leaves[1],
                spines,
                scenario.name(),
                ProtocolDiagnostics::Bgp,
            )
            .await;
            // Unlike the interop fanout's peer, the second leaf also has an NPU.
            leaves[1]
                .dendrite()
                .collect_diagnostics(&d, scenario.name())
                .await;
            leaves[1]
                .ddm()
                .collect_diagnostics(&d, scenario.name())
                .await;
        }
    }
    result
}

async fn body(
    d: &Arc<Runner>,
    leaves: [MgdNode; 2],
    spines: InteropRouters,
    scenario: SpineLeafScenario,
    commits: NpuvmCommits,
) -> Result<()> {
    // Each future owns a different console. Finish all of them before returning
    // an error so diagnostics never race an interrupted console login.
    let frr_setup = async {
        spines.cr1.install(d).await?;
        spines.cr1.enable_daemons(d, &["bgpd"]).await?;
        spines.cr1.shell(d, &config::frr(scenario)).await?;
        Ok::<_, anyhow::Error>(())
    };
    let eos_setup = async {
        spines.cr2.wait_for_init(d).await?;
        spines.cr2.shell(d, &config::eos(scenario)).await?;
        Ok::<_, anyhow::Error>(())
    };
    let junos_config = config::junos(scenario);
    let (leaf1, leaf2, frr, eos, junos) = tokio::join!(
        setup_leaf(d, leaves[0], 0, scenario, commits.clone()),
        setup_leaf(d, leaves[1], 1, scenario, commits),
        frr_setup,
        eos_setup,
        spines.cr3.setup(d, &junos_config),
    );
    let clients = [leaf1.context("setup ox1")?, leaf2.context("setup ox2")?];
    frr.context("setup FRR spine")?;
    eos.context("setup EOS spine")?;
    junos.context("setup Junos spine")?;

    let mut bird_links = Vec::new();
    for (index, leaf) in clients.iter().enumerate() {
        let interface = spines.bird.data_interface(d, index).await?;
        let local = spines.bird.link_local(d, &interface).await?;
        if scenario.numbered() {
            let (v4, v6) = addresses(index, 3, 2);
            d.exec(spines.bird.0, &format!(
                "ip addr replace {v4}/24 dev {interface} && ip -6 addr replace {v6}/64 dev {interface}"
            )).await?;
        }
        bird_links.push(BgpLink {
            interface,
            local,
            remote: leaf.bird_link_local,
        });
    }
    spines
        .bird
        .apply(d, &config::bird(scenario, &bird_links))
        .await?;

    let (first, second) = tokio::join!(
        expect_leaf(&clients[0], 0, scenario),
        expect_leaf(&clients[1], 1, scenario),
    );
    first.and(second)?;
    slog::info!(
        d.log,
        "{}: both leaves received and installed IPv4 and IPv6 routes through all four spines",
        scenario.name()
    );
    Ok(())
}

struct LeafClients {
    mgd: MgdClient,
    dpd: DpdClient,
    bird_link_local: Ipv6Addr,
}

async fn setup_leaf(
    d: &Arc<Runner>,
    leaf: MgdNode,
    index: usize,
    scenario: SpineLeafScenario,
    commits: NpuvmCommits,
) -> Result<LeafClients> {
    let mgmt = leaf.illumos().dhcp(d, HELIOS_MGMT_ADDR).await?;
    leaf.dendrite().npuvm(d.clone(), 4, 0, commits).await?;
    let dpd = leaf.dendrite().client(d, mgmt).await?;
    wait_for_dpd(&dpd, OP_TIMEOUT, &d.log).await?;
    let mut link_locals = Vec::new();
    for port in 0..SPINES.len() {
        let qsfp = format!("qsfp{port}");
        let interface = format!("tfport{qsfp}_0");
        softnpu_link_create(&dpd, &qsfp).await?;
        leaf.illumos()
            .wait_for_link(d, &interface, OP_TIMEOUT)
            .await?;
        let addr = leaf
            .illumos()
            .addrconf(d, &format!("{interface}/ll"))
            .await?;
        let IpAddr::V6(ll) = addr else {
            anyhow::bail!("{interface}: expected IPv6 link-local, got {addr}");
        };
        ensure!(
            ll.is_unicast_link_local(),
            "{interface}: {ll} is not link-local"
        );
        link_locals.push(ll);
        if scenario.numbered() {
            let (v4, v6) = addresses(index, port, 1);
            let port_id = PortId::Qsfp(qsfp.parse()?);
            dpd.link_ipv4_create(
                &port_id,
                &LinkId(0),
                &Ipv4Entry {
                    addr: v4,
                    tag: "falcon-lab".into(),
                },
            )
            .await?;
            dpd.link_ipv6_create(
                &port_id,
                &LinkId(0),
                &Ipv6Entry {
                    addr: v6,
                    tag: "falcon-lab".into(),
                },
            )
            .await?;
            leaf.illumos()
                .staticaddr(d, &format!("{interface}/v4"), &format!("{v4}/24"))
                .await?;
            leaf.illumos()
                .staticaddr(d, &format!("{interface}/v6"), &format!("{v6}/64"))
                .await?;
        }
    }

    leaf.run_mgd(d).await?;
    // The lowering loop needs ddmd even though this scenario only uses BGP.
    leaf.ddm().run_ddm(d).await?;
    let mgd = leaf.client(d, mgmt).await?;
    wait_for_mgd(&mgd, OP_TIMEOUT, &d.log).await?;
    let asn = LEAF_ASNS[index];
    mgd.create_router(&Router {
        asn,
        graceful_shutdown: false,
        id: asn,
        listen: "[::]:179".into(),
    })
    .await?;
    mgd.update_bestpath_fanout(&BestpathFanoutRequest {
        fanout: NonZeroU8::new(4).expect("four spines"),
    })
    .await?;
    for (port, (name, remote_asn)) in SPINES.iter().enumerate() {
        let interface = format!("tfportqsfp{port}_0");
        let mut neighbor = basic_unnumbered_neighbor(
            name,
            "spine-leaf",
            &interface,
            asn,
            1800,
        );
        neighbor.remote_asn = Some(*remote_asn);
        if scenario.numbered() {
            for v6 in [false, true] {
                mgd.create_neighbor(&numbered_neighbor(index, port, v6))
                    .await?;
            }
        } else {
            mgd.create_unnumbered_neighbor(&neighbor).await?;
        }
    }
    mgd.create_origin4(&Origin4 {
        asn,
        prefixes: vec![ORIGINS4[index].parse()?],
    })
    .await?;
    mgd.create_origin6(&Origin6 {
        asn,
        prefixes: vec![ORIGINS6[index].parse()?],
    })
    .await?;
    Ok(LeafClients {
        mgd,
        dpd,
        bird_link_local: link_locals[3],
    })
}

fn numbered_neighbor(leaf: usize, spine: usize, v6: bool) -> Neighbor {
    let (name, remote_asn) = SPINES[spine];
    let (local4, local6) = addresses(leaf, spine, 1);
    let (remote4, remote6) = addresses(leaf, spine, 2);
    let defaults =
        basic_unnumbered_neighbor(name, "spine-leaf", "", LEAF_ASNS[leaf], 0);
    Neighbor {
        asn: LEAF_ASNS[leaf],
        name: format!("{name}-v{}", if v6 { 6 } else { 4 }),
        group: "spine-leaf".into(),
        host: SocketAddr::new(
            if v6 { remote6.into() } else { remote4.into() },
            179,
        ),
        src_addr: Some(if v6 { local6.into() } else { local4.into() }),
        src_port: None,
        hold_time: 6,
        keepalive: 2,
        idle_hold_time: 0,
        delay_open: 0,
        connect_retry: 5,
        resolution: 100,
        passive: false,
        remote_asn: Some(remote_asn),
        min_ttl: None,
        md5_auth_key: None,
        multi_exit_discriminator: None,
        communities: Vec::new(),
        local_pref: None,
        enforce_first_as: true,
        vlan_id: None,
        ipv4_unicast: if v6 { None } else { defaults.ipv4_unicast },
        ipv6_unicast: if v6 { defaults.ipv6_unicast } else { None },
        deterministic_collision_resolution: false,
        idle_hold_jitter: None,
        connect_retry_jitter: None,
    }
}

async fn expect_leaf(
    leaf: &LeafClients,
    index: usize,
    scenario: SpineLeafScenario,
) -> Result<()> {
    let label = format!("ox{}", index + 1);
    let asn = LEAF_ASNS[index];
    for (name, _) in SPINES {
        let names = if scenario.numbered() {
            vec![format!("{name}-v4"), format!("{name}-v6")]
        } else {
            vec![name.to_owned()]
        };
        for name in names {
            wait_for_eq!(
                neighbor_fsm_state(&leaf.mgd, asn, &name).await,
                Some(FsmStateKind::Established),
                &format!("{label} {name} Established")
            );
        }
    }
    let v4 = ORIGINS4[1 - index];
    let v6 = ORIGINS6[1 - index];
    for (af, prefix) in [(AddressFamily::Ipv4, v4), (AddressFamily::Ipv6, v6)] {
        wait_for_eq!(
            mgd_imported_paths(&leaf.mgd, af, prefix).await,
            Some(4),
            &format!("{label} imported {prefix} through four spines")
        );
        wait_for_eq!(
            mgd_selected_paths(&leaf.mgd, af, prefix).await,
            Some(4),
            &format!("{label} selected {prefix} through four spines")
        );
    }
    // Check interfaces as well as count: four targets on one port must not
    // masquerade as installation through all four spines.
    let expected: Vec<_> =
        (0..4).map(|port| (format!("qsfp{port}"), 0)).collect();
    wait_for_eq!(
        installed_ports(&leaf.dpd, v4).await,
        Some(expected.clone()),
        &format!("{label} installed {v4} on all spine ports")
    );
    wait_for_eq!(
        installed_ports(&leaf.dpd, v6).await,
        Some(expected.clone()),
        &format!("{label} installed {v6} on all spine ports")
    );
    Ok(())
}

async fn installed_ports(
    dpd: &DpdClient,
    prefix: &str,
) -> Option<Vec<(String, u8)>> {
    let mut ports: Vec<_> = if prefix.contains(':') {
        dpd.route_ipv6_get(&prefix.parse().ok()?)
            .await
            .ok()?
            .into_inner()
            .into_iter()
            .map(|r| (r.port_id.to_string(), r.link_id.0))
            .collect()
    } else {
        dpd.route_ipv4_get(&prefix.parse().ok()?)
            .await
            .ok()?
            .into_inner()
            .into_iter()
            .map(|r| match r {
                Route::V4(r) => (r.port_id.to_string(), r.link_id.0),
                Route::V6(r) => (r.port_id.to_string(), r.link_id.0),
            })
            .collect()
    };
    ports.sort();
    Some(ports)
}
