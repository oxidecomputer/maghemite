//! Tests

#![allow(clippy::iter_nth_zero)]

use crate::{
    bgp::basic_unnumbered_neighbor,
    dendrite::{softnpu_link_create, wait_for_dpd},
    frr::FrrNode,
    mgd::wait_for_mgd,
    topo::{Trio, trio},
    wait_for_eq,
};
use anyhow::{Context, Result};
use bgp::session::FsmStateKind;
use libfalcon::Runner;
use mg_admin_client::types::Router;
use slog::info;
use std::time::Duration;

const TRIO_UNNUMBERED_TOPO_NAME: &str = "mgtriou";
const OP_TIMEOUT: Duration = Duration::from_secs(10);

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
) -> Result<()> {
    let Trio {
        mut d,
        ox,
        cr1,
        cr2,
    } = trio(TRIO_UNNUMBERED_TOPO_NAME)?;
    d.persistent = persistent;

    d.launch().await.context("launch failed")?;

    let ad = std::sync::Arc::new(d);

    let addr = ox.illumos().dhcp(&ad, "vioif1/dhcp").await?;

    // These take a minute, knock them out concurrently
    let mut js = tokio::task::JoinSet::new();
    js.spawn(frr_setup(cr1, ad.clone()));
    js.spawn(frr_setup(cr2, ad.clone()));
    js.spawn(ox.dendrite().npuvm(
        ad.clone(),
        2,
        0,
        npuvm_commit,
        dendrite_commit,
    ));
    for result in js.join_all().await.into_iter() {
        result?;
    }

    let mgd = ox.client(&ad, addr).await?;
    let dpd = ox.dendrite().client(&ad, addr).await?;

    // Wait for dpd to start
    wait_for_dpd(&dpd, OP_TIMEOUT, &ad.log).await?;

    for link in ["qsfp0", "qsfp1"] {
        softnpu_link_create(&dpd, link)
            .await
            .context(format!("create {link}"))?;
    }

    for link in ["tfportqsfp0_0", "tfportqsfp1_0"] {
        ox.illumos().wait_for_link(&ad, link, OP_TIMEOUT).await?;
        let addr = format!("{link}/ll");
        ox.illumos()
            .addrconf(&ad, &addr)
            .await
            .context(format!("create {addr}"))?;
    }

    ox.run_mgd(&ad).await?;
    ox.ddm().run_ddm(&ad).await?;

    // Wait for mgd to start
    wait_for_mgd(&mgd, OP_TIMEOUT, &ad.log).await?;

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

    mgd.create_unnumbered_neighbor(&basic_unnumbered_neighbor(
        "cr1",
        "test",
        "tfportqsfp0_0",
        33,
    ))
    .await
    .context("mgd: create cr1 unnumbered neighbor")?;

    mgd.create_unnumbered_neighbor(&basic_unnumbered_neighbor(
        "cr2",
        "test",
        "tfportqsfp1_0",
        33,
    ))
    .await
    .context("mgd: create cr2 unnumbered neighbor")?;

    wait_for_eq!(
        mgd.get_neighbors_v3(local_asn)
            .await
            .map(|x| x.len())
            .unwrap_or(0),
        2,
        "neighbors"
    );

    wait_for_eq!(
        mgd.get_neighbors_v3(local_asn)
            .await
            .map(|x| x.values().nth(0).map(|y| y.fsm_state))
            .unwrap_or(None),
        Some(FsmStateKind::Established),
        "first neighbor established"
    );

    wait_for_eq!(
        mgd.get_rib_imported(None, None)
            .await
            .map(|x| x.len())
            .unwrap_or(0),
        1,
        "one imported route"
    );

    wait_for_eq!(
        mgd.get_rib_imported(None, None)
            .await
            .map(|x| x.values().nth(0).map(|x| x.len()))
            .unwrap_or(None),
        Some(2),
        "two paths"
    );

    wait_for_eq!(
        dpd.route_ipv4_list(None, None)
            .await
            .map(|x| x.items.len())
            .unwrap_or(0),
        1,
        "dpd routes"
    );

    info!(ad.log, "trio bgp unnumbered test passed 🎉");

    Ok(())
}

async fn frr_setup(r: FrrNode, d: std::sync::Arc<Runner>) -> Result<()> {
    const BASE_CONFIG: &str = "
        configure
        ip forwarding
        ip route 1.2.3.0/24 null0
        route-map PERMIT-ALL permit 10
        router bgp 44
          timers bgp 2 6
          neighbor enp0s8 interface remote-as external
          neighbor enp0s8 capability extended-nexthop
          neighbor enp0s8 timers connect 1     
          neighbor enp0s8 route-map PERMIT-ALL out
          network 1.2.3.0/24
        exit
    ";

    r.install(&d).await?;
    r.enable_daemon(&d, "bgpd").await?;
    r.shell(&d, BASE_CONFIG).await?;
    Ok(())
}
