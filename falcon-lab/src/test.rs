//! Tests

use crate::{
    bgp::basic_unnumbered_neighbor,
    dendrite::softnpu_link_create,
    frr::FrrNode,
    topo::{Trio, trio},
};
use anyhow::{Context, Result, ensure};
use bgp::session::FsmStateKind;
use libfalcon::Runner;
use mg_admin_client::types::Router;
use slog::info;
use std::time::Duration;
use tokio::time::sleep;

const TRIO_UNNUMBERED_TOPO_NAME: &str = "mgtriou";

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

    // Wait for dendrite to start
    // XXX do better than arbitrary wait
    sleep(Duration::from_secs(5)).await;

    for link in ["qsfp0", "qsfp1"] {
        softnpu_link_create(&dpd, link)
            .await
            .context(format!("create {link}"))?;
    }

    // Wait for tfportd to create tfportqsfpX_X links
    // XXX do better than arbitrary wait
    sleep(Duration::from_secs(5)).await;

    for link in ["tfportqsfp0_0/ll", "tfportqsfp1_0/ll"] {
        ox.illumos()
            .addrconf(&ad, link)
            .await
            .context(format!("create {link}"))?;
    }

    ox.run_mgd(&ad).await?;
    ox.ddm().run_ddm(&ad).await?;

    // Wait for mgd to start
    // XXX do better than arbitrary wait
    sleep(Duration::from_secs(5)).await;

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

    // Wait for session to come up
    // XXX do better than arbitrary wait
    sleep(Duration::from_secs(10)).await;

    let nbrs = mgd
        .get_neighbors_v3(local_asn)
        .await
        .context("get neighbor status")?;

    let routes = mgd
        .get_rib_imported(None, None)
        .await
        .context("get rib imported")?;

    ensure!(
        nbrs.len() == 2,
        "should have two neighbors, found {}",
        nbrs.len()
    );
    ensure!(
        nbrs.values().collect::<Vec<_>>()[0].fsm_state
            == FsmStateKind::Established,
        "first neighbor should be established"
    );
    ensure!(
        nbrs.values().collect::<Vec<_>>()[1].fsm_state
            == FsmStateKind::Established,
        "second neighbor should be established"
    );
    ensure!(
        routes.len() == 1,
        "should have one route, found {}",
        routes.len()
    );
    let paths = routes.0.values().collect::<Vec<_>>()[0];
    ensure!(
        paths.len() == 2,
        "should have two paths for first route, found {}",
        paths.len()
    );

    let dpd_routes = dpd
        .route_ipv4_list(None, None)
        .await
        .context("get dpd routes")?
        .into_inner()
        .items;

    ensure!(
        dpd_routes.len() == 1,
        "should have one selected route in dpd, found {}",
        dpd_routes.len(),
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
