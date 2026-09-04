//! Scenario setup, assertions, and failure diagnostics.

#![allow(clippy::iter_nth_zero)]

use crate::{
    bgp::basic_unnumbered_neighbor,
    ddm::DdmNode,
    dendrite::{NpuvmCommits, softnpu_link_create, wait_for_dpd},
    diagnostics::ProtocolDiagnostics,
    eos::EosNode,
    frr::FrrNode,
    juniper::{JuniperNode, clear_staged_routing_configs},
    mgd::{MgdNode, wait_for_mgd},
    topo::{DdmTrio, Interop, MgdDuo, Topology},
    wait_for_eq, wait_for_eq_stable,
};
use anyhow::{Context, Result};
use clap::ValueEnum;
use ddm_admin_client::{
    Client as DdmClient,
    types::{ApplyRequest, PathVector},
};
use ddm_api_types::db::{InterfaceLifetime, RouterKind};
use dpd_client::{
    Client as DpdClient,
    types::{Ipv4Entry, Ipv6Entry, LinkId, PortId},
};
use libfalcon::Runner;
use mg_admin_client::{
    Client as MgdClient,
    types::{BfdPeerConfig, BfdPeerState, SessionMode},
};
use mg_api_types::bgp::config::{Origin4, Router};
use mg_api_types::bgp::history::Origin6;
use mg_api_types::bgp::session::FsmStateKind;
use mg_api_types::rdb::rib::AddressFamily;
use mg_api_types::rib::BestpathFanoutRequest;
use mg_api_types::static_routes::{
    AddStaticRoute4Request, AddStaticRoute6Request, StaticRoute4,
    StaticRoute4List, StaticRoute6, StaticRoute6List,
};
use oxnet::{Ipv4Net, Ipv6Net};
use slog::{info, warn};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU8,
    sync::Arc,
    time::Duration,
};
use tokio::time::timeout;

// Falcon derives dladm link names from the deployment name by appending the
// node, endpoint kind, and link type, and illumos reserves one byte of
// MAXLINKNAMELEN (32) for the NUL terminator. Check every deployment name at
// compile time so an incompatible name fails the build rather than a lab run.
const fn assert_falcon_compatible(name: &str) {
    let name = name.as_bytes();
    assert!(!name.is_empty() && name[0].is_ascii_alphabetic());
    let mut i = 0;
    while i < name.len() {
        assert!(name[i].is_ascii_alphanumeric() || name[i] == b'_');
        i += 1;
    }
    assert!(name.len() + "_peer_vn_vnic0".len() < 32);
}

const _: () = {
    use strum::VariantArray;
    let mut i = 0;
    while i < MgdDuoScenario::VARIANTS.len() {
        assert_falcon_compatible(MgdDuoScenario::VARIANTS[i].name());
        i += 1;
    }
    let mut i = 0;
    while i < InteropScenario::VARIANTS.len() {
        assert_falcon_compatible(InteropScenario::VARIANTS[i].name());
        i += 1;
    }
    let mut i = 0;
    while i < DdmTrioScenario::VARIANTS.len() {
        assert_falcon_compatible(DdmTrioScenario::VARIANTS[i].name());
        i += 1;
    }
};

pub(crate) struct ScenarioOptions {
    persistent: bool,
    diag_on_fail: bool,
    commits: NpuvmCommits,
}

impl ScenarioOptions {
    pub(crate) fn new(
        persistent: bool,
        diag_on_fail: bool,
        commits: NpuvmCommits,
    ) -> Self {
        Self {
            persistent,
            diag_on_fail,
            commits,
        }
    }
}

pub(crate) trait Scenario: Sized + Copy {
    type Topology: Topology<Scenario = Self>;

    async fn run(self, options: ScenarioOptions) -> Result<()>;

    async fn run_bare(self, persistent: bool) -> Result<()> {
        let mut topology = Self::Topology::build(self)?;
        let runner = topology.runner_mut();
        runner.persistent = persistent;
        timeout(LAUNCH_TIMEOUT, runner.launch())
            .await
            .context("launch timed out")?
            .context("launch failed")
    }

    fn cleanup(self) -> Result<()> {
        Self::Topology::build(self).map(drop)
    }
}

#[derive(Copy, Clone, Debug, ValueEnum, strum::VariantArray)]
pub(crate) enum MgdDuoScenario {
    Bare,
    BgpUnnumbered,
}

impl MgdDuoScenario {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bare => "mgdduo_bare",
            Self::BgpUnnumbered => "mgdduo_bgpu",
        }
    }
}

impl Scenario for MgdDuoScenario {
    type Topology = MgdDuo;

    async fn run(self, options: ScenarioOptions) -> Result<()> {
        match self {
            Self::Bare => self.run_bare(options.persistent).await,
            Self::BgpUnnumbered => {
                run_mgd_unnumbered(
                    self,
                    options.persistent,
                    options.diag_on_fail,
                )
                .await
            }
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum, strum::VariantArray)]
pub(crate) enum InteropScenario {
    Bare,
    BgpUnnumbered,
    BfdStaticRouting,
}

impl InteropScenario {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bare => "interop_bare",
            Self::BgpUnnumbered => "interop_bgpu",
            Self::BfdStaticRouting => "interop_bfd",
        }
    }
}

impl Scenario for InteropScenario {
    type Topology = Interop;

    async fn run(self, options: ScenarioOptions) -> Result<()> {
        match self {
            Self::Bare => {
                clear_staged_routing_configs()
                    .context("clear stale Junos config")?;
                self.run_bare(options.persistent).await
            }
            Self::BgpUnnumbered => {
                run_interop_unnumbered(
                    self,
                    options.persistent,
                    options.diag_on_fail,
                    options.commits,
                )
                .await
            }
            Self::BfdStaticRouting => {
                run_interop_bfd_static(
                    self,
                    options.persistent,
                    options.diag_on_fail,
                    options.commits,
                )
                .await
            }
        }
    }

    fn cleanup(self) -> Result<()> {
        cleanup_interop_deployment(self)
    }
}

#[derive(Copy, Clone, Debug, ValueEnum, strum::VariantArray)]
pub(crate) enum DdmTrioScenario {
    Bare,
    DdmApplyLifecycle,
}

impl DdmTrioScenario {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bare => "ddmtrio_bare",
            Self::DdmApplyLifecycle => "ddmtrio_apply",
        }
    }
}

impl Scenario for DdmTrioScenario {
    type Topology = DdmTrio;

    async fn run(self, options: ScenarioOptions) -> Result<()> {
        match self {
            Self::Bare => self.run_bare(options.persistent).await,
            Self::DdmApplyLifecycle => {
                run_ddm_apply_lifecycle(
                    self,
                    options.persistent,
                    options.diag_on_fail,
                )
                .await
            }
        }
    }
}

const CR1_BFD_FRR_CONFIG: &str = "cr1-bfd-frr.conf";
const OP_TIMEOUT: Duration = Duration::from_secs(10);
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(10 * 60);

// Helios nodes create a direct test link before their management link, so the
// peer-facing viona interface is vioif0 and the DHCP management interface is
// vioif1.
const HELIOS_PEER_LINK: &str = "vioif0";
const HELIOS_MGMT_ADDR: &str = "vioif1/dhcp";

// The ddm-trio hub's two peer links are created before its management link.
// Each leaf has one peer link followed by management.
const DDM_HUB_PEER1_IF: &str = "vioif0";
const DDM_HUB_PEER2_IF: &str = "vioif1";
const DDM_HUB_MGMT_ADDR: &str = "vioif2/dhcp";
const DDM_LEAF_PEER_IF: &str = "vioif0";
const DDM_LEAF_MGMT_ADDR: &str = "vioif1/dhcp";
const DDM_PEER1_PREFIX: &str = "fd00:dd01::/64";
const DDM_PEER2_PREFIX: &str = "fd00:dd02::/64";

// BFD-static test addressing. `OX_*` addresses are configured on the softnpu
// side of each link; the other addresses are configured on its peer.
const OX_CR1_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const CR1_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const OX_CR2_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 1);
const CR2_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);
const OX_CR3_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 1);
const CR3_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const OX_PEER_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 3, 1);
const PEER_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 3, 2);
const OX_CR1_V4_CIDR: &str = "10.0.0.1/24";
const OX_CR2_V4_CIDR: &str = "10.0.1.1/24";
const OX_CR3_V4_CIDR: &str = "10.0.2.1/24";
const OX_PEER_V4_CIDR: &str = "10.0.3.1/24";
const CR2_V4_CIDR: &str = "10.0.1.2/24";
const CR3_V4_CIDR: &str = "10.0.2.2/24";
const PEER_V4_CIDR: &str = "10.0.3.2/24";

const OX_CR1_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1); // fd00:1::1
const CR1_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 2); // fd00:1::2
const OX_CR2_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 2, 0, 0, 0, 0, 0, 1); // fd00:2::1
const CR2_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 2, 0, 0, 0, 0, 0, 2); // fd00:2::2
const OX_CR3_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 3, 0, 0, 0, 0, 0, 1); // fd00:3::1
const CR3_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 3, 0, 0, 0, 0, 0, 2); // fd00:3::2
const OX_PEER_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 4, 0, 0, 0, 0, 0, 1); // fd00:4::1
const PEER_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 4, 0, 0, 0, 0, 0, 2); // fd00:4::2
const OX_CR1_V6_CIDR: &str = "fd00:1::1/64";
const OX_CR2_V6_CIDR: &str = "fd00:2::1/64";
const OX_CR3_V6_CIDR: &str = "fd00:3::1/64";
const OX_PEER_V6_CIDR: &str = "fd00:4::1/64";
const CR2_V6_CIDR: &str = "fd00:2::2/64";
const CR3_V6_CIDR: &str = "fd00:3::2/64";
const PEER_V6_CIDR: &str = "fd00:4::2/64";

/// Destination prefixes with nexthops via every interop peer.
const TEST_PREFIX_V4: &str = "192.168.100.0/24";
const TEST_PREFIX_V6: &str = "fd01::/64";

/// BFD detection time: 1s * 3 = 3s.
///
/// mgd currently advertises a fixed 1s desired transmit interval, regardless of
/// its configured required receive interval. Keep the lab's receive interval at
/// 1s so peers that honor mgd's advertised desired transmit interval do not
/// send too slowly for mgd's detection time.
const BFD_REQUIRED_RX_US: u64 = 1_000_000;
const BFD_DETECTION_MULT: NonZeroU8 = NonZeroU8::new(3).unwrap();

/// Running interop topology plus clients ready for scenario configuration.
struct BootedInterop {
    ad: Arc<Runner>,
    ox: MgdNode,
    peer: MgdNode,
    cr1: FrrNode,
    cr2: EosNode,
    cr3: JuniperNode,
    mgd: MgdClient,
    peer_mgd: MgdClient,
    dpd: DpdClient,
    #[allow(dead_code)]
    mgmt_addr: IpAddr,
    scenario: InteropScenario,
    protocols: ProtocolDiagnostics,
}

#[derive(Copy, Clone)]
struct InteropRouters {
    cr1: FrrNode,
    cr2: EosNode,
    cr3: JuniperNode,
}

struct InteropPeerStates<T> {
    cr1: T,
    cr2: T,
    cr3: T,
    peer: T,
}

impl<T> InteropPeerStates<T> {
    fn new(cr1: T, cr2: T, cr3: T, peer: T) -> Self {
        Self {
            cr1,
            cr2,
            cr3,
            peer,
        }
    }
}

/// Output of `boot_mgd_duo`: two Helios nodes with mgd admin clients ready for
/// test-specific configuration.
struct BootedMgdDuo {
    ad: Arc<Runner>,
    ox1: MgdNode,
    ox2: MgdNode,
    mgd1: MgdClient,
    mgd2: MgdClient,
    scenario: MgdDuoScenario,
}

/// Output of `boot_ddm_trio`: three Helios nodes running ddmd with admin
/// clients ready for scenario-specific `ddm_apply` calls.
struct BootedDdmTrio {
    ad: Arc<Runner>,
    hub: DdmNode,
    peer1: DdmNode,
    peer2: DdmNode,
    hub_client: DdmClient,
    peer1_client: DdmClient,
    peer2_client: DdmClient,
    scenario: DdmTrioScenario,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DdmObservedState {
    hub_peers: usize,
    peer1_peers: usize,
    peer2_peers: usize,
    hub_prefixes: BTreeSet<Ipv6Net>,
    peer1_prefixes: BTreeSet<Ipv6Net>,
    peer2_prefixes: BTreeSet<Ipv6Net>,
}

/// Run a test body against a booted topology and dump diagnostics from every
/// VM if it fails. The body consumes the `BootedInterop`, so cache the bits
/// `collect_diagnostics` needs before handing it off.
async fn run_with_optional_diagnostics<F, Fut>(
    bt: BootedInterop,
    diag_on_fail: bool,
    body: F,
) -> Result<()>
where
    F: FnOnce(BootedInterop) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let ad = bt.ad.clone();
    let ox = bt.ox;
    let peer = bt.peer;
    let routers = InteropRouters {
        cr1: bt.cr1,
        cr2: bt.cr2,
        cr3: bt.cr3,
    };
    let mgd = bt.mgd.clone();
    let peer_mgd = bt.peer_mgd.clone();
    let topo_name = bt.scenario.name();
    let protocols = bt.protocols;
    let result = body(bt).await;
    if let Err(e) = &result {
        warn!(ad.log, "{topo_name} failed: {e:#}");
        // Some failure tests intentionally suspend routing daemons to verify
        // convergence. Resume them before diagnostics so collection can use
        // each vendor's normal CLI/API path rather than timing out on the
        // fault we injected.
        restore_interop_before_diagnostics(&ad, routers).await;
        if diag_on_fail {
            collect_interop_diagnostics(
                &ad, ox, peer, routers, topo_name, protocols,
            )
            .await;
            ox.collect_ndp_diagnostics(&ad, &mgd, topo_name).await;
            peer.collect_ndp_diagnostics(&ad, &peer_mgd, topo_name)
                .await;
        }
    }
    result
}

async fn restore_interop_before_diagnostics(
    ad: &Runner,
    routers: InteropRouters,
) {
    let InteropRouters { cr1, cr2, cr3 } = routers;
    match timeout(OP_TIMEOUT, cr1.start_frr(ad)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(ad.log, "failed to start cr1 frr before diagnostics: {e:#}")
        }
        Err(_) => {
            warn!(ad.log, "timed out starting cr1 frr before diagnostics")
        }
    }
    match timeout(OP_TIMEOUT, cr2.unpause(ad)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(ad.log, "failed to unpause cr2 before diagnostics: {e:#}")
        }
        Err(_) => warn!(ad.log, "timed out unpausing cr2 before diagnostics"),
    }
    match timeout(OP_TIMEOUT, cr3.unpause(ad)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(ad.log, "failed to unpause cr3 before diagnostics: {e:#}")
        }
        Err(_) => warn!(ad.log, "timed out unpausing cr3 before diagnostics"),
    }
}

/// Run a test body against a booted mgd-duo topology and dump diagnostics from
/// both Helios nodes if it fails.
async fn run_mgd_duo_with_optional_diagnostics<F, Fut>(
    bt: BootedMgdDuo,
    diag_on_fail: bool,
    body: F,
) -> Result<()>
where
    F: FnOnce(BootedMgdDuo) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let ad = bt.ad.clone();
    let ox1 = bt.ox1;
    let ox2 = bt.ox2;
    let topo_name = bt.scenario.name();
    let result = body(bt).await;
    if let Err(e) = &result {
        warn!(ad.log, "{topo_name} failed: {e:#}");
        if diag_on_fail {
            collect_mgd_duo_diagnostics(&ad, ox1, ox2, topo_name).await;
        }
    }
    result
}

/// Run a test body against a booted ddm-trio topology and dump diagnostics
/// from every Helios node if it fails.
async fn run_ddm_trio_with_optional_diagnostics<F, Fut>(
    bt: BootedDdmTrio,
    diag_on_fail: bool,
    body: F,
) -> Result<()>
where
    F: FnOnce(BootedDdmTrio) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let ad = bt.ad.clone();
    let nodes = [bt.hub, bt.peer1, bt.peer2];
    let topo_name = bt.scenario.name();
    let result = body(bt).await;
    if let Err(e) = &result {
        warn!(ad.log, "{topo_name} failed: {e:#}");
        if diag_on_fail {
            collect_ddm_trio_diagnostics(&ad, nodes, topo_name).await;
        }
    }
    result
}

/// Launch the ddm-trio topology, bring up link-local addresses on every peer
/// link, start ddmd (transit hub, server leaves) and wait for each admin API
/// to answer. The hub gets `hub_static_ifaces` on its command line; the
/// leaves start with no interfaces.
async fn boot_ddm_trio(
    scenario: DdmTrioScenario,
    persistent: bool,
    diag_on_fail: bool,
    hub_static_ifaces: &[&str],
) -> Result<BootedDdmTrio> {
    let topo_name = scenario.name();
    let DdmTrio {
        mut d,
        hub,
        peer1,
        peer2,
    } = DdmTrio::build(scenario)?;
    d.persistent = persistent;
    timeout(LAUNCH_TIMEOUT, d.launch())
        .await
        .context("launch timed out")?
        .context("launch failed")?;
    let ad = Arc::new(d);

    let result = async {
        let hub_illumos = hub.illumos();
        let peer1_illumos = peer1.illumos();
        let peer2_illumos = peer2.illumos();
        let (hub_addr, peer1_addr, peer2_addr) = tokio::try_join!(
            hub_illumos.dhcp(&ad, DDM_HUB_MGMT_ADDR),
            peer1_illumos.dhcp(&ad, DDM_LEAF_MGMT_ADDR),
            peer2_illumos.dhcp(&ad, DDM_LEAF_MGMT_ADDR),
        )?;
        let hub_peer1_ll = format!("{DDM_HUB_PEER1_IF}/ll");
        let hub_peer2_ll = format!("{DDM_HUB_PEER2_IF}/ll");
        let leaf_peer_ll = format!("{DDM_LEAF_PEER_IF}/ll");
        tokio::try_join!(
            hub_illumos.addrconf(&ad, &hub_peer1_ll),
            hub_illumos.addrconf(&ad, &hub_peer2_ll),
            peer1_illumos.addrconf(&ad, &leaf_peer_ll),
            peer2_illumos.addrconf(&ad, &leaf_peer_ll),
        )?;

        let hub_client = hub.client(&ad, hub_addr).await?;
        let peer1_client = peer1.client(&ad, peer1_addr).await?;
        let peer2_client = peer2.client(&ad, peer2_addr).await?;
        tokio::try_join!(
            hub.run_ddm(&ad, RouterKind::Transit, hub_static_ifaces),
            peer1.run_ddm(&ad, RouterKind::Server, &[]),
            peer2.run_ddm(&ad, RouterKind::Server, &[]),
        )?;
        tokio::try_join!(
            hub.wait_for_api(&hub_client, OP_TIMEOUT, &ad),
            peer1.wait_for_api(&peer1_client, OP_TIMEOUT, &ad),
            peer2.wait_for_api(&peer2_client, OP_TIMEOUT, &ad),
        )?;

        Ok((hub_client, peer1_client, peer2_client))
    }
    .await;

    match result {
        Ok((hub_client, peer1_client, peer2_client)) => Ok(BootedDdmTrio {
            ad,
            hub,
            peer1,
            peer2,
            hub_client,
            peer1_client,
            peer2_client,
            scenario,
        }),
        Err(e) => {
            warn!(ad.log, "{topo_name} boot failed: {e:#}");
            if diag_on_fail {
                collect_ddm_trio_diagnostics(
                    &ad,
                    [hub, peer1, peer2],
                    topo_name,
                )
                .await;
            }
            Err(e)
        }
    }
}

/// Launch two Helios nodes with a direct link between them and obtain mgd
/// admin clients over their management links.
async fn boot_mgd_duo(
    scenario: MgdDuoScenario,
    persistent: bool,
    diag_on_fail: bool,
) -> Result<BootedMgdDuo> {
    let topo_name = scenario.name();
    let MgdDuo { mut d, ox1, ox2 } = MgdDuo::build(scenario)?;
    d.persistent = persistent;
    d.launch().await.context("launch failed")?;
    let ad = Arc::new(d);

    let result = async {
        let ox1_illumos = ox1.illumos();
        let ox2_illumos = ox2.illumos();
        let (mgmt1, mgmt2) = tokio::try_join!(
            ox1_illumos.dhcp(&ad, HELIOS_MGMT_ADDR),
            ox2_illumos.dhcp(&ad, HELIOS_MGMT_ADDR),
        )?;
        let mgd1 = ox1.client(&ad, mgmt1).await?;
        let mgd2 = ox2.client(&ad, mgmt2).await?;

        Ok((mgd1, mgd2))
    }
    .await;

    match result {
        Ok((mgd1, mgd2)) => Ok(BootedMgdDuo {
            ad,
            ox1,
            ox2,
            mgd1,
            mgd2,
            scenario,
        }),
        Err(e) => {
            warn!(ad.log, "{topo_name} boot failed: {e:#}");
            if diag_on_fail {
                collect_mgd_duo_boot_diagnostics(&ad, ox1, ox2, topo_name)
                    .await;
            }
            Err(e)
        }
    }
}

/// Launch the interop topology and complete the work shared by every interop
/// test: dhcp mgmt, concurrent vendor-peer install + npuvm setup, peer mgd and
/// dpd startup, softnpu link creation, and tfport readiness. The caller
/// supplies a closure that populates a `JoinSet` with vendor-peer setup futures
/// so that they run concurrently with the npuvm install.
async fn boot_interop<F>(
    scenario: InteropScenario,
    persistent: bool,
    diag_on_fail: bool,
    commits: NpuvmCommits,
    protocols: ProtocolDiagnostics,
    spawn_peer_setups: F,
) -> Result<BootedInterop>
where
    F: FnOnce(
        FrrNode,
        EosNode,
        JuniperNode,
        Arc<Runner>,
    ) -> tokio::task::JoinSet<Result<()>>,
{
    let Interop {
        mut d,
        ox,
        peer,
        cr1,
        cr2,
        cr3,
    } = Interop::build(scenario)?;
    let topo_name = scenario.name();
    d.persistent = persistent;
    clear_staged_routing_configs().context("clear stale Junos config")?;
    info!(d.log, "{topo_name}: launching interop topology");
    timeout(LAUNCH_TIMEOUT, d.launch())
        .await
        .context("launch timed out")?
        .context("launch failed")?;
    info!(d.log, "{topo_name}: interop topology launch complete");
    let ad = Arc::new(d);

    // Any failure between launch and Ok needs to dump diagnostics from the
    // running deployment. Wrap the rest of boot in a closure so we have a
    // single Err path to hook.
    let result = boot_interop_inner(
        &ad,
        ox,
        peer,
        InteropRouters { cr1, cr2, cr3 },
        commits,
        spawn_peer_setups,
    )
    .await;

    match result {
        Ok((mgd, peer_mgd, dpd, mgmt_addr)) => Ok(BootedInterop {
            ad,
            ox,
            peer,
            cr1,
            cr2,
            cr3,
            mgd,
            peer_mgd,
            dpd,
            mgmt_addr,
            scenario,
            protocols,
        }),
        Err(e) => {
            warn!(ad.log, "{topo_name} boot failed: {e:#}");
            if diag_on_fail {
                collect_interop_boot_diagnostics(
                    &ad,
                    ox,
                    peer,
                    InteropRouters { cr1, cr2, cr3 },
                    topo_name,
                )
                .await;
            }
            Err(e)
        }
    }
}

async fn boot_interop_inner<F>(
    ad: &Arc<Runner>,
    ox: MgdNode,
    peer: MgdNode,
    routers: InteropRouters,
    commits: NpuvmCommits,
    spawn_peer_setups: F,
) -> Result<(MgdClient, MgdClient, DpdClient, IpAddr)>
where
    F: FnOnce(
        FrrNode,
        EosNode,
        JuniperNode,
        Arc<Runner>,
    ) -> tokio::task::JoinSet<Result<()>>,
{
    let InteropRouters { cr1, cr2, cr3 } = routers;
    let ox_illumos = ox.illumos();
    let peer_illumos = peer.illumos();
    let (mgmt_addr, peer_mgmt_addr) = tokio::try_join!(
        ox_illumos.dhcp(ad, HELIOS_MGMT_ADDR),
        peer_illumos.dhcp(ad, HELIOS_MGMT_ADDR),
    )?;

    let mut js = spawn_peer_setups(cr1, cr2, cr3, ad.clone());
    let npuvm_ad = ad.clone();
    js.spawn(async move {
        ox.dendrite()
            .npuvm(npuvm_ad, 4, 0, commits)
            .await
            .context("setup ox npuvm")
    });
    for result in js.join_all().await.into_iter() {
        result?;
    }

    let (mgd, peer_mgd) = tokio::try_join!(
        ox.client(ad, mgmt_addr),
        peer.client(ad, peer_mgmt_addr),
    )?;
    peer.run_mgd(ad).await?;
    wait_for_mgd(&peer_mgd, OP_TIMEOUT, &ad.log)
        .await
        .context("wait for peer mgd")?;

    let dpd = ox.dendrite().client(ad, mgmt_addr).await?;
    wait_for_dpd(&dpd, OP_TIMEOUT, &ad.log)
        .await
        .context("wait_for_dpd")?;

    for link in ["qsfp0", "qsfp1", "qsfp2", "qsfp3"] {
        softnpu_link_create(&dpd, link)
            .await
            .context(format!("create {link}"))?;
    }
    for link in [
        "tfportqsfp0_0",
        "tfportqsfp1_0",
        "tfportqsfp2_0",
        "tfportqsfp3_0",
    ] {
        ox.illumos().wait_for_link(ad, link, OP_TIMEOUT).await?;
    }

    Ok((mgd, peer_mgd, dpd, mgmt_addr))
}

/// Always attempt both deployment and staged-config cleanup. In particular, a
/// filesystem error must not leave a persistent Falcon deployment running.
fn cleanup_interop_deployment(scenario: InteropScenario) -> Result<()> {
    let deployment_result = Interop::build(scenario).map(drop);
    let config_result =
        clear_staged_routing_configs().context("clear stale Junos config");
    deployment_result?;
    config_result
}

async fn run_ddm_apply_lifecycle(
    scenario: DdmTrioScenario,
    persistent: bool,
    diag_on_fail: bool,
) -> Result<()> {
    let bt =
        boot_ddm_trio(scenario, persistent, diag_on_fail, &[DDM_HUB_PEER2_IF])
            .await?;
    run_ddm_trio_with_optional_diagnostics(
        bt,
        diag_on_fail,
        ddm_apply_lifecycle_body,
    )
    .await
}

/// The hub starts with a static (`-a`) interface toward peer2 and no dynamic
/// interfaces. Everything toward peer1, and both leaves' interfaces, are
/// driven through `ddm_apply`.
async fn ddm_apply_lifecycle_body(bt: BootedDdmTrio) -> Result<()> {
    let BootedDdmTrio {
        ad,
        hub_client,
        peer1_client,
        peer2_client,
        ..
    } = bt;
    let prefix1: Ipv6Net = DDM_PEER1_PREFIX.parse()?;
    let prefix2: Ipv6Net = DDM_PEER2_PREFIX.parse()?;
    let hub_static_only = BTreeMap::from([(
        DDM_HUB_PEER2_IF.to_string(),
        InterfaceLifetime::Static,
    )]);

    info!(ad.log, "peering over the hub's static DDM interface");
    wait_for_eq!(
        observe_ddm_interfaces(&hub_client).await,
        Some(hub_static_only.clone()),
        1,
        10,
        "hub reports its command-line interface as static"
    );
    apply_ddm(&peer2_client, &[DDM_LEAF_PEER_IF]).await?;
    peer2_client.advertise_prefixes(&vec![prefix2]).await?;
    let static_only_up = DdmObservedState {
        hub_peers: 1,
        peer1_peers: 0,
        peer2_peers: 1,
        hub_prefixes: BTreeSet::from([prefix2]),
        peer1_prefixes: BTreeSet::new(),
        peer2_prefixes: BTreeSet::new(),
    };
    wait_for_eq_stable!(
        observe_ddm_state(&hub_client, &peer1_client, &peer2_client).await,
        Some(static_only_up.clone()),
        3,
        1,
        30,
        "static DDM interface exchanges routes with a dynamic peer"
    );

    info!(
        ad.log,
        "adding a dynamic DDM interface alongside the static one"
    );
    apply_ddm(&hub_client, &[DDM_HUB_PEER1_IF]).await?;
    apply_ddm(&peer1_client, &[DDM_LEAF_PEER_IF]).await?;
    peer1_client.advertise_prefixes(&vec![prefix1]).await?;
    let both_up = DdmObservedState {
        hub_peers: 2,
        peer1_peers: 1,
        peer2_peers: 1,
        hub_prefixes: BTreeSet::from([prefix1, prefix2]),
        peer1_prefixes: BTreeSet::from([prefix2]),
        peer2_prefixes: BTreeSet::from([prefix1]),
    };
    wait_for_eq_stable!(
        observe_ddm_state(&hub_client, &peer1_client, &peer2_client).await,
        Some(both_up.clone()),
        3,
        1,
        30,
        "static and dynamic DDM interfaces exchange independent routes"
    );
    wait_for_eq!(
        observe_ddm_interfaces(&hub_client).await,
        Some(BTreeMap::from([
            (DDM_HUB_PEER1_IF.to_string(), InterfaceLifetime::Dynamic),
            (DDM_HUB_PEER2_IF.to_string(), InterfaceLifetime::Static),
        ])),
        1,
        10,
        "hub reports one dynamic and one static interface"
    );

    info!(ad.log, "reapplying identical desired state");
    apply_ddm(&hub_client, &[DDM_HUB_PEER1_IF]).await?;
    wait_for_eq_stable!(
        observe_ddm_state(&hub_client, &peer1_client, &peer2_client).await,
        Some(both_up.clone()),
        3,
        1,
        10,
        "identical ddm_apply is idempotent"
    );

    info!(ad.log, "naming the static interface in ddm_apply");
    apply_ddm(&hub_client, &[DDM_HUB_PEER1_IF, DDM_HUB_PEER2_IF]).await?;
    wait_for_eq_stable!(
        observe_ddm_state(&hub_client, &peer1_client, &peer2_client).await,
        Some(both_up.clone()),
        3,
        1,
        10,
        "a static interface named in ddm_apply is left alone"
    );
    wait_for_eq!(
        observe_ddm_interfaces(&hub_client).await,
        Some(BTreeMap::from([
            (DDM_HUB_PEER1_IF.to_string(), InterfaceLifetime::Dynamic),
            (DDM_HUB_PEER2_IF.to_string(), InterfaceLifetime::Static),
        ])),
        1,
        10,
        "naming a static interface does not change its lifetime"
    );

    info!(
        ad.log,
        "removing every dynamic hub interface with ddm_apply({{}})"
    );
    apply_ddm(&hub_client, &[]).await?;
    wait_for_eq_stable!(
        observe_ddm_state(&hub_client, &peer1_client, &peer2_client).await,
        Some(static_only_up.clone()),
        3,
        1,
        30,
        "removed dynamic interface withdraws its routes while the static one remains"
    );
    wait_for_eq!(
        observe_ddm_interfaces(&hub_client).await,
        Some(hub_static_only.clone()),
        1,
        10,
        "empty ddm_apply leaves only the static interface"
    );

    info!(
        ad.log,
        "removing peer2's dynamic interface with ddm_apply({{}})"
    );
    apply_ddm(&peer2_client, &[]).await?;
    wait_for_eq_stable!(
        observe_ddm_state(&hub_client, &peer1_client, &peer2_client).await,
        Some(DdmObservedState {
            hub_peers: 0,
            peer1_peers: 0,
            peer2_peers: 0,
            hub_prefixes: BTreeSet::new(),
            peer1_prefixes: BTreeSet::new(),
            peer2_prefixes: BTreeSet::new(),
        }),
        3,
        1,
        30,
        "empty desired state tears down every adjacency and learned route"
    );

    info!(ad.log, "DDM apply lifecycle test passed 🎉");
    Ok(())
}

async fn apply_ddm(client: &DdmClient, interfaces: &[&str]) -> Result<()> {
    client
        .ddm_apply(&ApplyRequest {
            ddm_interfaces: interfaces
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        })
        .await?;
    Ok(())
}

/// Every interface ddmd knows about, keyed by name, with its lifetime.
async fn observe_ddm_interfaces(
    client: &DdmClient,
) -> Option<BTreeMap<String, InterfaceLifetime>> {
    Some(
        client
            .get_interfaces()
            .await
            .ok()?
            .into_inner()
            .into_values()
            .map(|info| (info.name, info.lifetime))
            .collect(),
    )
}

async fn observe_ddm_state(
    hub: &DdmClient,
    peer1: &DdmClient,
    peer2: &DdmClient,
) -> Option<DdmObservedState> {
    let (
        hub_peers,
        peer1_peers,
        peer2_peers,
        hub_prefixes,
        peer1_prefixes,
        peer2_prefixes,
    ) = tokio::join!(
        hub.get_peers(),
        peer1.get_peers(),
        peer2.get_peers(),
        hub.get_prefixes(),
        peer1.get_prefixes(),
        peer2.get_prefixes(),
    );
    let destinations = |prefixes: HashMap<String, Vec<PathVector>>| {
        prefixes
            .into_values()
            .flatten()
            .map(|path| path.destination)
            .collect()
    };
    Some(DdmObservedState {
        hub_peers: hub_peers.ok()?.len(),
        peer1_peers: peer1_peers.ok()?.len(),
        peer2_peers: peer2_peers.ok()?.len(),
        hub_prefixes: destinations(hub_prefixes.ok()?.into_inner()),
        peer1_prefixes: destinations(peer1_prefixes.ok()?.into_inner()),
        peer2_prefixes: destinations(peer2_prefixes.ok()?.into_inner()),
    })
}

async fn run_mgd_unnumbered(
    scenario: MgdDuoScenario,
    persistent: bool,
    diag_on_fail: bool,
) -> Result<()> {
    let bt = boot_mgd_duo(scenario, persistent, diag_on_fail).await?;

    run_mgd_duo_with_optional_diagnostics(bt, diag_on_fail, mgd_unnumbered_body)
        .await
}

async fn mgd_unnumbered_body(bt: BootedMgdDuo) -> Result<()> {
    let BootedMgdDuo {
        ad,
        ox1,
        ox2,
        mgd1,
        mgd2,
        ..
    } = bt;

    for ox in [ox1, ox2] {
        let addr = format!("{HELIOS_PEER_LINK}/ll");
        ox.illumos()
            .addrconf(&ad, &addr)
            .await
            .context(format!("create {addr}"))?;
    }

    tokio::try_join!(ox1.run_mgd(&ad), ox2.run_mgd(&ad))?;
    tokio::try_join!(
        wait_for_mgd(&mgd1, OP_TIMEOUT, &ad.log),
        wait_for_mgd(&mgd2, OP_TIMEOUT, &ad.log),
    )?;

    const OX1_ASN: u32 = 33;
    const OX2_ASN: u32 = 44;

    info!(ad.log, "adding BGP routers to both mgd nodes");
    let ox1_router = Router {
        asn: OX1_ASN,
        graceful_shutdown: false,
        id: 33,
        listen: "[::]:179".to_owned(),
    };
    let ox2_router = Router {
        asn: OX2_ASN,
        graceful_shutdown: false,
        id: 44,
        listen: "[::]:179".to_owned(),
    };
    tokio::try_join!(
        mgd1.create_router(&ox1_router),
        mgd2.create_router(&ox2_router),
    )
    .context("mgd: create routers")?;

    info!(ad.log, "adding unnumbered BGP neighbors to both mgd nodes");
    let ox1_neighbor = basic_unnumbered_neighbor(
        "ox2",
        "mgd-duo",
        HELIOS_PEER_LINK,
        OX1_ASN,
        0,
    );
    let ox2_neighbor = basic_unnumbered_neighbor(
        "ox1",
        "mgd-duo",
        HELIOS_PEER_LINK,
        OX2_ASN,
        0,
    );
    tokio::try_join!(
        mgd1.create_unnumbered_neighbor(&ox1_neighbor),
        mgd2.create_unnumbered_neighbor(&ox2_neighbor),
    )
    .context("mgd: create unnumbered neighbors")?;

    wait_for_eq!(
        mgd1.get_neighbors(OX1_ASN)
            .await
            .map(|x| x.into_inner().len())
            .unwrap_or(0),
        1,
        "mgd1 neighbor count"
    );
    wait_for_eq!(
        mgd2.get_neighbors(OX2_ASN)
            .await
            .map(|x| x.into_inner().len())
            .unwrap_or(0),
        1,
        "mgd2 neighbor count"
    );

    wait_for_eq!(
        neighbor_fsm_state(&mgd1, OX1_ASN, "ox2").await,
        Some(FsmStateKind::Established),
        "mgd1 bgp ox2 established"
    );
    wait_for_eq!(
        neighbor_fsm_state(&mgd2, OX2_ASN, "ox1").await,
        Some(FsmStateKind::Established),
        "mgd2 bgp ox1 established"
    );

    info!(ad.log, "mgd-to-mgd bgp unnumbered test passed 🎉");

    Ok(())
}

async fn run_interop_unnumbered(
    scenario: InteropScenario,
    persistent: bool,
    diag_on_fail: bool,
    commits: NpuvmCommits,
) -> Result<()> {
    let bt = boot_interop(
        scenario,
        persistent,
        diag_on_fail,
        commits,
        ProtocolDiagnostics::Bgp,
        |cr1, cr2, cr3, ad| {
            let mut js = tokio::task::JoinSet::new();
            let cr1_ad = ad.clone();
            let cr2_ad = ad.clone();
            let cr3_ad = ad;
            js.spawn(async move {
                frr_setup(cr1, cr1_ad).await.context("setup cr1 frr")
            });
            js.spawn(async move {
                eos_setup(cr2, cr2_ad).await.context("setup cr2 eos")
            });
            js.spawn(async move {
                juniper_setup(cr3, cr3_ad)
                    .await
                    .context("setup cr3 juniper")
            });
            js
        },
    )
    .await?;

    run_with_optional_diagnostics(bt, diag_on_fail, interop_unnumbered_body)
        .await
}

async fn interop_unnumbered_body(bt: BootedInterop) -> Result<()> {
    let BootedInterop {
        ad,
        ox,
        peer,
        cr1,
        cr2,
        cr3,
        mgd,
        peer_mgd,
        dpd,
        ..
    } = bt;
    let peers = InteropRouters { cr1, cr2, cr3 };

    for link in [
        "tfportqsfp0_0/ll",
        "tfportqsfp1_0/ll",
        "tfportqsfp2_0/ll",
        "tfportqsfp3_0/ll",
    ] {
        ox.illumos()
            .addrconf(&ad, link)
            .await
            .context(format!("create {link}"))?;
    }
    let peer_addr = format!("{HELIOS_PEER_LINK}/ll");
    peer.illumos()
        .addrconf(&ad, &peer_addr)
        .await
        .context(format!("create {peer_addr}"))?;

    ox.run_mgd(&ad).await?;
    ox.ddm().run_ddm(&ad, RouterKind::Server, &[]).await?;
    wait_for_mgd(&mgd, OP_TIMEOUT, &ad.log).await?;

    // Fanout of 4 so all peer paths survive best-path selection and we can
    // validate ECMP in loc_rib and dpd.
    mgd.update_bestpath_fanout(&BestpathFanoutRequest {
        fanout: std::num::NonZeroU8::new(4).expect("fanout > 0"),
    })
    .await
    .context("mgd: set bestpath fanout")?;

    const LOCAL_ASN: u32 = 33;
    const PEER_ASN: u32 = 47;
    const PEER_V4_PREFIX: &str = "1.2.3.0/24";
    const PEER_V6_PREFIX: &str = "fd99::/64";
    const OX_V4_ORIGIN: &str = "4.5.6.0/24";
    const OX_V6_ORIGIN: &str = "fdee::/64";

    info!(ad.log, "adding BGP routers to both mgd nodes");

    mgd.create_router(&Router {
        asn: LOCAL_ASN,
        graceful_shutdown: false,
        id: 33,
        listen: "[::]:179".to_owned(),
    })
    .await
    .context("mgd: create router")?;
    peer_mgd
        .create_router(&Router {
            asn: PEER_ASN,
            graceful_shutdown: false,
            id: 47,
            listen: "[::]:179".to_owned(),
        })
        .await
        .context("peer mgd: create router")?;

    mgd.create_unnumbered_neighbor(&basic_unnumbered_neighbor(
        "cr1",
        "test",
        "tfportqsfp0_0",
        LOCAL_ASN,
        0,
    ))
    .await
    .context("mgd: create cr1 unnumbered neighbor")?;

    mgd.create_unnumbered_neighbor(&basic_unnumbered_neighbor(
        "cr2",
        "test",
        "tfportqsfp1_0",
        LOCAL_ASN,
        1800,
    ))
    .await
    .context("mgd: create cr2 unnumbered neighbor")?;

    mgd.create_unnumbered_neighbor(&basic_unnumbered_neighbor(
        "cr3",
        "test",
        "tfportqsfp2_0",
        LOCAL_ASN,
        1800,
    ))
    .await
    .context("mgd: create cr3 unnumbered neighbor")?;

    mgd.create_unnumbered_neighbor(&basic_unnumbered_neighbor(
        "peer",
        "test",
        "tfportqsfp3_0",
        LOCAL_ASN,
        0,
    ))
    .await
    .context("mgd: create peer unnumbered neighbor")?;

    peer_mgd
        .create_unnumbered_neighbor(&basic_unnumbered_neighbor(
            "ox",
            "test",
            HELIOS_PEER_LINK,
            PEER_ASN,
            0,
        ))
        .await
        .context("peer mgd: create ox unnumbered neighbor")?;

    mgd.create_origin4(&Origin4 {
        asn: LOCAL_ASN,
        prefixes: vec![OX_V4_ORIGIN.parse().expect("parse ipv4 origin")],
    })
    .await
    .context("announce v4 prefix")?;

    mgd.create_origin6(&Origin6 {
        asn: LOCAL_ASN,
        prefixes: vec![OX_V6_ORIGIN.parse().expect("parse ipv6 origin")],
    })
    .await
    .context("announce v6 prefix")?;

    peer_mgd
        .create_origin4(&Origin4 {
            asn: PEER_ASN,
            prefixes: vec![
                PEER_V4_PREFIX.parse().expect("parse peer ipv4 origin"),
            ],
        })
        .await
        .context("peer mgd: announce v4 prefix")?;
    peer_mgd
        .create_origin6(&Origin6 {
            asn: PEER_ASN,
            prefixes: vec![
                PEER_V6_PREFIX.parse().expect("parse peer ipv6 origin"),
            ],
        })
        .await
        .context("peer mgd: announce v6 prefix")?;

    wait_for_eq!(
        mgd.get_neighbors(LOCAL_ASN)
            .await
            .map(|x| x.into_inner().len())
            .unwrap_or(0),
        4,
        "mgd neighbor count"
    );

    expect_bgp_neighbor_states(
        &mgd,
        LOCAL_ASN,
        InteropPeerStates::new(
            FsmStateKind::Established,
            FsmStateKind::Established,
            FsmStateKind::Established,
            FsmStateKind::Established,
        ),
    )
    .await?;
    wait_for_eq!(
        neighbor_fsm_state(&peer_mgd, PEER_ASN, "ox").await,
        Some(FsmStateKind::Established),
        "peer mgd bgp ox established"
    );

    // All peers advertise the same prefix, so mgd should see a single
    // imported entry per family with four paths, and — with fanout=4 — the
    // same four paths should survive into the selected (loc) RIB.
    wait_for_eq!(
        mgd_imported_paths(&mgd, AddressFamily::Ipv4, PEER_V4_PREFIX).await,
        Some(4),
        "mgd imported paths for 1.2.3.0/24"
    );
    wait_for_eq!(
        mgd_imported_paths(&mgd, AddressFamily::Ipv6, PEER_V6_PREFIX).await,
        Some(4),
        "mgd imported paths for fd99::/64"
    );
    wait_for_eq!(
        mgd_selected_paths(&mgd, AddressFamily::Ipv4, PEER_V4_PREFIX).await,
        Some(4),
        "mgd selected paths for 1.2.3.0/24"
    );
    wait_for_eq!(
        mgd_selected_paths(&mgd, AddressFamily::Ipv6, PEER_V6_PREFIX).await,
        Some(4),
        "mgd selected paths for fd99::/64"
    );

    // dpd should have the specific prefixes, each with four ECMP targets.
    let peer_v4: Ipv4Net =
        PEER_V4_PREFIX.parse().expect("parse peer v4 prefix");
    let peer_v6: Ipv6Net =
        PEER_V6_PREFIX.parse().expect("parse peer v6 prefix");
    wait_for_eq!(
        dpd_v4_targets(&dpd, &peer_v4).await.len(),
        4,
        "dpd ipv4 targets for 1.2.3.0/24"
    );
    wait_for_eq!(
        dpd_v6_targets(&dpd, &peer_v6).await.len(),
        4,
        "dpd ipv6 targets for fd99::/64"
    );

    // Each peer should have imported ox's originated prefixes.
    let ox_v4: Ipv4Net = OX_V4_ORIGIN.parse().expect("parse ox v4 origin");
    let ox_v6: Ipv6Net = OX_V6_ORIGIN.parse().expect("parse ox v6 origin");
    wait_for_eq!(
        peers
            .cr1
            .bgp_ipv4_imported(&ad)
            .await
            .map(|r| r.all().any(|(p, _)| *p == ox_v4))
            .unwrap_or(false),
        true,
        "cr1 imported 4.5.6.0/24"
    );
    wait_for_eq!(
        peers
            .cr1
            .bgp_ipv6_imported(&ad)
            .await
            .map(|r| r.all().any(|(p, _)| *p == ox_v6))
            .unwrap_or(false),
        true,
        "cr1 imported fdee::/64"
    );
    wait_for_eq!(
        peers
            .cr2
            .bgp_ipv4_imported(&ad)
            .await
            .map(|r| r.all().any(|(p, _)| *p == ox_v4))
            .unwrap_or(false),
        true,
        "cr2 imported 4.5.6.0/24"
    );
    wait_for_eq!(
        peers
            .cr2
            .bgp_ipv6_imported(&ad)
            .await
            .map(|r| r.all().any(|(p, _)| *p == ox_v6))
            .unwrap_or(false),
        true,
        "cr2 imported fdee::/64"
    );
    wait_for_eq!(
        peers
            .cr3
            .bgp_route_imported(&ad, OX_V4_ORIGIN)
            .await
            .unwrap_or(false),
        true,
        "cr3 imported 4.5.6.0/24"
    );
    wait_for_eq!(
        peers
            .cr3
            .bgp_route_imported(&ad, OX_V6_ORIGIN)
            .await
            .unwrap_or(false),
        true,
        "cr3 imported fdee::/64"
    );
    wait_for_eq!(
        mgd_imported_paths(&peer_mgd, AddressFamily::Ipv4, OX_V4_ORIGIN).await,
        Some(1),
        "peer imported 4.5.6.0/24"
    );
    wait_for_eq!(
        mgd_imported_paths(&peer_mgd, AddressFamily::Ipv6, OX_V6_ORIGIN).await,
        Some(1),
        "peer imported fdee::/64"
    );

    info!(ad.log, "interop bgp unnumbered test passed 🎉");

    Ok(())
}

/// Snapshot logs and live state from every configured interop VM into `/work/` so
/// a failed run preserves the evidence past deployment teardown. The actual
/// per-daemon and per-peer collection lives on each node type's
/// `collect_diagnostics` method; this function is just the composition.
async fn collect_interop_diagnostics(
    d: &Runner,
    ox: MgdNode,
    peer: MgdNode,
    routers: InteropRouters,
    topo_name: &str,
    protocols: ProtocolDiagnostics,
) {
    let InteropRouters { cr1, cr2, cr3 } = routers;
    warn!(d.log, "collecting diagnostics for {topo_name}");
    // ox VM: illumos network state, plus each daemon's log via its lens.
    ox.illumos().collect_diagnostics(d, topo_name).await;
    ox.dendrite().collect_diagnostics(d, topo_name).await;
    ox.ddm().collect_diagnostics(d, topo_name).await;
    ox.collect_diagnostics(d, topo_name).await;
    peer.illumos().collect_diagnostics(d, topo_name).await;
    peer.collect_diagnostics(d, topo_name).await;
    // Peer routers.
    cr1.collect_diagnostics(d, topo_name, protocols).await;
    cr2.collect_diagnostics(d, topo_name, protocols).await;
    cr3.collect_diagnostics(d, topo_name, protocols).await;
}

/// Boot/setup failures happen before the topology is fully configured, so avoid
/// network-state snapshots (`ip*`, `ipadm`, routes, neighbors). Collect only
/// lightweight service/container state that explains which setup task failed.
async fn collect_interop_boot_diagnostics(
    d: &Runner,
    ox: MgdNode,
    peer: MgdNode,
    routers: InteropRouters,
    topo_name: &str,
) {
    let InteropRouters { cr1, cr2, cr3 } = routers;
    warn!(d.log, "collecting boot diagnostics for {topo_name}");
    crate::diagnostics::capture(d, ox.0, topo_name, "ox-svcs-xv", "svcs -xv")
        .await;
    ox.dendrite().collect_diagnostics(d, topo_name).await;
    crate::diagnostics::capture(
        d,
        peer.0,
        topo_name,
        "peer-svcs-xv",
        "svcs -xv",
    )
    .await;
    peer.collect_diagnostics(d, topo_name).await;

    crate::diagnostics::capture(
        d,
        cr1.0,
        topo_name,
        "cr1-frr-status",
        "systemctl status frr --no-pager || true",
    )
    .await;
    crate::diagnostics::capture(
        d,
        cr1.0,
        topo_name,
        "cr1-frr-journal",
        "journalctl -u frr --no-pager -n 200 || true",
    )
    .await;

    for (label, cmd) in [
        ("cr2-docker-ps", "docker ps -a"),
        (
            "cr2-docker-logs",
            "timeout 5s docker logs --tail 500 ceos || true",
        ),
    ] {
        crate::diagnostics::capture(d, cr2.0, topo_name, label, cmd).await;
    }

    cr3.collect_boot_diagnostics(d, topo_name).await;
}

/// Snapshot logs and live state from both Helios mgd peers in the mgd-duo
/// topology.
async fn collect_mgd_duo_diagnostics(
    d: &Runner,
    ox1: MgdNode,
    ox2: MgdNode,
    topo_name: &str,
) {
    warn!(d.log, "collecting diagnostics for {topo_name}");
    for ox in [ox1, ox2] {
        ox.illumos().collect_diagnostics(d, topo_name).await;
        ox.collect_diagnostics(d, topo_name).await;
    }
}

/// Boot/setup diagnostics for the mgd-duo topology, intentionally excluding
/// network snapshots because address/link setup may be the part that failed.
async fn collect_mgd_duo_boot_diagnostics(
    d: &Runner,
    ox1: MgdNode,
    ox2: MgdNode,
    topo_name: &str,
) {
    warn!(d.log, "collecting boot diagnostics for {topo_name}");
    for ox in [ox1, ox2] {
        let name = d.get_node(ox.0).name.clone();
        crate::diagnostics::capture(
            d,
            ox.0,
            topo_name,
            &format!("{name}-svcs-xv"),
            "svcs -xv",
        )
        .await;
    }
}

/// Snapshot logs and live DDM state from every Helios node in the ddm-trio
/// topology.
async fn collect_ddm_trio_diagnostics(
    d: &Runner,
    nodes: [DdmNode; 3],
    topo_name: &str,
) {
    warn!(d.log, "collecting diagnostics for {topo_name}");
    for node in nodes {
        node.illumos().collect_diagnostics(d, topo_name).await;
        node.collect_diagnostics(d, topo_name).await;
    }
}

async fn frr_setup(r: FrrNode, d: Arc<Runner>) -> Result<()> {
    const BASE_CONFIG: &str = "
        configure
        ip forwarding
        ipv6 forwarding
        ip route 1.2.3.0/24 null0
        ipv6 route fd99::/64 null0
        router bgp 44
          no bgp ebgp-requires-policy
          timers bgp 2 6
          neighbor enp0s8 interface remote-as external
          neighbor enp0s8 timers connect 1     
          address-family ipv4 unicast
            network 1.2.3.0/24
            neighbor enp0s8 activate
          exit-address-family
          address-family ipv6 unicast
            network fd99::/64
            neighbor enp0s8 activate
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

async fn juniper_setup(r: JuniperNode, d: Arc<Runner>) -> Result<()> {
    info!(d.log, "{}: starting juniper unnumbered setup", r.name(&d));
    const BASE_CONFIG: &str = "
        set interfaces eth1 unit 0 family inet
        set interfaces eth1 unit 0 family inet6
        set protocols router-advertisement interface eth1
        set routing-options router-id 1.2.3.2
        set routing-options autonomous-system 46
        set routing-options static route 1.2.3.0/24 discard
        set routing-options rib inet6.0 static route fd99::/64 discard
        set policy-options policy-statement expo term announce4 from route-filter 1.2.3.0/24 exact
        set policy-options policy-statement expo term announce4 then accept
        set policy-options policy-statement expo term announce6 from route-filter fd99::/64 exact
        set policy-options policy-statement expo term announce6 then accept
        set policy-options policy-statement expo then reject
        set protocols bgp group unnumbered type external
        set protocols bgp group unnumbered family inet unicast extended-nexthop
        set protocols bgp group unnumbered family inet6 unicast
        set protocols bgp group unnumbered peer-as 33
        set protocols bgp group unnumbered export expo
        set protocols bgp group unnumbered dynamic-neighbor bgp_unnumbered peer-auto-discovery family inet6 ipv6-nd
        set protocols bgp group unnumbered dynamic-neighbor bgp_unnumbered peer-auto-discovery interface eth1
    ";

    r.setup(&d, BASE_CONFIG).await?;
    Ok(())
}

async fn run_interop_bfd_static(
    scenario: InteropScenario,
    persistent: bool,
    diag_on_fail: bool,
    commits: NpuvmCommits,
) -> Result<()> {
    let bt = boot_interop(
        scenario,
        persistent,
        diag_on_fail,
        commits,
        ProtocolDiagnostics::Bfd,
        |cr1, cr2, cr3, ad| {
            let mut js = tokio::task::JoinSet::new();
            let cr1_ad = ad.clone();
            let cr2_ad = ad.clone();
            let cr3_ad = ad;
            js.spawn(async move {
                frr_bfd_setup(cr1, cr1_ad)
                    .await
                    .context("setup cr1 frr bfd")
            });
            js.spawn(async move {
                eos_bfd_setup(cr2, cr2_ad)
                    .await
                    .context("setup cr2 eos bfd")
            });
            js.spawn(async move {
                juniper_bfd_setup(cr3, cr3_ad)
                    .await
                    .context("setup cr3 juniper bfd")
            });
            js
        },
    )
    .await?;

    run_with_optional_diagnostics(bt, diag_on_fail, interop_bfd_static_body)
        .await
}

async fn interop_bfd_static_body(bt: BootedInterop) -> Result<()> {
    let BootedInterop {
        ad,
        ox,
        peer,
        cr1,
        cr2,
        cr3,
        mgd,
        peer_mgd,
        dpd,
        ..
    } = bt;
    let peers = InteropRouters { cr1, cr2, cr3 };

    // Register each ox-side address with dpd so softnpu punts packets for
    // those destinations to the CPU port. Link-local v6 is handled
    // implicitly by the P4 pipeline, but globally-scoped addresses need an
    // explicit per-link mapping. IPv6 is also disabled by default per-link
    // in the P4 pipeline, so enable it before registering v6 addresses.
    for (qsfp, v4, v6) in [
        ("qsfp0", OX_CR1_V4, OX_CR1_V6),
        ("qsfp1", OX_CR2_V4, OX_CR2_V6),
        ("qsfp2", OX_CR3_V4, OX_CR3_V6),
        ("qsfp3", OX_PEER_V4, OX_PEER_V6),
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
        ("tfportqsfp2_0", OX_CR3_V4_CIDR, OX_CR3_V6_CIDR),
        ("tfportqsfp3_0", OX_PEER_V4_CIDR, OX_PEER_V6_CIDR),
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

    let peer_ll = format!("{HELIOS_PEER_LINK}/ll");
    peer.illumos()
        .addrconf(&ad, &peer_ll)
        .await
        .context(format!("addrconf {peer_ll}"))?;
    for (suffix, cidr) in [("v4", PEER_V4_CIDR), ("v6", PEER_V6_CIDR)] {
        let addrobj = format!("{HELIOS_PEER_LINK}/{suffix}");
        peer.illumos()
            .staticaddr(&ad, &addrobj, cidr)
            .await
            .context(format!("assign {cidr} to {HELIOS_PEER_LINK}"))?;
    }

    ox.run_mgd(&ad).await?;
    // mg-lower's sync loop queries ddm on every prefix change and bails the
    // whole sync when ddm is unreachable. We don't exercise DDM here, but
    // ddmd has to be up for static routes to lower into dpd.
    ox.ddm().run_ddm(&ad, RouterKind::Server, &[]).await?;
    wait_for_mgd(&mgd, OP_TIMEOUT, &ad.log).await?;

    // Default fanout is 1, which collapses the static paths into a single
    // selected nexthop. Bump to 4 so all paths propagate through best-path
    // selection and land in dpd as ECMP.
    mgd.update_bestpath_fanout(&BestpathFanoutRequest {
        fanout: std::num::NonZeroU8::new(4).expect("fanout > 0"),
    })
    .await
    .context("mgd: set bestpath fanout")?;

    let prefix_v4: Ipv4Net =
        TEST_PREFIX_V4.parse().expect("parse v4 test prefix");
    let prefix_v6: Ipv6Net =
        TEST_PREFIX_V6.parse().expect("parse v6 test prefix");

    info!(ad.log, "installing static v4 route {TEST_PREFIX_V4}");
    mgd.static_add_v4_route(&AddStaticRoute4Request {
        routes: StaticRoute4List {
            list: [CR1_V4, CR2_V4, CR3_V4, PEER_V4]
                .into_iter()
                .map(|nh| StaticRoute4 {
                    prefix: prefix_v4,
                    nexthop: IpAddr::V4(nh),
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
            list: [CR1_V6, CR2_V6, CR3_V6, PEER_V6]
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

    info!(
        ad.log,
        "adding BFD peers for cr1, cr2, cr3, and peer (dual-stack)"
    );
    for (peer, listen) in [
        (IpAddr::V4(CR1_V4), IpAddr::V4(OX_CR1_V4)),
        (IpAddr::V4(CR2_V4), IpAddr::V4(OX_CR2_V4)),
        (IpAddr::V4(CR3_V4), IpAddr::V4(OX_CR3_V4)),
        (IpAddr::V4(PEER_V4), IpAddr::V4(OX_PEER_V4)),
        (IpAddr::V6(CR1_V6), IpAddr::V6(OX_CR1_V6)),
        (IpAddr::V6(CR2_V6), IpAddr::V6(OX_CR2_V6)),
        (IpAddr::V6(CR3_V6), IpAddr::V6(OX_CR3_V6)),
        (IpAddr::V6(PEER_V6), IpAddr::V6(OX_PEER_V6)),
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
    configure_peer_bfd(&peer_mgd).await?;

    use BfdPeerState::{Down, Up};

    info!(ad.log, "phase 1: all peers up");
    expect_bfd(
        &mgd,
        &peer_mgd,
        peers,
        &ad,
        InteropPeerStates::new(Up, Up, Up, Up),
    )
    .await?;
    expect_route(
        &dpd,
        &prefix_v4,
        &prefix_v6,
        InteropPeerStates::new(true, true, true, true),
        "phase 1",
    )
    .await?;

    info!(ad.log, "phase 2: stop frr on cr1");
    cr1.stop_frr(&ad).await?;
    expect_bfd(
        &mgd,
        &peer_mgd,
        peers,
        &ad,
        InteropPeerStates::new(Down, Up, Up, Up),
    )
    .await?;
    expect_route(
        &dpd,
        &prefix_v4,
        &prefix_v6,
        InteropPeerStates::new(false, true, true, true),
        "phase 2",
    )
    .await?;

    info!(ad.log, "phase 3: pause ceos on cr2");
    cr2.pause(&ad).await?;
    expect_bfd(
        &mgd,
        &peer_mgd,
        peers,
        &ad,
        InteropPeerStates::new(Down, Down, Up, Up),
    )
    .await?;
    expect_route(
        &dpd,
        &prefix_v4,
        &prefix_v6,
        InteropPeerStates::new(false, false, true, true),
        "phase 3",
    )
    .await?;

    info!(ad.log, "phase 4: pause cRPD on cr3");
    cr3.pause(&ad).await?;
    expect_bfd(
        &mgd,
        &peer_mgd,
        peers,
        &ad,
        InteropPeerStates::new(Down, Down, Down, Up),
    )
    .await?;
    expect_route(
        &dpd,
        &prefix_v4,
        &prefix_v6,
        InteropPeerStates::new(false, false, false, true),
        "phase 4",
    )
    .await?;

    info!(ad.log, "phase 5: stop mgd on peer");
    peer.stop_mgd(&ad).await?;
    expect_bfd(
        &mgd,
        &peer_mgd,
        peers,
        &ad,
        InteropPeerStates::new(Down, Down, Down, Down),
    )
    .await?;
    // With every nexthop shutdown, all shutdown nexthops are reinstated.
    expect_route(
        &dpd,
        &prefix_v4,
        &prefix_v6,
        InteropPeerStates::new(true, true, true, true),
        "phase 5",
    )
    .await?;

    info!(ad.log, "phase 6: start frr on cr1");
    cr1.start_frr(&ad).await?;
    expect_bfd(
        &mgd,
        &peer_mgd,
        peers,
        &ad,
        InteropPeerStates::new(Up, Down, Down, Down),
    )
    .await?;
    expect_route(
        &dpd,
        &prefix_v4,
        &prefix_v6,
        InteropPeerStates::new(true, false, false, false),
        "phase 6",
    )
    .await?;

    info!(ad.log, "phase 7: unpause ceos on cr2");
    cr2.unpause(&ad).await?;
    expect_bfd(
        &mgd,
        &peer_mgd,
        peers,
        &ad,
        InteropPeerStates::new(Up, Up, Down, Down),
    )
    .await?;
    expect_route(
        &dpd,
        &prefix_v4,
        &prefix_v6,
        InteropPeerStates::new(true, true, false, false),
        "phase 7",
    )
    .await?;

    info!(ad.log, "phase 8: unpause cRPD on cr3");
    cr3.unpause(&ad).await?;
    expect_bfd(
        &mgd,
        &peer_mgd,
        peers,
        &ad,
        InteropPeerStates::new(Up, Up, Up, Down),
    )
    .await?;
    expect_route(
        &dpd,
        &prefix_v4,
        &prefix_v6,
        InteropPeerStates::new(true, true, true, false),
        "phase 8",
    )
    .await?;

    info!(ad.log, "phase 9: restart mgd on peer");
    peer.run_mgd(&ad).await?;
    wait_for_mgd(&peer_mgd, OP_TIMEOUT, &ad.log).await?;
    // BFD sessions are process-local, so restore them after restarting mgd.
    configure_peer_bfd(&peer_mgd).await?;
    expect_bfd(
        &mgd,
        &peer_mgd,
        peers,
        &ad,
        InteropPeerStates::new(Up, Up, Up, Up),
    )
    .await?;
    expect_route(
        &dpd,
        &prefix_v4,
        &prefix_v6,
        InteropPeerStates::new(true, true, true, true),
        "phase 9",
    )
    .await?;

    info!(ad.log, "interop bfd static routing test passed 🎉");

    Ok(())
}

async fn configure_peer_bfd(mgd: &MgdClient) -> Result<()> {
    for (peer, listen) in [
        (IpAddr::V4(OX_PEER_V4), IpAddr::V4(PEER_V4)),
        (IpAddr::V6(OX_PEER_V6), IpAddr::V6(PEER_V6)),
    ] {
        mgd.add_bfd_peer(&BfdPeerConfig {
            peer,
            listen,
            required_rx: BFD_REQUIRED_RX_US,
            detection_threshold: BFD_DETECTION_MULT,
            mode: SessionMode::SingleHop,
        })
        .await
        .context(format!("peer mgd: add bfd peer {peer}"))?;
    }
    Ok(())
}

async fn frr_bfd_setup(r: FrrNode, d: Arc<Runner>) -> Result<()> {
    // Address the softnpu-facing link (v4 + v6) and bring up passive BFD peers
    // for each family. Once mgd initiates BFD to these addresses the sessions
    // establish bidirectionally.
    r.install(&d).await?;
    r.stage_config(
        CR1_BFD_FRR_CONFIG,
        include_str!("../config/cr1-bfd-frr.conf"),
    )?;
    r.enable_daemons(&d, &["bfdd"]).await?;
    r.stop_frr(&d).await?;
    r.install_staged_config(&d, CR1_BFD_FRR_CONFIG).await?;
    r.start_frr(&d).await?;
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

async fn juniper_bfd_setup(r: JuniperNode, d: Arc<Runner>) -> Result<()> {
    info!(d.log, "{}: starting juniper bfd setup", r.name(&d));
    // Address the softnpu-facing link (v4 + v6) and install dummy
    // BFD-tracked static routes whose nexthops are the ox side of the link.
    // Junos creates BFD sessions for those nexthops; mgd creates matching
    // sessions toward the Junos addresses in the test body. Disable Junos BFD
    // timer adaptation for now: mgd has known RFC 5880 timer-negotiation bugs
    // (oxidecomputer/maghemite#798), and Junos adaptive backoff can otherwise
    // make this interop test flap.
    let rx_ms = BFD_REQUIRED_RX_US / 1000;
    let config = format!(
        "
        set interfaces eth1 unit 0 family inet address {cr_v4_cidr}
        set interfaces eth1 unit 0 family inet6 address {cr_v6_cidr}
        set routing-options static route 100.65.0.0/24 next-hop {ox_v4}
        set routing-options static route 100.65.0.0/24 bfd-liveness-detection minimum-interval {rx_ms}
        set routing-options static route 100.65.0.0/24 bfd-liveness-detection multiplier {mult}
        set routing-options static route 100.65.0.0/24 bfd-liveness-detection no-adaptation
        set routing-options rib inet6.0 static route 3ffe::/64 next-hop {ox_v6}
        set routing-options rib inet6.0 static route 3ffe::/64 bfd-liveness-detection minimum-interval {rx_ms}
        set routing-options rib inet6.0 static route 3ffe::/64 bfd-liveness-detection multiplier {mult}
        set routing-options rib inet6.0 static route 3ffe::/64 bfd-liveness-detection no-adaptation
        ",
        cr_v4_cidr = CR3_V4_CIDR,
        cr_v6_cidr = CR3_V6_CIDR,
        ox_v4 = OX_CR3_V4,
        ox_v6 = OX_CR3_V6,
        mult = BFD_DETECTION_MULT,
    );

    r.setup(&d, &config).await?;
    Ok(())
}

/// Expect a scalar BFD state per peer. Since failure injection targets the
/// peer daemon as a whole, the v4 and v6 sessions to a given peer always
/// share the same state.
///
/// ox mgd-side state is always checked. Peer-side state is checked only when
/// the peer is expected `Up`: a paused or stopped daemon cannot answer
/// queries, so `Down` phases have no observable peer-side truth.
const BFD_STABLE_SAMPLES: usize = 5;

async fn expect_bfd(
    mgd: &MgdClient,
    peer_mgd: &MgdClient,
    peers: InteropRouters,
    d: &Runner,
    states: InteropPeerStates<BfdPeerState>,
) -> Result<()> {
    for (peer, want) in [
        (IpAddr::V4(CR1_V4), states.cr1),
        (IpAddr::V6(CR1_V6), states.cr1),
        (IpAddr::V4(CR2_V4), states.cr2),
        (IpAddr::V6(CR2_V6), states.cr2),
        (IpAddr::V4(CR3_V4), states.cr3),
        (IpAddr::V6(CR3_V6), states.cr3),
        (IpAddr::V4(PEER_V4), states.peer),
        (IpAddr::V6(PEER_V6), states.peer),
    ] {
        let desc = format!("mgd bfd {peer} -> {want:?}");
        wait_for_eq_stable!(
            bfd_state(mgd, peer).await,
            Some(want),
            BFD_STABLE_SAMPLES,
            &desc
        );
    }

    if matches!(states.cr1, BfdPeerState::Up) {
        for peer in [IpAddr::V4(OX_CR1_V4), IpAddr::V6(OX_CR1_V6)] {
            let desc = format!("cr1 bfd {peer} -> Up");
            wait_for_eq_stable!(
                peers.cr1.bfd_peer_up(d, peer).await.unwrap_or(false),
                true,
                BFD_STABLE_SAMPLES,
                &desc
            );
        }
    }
    if matches!(states.cr2, BfdPeerState::Up) {
        for peer in [IpAddr::V4(OX_CR2_V4), IpAddr::V6(OX_CR2_V6)] {
            let desc = format!("cr2 bfd {peer} -> Up");
            wait_for_eq_stable!(
                peers.cr2.bfd_peer_up(d, peer).await.unwrap_or(false),
                true,
                BFD_STABLE_SAMPLES,
                &desc
            );
        }
    }
    if matches!(states.cr3, BfdPeerState::Up) {
        for peer in [IpAddr::V4(OX_CR3_V4), IpAddr::V6(OX_CR3_V6)] {
            let desc = format!("cr3 bfd {peer} -> Up");
            wait_for_eq_stable!(
                peers.cr3.bfd_peer_up(d, peer).await.unwrap_or(false),
                true,
                BFD_STABLE_SAMPLES,
                &desc
            );
        }
    }
    if matches!(states.peer, BfdPeerState::Up) {
        for remote in [IpAddr::V4(OX_PEER_V4), IpAddr::V6(OX_PEER_V6)] {
            let desc = format!("peer bfd {remote} -> Up");
            wait_for_eq_stable!(
                bfd_state(peer_mgd, remote).await,
                Some(BfdPeerState::Up),
                BFD_STABLE_SAMPLES,
                &desc
            );
        }
    }
    Ok(())
}

/// Expect the test's v4 + v6 prefixes to resolve to the given peer subset as
/// dpd targets.
async fn expect_route(
    dpd: &DpdClient,
    prefix_v4: &Ipv4Net,
    prefix_v6: &Ipv6Net,
    included: InteropPeerStates<bool>,
    phase: &str,
) -> Result<()> {
    // Push peers in address order so the list is already in the sorted order
    // that dpd_v*_targets returns.
    let mut want_v4: Vec<IpAddr> = Vec::new();
    let mut want_v6: Vec<IpAddr> = Vec::new();
    if included.cr1 {
        want_v4.push(IpAddr::V4(CR1_V4));
        want_v6.push(IpAddr::V6(CR1_V6));
    }
    if included.cr2 {
        want_v4.push(IpAddr::V4(CR2_V4));
        want_v6.push(IpAddr::V6(CR2_V6));
    }
    if included.cr3 {
        want_v4.push(IpAddr::V4(CR3_V4));
        want_v6.push(IpAddr::V6(CR3_V6));
    }
    if included.peer {
        want_v4.push(IpAddr::V4(PEER_V4));
        want_v6.push(IpAddr::V6(PEER_V6));
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

async fn expect_bgp_neighbor_states(
    mgd: &MgdClient,
    local_asn: u32,
    states: InteropPeerStates<FsmStateKind>,
) -> Result<()> {
    for (name, want) in [
        ("cr1", states.cr1),
        ("cr2", states.cr2),
        ("cr3", states.cr3),
        ("peer", states.peer),
    ] {
        let desc = format!("mgd bgp {name} -> {want:?}");
        wait_for_eq!(
            neighbor_fsm_state(mgd, local_asn, name).await,
            Some(want),
            &desc
        );
    }
    Ok(())
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

/// All dpd target addresses for the given v4 prefix. Targets may be v4
/// (static routes) or v6 (BGP-unnumbered uses v6 link-local next-hops for
/// v4 prefixes), so the return type is `IpAddr`.
async fn dpd_v4_targets(dpd: &DpdClient, prefix: &Ipv4Net) -> Vec<IpAddr> {
    let items = match dpd.route_ipv4_list(None, None).await {
        Ok(r) => r.into_inner().items,
        Err(_) => return Vec::new(),
    };
    let want_cidr = prefix.to_string();
    let mut out: Vec<IpAddr> = items
        .into_iter()
        .filter(|r| r.cidr.to_string() == want_cidr)
        .flat_map(|r| {
            r.targets.into_iter().map(|t| match t {
                dpd_client::types::Route::V4(rt) => IpAddr::V4(rt.tgt_ip),
                dpd_client::types::Route::V6(rt) => IpAddr::V6(rt.tgt_ip),
            })
        })
        .collect();
    out.sort();
    out
}

async fn dpd_v6_targets(dpd: &DpdClient, prefix: &Ipv6Net) -> Vec<IpAddr> {
    let items = match dpd.route_ipv6_list(None, None).await {
        Ok(r) => r.into_inner().items,
        Err(_) => return Vec::new(),
    };
    let want_cidr = prefix.to_string();
    let mut out: Vec<IpAddr> = items
        .into_iter()
        .filter(|r| r.cidr.to_string() == want_cidr)
        .flat_map(|r| r.targets.into_iter().map(|t| IpAddr::V6(t.tgt_ip)))
        .collect();
    out.sort();
    out
}
