// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Result, anyhow};
use client_common::{eprintln_nopipe, println_nopipe};
use ddm_admin_client::Client;
use ddm_api_types_versions::latest::db::PeerStatus;
use ddm_api_types_versions::latest::external_peers::ExternalPeers;
use ddm_api_types_versions::latest::net::{MulticastOrigin, TunnelOrigin, Vni};
use dpd_types_versions::latest::link::LinkId;
use dpd_types_versions::latest::mcast::{
    Direction, MulticastGroupCreateUnderlayEntry, MulticastGroupMember,
    MulticastGroupUnderlayResponse,
};
use oxnet::Ipv6Net;
use slog::{Drain, Logger};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;
use std::net::Ipv6Addr;
use std::ops::{Deref, DerefMut};
use std::thread::sleep;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;
use zone::Zlogin;
use ztest::*;

#[macro_export]
macro_rules! retry_cmd {
    ($cmd:expr, $period:expr, $count:expr) => {{
        let mut done = false;
        for _ in 0..$count - 1 {
            if $cmd.is_ok() {
                done = true;
                break;
            }
            sleep(Duration::from_secs($period))
        }
        if !done {
            $cmd?;
        }
    }};
}

macro_rules! softnpu_dump {
    ($softnpu:expr) => {{
        retry_cmd!(
            $softnpu.zexec(
                "/opt/scadm standalone \
                --client /opt/mnt/client \
                --server /opt/mnt/server dump-state"
            ),
            1,
            10
        );
    }};
}

macro_rules! ip6_net {
    ($x:expr) => {
        $x.parse().unwrap()
    };
}

type MulticastImports = HashSet<(String, MulticastOrigin, u64)>;

macro_rules! assert_client_state {
    ($client:expr, $read:expr, $expected:expr, $period:expr, $count:expr) => {{
        let expected = $expected;
        let mut actual = $read.await;
        for _ in 0..$count {
            if actual.as_ref().ok() == Some(&expected) {
                break;
            }
            sleep(Duration::from_secs($period));
            actual = $read.await;
        }
        if actual.as_ref().ok() != Some(&expected) {
            eprintln_nopipe!(
                "{}: expected {expected:#?}, last response: {actual:#?}",
                stringify!($client),
            );
            dump_client_state(stringify!($client), $client).await;
        }
        assert_eq!(actual.ok(), Some(expected));
    }};
    ($client:expr, $read:expr, $expected:expr) => {
        assert_client_state!($client, $read, $expected, 1, 10)
    };
}

macro_rules! assert_multicast_imports {
    ($client:expr, [$(($iface:expr, $origin:expr)),* $(,)?]
        $(, $period:expr, $count:expr)?) => {{
        let expected: MulticastImports =
            [$(($iface.to_string(), ($origin).clone(), ($origin).metric())),*]
                .into_iter()
                .collect();
        assert_client_state!(
            $client,
            multicast_imports($client),
            expected
            $(, $period, $count)?
        );
    }};
}

macro_rules! assert_multicast_origins {
    ($client:expr, [$($origin:expr),* $(,)?]) => {{
        let expected: HashSet<(MulticastOrigin, u64)> =
            [$((($origin).clone(), ($origin).metric())),*]
                .into_iter()
                .collect();
        assert_client_state!($client, multicast_origins($client), expected);
    }};
}

const ZONE_BRAND: &str = "omicron1";

/// How long to wait for a stopped ddmd to exit, and how often to check.
const DDMD_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const DDMD_STOP_POLL: Duration = Duration::from_millis(100);

const MULTICAST_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(30);
const MULTICAST_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The VNI shared by every multicast origin these tests advertise.
const MULTICAST_VNI: u32 = 77;

/// The duration for holding multicast members steady after an import change.
const MEMBER_HOLD: Duration = Duration::from_secs(3);

/// How often the failover observer samples, less coarse than
/// [`MULTICAST_POLL_INTERVAL`] to narrow the window a flap could slip by.
const FAILOVER_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long the failover observer keeps watching after the transit converges.
const FAILOVER_SETTLE: Duration = Duration::from_secs(3);

/// DPD API version for the raw underlay-group requests.
///
/// This is the version the pinned `dpd-client` is generated from, matching
/// both what `ddmd` sends out and the `latest` types these requests use.
fn dpd_api_version() -> &'static str {
    <dpd_client::Client as dpd_client::ClientInfo<_>>::api_version()
}

struct SoftnpuZone<'a> {
    zfs: &'a Zfs,
    zone: Zone,
    testname: &'a str,
}

impl<'a> SoftnpuZone<'a> {
    fn new(
        name: &str,
        zfs: &'a Zfs,
        ifx: &[&'a str],
        testname: &'a str,
    ) -> Result<Self> {
        let softnpu_mount = format!("/tmp/softnpu/{testname}/{name}");
        std::fs::create_dir_all(&softnpu_mount)?;
        let fs = &[FsMount::new(&softnpu_mount, "/opt/mnt")];

        let zone = Zone::new(name, ZONE_BRAND, zfs, ifx, fs)?;
        Ok(Self {
            zfs,
            zone,
            testname,
        })
    }

    fn setup(&self) -> Result<()> {
        self.zone.wait_for_network()?;
        self.zfs.copy_workspace_to_zone(
            &self.zone.name,
            "download/softnpu",
            "opt/",
        )?;
        self.zfs.copy_workspace_to_zone(
            &self.zone.name,
            "download/scadm",
            "opt/",
        )?;
        self.zfs.copy_workspace_to_zone(
            &self.zone.name,
            "download/libsidecar_lite.so",
            "opt/",
        )?;
        self.zfs.copy_workspace_to_zone(
            &self.zone.name,
            &format!(
                "tests/conf/softnpu-{}-{}.toml",
                self.testname, self.zone.name
            ),
            "opt/softnpu.toml",
        )?;
        self.zone.zexec(&format!(
            "{} {} {} {}  &> {} &",
            "RUST_LOG=debug RUST_BACKTRACE=1",
            "/opt/softnpu",
            "--uds-path /opt/mnt",
            "/opt/softnpu.toml",
            "/opt/softnpu.log",
        ))?;
        Ok(())
    }

    pub fn zexec(&self, cmd: &str) -> Result<String> {
        self.zone.zexec(cmd)
    }
}

impl Drop for SoftnpuZone<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.zone.zexec("pkill softnpu") {
            eprintln_nopipe!("failed to stop softnpu: {}", e);
        }
        if let Err(e) = self.zfs.copy_from_zone(
            &self.zone.name,
            "opt/softnpu.log",
            &format!("/work/{}-softnpu.log", self.zone.name),
        ) {
            eprintln_nopipe!(
                "failed to copy zone log file for {}: {}",
                self.zone.name,
                e,
            );
        }
    }
}

struct RouterZone<'a> {
    ifx: Vec<&'a str>,
    zfs: &'a Zfs,
    zone: Zone,
    transit: bool,
    testname: String,
    port_map: BTreeMap<String, String>,
}

impl<'a> RouterZone<'a> {
    fn server(
        name: &str,
        zfs: &'a Zfs,
        mgmt: &'a str,
        rtr_ifx: &[&'a str],
    ) -> Result<Self> {
        Self::new(name, zfs, mgmt, rtr_ifx, false, "", "")
    }

    fn transit(
        name: &str,
        zfs: &'a Zfs,
        mgmt: &'a str,
        rtr_ifx: &[&'a str],
        testname: &str,
        softnpu_name: &str,
    ) -> Result<Self> {
        Self::new(name, zfs, mgmt, rtr_ifx, true, testname, softnpu_name)
    }

    fn new(
        name: &str,
        zfs: &'a Zfs,
        mgmt: &'a str,
        rtr_ifx: &[&'a str],
        transit: bool,
        testname: &str,
        softnpu_name: &str,
    ) -> Result<Self> {
        let mut ifx = vec![mgmt];
        ifx.extend_from_slice(rtr_ifx);

        let fs = if transit {
            let softnpu_mount =
                format!("/tmp/softnpu/{testname}/{softnpu_name}");
            std::fs::create_dir_all(&softnpu_mount)?;
            vec![FsMount::new(&softnpu_mount, "/opt/mnt")]
        } else {
            vec![]
        };

        let zone = Zone::new(name, ZONE_BRAND, zfs, &ifx, &fs)?;
        Ok(Self {
            ifx,
            zfs,
            zone,
            transit,
            testname: testname.into(),
            port_map: BTreeMap::default(),
        })
    }

    fn set_port_map(&mut self, pm: BTreeMap<String, String>) {
        self.port_map = pm;
    }

    fn stop_router(&self) -> Result<String> {
        let output = self.zone.zexec("pkill -x ddmd")?;
        let deadline = Instant::now() + DDMD_STOP_TIMEOUT;
        loop {
            let state = self.zone.zexec(
                "pgrep -x ddmd > /dev/null; \
                ddmd_status=$?; \
                case \"$ddmd_status\" in \
                0) echo running;; \
                1) echo stopped;; \
                *) exit \"$ddmd_status\";; \
                esac",
            )?;
            match state.trim() {
                "stopped" => return Ok(output),
                "running" => {}
                state => {
                    return Err(anyhow!(
                        "unexpected ddmd process state in zone {}: {state}",
                        self.zone.name,
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err(anyhow!(
                    "timed out waiting for ddmd to exit in zone {}",
                    self.zone.name,
                ));
            }
            sleep(DDMD_STOP_POLL);
        }
    }

    /// Wait for an SMF service in this zone to arrive online, failing fast if
    /// it starts in maintenance.
    fn wait_for_service_online(&self, fmri: &str) -> Result<()> {
        for _ in 0..30 {
            let state = self
                .zone
                .zexec(&format!("svcs -Ho state {fmri}"))
                .unwrap_or_default();
            match state.trim() {
                "online" => return Ok(()),
                "maintenance" => {
                    return Err(anyhow!(
                        "{fmri} entered maintenance in zone {}",
                        self.zone.name,
                    ));
                }
                _ => sleep(Duration::from_secs(1)),
            }
        }
        Err(anyhow!(
            "timed out waiting for {fmri} to come online in zone {}",
            self.zone.name,
        ))
    }

    fn start_router(&self, restart_dpd: bool) -> Result<()> {
        let mapped_ports = self.ifx[1..]
            .iter()
            .map(|x| x.to_string())
            .map(|x| self.port_map.get(&x).unwrap_or(&x).clone())
            .collect::<Vec<_>>();

        let rear_ports = mapped_ports
            .iter()
            .filter(|&x| x.contains("rear"))
            .cloned()
            .collect::<Vec<_>>();
        let front_ports = mapped_ports
            .iter()
            .filter(|&x| x.contains("qsfp"))
            .cloned()
            .collect::<Vec<_>>();

        let addrs = if self.transit {
            &rear_ports
        } else {
            &mapped_ports
        }
        .iter()
        .map(|x| format!("-a {}/v6", x))
        .collect::<Vec<String>>()
        .join(" ");

        let ddm = "/opt/ddmd";

        // Tighter solicit interval and expire threshold are to speed up tests.
        let extra_args = format!(
            "--rack-uuid {} --sled-uuid {} --solicit-interval 200 --expire-threshold 500",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );

        if self.transit {
            if restart_dpd {
                self.zone.zexec("svcadm disable dendrite")?;
                self.zone.zexec("svcadm disable tfport")?;
                self.zone.zexec(
                    "svccfg -s dendrite setprop config/address = [::1]:12224",
                )?;
                self.zone
                    .zexec("svccfg -s dendrite setprop config/mgmt = uds")?;
                self.zone.zexec(
                    "svccfg -s dendrite setprop config/uds_path = /opt/mnt",
                )?;
                self.zone.zexec(&format!(
                    "svccfg -s dendrite setprop config/front_ports = {}",
                    front_ports.len(),
                ))?;
                self.zone.zexec(&format!(
                    "svccfg -s dendrite setprop config/rear_ports = {}",
                    rear_ports.len(),
                ))?;
                self.zone.zexec("svcadm refresh dendrite:default")?;
                self.zone.zexec("svcadm enable dendrite:default")?;
                println_nopipe!("waiting for dendrite to come online ...");
                self.wait_for_service_online("dendrite:default")?;
                self.zone.zexec(
                    "svccfg -s tfport setprop config/pkt_source = none",
                )?;
                self.zone.zexec(
                    "svccfg -s tfport setprop config/flags = --sync-only",
                )?;
                self.zone.zexec("svcadm refresh tfport:default")?;
                self.zone.zexec("svcadm enable tfport")?;
                println_nopipe!("waiting for tfport to come online ...");
                self.wait_for_service_online("tfport:default")?;
            }
            self.zone.zexec(&format!(
                "{} {ddm} --kind transit --dendrite {} {} &> /opt/ddmd.log &",
                "RUST_LOG=trace RUST_BACKTRACE=1", extra_args, addrs
            ))?;

            self.zone.zexec("ipadm")?;
        } else {
            self.zone.zexec(&format!(
                "{} {ddm} --kind server {} {} &> /opt/ddmd.log &",
                "RUST_LOG=trace RUST_BACKTRACE=1", extra_args, addrs
            ))?;
        }
        Ok(())
    }

    fn setup(&self, index: u8) -> Result<()> {
        println_nopipe!("running zone {} setup", self.zone.name);

        let z = Zlogin::new(&self.zone.name);
        self.zone.wait_for_network()?;
        self.zone.zcmd(&z, "dladm")?;
        self.zone.zcmd(
            &z,
            &format!(
                "ipadm create-addr -t -T static -a 10.0.0.{}/24 {}/v4",
                index, self.ifx[0],
            ),
        )?;

        for (link, vnic) in &self.port_map {
            self.zone
                .zexec(&format!("dladm create-vnic -t -l {link} {vnic}"))?;
        }

        let mapped_ports = self.ifx[1..]
            .iter()
            .map(|x| x.to_string())
            .map(|x| self.port_map.get(&x).unwrap_or(&x).clone())
            .collect::<Vec<_>>();

        for ifx in &mapped_ports {
            self.zone.zcmd(
                &z,
                &format!("ipadm create-addr -t -T addrconf {}/v6", ifx),
            )?;
        }

        self.zone.zcmd(
            &z,
            &format!(
                "ipadm create-addr -t -T static -a fd00:{}::1/64 lo0/u6",
                index,
            ),
        )?;

        if self.transit {
            self.zfs.copy_workspace_to_zone_recursive(
                &self.zone.name,
                "download/zones/dendrite/root/opt",
                "",
            )?;
            self.zfs.copy_workspace_to_zone_recursive(
                &self.zone.name,
                "download/zones/dendrite/root/var",
                "",
            )?;
            self.zfs.copy_workspace_to_zone(
                &self.zone.name,
                &format!("tests/conf/dpd-ports-{}.toml", self.testname),
                "opt/dpd-ports.toml",
            )?;
            // Wait for these files to show up in the zone. Testing has shown
            // that this is not instant and subsequent steps can fail if the
            // copy is not complete.
            println_nopipe!(
                "waiting 3s for copy of files to zone to complete ..."
            );
            sleep(Duration::from_secs(3));
            self.zone.zcmd(
                &z,
                "svccfg import /var/svc/manifest/site/dendrite/manifest.xml",
            )?;
            self.zone.zcmd(
                &z,
                "svccfg import /var/svc/manifest/site/tfport/manifest.xml",
            )?;
        }

        self.zfs.copy_bin_to_zone(&self.zone.name, "ddmd")?;
        self.zfs.copy_bin_to_zone(&self.zone.name, "ddmadm")?;

        self.start_router(true)?;

        Ok(())
    }
}

impl std::ops::Deref for RouterZone<'_> {
    type Target = Zone;
    fn deref(&self) -> &Zone {
        &self.zone
    }
}

impl Drop for RouterZone<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.zone.zexec("pkill ddmd") {
            eprintln_nopipe!("failed to stop ddmd: {}", e);
        }
        if let Err(e) = self.zfs.copy_from_zone(
            &self.zone.name,
            "opt/ddmd.log",
            &format!("/work/{}.log", self.zone.name),
        ) {
            eprintln_nopipe!(
                "failed to copy zone log file for {}: {}",
                self.zone.name,
                e,
            );
        }
        if self.transit
            && let Err(e) = self.zfs.copy_from_zone(
                &self.zone.name,
                "/var/svc/log/oxide-dendrite:default.log",
                &format!("/work/{}-dpd.log", self.zone.name),
            )
        {
            eprintln_nopipe!(
                "failed to copy zone dpd log file for {}: {}",
                self.zone.name,
                e,
            );
        }
    }
}

macro_rules! run_topo {
    ($fn:expr) => {
        if env::var("TEST_INTERACTIVE").is_err() {
            $fn
        } else {
            println_nopipe!("running interactive test");
            let mut line = String::new();
            let result = $fn;
            println_nopipe!("test result {:?}", result);
            println_nopipe!("press enter to continue");
            std::io::stdin().read_line(&mut line).unwrap();
            result
        }
    };
}

#[tokio::test]
async fn test_trio() -> Result<()> {
    // A trio. Two server routers and one transit router.
    //
    //                                                    sled1
    //                                                 ,----------,
    //       scrimlet              sidecar           ,-----,  ,-----,
    //     ,-----------,     ,-----------------,   ,-| sl0 |  | mg2 |-*
    //     |      ,-----,  ,-----, ,-----, ,-----, | '-----'  '-----'
    //    ,-----, | tf0 |--| sr0 |-|     |-| sw0 |-'   '----------'
    //  *-| mg1 | '-----'  '-----' |soft | '-----'
    //    '-----' ,-----,  ,-----, |  npu| ,-----,        sled2
    //     |      | tf1 |--| sr1 |-|     |-| sw1 |-,   ,----------,
    //     |      '-----'  '-----' '-----' '-----' | ,-----,  ,-----,
    //     '-----------'     '-----------------'   '-| sl1 |  | mg3 |-*
    //                                               '-----'  '-----'
    //                                                 '----------'
    let sl0_sw0 = SimnetLink::new("sl0", "sw0")?;
    let sl1_sw1 = SimnetLink::new("sl1", "sw1")?;
    let tf0_sr0 = SimnetLink::new("tfportrear0_0", "sr0")?;
    let tf1_sr1 = SimnetLink::new("tfportrear1_0", "sr1")?;

    let mgmt0 = Etherstub::new("mgmt0")?;

    let mg0 = Vnic::new("mg0", &mgmt0.name)?;
    let mg1 = Vnic::new("mg1", &mgmt0.name)?;
    let mg2 = Vnic::new("mg2", &mgmt0.name)?;
    let mg3 = Vnic::new("mg3", &mgmt0.name)?;

    let _mgip = Ip::new("10.0.0.254/24", &mg0.name, "test")?;

    let zfs = Zfs::new("mgtrio")?;

    let sidecar = SoftnpuZone::new(
        "sidecar.trio",
        &zfs,
        &[
            &tf0_sr0.end_b,
            &tf1_sr1.end_b,
            &sl0_sw0.end_b,
            &sl1_sw1.end_b,
        ],
        "trio",
    )?;

    println_nopipe!("start zone s1");
    let s1 = RouterZone::server("s1.trio", &zfs, &mg2.name, &[&sl0_sw0.end_a])?;
    println_nopipe!("start zone s2");
    let s2 = RouterZone::server("s2.trio", &zfs, &mg3.name, &[&sl1_sw1.end_a])?;
    println_nopipe!("start zone t1");
    let t1 = RouterZone::transit(
        "t1.trio",
        &zfs,
        &mg1.name,
        &[&tf0_sr0.end_a, &tf1_sr1.end_a],
        "trio",
        "sidecar.trio",
    )?;

    println_nopipe!("waiting for zones to come up");
    sleep(Duration::from_secs(10));

    sidecar.setup()?;
    s1.setup(1)?;
    s2.setup(2)?;
    t1.setup(3)?;

    run_topo!(run_trio_tests(&s1, &s2, &t1, &sidecar).await)
}

async fn run_trio_tests(
    zs1: &RouterZone<'_>,
    zs2: &RouterZone<'_>,
    zt1: &RouterZone<'_>,
    softnpu: &SoftnpuZone<'_>,
) -> Result<()> {
    let log = init_logger();
    let s1 = Client::new("http://10.0.0.1:8000", log.clone());
    let s2 = Client::new("http://10.0.0.2:8000", log.clone());
    let t1 = Client::new("http://10.0.0.3:8000", log.clone());

    assert_client_state!(&s1, peer_count(&s1), 1);
    assert_client_state!(&s2, peer_count(&s2), 1);
    assert_client_state!(&t1, peer_count(&t1), 2);

    println_nopipe!("initial peering test passed");

    s1.advertise_prefixes(&vec!["fd00:1::/64".parse().unwrap()])
        .await?;

    wait_for_eq!(prefix_count(&s1).await?, 0);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await?, 1);

    println_nopipe!("advertise from one passed");

    s2.advertise_prefixes(&vec!["fd00:2::/64".parse().unwrap()])
        .await?;

    wait_for_eq!(prefix_count(&s1).await?, 1);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await?, 2);

    println_nopipe!("advertise from two passed");

    retry_cmd!(zs1.zexec("ping fd00:2::1"), 1, 10);
    retry_cmd!(zs2.zexec("ping fd00:1::1"), 1, 10);

    println_nopipe!("connectivity test passed");

    zt1.stop_router()?;
    wait_for_eq!(prefix_count(&s1).await?, 0);
    wait_for_eq!(prefix_count(&s2).await?, 0);
    zt1.start_router(false)?;
    wait_for_eq!(prefix_count(&s1).await?, 1);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await.unwrap_or(99), 2);
    retry_cmd!(zs1.zexec("ping fd00:2::1"), 1, 10);
    retry_cmd!(zs2.zexec("ping fd00:1::1"), 1, 10);

    println_nopipe!("transit router restart passed");

    softnpu_dump!(softnpu);
    zs1.stop_router()?;
    wait_for_eq!(prefix_count(&s2).await?, 0);
    wait_for_eq!(prefix_count(&t1).await?, 1);
    softnpu_dump!(softnpu);
    zs1.start_router(false)?;

    wait_for_eq!(prefix_count(&s1).await.unwrap_or(99), 1);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await?, 2);
    softnpu_dump!(softnpu);

    s1.advertise_prefixes(&vec!["fd00:1::/64".parse().unwrap()])
        .await?;

    wait_for_eq!(prefix_count(&s1).await?, 1);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await?, 2);

    retry_cmd!(zs2.zexec("netstat -nr -f inet6"), 1, 10);
    retry_cmd!(zs2.zexec("ipadm"), 1, 10);
    retry_cmd!(zs2.zexec("route -nv get -inet6 fd00:1::1"), 1, 10);
    retry_cmd!(zs2.zexec("ndp -na"), 1, 10);
    softnpu_dump!(softnpu);
    retry_cmd!(zt1.zexec("/opt/oxide/dendrite/bin/swadm route list"), 1, 10);
    retry_cmd!(zt1.zexec("/opt/oxide/dendrite/bin/swadm arp list"), 1, 10);
    retry_cmd!(zt1.zexec("/opt/oxide/dendrite/bin/swadm addr list"), 1, 10);
    retry_cmd!(
        zs1.zexec(
            "ipadm;\
            route -nv get -inet6 fd00:2::1;\
            ndp -na;\
            netstat -nr -f inet6;\
            ping -ns fd00:2::1 60 2"
        ),
        1,
        10
    );
    retry_cmd!(zs2.zexec("ping fd00:1::1"), 1, 10);

    println_nopipe!("server router restart passed");

    let peers = t1.get_peers().await?;
    let p0: Ipv6Addr = peers
        .values()
        .next()
        .ok_or(anyhow!("expected transit peer"))?
        .addr;

    t1.expire_peer(&p0).await?;
    wait_for_eq!(prefix_count(&s1).await?, 1);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await?, 2);

    s2.withdraw_prefixes(&vec!["fd00:2::/64".parse().unwrap()])
        .await?;

    wait_for_eq!(prefix_count(&s1).await?, 0);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await?, 1);

    s2.advertise_prefixes(&vec!["fd00:2::/64".parse().unwrap()])
        .await?;

    wait_for_eq!(prefix_count(&s1).await?, 1);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await?, 2);

    println_nopipe!("peer expiration recovery passed");

    s2.advertise_prefixes(&vec![
        "fd00:2::/64".parse().unwrap(),
        "fd00:3::/64".parse().unwrap(),
        "fd00:4::/64".parse().unwrap(),
    ])
    .await?;
    // ensure that when an advertisement with a duplicate route is made, all
    // routes make it in the kernel of receivers.
    wait_for_eq!(prefix_count(&s1).await?, 3);

    let kernel_count = zs1.zexec("netstat -nrf inet6 | grep fd00 | wc -l")?;
    assert_eq!(kernel_count, "3");

    println_nopipe!("redundant advertise passed");

    wait_for_eq!(tunnel_originated_endpoint_count(&t1).await?, 0);

    t1.advertise_tunnel_endpoints(&vec![TunnelOrigin {
        overlay_prefix: "203.0.113.0/24".parse().unwrap(),
        boundary_addr: "fd00:1701::1".parse().unwrap(),
        vni: 47,
        metric: 0,
    }])
    .await?;

    wait_for_eq!(tunnel_originated_endpoint_count(&t1).await?, 1);
    wait_for_eq!(tunnel_endpoint_count(&t1).await?, 0);
    wait_for_eq!(tunnel_endpoint_count(&s1).await?, 1);
    wait_for_eq!(tunnel_endpoint_count(&s2).await?, 1);

    println_nopipe!("tunnel endpoint advertise passed");

    // redundant advertise should not change things

    t1.advertise_tunnel_endpoints(&vec![TunnelOrigin {
        overlay_prefix: "203.0.113.0/24".parse().unwrap(),
        boundary_addr: "fd00:1701::1".parse().unwrap(),
        vni: 47,
        metric: 0,
    }])
    .await?;

    sleep(Duration::from_secs(5));

    wait_for_eq!(tunnel_originated_endpoint_count(&t1).await?, 1);
    wait_for_eq!(tunnel_endpoint_count(&t1).await?, 0);
    wait_for_eq!(tunnel_endpoint_count(&s1).await?, 1);
    wait_for_eq!(tunnel_endpoint_count(&s2).await?, 1);

    println_nopipe!("redundant tunnel endpoint advertise passed");

    zs1.stop_router()?;
    sleep(Duration::from_secs(5));
    zs1.start_router(false)?;
    sleep(Duration::from_secs(5));
    let s1 = Client::new("http://10.0.0.1:8000", log.clone());
    wait_for_eq!(tunnel_endpoint_count(&s1).await?, 1);

    println_nopipe!("tunnel router restart passed");

    t1.withdraw_tunnel_endpoints(&vec![TunnelOrigin {
        overlay_prefix: "203.0.113.0/24".parse().unwrap(),
        boundary_addr: "fd00:1701::1".parse().unwrap(),
        vni: 47,
        metric: 0,
    }])
    .await?;

    wait_for_eq!(tunnel_originated_endpoint_count(&t1).await?, 0);
    wait_for_eq!(tunnel_endpoint_count(&t1).await?, 0);
    wait_for_eq!(tunnel_endpoint_count(&s1).await?, 0);
    wait_for_eq!(tunnel_endpoint_count(&s2).await?, 0);

    println_nopipe!("tunnel endpoint withdraw passed");

    run_trio_mcast(zs1, zt1, &s1, &s2, &t1, &log).await
}

/// Multicast group advertise/withdraw across the trio.
///
/// This emulates how mg-lower operates in the switch zone when publishing
/// overlay→underlay multicast bindings: the transit router
/// originates an advertisement and the server routers learn it via
/// the DDM exchange.
///
/// ```text
///   transit-originated:     s1 ----- t1 ----- s2
///                                  (O4, O6)
///
///   server-originated:      s1 ----- t1 ----- s2
///                          (O4)
/// ```
///
/// 1. t1 originates an IPv4 and an IPv6 group, and both servers import
///    them. t1 imports nothing in return (a re-import would cause a loop).
/// 2. s1 restarts and re-learns both groups from t1.
/// 3. t1 withdraws, and both servers clear.
/// 4. s1 originates O4. t1 redistributes it to s2, s1 imports nothing in
///    return, and t1 programs rear0 for O4's underlay group.
/// 5. s2 also subscribes to O4. t1 programs rear0 and rear1, then rear1 once
///    s1 withdraws, and drains the group when s2 withdraws.
/// 6. s1 subscribes to an origin whose underlay group doesn't exist yet. The
///    group is still missing until it is created, after which the
///    periodic sweep programs rear0. s1 withdraws, and the group drains.
async fn run_trio_mcast(
    zs1: &RouterZone<'_>,
    zt1: &RouterZone<'_>,
    s1: &Client,
    s2: &Client,
    t1: &Client,
    log: &Logger,
) -> Result<()> {
    assert_multicast_origins!(t1, []);

    // Cover advertisement and withdrawal for both IP families.
    let mcast_origin_v4 = MulticastOrigin::new(
        "233.252.0.1".parse().unwrap(),
        "ff04::100".parse().unwrap(),
        Vni::try_from(MULTICAST_VNI).unwrap(),
        None,
    )
    .unwrap();

    let mcast_origin_v6 = MulticastOrigin::new(
        "ff0e::1".parse().unwrap(),
        "ff04::101".parse().unwrap(),
        Vni::try_from(MULTICAST_VNI).unwrap(),
        None,
    )
    .unwrap();

    let ipv4_origin_underlay = create_multicast_underlay_group(
        zt1,
        mcast_origin_v4.underlay_group().into(),
    )?;
    let s1_member = [underlay_member("rear0")];
    let s2_member = [underlay_member("rear1")];

    t1.advertise_multicast_groups(&vec![
        mcast_origin_v4.clone(),
        mcast_origin_v6.clone(),
    ])
    .await?;

    assert_multicast_origins!(t1, [mcast_origin_v4, mcast_origin_v6]);
    assert_multicast_imports!(
        s1,
        [("sl0", mcast_origin_v4), ("sl0", mcast_origin_v6)]
    );
    assert_multicast_imports!(
        s2,
        [("sl1", mcast_origin_v4), ("sl1", mcast_origin_v6)]
    );
    // A looped announcement bouncing back from a server would show up here.
    assert_eq!(multicast_imports(t1).await?, MulticastImports::new());

    println_nopipe!("multicast group advertise passed");

    // Server router restart: s1's view of the multicast group must converge
    // again after ddmd restarts. `assert_multicast_imports!` retries through
    // the restart window.
    zs1.stop_router()?;
    zs1.start_router(false)?;
    let s1 = Client::new("http://10.0.0.1:8000", log.clone());
    assert_multicast_imports!(
        &s1,
        [("sl0", mcast_origin_v4), ("sl0", mcast_origin_v6)]
    );

    println_nopipe!("multicast router restart passed");

    t1.withdraw_multicast_groups(&vec![
        mcast_origin_v4.clone(),
        mcast_origin_v6.clone(),
    ])
    .await?;

    assert_multicast_origins!(t1, []);
    // A periodic pull can also clear the routes within this deadline.
    assert_multicast_imports!(&s1, [], 1, 5);
    assert_multicast_imports!(s2, [], 1, 5);
    assert_eq!(multicast_imports(t1).await?, MulticastImports::new());

    println_nopipe!("multicast group withdraw passed");

    s1.advertise_multicast_groups(&vec![mcast_origin_v4.clone()])
        .await?;

    assert_multicast_origins!(&s1, [mcast_origin_v4]);
    assert_multicast_imports!(t1, [("tfportrear0_0", mcast_origin_v4)]);
    assert_multicast_imports!(s2, [("sl1", mcast_origin_v4)]);
    assert_eq!(multicast_imports(&s1).await?, MulticastImports::new());

    wait_for_multicast_members(zt1, &ipv4_origin_underlay, &s1_member)?;

    println_nopipe!("multicast server-originated redistribution passed");

    let origin = mcast_origin_v4;
    let group = &ipv4_origin_underlay;
    s2.advertise_multicast_groups(&vec![origin.clone()]).await?;
    assert_multicast_imports!(
        t1,
        [("tfportrear0_0", origin), ("tfportrear1_0", origin)]
    );
    wait_for_multicast_members(
        zt1,
        group,
        &[s1_member[0].clone(), s2_member[0].clone()],
    )?;

    s1.withdraw_multicast_groups(&vec![origin.clone()]).await?;
    assert_multicast_origins!(&s1, []);
    assert_multicast_imports!(t1, [("tfportrear1_0", origin)], 1, 5);
    wait_for_multicast_members(zt1, group, &s2_member)?;

    s2.withdraw_multicast_groups(&vec![origin]).await?;
    assert_multicast_imports!(t1, [], 1, 5);
    assert_multicast_imports!(&s1, [], 1, 5);
    assert_multicast_imports!(s2, [], 1, 5);
    wait_for_multicast_members(zt1, group, &[])?;

    println_nopipe!("multicast underlay replication members passed");

    let delayed_origin = MulticastOrigin::new(
        "233.252.0.2".parse().unwrap(),
        "ff04::102".parse().unwrap(),
        Vni::try_from(MULTICAST_VNI).unwrap(),
        None,
    )
    .unwrap();
    let delayed_group_ip: Ipv6Addr = delayed_origin.underlay_group().into();

    s1.advertise_multicast_groups(&vec![delayed_origin.clone()])
        .await?;
    assert_multicast_imports!(t1, [("tfportrear0_0", delayed_origin)]);
    assert_multicast_imports!(s2, [("sl1", delayed_origin)]);
    assert_multicast_underlay_group_missing(zt1, delayed_group_ip)?;

    let delayed_group = create_multicast_underlay_group(zt1, delayed_group_ip)?;
    wait_for_multicast_members(zt1, &delayed_group, &s1_member)?;

    s1.withdraw_multicast_groups(&vec![delayed_origin]).await?;
    assert_multicast_imports!(t1, []);
    wait_for_multicast_members(zt1, &delayed_group, &[])?;

    println_nopipe!("multicast delayed underlay group creation passed");

    Ok(())
}

fn assert_multicast_underlay_group_missing(
    zone: &RouterZone<'_>,
    group_ip: Ipv6Addr,
) -> Result<()> {
    let version = dpd_api_version();
    let status = zone.zexec(&format!(
        "curl --noproxy '*' --globoff --silent --show-error \
         --max-time 5 --output /dev/null --write-out '%{{http_code}}' \
         --header 'api-version: {version}' \
         'http://[::1]:12224/multicast/underlay-groups/{group_ip}'"
    ))?;
    if status.trim() != "404" {
        return Err(anyhow!(
            "underlay group {group_ip}: expected HTTP 404, got {status:?}"
        ));
    }
    Ok(())
}

fn create_multicast_underlay_group(
    zone: &RouterZone<'_>,
    group_ip: Ipv6Addr,
) -> Result<MulticastGroupUnderlayResponse> {
    create_multicast_underlay_group_with(zone, group_ip, &[])
}

fn create_multicast_underlay_group_with(
    zone: &RouterZone<'_>,
    group_ip: Ipv6Addr,
    members: &[MulticastGroupMember],
) -> Result<MulticastGroupUnderlayResponse> {
    let body = serde_json::to_string(&MulticastGroupCreateUnderlayEntry {
        group_ip: group_ip.try_into()?,
        tag: Some(format!("{}:{group_ip}", zone.zone.name)),
        members: members.to_vec(),
    })?
    .replace('\'', "'\\''");
    let version = dpd_api_version();
    let response = zone.zexec(&format!(
        "curl --noproxy '*' --globoff --fail --silent --show-error \
         --max-time 5 --request POST \
         --header 'api-version: {version}' \
         --header 'Content-Type: application/json' --data '{body}' \
         'http://[::1]:12224/multicast/underlay-groups'"
    ))?;
    Ok(serde_json::from_str(&response)?)
}

fn get_multicast_underlay_group(
    zone: &RouterZone<'_>,
    group: &MulticastGroupUnderlayResponse,
) -> Result<MulticastGroupUnderlayResponse> {
    let version = dpd_api_version();
    let body = zone.zexec(&format!(
        "curl --noproxy '*' --globoff --fail --silent --show-error \
         --max-time 5 --header 'api-version: {version}' \
         'http://[::1]:12224/multicast/underlay-groups/{}'",
        group.group_ip,
    ))?;
    Ok(serde_json::from_str(&body)?)
}

fn same_group(
    actual: &MulticastGroupUnderlayResponse,
    group: &MulticastGroupUnderlayResponse,
) -> bool {
    actual.group_ip == group.group_ip
        && actual.tag == group.tag
        && actual.external_group_id == group.external_group_id
        && actual.underlay_group_id == group.underlay_group_id
}

fn same_membership(
    actual: &[MulticastGroupMember],
    members: &[MulticastGroupMember],
) -> bool {
    actual.len() == members.len()
        && members.iter().all(|member| actual.contains(member))
}

fn wait_for_multicast_members(
    zone: &RouterZone<'_>,
    group: &MulticastGroupUnderlayResponse,
    members: &[MulticastGroupMember],
) -> Result<()> {
    let start = Instant::now();
    loop {
        let response = get_multicast_underlay_group(zone, group);
        if let Ok(actual) = &response
            && same_group(actual, group)
            && same_membership(&actual.members, members)
        {
            return Ok(());
        }
        if start.elapsed() >= MULTICAST_CONVERGENCE_TIMEOUT {
            return Err(anyhow!(
                "underlay group {} did not converge to {members:?}; \
                 last response: {response:?}",
                group.group_ip,
            ));
        }
        sleep(MULTICAST_POLL_INTERVAL);
    }
}

fn assert_multicast_members_unchanged(
    zone: &RouterZone<'_>,
    group: &MulticastGroupUnderlayResponse,
    members: &[MulticastGroupMember],
    window: Duration,
) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < window {
        let actual = get_multicast_underlay_group(zone, group)?;
        if !same_group(&actual, group)
            || !same_membership(&actual.members, members)
        {
            return Err(anyhow!(
                "underlay group {} left {members:?} within {window:?}: \
                 {actual:?}",
                group.group_ip,
            ));
        }
        sleep(MULTICAST_POLL_INTERVAL);
    }
    Ok(())
}

#[tokio::test]
async fn test_dual_sidecar() -> Result<()> {
    //                sidecar A                    sidecar B
    //   t1 rear0 --- sr0 | sw0 --- sl0  s1  sl1 --- sw2 | sr2 --- rear0 t2
    //   t1 rear1 --- sr1 | sw1 --- sl2  s2  sl3 --- sw3 | sr3 --- rear1 t2
    let tra_sr_0 = SimnetLink::new("tra0", "sr0")?;
    let tra_sr_1 = SimnetLink::new("tra1", "sr1")?;
    let trb_sr_2 = SimnetLink::new("trb0", "sr2")?;
    let trb_sr_3 = SimnetLink::new("trb1", "sr3")?;

    let sl0_sw0 = SimnetLink::new("sl0", "sw0")?;
    let sl2_sw1 = SimnetLink::new("sl2", "sw1")?;
    let sl1_sw2 = SimnetLink::new("sl1", "sw2")?;
    let sl3_sw3 = SimnetLink::new("sl3", "sw3")?;

    let mgmt0 = Etherstub::new("mgmt0")?;
    let mg0 = Vnic::new("mg0", &mgmt0.name)?;
    let mgd1 = Vnic::new("mgd1", &mgmt0.name)?;
    let mgd2 = Vnic::new("mgd2", &mgmt0.name)?;
    let mgd3 = Vnic::new("mgd3", &mgmt0.name)?;
    let mgd4 = Vnic::new("mgd4", &mgmt0.name)?;

    let _mgip = Ip::new("10.0.0.254/24", &mg0.name, "test")?;

    let zfs = Zfs::new("mgdual")?;

    let sidecar_a = SoftnpuZone::new(
        "sidecar_a.dual",
        &zfs,
        &[
            &tra_sr_0.end_b,
            &tra_sr_1.end_b,
            &sl0_sw0.end_b,
            &sl2_sw1.end_b,
        ],
        "dual",
    )?;
    let sidecar_b = SoftnpuZone::new(
        "sidecar_b.dual",
        &zfs,
        &[
            &trb_sr_2.end_b,
            &trb_sr_3.end_b,
            &sl1_sw2.end_b,
            &sl3_sw3.end_b,
        ],
        "dual",
    )?;

    println_nopipe!("start zone s1");
    let s1 = RouterZone::server(
        "s1.dual",
        &zfs,
        &mgd1.name,
        &[&sl0_sw0.end_a, &sl1_sw2.end_a],
    )?;
    println_nopipe!("start zone s2");
    let s2 = RouterZone::server(
        "s2.dual",
        &zfs,
        &mgd2.name,
        &[&sl2_sw1.end_a, &sl3_sw3.end_a],
    )?;

    println_nopipe!("start zone t1");
    let mut t1 = RouterZone::transit(
        "t1.dual",
        &zfs,
        &mgd3.name,
        &[&tra_sr_0.end_a, &tra_sr_1.end_a],
        "dual",
        "sidecar_a.dual",
    )?;
    t1.set_port_map(BTreeMap::from([
        ("tra0".into(), "tfportrear0_0".into()),
        ("tra1".into(), "tfportrear1_0".into()),
    ]));

    println_nopipe!("start zone t2");
    let mut t2 = RouterZone::transit(
        "t2.dual",
        &zfs,
        &mgd4.name,
        &[&trb_sr_2.end_a, &trb_sr_3.end_a],
        "dual",
        "sidecar_b.dual",
    )?;
    t2.set_port_map(BTreeMap::from([
        ("trb0".into(), "tfportrear0_0".into()),
        ("trb1".into(), "tfportrear1_0".into()),
    ]));

    println_nopipe!("waiting for zones to come up");
    sleep(Duration::from_secs(10));

    sidecar_a.setup()?;
    sidecar_b.setup()?;
    s1.setup(1)?;
    s2.setup(2)?;
    t1.setup(3)?;
    t2.setup(4)?;

    run_topo!(run_dual_sidecar_mcast(&s1, &t1, &t2).await)
}

async fn run_dual_sidecar_mcast(
    zs1: &RouterZone<'_>,
    zt1: &RouterZone<'_>,
    zt2: &RouterZone<'_>,
) -> Result<()> {
    let log = init_logger();
    let s1 = Client::new("http://10.0.0.1:8000", log.clone());
    let s2 = Client::new("http://10.0.0.2:8000", log.clone());
    let t1 = Client::new("http://10.0.0.3:8000", log.clone());
    let t2 = Client::new("http://10.0.0.4:8000", log.clone());

    assert_client_state!(&s1, peer_count(&s1), 2);
    assert_client_state!(&s2, peer_count(&s2), 2);
    assert_client_state!(&t1, peer_count(&t1), 2);
    assert_client_state!(&t2, peer_count(&t2), 2);

    println_nopipe!("dual sidecar peering passed");

    let origin = MulticastOrigin::new(
        "233.252.0.20".parse().unwrap(),
        "ff04::120".parse().unwrap(),
        Vni::try_from(MULTICAST_VNI).unwrap(),
        None,
    )
    .unwrap();
    let group_ip: Ipv6Addr = origin.underlay_group().into();
    let group_a = create_multicast_underlay_group(zt1, group_ip)?;
    let group_b = create_multicast_underlay_group(zt2, group_ip)?;
    let s1_member = [underlay_member("rear0")];
    let s2_member = [underlay_member("rear1")];
    let both = [s1_member[0].clone(), s2_member[0].clone()];

    s1.advertise_multicast_groups(&vec![origin.clone()]).await?;
    assert_multicast_imports!(&t1, [("tfportrear0_0", origin)]);
    assert_multicast_imports!(&t2, [("tfportrear0_0", origin)]);
    wait_for_multicast_members(zt1, &group_a, &s1_member)?;
    wait_for_multicast_members(zt2, &group_b, &s1_member)?;

    s2.advertise_multicast_groups(&vec![origin.clone()]).await?;
    assert_multicast_imports!(
        &t1,
        [("tfportrear0_0", origin), ("tfportrear1_0", origin)]
    );
    assert_multicast_imports!(
        &t2,
        [("tfportrear0_0", origin), ("tfportrear1_0", origin)]
    );
    wait_for_multicast_members(zt1, &group_a, &both)?;
    wait_for_multicast_members(zt2, &group_b, &both)?;
    assert_multicast_imports!(&s1, [("sl0", origin), ("sl1", origin)]);

    println_nopipe!("dual sidecar subscription passed");

    zt2.stop_router()?;
    zt2.start_router(false)?;
    let t2 = Client::new("http://10.0.0.4:8000", log.clone());
    assert_multicast_imports!(
        &t2,
        [("tfportrear0_0", origin), ("tfportrear1_0", origin)]
    );
    assert_multicast_members_unchanged(zt2, &group_b, &both, MEMBER_HOLD)?;

    println_nopipe!("dual sidecar transit restart passed");

    zs1.zexec("ipadm delete-addr sl1/v6")?;
    assert_client_state!(&s1, exchange_peer_count(&s1), 1, 1, 30);
    assert_multicast_imports!(&t2, [("tfportrear1_0", origin)], 1, 30);
    assert_multicast_imports!(&s1, [("sl0", origin)], 1, 30);
    wait_for_multicast_members(zt2, &group_b, &s2_member)?;
    assert_multicast_members_unchanged(zt1, &group_a, &both, MEMBER_HOLD)?;

    zs1.zexec("ipadm create-addr -t -T addrconf sl1/v6")?;
    assert_client_state!(&s1, exchange_peer_count(&s1), 2, 1, 30);
    assert_multicast_imports!(
        &t2,
        [("tfportrear0_0", origin), ("tfportrear1_0", origin)],
        1,
        30
    );
    wait_for_multicast_members(zt2, &group_b, &both)?;
    assert_multicast_imports!(&s1, [("sl0", origin), ("sl1", origin)], 1, 30);

    println_nopipe!("dual sidecar link failover passed");

    Ok(())
}

#[tokio::test]
async fn test_quartet() -> Result<()> {
    // A quartet of routers in a star topology.
    //
    //                                                    sled1
    //                                                 ,----------,
    //                                               ,-----,  ,-----,
    //                                             ,-| sl0 |  | mg2 |-*
    //       scrimlet              sidecar         | '-----'  '-----'
    //     ,-----------,     ,-----------------,   |   '----------'
    //     |      ,-----,  ,-----, ,-----, ,-----, |
    //     |      | tf0 |--| sr0 |-|     |-| sw0 |-'      sled2
    //     |      '-----'  '-----' |     | '-----'     ,----------,
    //    ,-----, ,-----,  ,-----, |soft | ,-----,   ,-----,  ,-----,
    //  *-| mg1 | | tf1 |--| sr1 |-|  npu|-| sw1 |---| sl1 |  | mg3 |-*
    //    '-----' '-----'  '-----' |     | '-----'   '-----'  '-----'
    //     |      ,-----,  ,-----, |     | ,-----,     '----------'
    //     |      | tf2 |--| sr2 |-|     |-| sw2 |-,
    //     |      '-----'  '-----' '-----' '-----' |      sled3
    //     '-----------'     '-----------------'   |   ,----------,
    //                                             | ,-----,  ,-----,
    //                                             '-| sl2 |  | mg4 |-*
    //                                               '-----'  '-----'
    //                                                 '----------'
    //

    let sl0_sw0 = SimnetLink::new("sl0", "sw0")?;
    let sl1_sw1 = SimnetLink::new("sl1", "sw1")?;
    let sl2_sw2 = SimnetLink::new("sl2", "sw2")?;
    let tf0_sr0 = SimnetLink::new("tfportrear0_0", "sr0")?;
    let tf1_sr1 = SimnetLink::new("tfportrear1_0", "sr1")?;
    let tf2_sr2 = SimnetLink::new("tfportrear2_0", "sr2")?;

    let mgmt0 = Etherstub::new("mgmt0")?;

    let mg0 = Vnic::new("mg0", &mgmt0.name)?;
    let mgs1 = Vnic::new("mgs1", &mgmt0.name)?;
    let mgs2 = Vnic::new("mgs2", &mgmt0.name)?;
    let mgs3 = Vnic::new("mgs3", &mgmt0.name)?;
    let mgt1 = Vnic::new("mgt1", &mgmt0.name)?;

    let _mgip = Ip::new("10.0.0.254/24", &mg0.name, "test")?;

    let zfs = Zfs::new("mgtest")?;

    let sidecar = SoftnpuZone::new(
        "sidecar.quartet",
        &zfs,
        &[
            &tf0_sr0.end_b,
            &tf1_sr1.end_b,
            &tf2_sr2.end_b,
            &sl0_sw0.end_b,
            &sl1_sw1.end_b,
            &sl2_sw2.end_b,
        ],
        "quartet",
    )?;

    println_nopipe!("start zone s1");
    let s1 =
        RouterZone::server("s1.quartet", &zfs, &mgs1.name, &[&sl0_sw0.end_a])?;
    println_nopipe!("start zone s2");
    let s2 =
        RouterZone::server("s2.quartet", &zfs, &mgs2.name, &[&sl1_sw1.end_a])?;
    println_nopipe!("start zone s3");
    let s3 =
        RouterZone::server("s3.quartet", &zfs, &mgs3.name, &[&sl2_sw2.end_a])?;
    println_nopipe!("start zone t1");
    let t1 = RouterZone::transit(
        "t1.quartet",
        &zfs,
        &mgt1.name,
        &[&tf0_sr0.end_a, &tf1_sr1.end_a, &tf2_sr2.end_a],
        "quartet",
        "sidecar.quartet",
    )?;

    println_nopipe!("waiting for zones to come up");
    sleep(Duration::from_secs(10));

    sidecar.setup()?;
    s1.setup(1)?;
    s2.setup(2)?;
    s3.setup(3)?;
    t1.setup(4)?;

    run_topo!(run_quartet_tests(&s1, &s2, &s3, &t1).await)?;

    Ok(())
}

async fn run_quartet_tests(
    _zs1: &RouterZone<'_>,
    _zs2: &RouterZone<'_>,
    zs3: &RouterZone<'_>,
    zt1: &RouterZone<'_>,
) -> Result<()> {
    let log = init_logger();
    let s1 = Client::new("http://10.0.0.1:8000", log.clone());
    let s2 = Client::new("http://10.0.0.2:8000", log.clone());
    let s3 = Client::new("http://10.0.0.3:8000", log.clone());
    let t1 = Client::new("http://10.0.0.4:8000", log.clone());

    assert_client_state!(&s1, peer_count(&s1), 1);
    assert_client_state!(&s2, peer_count(&s2), 1);
    assert_client_state!(&s3, peer_count(&s3), 1);
    assert_client_state!(&t1, peer_count(&t1), 3);

    println_nopipe!("initial peering test passed");

    s1.advertise_prefixes(&vec!["fd00:1::/64".parse().unwrap()])
        .await?;

    s3.advertise_prefixes(&vec!["fd00:3::/64".parse().unwrap()])
        .await?;

    // s1/s3 should now have 1 prefix
    wait_for_eq!(prefix_count(&s1).await?, 1);
    wait_for_eq!(prefix_count(&s3).await?, 1);

    // s3 should be able to ping s1
    retry_cmd!(zs3.zexec("ping fd00:1::1"), 1, 10);

    // s2 hijacks s1's prefix
    s2.advertise_prefixes(&vec!["fd00:1::/64".parse().unwrap()])
        .await?;

    // s3 should now have 2 prefixes
    wait_for_eq!(prefix_count(&s3).await?, 2);

    s2.withdraw_prefixes(&vec!["fd00:1::/64".parse().unwrap()])
        .await?;

    // wait for withdraw propagation
    sleep(Duration::from_secs(5));

    // unhijack
    s1.advertise_prefixes(&vec!["fd00:1::/64".parse().unwrap()])
        .await?;
    sleep(Duration::from_secs(5));

    // s3 should still have 1 prefix left
    wait_for_eq!(prefix_count(&s3).await?, 1);

    // s3 should be able to ping s1 even after s2 withdrew s1's prefix
    retry_cmd!(zs3.zexec("ping fd00:1::1"), 1, 10);

    run_quartet_mcast_failover(&s1, &s2, &s3, &t1).await?;
    run_quartet_mcast_resync(zs3, zt1, &s1, &s3, &t1).await
}

/// ```text
///       s1 ----,
///  (origin O)   \
///                t1 ---- s3
///               /
///       s2 ----'
///  (origin O)
/// ```
///
/// - s1 withdraws origin O. t1 still reaches O via s2. The observer checks
///   s3's route through t1's convergence and for [`FAILOVER_SETTLE`] afterward.
/// - s1 still holds s2's copy of O via t1, and s2 drops the copy it
///   learned from s1.
/// - s2 withdraws O, and t1, s1, and s3 clear.
async fn run_quartet_mcast_failover(
    s1: &Client,
    s2: &Client,
    s3: &Client,
    t1: &Client,
) -> Result<()> {
    let origin = MulticastOrigin::new(
        "233.252.0.10".parse().unwrap(),
        "ff04::110".parse().unwrap(),
        Vni::try_from(MULTICAST_VNI).unwrap(),
        None,
    )
    .unwrap();

    s1.advertise_multicast_groups(&vec![origin.clone()]).await?;
    s2.advertise_multicast_groups(&vec![origin.clone()]).await?;

    assert_multicast_imports!(
        t1,
        [("tfportrear0_0", origin), ("tfportrear1_0", origin)]
    );
    assert_multicast_imports!(s1, [("sl0", origin)]);
    assert_multicast_imports!(s2, [("sl1", origin)]);
    assert_multicast_imports!(s3, [("sl2", origin)]);
    println_nopipe!("multicast dual origination passed");

    let expected = MulticastImports::from([(
        "sl2".to_string(),
        origin.clone(),
        origin.metric(),
    )]);
    let expected_transit = MulticastImports::from([(
        "tfportrear1_0".to_string(),
        origin.clone(),
        origin.metric(),
    )]);
    let (ready_tx, ready_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();

    let failover = async {
        ready_rx.await?;
        s1.withdraw_multicast_groups(&vec![origin.clone()]).await?;
        wait_for_imports(
            "t1",
            t1,
            &expected_transit,
            MULTICAST_CONVERGENCE_TIMEOUT,
        )
        .await?;
        tokio::time::sleep(FAILOVER_SETTLE).await;
        done_tx
            .send(())
            .map_err(|_| anyhow!("s3 observation stopped before completion"))
    };
    tokio::try_join!(
        observe_imports_unchanged("s3", s3, &expected, ready_tx, done_rx),
        failover,
    )?;

    assert_multicast_imports!(s1, [("sl0", origin)]);
    assert_multicast_imports!(s2, []);
    println_nopipe!("multicast failover passed");

    s2.withdraw_multicast_groups(&vec![origin]).await?;
    assert_multicast_imports!(t1, []);
    assert_multicast_imports!(s1, []);
    assert_multicast_imports!(s3, []);
    println_nopipe!("multicast final withdrawal passed");

    Ok(())
}

/// ```text
///   s1 ----- t1 ----- s3
///  (O)        |
///             '-- injected push (curl from t1's zone) --> s3
/// ```
///
/// - s3 learns about O via t1. An injected withdrawal of O removes it from
///   s3, and s3's periodic pull of t1 restores it.
/// - s1 withdraws O and s3 clears it. An injected announcement of O re-adds
///   it, and the next periodic pull of t1 drops it, since t1 no longer has
///   it.
/// - s3 keeps its session with t1 throughout.
async fn run_quartet_mcast_resync(
    zs3: &RouterZone<'_>,
    zt1: &RouterZone<'_>,
    s1: &Client,
    s3: &Client,
    t1: &Client,
) -> Result<()> {
    let origin = MulticastOrigin::new(
        "233.252.0.11".parse().unwrap(),
        "ff04::111".parse().unwrap(),
        Vni::try_from(MULTICAST_VNI).unwrap(),
        None,
    )
    .unwrap();

    s1.advertise_multicast_groups(&vec![origin.clone()]).await?;
    assert_multicast_imports!(t1, [("tfportrear0_0", origin)]);
    assert_multicast_imports!(s3, [("sl2", origin)]);

    let peers = t1.get_peers().await?;
    let peer = peers
        .values()
        .find(|peer| peer.host == zs3.zone.name)
        .ok_or_else(|| anyhow!("t1 has no peer for {}", zs3.zone.name))?;
    let if_name = peer
        .if_name
        .as_ref()
        .ok_or_else(|| anyhow!("s3 peer has no interface name"))?;
    let uri = format!("http://[{}%25{if_name}]:56797/v4/push", peer.addr);
    let groups = s3.get_multicast_groups().await?;
    let route = groups
        .iter()
        .map(|imported| &imported.route)
        .find(|route| route.origin == origin)
        .ok_or_else(|| anyhow!("s3 has not imported the test origin"))?;
    let vector = serde_json::json!({
        "origin": route.origin,
        "path": route.path,
    });

    let push = |announce: bool| -> Result<()> {
        let mut multicast = serde_json::json!({
            "announce": [],
            "withdraw": [],
        });
        multicast[if announce { "announce" } else { "withdraw" }] =
            serde_json::json!([vector]);
        let body = serde_json::json!({ "multicast": multicast })
            .to_string()
            .replace('\'', "'\\''");
        let status = zt1.zexec(&format!(
            "curl --noproxy '*' --globoff --fail --silent --show-error \
             --max-time 5 --request PUT \
             --header 'Content-Type: application/json' --data '{body}' \
             --write-out '%{{http_code}}' '{uri}'",
        ))?;
        if status.trim() != "204" {
            return Err(anyhow!("multicast push returned {status}"));
        }
        Ok(())
    };

    let peers = s3.get_peers().await?;
    let Some(PeerStatus::Exchange(uptime)) =
        peers.values().next().map(|peer| &peer.status)
    else {
        return Err(anyhow!("s3 peer is not in Exchange"));
    };
    let started = Instant::now();

    assert_client_state!(
        s3,
        async {
            push(false)?;
            multicast_imports(s3).await
        },
        MulticastImports::new()
    );
    assert_multicast_imports!(s3, [("sl2", origin)], 1, 30);
    println_nopipe!("multicast resync import passed");

    s1.withdraw_multicast_groups(&vec![origin.clone()]).await?;
    assert_multicast_imports!(t1, []);
    assert_multicast_imports!(s3, []);
    assert_client_state!(
        s3,
        async {
            push(true)?;
            multicast_imports(s3).await
        },
        MulticastImports::from([(
            "sl2".to_string(),
            origin.clone(),
            origin.metric(),
        )])
    );
    assert_multicast_imports!(s3, [], 1, 30);
    println_nopipe!("multicast resync withdrawal passed");

    let min_uptime = *uptime + started.elapsed();
    let peers = s3.get_peers().await?;
    assert!(matches!(
        peers.values().next().map(|peer| &peer.status),
        Some(PeerStatus::Exchange(uptime)) if *uptime >= min_uptime
    ));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_external_peer_sextet() -> Result<()> {
    // A sextet of routers in a multi-rack topology.
    //
    //                                                    sled1
    //                                                 ,----------,
    //                                               ,-----,  ,-----,
    //                                             ,-| sl0 |  | mg2 |-*
    //       scrimletA             sidecarA        | '-----'  '-----'
    //     ,-----------,     ,-----------------,   |   '----------'
    //     |      ,-----,  ,-----, ,-----, ,-----, |
    //     |      | tr0a|--| sr0 |-|     |-| sw2 |-'      sled2
    //     |      '-----'  '-----' |     | '-----'     ,----------,
    //    ,-----, ,-----,  ,-----, |soft | ,-----,   ,-----,  ,-----,
    //  *-| mg1 | | tr1a|--| sr1 |-|  npu|-| sw3 |---| sl1 |  | mg3 |-*
    //    '-----' '-----'  '-----' |     | '-----'   '-----'  '-----'
    //     |      ,-----,  ,-----, |     | ,-----,     '----------'
    //     |      | tq0a|--| sq0 |-|     |-| sw0 |----,
    //     |      '-----'  '-----' |     | '-----'    |
    //     |      ,-----,  ,-----, |     | ,-----,    |
    //     |      | tq1a|--| sq1 |-|     |-| sw1 |-,  |
    //     |      '-----'  '-----' '-----' '-----' |  |
    //     '-----------'     '-----------------'   |  |
    //                                             |  |
    //                                             |  |
    //                                             |  |
    //       scrimletB             sidecarB        |  |
    //     ,-----------,     ,-----------------,   |  |
    //     |      ,-----,  ,-----, ,-----, ,-----, |  |
    //     |      | tq0b|--| sq2 |-|     |-| sw4 |-'  |
    //     |      '-----'  '-----' |     | '-----'    |
    //    ,-----, ,-----,  ,-----, |soft | ,-----,    |
    //  *-| mg4 | | tq1b|--| sq3 |-|  npu|-| sw5 |----'   sled3
    //    '-----' '-----'  '-----' |     | '-----'     ,----------,
    //     |      ,-----,  ,-----, |     | ,-----,   ,-----,  ,-----,
    //     |      | tr0b|--| sr2 |-|     |-| sw6 |---| sl2 |  | mg5 |-*
    //     |      '-----'  '-----' |     | '-----'   '-----'  '-----'
    //     |      ,-----,  ,-----, |     | ,-----,     '----------'
    //     |      | tr1b|--| sr3 |-|     |-| sw7 |-,
    //     |      '-----'  '-----' '-----' '-----' |      sled4
    //     '-----------'     '-----------------'   |   ,----------,
    //                                             | ,-----,  ,-----,
    //                                             '-| sl3 |  | mg6 |-*
    //                                               '-----'  '-----'
    //                                                 '----------'

    // Scrimlet A <-> Sidecar A
    let tqa_sq_0 = SimnetLink::new("tqa0", "sq0")?;
    let tqa_sq_1 = SimnetLink::new("tqa1", "sq1")?;
    let tra_sr_0 = SimnetLink::new("tra0", "sr0")?;
    let tra_sr_1 = SimnetLink::new("tra1", "sr1")?;

    // Sidecar A <-> Sleds
    let sl0_sw2 = SimnetLink::new("sl0", "sw2")?;
    let sl1_sw3 = SimnetLink::new("sl1", "sw3")?;

    // Scrimlet B <-> Sidecar B
    let tqb_sq_0 = SimnetLink::new("tqb0", "sq2")?;
    let tqb_sq_1 = SimnetLink::new("tqb1", "sq3")?;
    let trb_sr_0 = SimnetLink::new("trb0", "sr2")?;
    let trb_sr_1 = SimnetLink::new("trb1", "sr3")?;

    // Sidecar B <-> Sleds
    let sl2_sw6 = SimnetLink::new("sl2", "sw6")?;
    let sl3_sw7 = SimnetLink::new("sl3", "sw7")?;

    // Sidecar A <-> Sidecar B
    let sw0_sw4 = SimnetLink::new("sw0", "sw5")?;
    let sw1_sw5 = SimnetLink::new("sw1", "sw4")?;

    let mgmt0 = Etherstub::new("mgmt0")?;
    let mg0 = Vnic::new("mg0", &mgmt0.name)?;
    let mgs1 = Vnic::new("mgs1", &mgmt0.name)?;
    let mgs2 = Vnic::new("mgs2", &mgmt0.name)?;
    let mgs3 = Vnic::new("mgs3", &mgmt0.name)?;
    let mgs4 = Vnic::new("mgs4", &mgmt0.name)?;
    let mgs5 = Vnic::new("mgs5", &mgmt0.name)?;
    let mgs6 = Vnic::new("mgs6", &mgmt0.name)?;

    let _mgip = Ip::new("10.0.0.254/24", &mg0.name, "test")?;

    let zfs = Zfs::new("mgtest")?;

    let sidecar_a = SoftnpuZone::new(
        "sidecar_a.sextet",
        &zfs,
        &[
            &tqa_sq_0.end_b,
            &tqa_sq_1.end_b,
            &tra_sr_0.end_b,
            &tra_sr_1.end_b,
            &sl0_sw2.end_b,
            &sl1_sw3.end_b,
            &sw0_sw4.end_a,
            &sw1_sw5.end_a,
        ],
        "sextet",
    )?;

    let sidecar_b = SoftnpuZone::new(
        "sidecar_b.sextet",
        &zfs,
        &[
            &tqb_sq_0.end_b,
            &tqb_sq_1.end_b,
            &trb_sr_0.end_b,
            &trb_sr_1.end_b,
            &sl2_sw6.end_b,
            &sl3_sw7.end_b,
            &sw0_sw4.end_b,
            &sw1_sw5.end_b,
        ],
        "sextet",
    )?;

    println_nopipe!("start zone s1");
    let s1 =
        RouterZone::server("s1.sextet", &zfs, &mgs2.name, &[&sl0_sw2.end_a])?;

    println_nopipe!("start zone s2");
    let s2 =
        RouterZone::server("s2.sextet", &zfs, &mgs3.name, &[&sl1_sw3.end_a])?;

    println_nopipe!("start zone s3");
    let s3 =
        RouterZone::server("s3.sextet", &zfs, &mgs5.name, &[&sl2_sw6.end_a])?;

    println_nopipe!("start zone s4");
    let s4 =
        RouterZone::server("s4.sextet", &zfs, &mgs6.name, &[&sl3_sw7.end_a])?;

    println_nopipe!("start zone t1");
    let mut t1 = RouterZone::transit(
        "t1.sextet",
        &zfs,
        &mgs1.name,
        &[
            &tqa_sq_0.end_a,
            &tqa_sq_1.end_a,
            &tra_sr_0.end_a,
            &tra_sr_1.end_a,
        ],
        "sextet",
        "sidecar_a.sextet",
    )?;
    t1.set_port_map(BTreeMap::from([
        ("tra0".into(), "tfportrear0_0".into()),
        ("tra1".into(), "tfportrear1_0".into()),
        ("tqa0".into(), "tfportqsfp0_0".into()),
        ("tqa1".into(), "tfportqsfp1_0".into()),
    ]));

    println_nopipe!("start zone t2");
    let mut t2 = RouterZone::transit(
        "t2.sextet",
        &zfs,
        &mgs4.name,
        &[
            &tqb_sq_0.end_a,
            &tqb_sq_1.end_a,
            &trb_sr_0.end_a,
            &trb_sr_1.end_a,
        ],
        "sextet",
        "sidecar_b.sextet",
    )?;
    t2.set_port_map(BTreeMap::from([
        ("trb0".into(), "tfportrear0_0".into()),
        ("trb1".into(), "tfportrear1_0".into()),
        ("tqb0".into(), "tfportqsfp0_0".into()),
        ("tqb1".into(), "tfportqsfp1_0".into()),
    ]));

    println_nopipe!("waiting for zones to come up");
    sleep(Duration::from_secs(10));

    sidecar_a.setup()?;
    sidecar_b.setup()?;
    s1.setup(1)?;
    s2.setup(2)?;
    s3.setup(3)?;
    s4.setup(4)?;
    t1.setup(5)?;
    t2.setup(6)?;

    run_topo!(run_sextet_tests(&s1, &s2, &s3, &s4, &t1, &t2).await)?;

    Ok(())
}

async fn run_sextet_tests(
    _zs1: &RouterZone<'_>,
    _zs2: &RouterZone<'_>,
    _zs3: &RouterZone<'_>,
    _zs4: &RouterZone<'_>,
    zt1: &RouterZone<'_>,
    zt2: &RouterZone<'_>,
) -> Result<()> {
    let log = init_logger();

    // A ddm client that dumps out information when it drops. Primarily used for
    // debugging test failures when an assert pops.
    struct DropDump {
        c: Client,
        name: String,
    }
    impl Deref for DropDump {
        type Target = Client;
        fn deref(&self) -> &Self::Target {
            &self.c
        }
    }
    impl DerefMut for DropDump {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.c
        }
    }
    impl Drop for DropDump {
        fn drop(&mut self) {
            // Async just loves to make things difficult, it's taken over all
            // the things, but heaven forbid you need to do an async thing in
            // the most basic of object lifecycle management traits ...
            let rt = tokio::runtime::Handle::current();
            let c = self.c.clone();
            let name = self.name.clone();
            tokio::task::block_in_place(|| {
                rt.block_on(async move {
                    dump_client_state(&name, &c).await;
                });
            });
        }
    }

    macro_rules! drop_dump {
        ($name:ident, $endpoint:expr) => {
            let $name = DropDump {
                c: Client::new($endpoint, log.clone()),
                name: stringify!($name).to_string(),
            };
        };
    }

    #[derive(Default)]
    struct PeerCounts {
        s1: usize,
        s2: usize,
        s3: usize,
        s4: usize,
        t1: usize,
        t2: usize,
    }
    impl PeerCounts {
        fn server(mut self, c: usize) -> Self {
            self.s1 = c;
            self.s2 = c;
            self.s3 = c;
            self.s4 = c;
            self
        }
        fn transit(mut self, c: usize) -> Self {
            self.t1 = c;
            self.t2 = c;
            self
        }
    }

    struct PeerReachablePrefixes {
        s1: BTreeSet<Ipv6Net>,
        s2: BTreeSet<Ipv6Net>,
        s3: BTreeSet<Ipv6Net>,
        s4: BTreeSet<Ipv6Net>,
        t1: BTreeSet<Ipv6Net>,
        t2: BTreeSet<Ipv6Net>,
    }

    drop_dump!(s1, "http://10.0.0.1:8000");
    drop_dump!(s2, "http://10.0.0.2:8000");
    drop_dump!(s3, "http://10.0.0.3:8000");
    drop_dump!(s4, "http://10.0.0.4:8000");
    drop_dump!(t1, "http://10.0.0.5:8000");
    drop_dump!(t2, "http://10.0.0.6:8000");

    // While this would be better as a simple lambda function, when an assert
    // pops within we only see the line number of the asserting statement in the
    // lambda and all that's available in RUST_BACKTRACE=1 is a pile of useless
    // tokio noise.
    macro_rules! assert_peer_count {
        ($client:expr, $count:expr) => {{
            println_nopipe!(
                "ensure {} has {} peers",
                stringify!($client),
                $count
            );
            assert_client_state!(&$client, peer_count(&$client), $count);
        }};
    }

    macro_rules! assert_peer_counts {
        ($c:expr) => {{
            assert_peer_count!(s1, $c.s1);
            assert_peer_count!(s2, $c.s2);
            assert_peer_count!(s3, $c.s3);
            assert_peer_count!(s4, $c.s4);
            assert_peer_count!(t1, $c.t1);
            assert_peer_count!(t2, $c.t2);
        }};
    }

    macro_rules! assert_peer_reach {
        ($client:expr, $reach:expr) => {{
            println_nopipe!(
                "ensure {} has imported prefixes {:?}",
                stringify!($client),
                $reach
            );
            assert_client_state!(
                &$client,
                async {
                    $client.get_prefixes().await.map(|x| {
                        x.values()
                            .flatten()
                            .map(|route| route.destination)
                            .collect::<BTreeSet<_>>()
                    })
                },
                $reach
            );
        }};
    }

    macro_rules! assert_reach {
        ($r:expr) => {{
            assert_peer_reach!(s1, $r.s1.clone());
            assert_peer_reach!(s2, $r.s2.clone());
            assert_peer_reach!(s3, $r.s3.clone());
            assert_peer_reach!(s4, $r.s4.clone());
            assert_peer_reach!(t1, $r.t1.clone());
            assert_peer_reach!(t2, $r.t2.clone());
        }};
    }

    macro_rules! assert_nexthops_are_peers {
        ($client:expr) => {{
            let pfx_nexthops =
                $client.get_prefixes().await.expect("get prefixes");
            let peers = $client
                .get_peers()
                .await
                .expect("get peers")
                .values()
                .map(|x| x.addr.to_string())
                .collect::<Vec<_>>();

            for p in pfx_nexthops.keys() {
                assert!(peers.contains(p), "nexthop {p} is not a peer");
            }
        }};
    }

    macro_rules! assert_all_nexthops_are_peers {
        () => {{
            assert_nexthops_are_peers!(s1);
            assert_nexthops_are_peers!(s2);
            assert_nexthops_are_peers!(s3);
            assert_nexthops_are_peers!(s4);
            assert_nexthops_are_peers!(t1);
            assert_nexthops_are_peers!(t2);
        }};
    }

    //
    // Initialize announcements for each server peer
    //

    let s1_origin: Vec<Ipv6Net> = [ip6_net!("fd00:1::/64")].into();
    let s2_origin: Vec<Ipv6Net> = [ip6_net!("fd00:2::/64")].into();
    let s3_origin: Vec<Ipv6Net> = [ip6_net!("fd00:3::/64")].into();
    let s4_origin: Vec<Ipv6Net> = [ip6_net!("fd00:4::/64")].into();
    let t1_origin: Vec<Ipv6Net> = s1_origin
        .clone()
        .into_iter()
        .chain(s2_origin.clone())
        .collect();
    let t2_origin: Vec<Ipv6Net> = s3_origin
        .clone()
        .into_iter()
        .chain(s4_origin.clone())
        .collect();

    s1.advertise_prefixes(&s1_origin).await?;
    s2.advertise_prefixes(&s2_origin).await?;
    s3.advertise_prefixes(&s3_origin).await?;
    s4.advertise_prefixes(&s4_origin).await?;

    //
    // Starting out we should have just the backplane peers.
    //

    assert_peer_counts!(PeerCounts::default().server(1).transit(2));

    //
    // Specifying two external peers should result in two additional peers for
    // each transit router and no changes for the number of server router peers.
    //

    // The address objects for each qsfp on each switch in the test environment.
    const QSFP0: &str = "tfportqsfp0_0/v6";
    const QSFP1: &str = "tfportqsfp1_0/v6";

    let ext_peers_both = ExternalPeers {
        address_objects: [QSFP0, QSFP1].map(String::from).into(),
    };
    t1.set_external_peers(&ext_peers_both).await?;
    t2.set_external_peers(&ext_peers_both).await?;
    assert_peer_counts!(PeerCounts::default().server(1).transit(4));

    //
    // Going down to the 1st peer should result in three peering sessions
    // per transit router. Note in the model above that qsfp0/qsfp1 are cross
    // connected between the two transit routers. Here we are connecting
    // swA/qsfp0 <-> swB/qsfp1
    //

    let ext_peers_qsfp0 = ExternalPeers {
        address_objects: [QSFP0].map(String::from).into(),
    };
    let ext_peers_qsfp1 = ExternalPeers {
        address_objects: [QSFP1].map(String::from).into(),
    };
    t1.set_external_peers(&ext_peers_qsfp0).await?;
    t2.set_external_peers(&ext_peers_qsfp1).await?;
    assert_peer_counts!(PeerCounts::default().server(1).transit(3));

    //
    // Go back to full peering and then switch to swA/qsfp1 <-> swB/qsfp0
    //

    t1.set_external_peers(&ext_peers_both).await?;
    t2.set_external_peers(&ext_peers_both).await?;
    assert_peer_counts!(PeerCounts::default().server(1).transit(4));
    t1.set_external_peers(&ext_peers_qsfp1).await?;
    t2.set_external_peers(&ext_peers_qsfp0).await?;
    assert_peer_counts!(PeerCounts::default().server(1).transit(3));

    //
    // Switch from swA/qsfp1 <-> swB/qsfp0 to swA/qsfp0 <-> swB/qsfp1
    //

    t1.set_external_peers(&ext_peers_qsfp0).await?;
    t2.set_external_peers(&ext_peers_qsfp1).await?;
    assert_peer_counts!(PeerCounts::default().server(1).transit(3));

    //
    // Go to no external peers
    //

    let ext_peers_none = ExternalPeers {
        address_objects: BTreeSet::default(),
    };
    t1.set_external_peers(&ext_peers_none).await?;
    t2.set_external_peers(&ext_peers_none).await?;
    assert_peer_counts!(PeerCounts::default().server(1).transit(2));

    //
    // A bit of combinatorial exercise
    //

    fn peer_is_set(x: &ExternalPeers, s: &str) -> bool {
        x.address_objects.contains(&String::from(s))
    }

    fn expected_external_peerings(
        x: &ExternalPeers,
        y: &ExternalPeers,
    ) -> PeerCounts {
        // The count starts at two because each transit router has two backplane
        // connections that we each expect to have a server peering session on.
        let mut ext_count: usize = 2;

        // A peering is expected when qsfp0 and qsfp1 are configured as an
        // external router in either direction. This is a property of the
        // testing topology (see diagram in test_external_peer_sextet).
        if peer_is_set(x, QSFP0) && peer_is_set(y, QSFP1) {
            ext_count += 1;
        }
        if peer_is_set(x, QSFP1) && peer_is_set(y, QSFP0) {
            ext_count += 1;
        }
        PeerCounts::default().server(1).transit(ext_count)
    }

    let expected_reachable_prefixes =
        |x: &ExternalPeers, y: &ExternalPeers| -> PeerReachablePrefixes {
            let counts = expected_external_peerings(x, y);
            // Servers can always see the originated prefixes of other routers
            // reachable over a single hop transit router path (e.g. in the same
            // rack). Transit routers can always see the originated prefixes of
            // their directly connected server routers.
            let mut reach = PeerReachablePrefixes {
                s1: s2_origin.iter().cloned().collect(),
                s2: s1_origin.iter().cloned().collect(),
                s3: s4_origin.iter().cloned().collect(),
                s4: s3_origin.iter().cloned().collect(),
                t1: t1_origin.iter().cloned().collect(),
                t2: t2_origin.iter().cloned().collect(),
            };
            // If there is any peering between transit routers, each server router
            // should see prefixes originated from the router adjacent to their
            // transit router.
            if counts.t1 > 2 || counts.t2 > 2 {
                // Origins from servers connected to t2 propagating to servers
                // connected to t1.
                reach.s1.extend(&s3_origin);
                reach.s1.extend(&s4_origin);
                reach.s2.extend(&s3_origin);
                reach.s2.extend(&s4_origin);

                // Origins from servers connected to t1 propagating to servers
                // connected to t2.
                reach.s3.extend(&s1_origin);
                reach.s3.extend(&s2_origin);
                reach.s4.extend(&s1_origin);
                reach.s4.extend(&s2_origin);

                // Origins from transit routers propagate to each other.
                reach.t1.extend(&t2_origin);
                reach.t2.extend(&t1_origin);
            }
            reach
        };

    // The choices we have for each switch are none, one or both peers where the
    // one case can be either of the peers.
    let choices = [
        ext_peers_none,
        ext_peers_qsfp0,
        ext_peers_qsfp1,
        ext_peers_both,
    ];

    // Go through 100 rounds. Ideally we'd have more than this, but peer
    // expiration and re-establishment is currently a second or two, so at 100
    // rounds this is already taking over a minute. It'd be nice to have really
    // quick peering timer settings for tests so we can rapidly iterate through
    // sweeps like this.
    const N: usize = 100;
    for i in 0..N {
        println_nopipe!("{i}/{N}");
        let a: usize = rand::random_range(0..choices.len());
        let b: usize = rand::random_range(0..choices.len());

        let x = &choices[a];
        let y = &choices[b];

        t1.set_external_peers(x).await?;
        t2.set_external_peers(y).await?;
        let counts = expected_external_peerings(x, y);
        assert_peer_counts!(counts);

        let xx = t1.get_external_peers().await?.into_inner();
        let yy = t2.get_external_peers().await?.into_inner();

        assert_eq!(x, &xx, "t1 reports different peers than we set");
        assert_eq!(y, &yy, "t2 reports different peers than we set");

        let reach = expected_reachable_prefixes(x, y);
        assert_reach!(reach);

        assert_all_nexthops_are_peers!();
    }

    run_sextet_mcast(zt1, zt2, &s1, &s3, &t1, &t2).await
}

fn underlay_member(port: &str) -> MulticastGroupMember {
    MulticastGroupMember {
        port_id: port.parse().unwrap(),
        link_id: LinkId(0),
        direction: Direction::Underlay,
    }
}

fn external_member(port: &str) -> MulticastGroupMember {
    MulticastGroupMember {
        port_id: port.parse().unwrap(),
        link_id: LinkId(0),
        direction: Direction::External,
    }
}

/// Multicast replication members across the two racks of the sextet.
///
/// Each transit router's `ddmd` programs the underlay members of its own
/// switch from the subscriptions it imports. Subscriptions still cross racks
/// over the qsfp external peers, but only rear ports become members, since
/// members on both parallel qsfp links would circulate replicas between the
/// racks. The two qsfp links are cross-connected, akin to the diagram on
/// `test_external_peer_sextet`.
///
/// ```text
///          rack A                                        rack B
///   s1 ---- rear0 [t1] qsfp0 ------------------ qsfp1 [t2] rear0 ---- s3
///                      qsfp1 ------------------ qsfp0
/// ```
///
/// This test checks cross-rack subscriptions and local replication membership.
/// Cross-rack underlay replication remains unsupported until inter-rack
/// replication prevents cycles.
///
/// 1. Peer t1/qsfp0 <-> t2/qsfp1 only, and s1 subscribes. t1 programs rear0;
///    t2 imports the subscription over qsfp1 but doesn't program anything.
/// 2. s3 subscribes. Each switch imports the other rack's subscription over
///    qsfp and programs only its own rear0.
/// 3. Move the peering to t1/qsfp1 <-> t2/qsfp0. The imports follow the link;
///    both switches stay at rear0.
/// 4. Peer over both links. Each switch imports the other rack over two next
///    hops, a case that would cause looping with qsfp members, and stays at
///    rear0.
/// 5. Drop back to t1/qsfp0 <-> t2/qsfp1. Each switch loses only the dropped
///    link's import, remaining at rear0.
/// 6. s3 withdraws. t1 keeps rear0 and t2 drains to empty membership.
/// 7. s1 withdraws. t2 drops its import, and t1 keeps only its `External`
///    member.
async fn run_sextet_mcast(
    zt1: &RouterZone<'_>,
    zt2: &RouterZone<'_>,
    s1: &Client,
    s3: &Client,
    t1: &Client,
    t2: &Client,
) -> Result<()> {
    const QSFP0: &str = "tfportqsfp0_0/v6";
    const QSFP1: &str = "tfportqsfp1_0/v6";
    let external_peers = |aobjs: &[&str]| ExternalPeers {
        address_objects: aobjs.iter().map(|x| x.to_string()).collect(),
    };

    //
    // Nexus creates each underlay group before subscriptions arrive.
    // Each switch gets its own copy of the group.
    //

    let origin = MulticastOrigin::new(
        "233.252.0.2".parse().unwrap(),
        "ff04::200".parse().unwrap(),
        Vni::try_from(MULTICAST_VNI).unwrap(),
        None,
    )
    .unwrap();
    let rear0 = [underlay_member("rear0")];
    let t1_external = [external_member("qsfp0")];
    let t1_members = [rear0[0].clone(), t1_external[0].clone()];

    // Nexus-owned `External` member on t1, which ddmd must never remove.
    let group_t1 = create_multicast_underlay_group_with(
        zt1,
        origin.underlay_group().into(),
        &t1_external,
    )?;
    let group_t2 =
        create_multicast_underlay_group(zt2, origin.underlay_group().into())?;

    //
    // Peer swA/qsfp0 <-> swB/qsfp1 only, then subscribe s1. t1 learns the
    // subscription from s1 on rear0 and redistributes it to t2, which imports
    // it over qsfp1. t2 has no local subscriber and leaves its group empty.
    //

    t1.set_external_peers(&external_peers(&[QSFP0])).await?;
    t2.set_external_peers(&external_peers(&[QSFP1])).await?;

    s1.advertise_multicast_groups(&vec![origin.clone()]).await?;
    assert_multicast_imports!(t1, [("tfportrear0_0", origin)]);
    assert_multicast_imports!(t2, [("tfportqsfp1_0", origin)]);
    wait_for_multicast_members(zt1, &group_t1, &t1_members)?;
    wait_for_multicast_members(zt2, &group_t2, &[])?;

    println_nopipe!("sextet multicast remote import passed");

    //
    // A 2nd subscriber in rack B provides each switch with a local rear member.
    // Each switch also imports the other rack's subscription over qsfp, and the
    // exact wait on t2 fails if that import resolves to a qsfp member.
    //

    s3.advertise_multicast_groups(&vec![origin.clone()]).await?;
    assert_multicast_imports!(
        t1,
        [("tfportrear0_0", origin), ("tfportqsfp0_0", origin)]
    );
    assert_multicast_imports!(
        t2,
        [("tfportrear0_0", origin), ("tfportqsfp1_0", origin)]
    );
    wait_for_multicast_members(zt2, &group_t2, &rear0)?;

    println_nopipe!("sextet multicast subscribers in both racks passed");

    //
    // Switch to swA/qsfp1 <-> swB/qsfp0. Shutting down the old external peer
    // expires its routes, and the imports move to the new link while ddmd
    // programs only rear0 on both switches.
    //

    t1.set_external_peers(&external_peers(&[QSFP1])).await?;
    t2.set_external_peers(&external_peers(&[QSFP0])).await?;
    assert_multicast_imports!(
        t1,
        [("tfportrear0_0", origin), ("tfportqsfp1_0", origin)]
    );
    assert_multicast_imports!(
        t2,
        [("tfportrear0_0", origin), ("tfportqsfp0_0", origin)]
    );

    println_nopipe!("sextet multicast external link move passed");

    //
    // Peer over both links. Each switch now learns the other rack's
    // subscriber over two nexthops. With qsfp members, replicas would cycle
    // between the racks here, so ddmd still programs only rear0.
    //

    let both = external_peers(&[QSFP0, QSFP1]);
    t1.set_external_peers(&both).await?;
    t2.set_external_peers(&both).await?;
    for client in [t1, t2] {
        assert_multicast_imports!(
            client,
            [
                ("tfportrear0_0", origin),
                ("tfportqsfp0_0", origin),
                ("tfportqsfp1_0", origin),
            ]
        );
    }
    wait_for_multicast_members(zt1, &group_t1, &t1_members)?;
    wait_for_multicast_members(zt2, &group_t2, &rear0)?;

    println_nopipe!("sextet multicast both external links passed");

    t1.set_external_peers(&external_peers(&[QSFP0])).await?;
    t2.set_external_peers(&external_peers(&[QSFP1])).await?;
    assert_multicast_imports!(
        t1,
        [("tfportrear0_0", origin), ("tfportqsfp0_0", origin)]
    );
    assert_multicast_imports!(
        t2,
        [("tfportrear0_0", origin), ("tfportqsfp1_0", origin)]
    );
    wait_for_multicast_members(zt1, &group_t1, &t1_members)?;
    wait_for_multicast_members(zt2, &group_t2, &rear0)?;

    println_nopipe!("sextet multicast partial link loss passed");

    //
    // With only s1 subscribed, t1 holds rear0 and t2 drains its rear0.
    //

    s3.withdraw_multicast_groups(&vec![origin.clone()]).await?;
    assert_multicast_imports!(t1, [("tfportrear0_0", origin)]);
    assert_multicast_imports!(t2, [("tfportqsfp1_0", origin)]);
    wait_for_multicast_members(zt2, &group_t2, &[])?;

    println_nopipe!("sextet multicast remote withdraw passed");

    //
    // Withdrawing the last subscriber drains both groups. The groups remain
    // in DPD for Nexus to delete, and the external peers are cleared for any
    // test that runs after this one.
    //

    s1.withdraw_multicast_groups(&vec![origin]).await?;
    assert_multicast_imports!(t1, []);
    assert_multicast_imports!(t2, []);
    wait_for_multicast_members(zt1, &group_t1, &t1_external)?;
    wait_for_multicast_members(zt2, &group_t2, &[])?;

    t1.set_external_peers(&external_peers(&[])).await?;
    t2.set_external_peers(&external_peers(&[])).await?;

    println_nopipe!("sextet multicast withdraw passed");

    Ok(())
}

async fn prefix_count(c: &Client) -> Result<usize> {
    Ok(c.get_prefixes()
        .await?
        .values()
        .map(|x| x.len())
        .sum::<usize>())
}

async fn peer_count(c: &Client) -> Result<usize> {
    Ok(c.get_peers().await?.len())
}

async fn exchange_peer_count(c: &Client) -> Result<usize> {
    Ok(c.get_peers()
        .await?
        .values()
        .filter(|peer| matches!(peer.status, PeerStatus::Exchange(_)))
        .count())
}

async fn tunnel_endpoint_count(c: &Client) -> Result<usize> {
    Ok(c.get_tunnel_endpoints().await?.len())
}

async fn tunnel_originated_endpoint_count(c: &Client) -> Result<usize> {
    Ok(c.get_originated_tunnel_endpoints().await?.len())
}

async fn multicast_imports(c: &Client) -> Result<MulticastImports> {
    Ok(c.get_multicast_groups()
        .await?
        .iter()
        .map(|imported| {
            (
                imported.if_name.clone(),
                imported.route.origin.clone(),
                imported.route.origin.metric(),
            )
        })
        .collect())
}

async fn multicast_origins(
    c: &Client,
) -> Result<HashSet<(MulticastOrigin, u64)>> {
    Ok(c.get_originated_multicast_groups()
        .await?
        .iter()
        .map(|origin| (origin.clone(), origin.metric()))
        .collect())
}

/// Wait for `client`'s multicast imports to equal what's `expected`.
///
/// Unlike [`assert_multicast_imports!`], this yields between reads, which means
/// it can run alongside another future in the same task.
async fn wait_for_imports(
    name: &str,
    client: &Client,
    expected: &MulticastImports,
    timeout: Duration,
) -> Result<()> {
    tokio::time::timeout(timeout, async {
        while multicast_imports(client).await? != *expected {
            tokio::time::sleep(FAILOVER_POLL_INTERVAL).await;
        }
        Ok(())
    })
    .await
    .map_err(|_| anyhow!("{name} imports did not converge to {expected:#?}"))?
}

/// Fail if any read of `client`'s multicast imports differs from `expected`.
///
/// This signals `ready` after the 1st matching read, and then keeps sampling
/// until `done` arrives.
async fn observe_imports_unchanged(
    name: &str,
    client: &Client,
    expected: &MulticastImports,
    ready: oneshot::Sender<()>,
    mut done: oneshot::Receiver<()>,
) -> Result<()> {
    let mut ready = Some(ready);
    loop {
        let imports = multicast_imports(client).await?;
        if imports != *expected {
            dump_client_state(name, client).await;
            return Err(anyhow!("{name} imports changed: {imports:#?}"));
        }
        if let Some(ready) = ready.take() {
            ready
                .send(())
                .map_err(|_| anyhow!("stopped before {name} was observed"))?;
        }
        match done.try_recv() {
            Ok(()) => return Ok(()),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Closed) => {
                return Err(anyhow!("stopped before {name} observation ended"));
            }
        }
        tokio::time::sleep(FAILOVER_POLL_INTERVAL).await;
    }
}

async fn dump_client_state(name: &str, c: &Client) {
    let dump = async {
        println_nopipe!("{name}:");
        println_nopipe!("peers: {:#?}", c.get_peers().await);
        println_nopipe!("prefixes: {:#?}", c.get_prefixes().await);
        println_nopipe!(
            "originated multicast: {:#?}",
            c.get_originated_multicast_groups().await
        );
        println_nopipe!(
            "imported multicast: {:#?}",
            c.get_multicast_groups().await
        );
    };
    if tokio::time::timeout(Duration::from_secs(10), dump)
        .await
        .is_err()
    {
        eprintln_nopipe!("{name}: diagnostic dump timed out");
    }
}

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, slog::o!())
}
