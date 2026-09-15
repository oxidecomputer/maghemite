// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Result, anyhow};
use client_common::{eprintln_nopipe, println_nopipe};
use ddm_admin_client::Client;
use ddm_api_types_versions::latest::external_peers::ExternalPeers;
use ddm_api_types_versions::latest::net::TunnelOrigin;
use oxnet::Ipv6Net;
use slog::{Drain, Logger};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::Ipv6Addr;
use std::ops::{Deref, DerefMut};
use std::thread::sleep;
use std::time::Duration;
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

const ZONE_BRAND: &str = "omicron1";

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
        self.zone.zexec("pkill ddmd")
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
            "--rack-uuid {} --sled-uuid {} --solicit-interval 20 --expire-threshold 50",
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
                // wait for dendrite to come up
                println_nopipe!("wait 10s for dendrite to come up ...");
                sleep(Duration::from_secs(10));
                self.zone.zexec(
                    "svccfg -s tfport setprop config/pkt_source = none",
                )?;
                self.zone.zexec(
                    "svccfg -s tfport setprop config/flags = --sync-only",
                )?;
                self.zone.zexec("svcadm refresh tfport:default")?;
                self.zone.zexec("svcadm enable tfport")?;
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
async fn test_trio_v3() -> Result<()> {
    test_trio().await
}

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

    // If we never get a response from a server, return 99 as a sentinel value.
    wait_for_eq!(s1.get_peers().await.map_or(99, |x| x.len()), 1);
    wait_for_eq!(s2.get_peers().await.map_or(99, |x| x.len()), 1);
    wait_for_eq!(t1.get_peers().await.map_or(99, |x| x.len()), 2);

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
    _zt1: &RouterZone<'_>,
) -> Result<()> {
    let log = init_logger();
    let s1 = Client::new("http://10.0.0.1:8000", log.clone());
    let s2 = Client::new("http://10.0.0.2:8000", log.clone());
    let s3 = Client::new("http://10.0.0.3:8000", log.clone());
    let t1 = Client::new("http://10.0.0.4:8000", log.clone());

    // If we never get a response from a server, return 99 as a sentinel value.
    wait_for_eq!(s1.get_peers().await.map_or(99, |x| x.len()), 1);
    wait_for_eq!(s2.get_peers().await.map_or(99, |x| x.len()), 1);
    wait_for_eq!(s3.get_peers().await.map_or(99, |x| x.len()), 1);
    wait_for_eq!(t1.get_peers().await.map_or(99, |x| x.len()), 3);

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
    _zt1: &RouterZone<'_>,
    _zt2: &RouterZone<'_>,
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
                    println_nopipe!("{name}:");
                    if let Ok(peers) = c.get_peers().await {
                        println_nopipe!("peers: {peers:#?}");
                    }
                    if let Ok(prefixes) = c.get_prefixes().await {
                        println_nopipe!("prefixes: {prefixes:#?}");
                    }
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
            wait_for_eq!(
                $client.get_peers().await.map(|x| x.len()).ok(),
                Some($count)
            );
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
            wait_for_eq!(
                $client
                    .get_prefixes()
                    .await
                    .map(|x| x
                        .values()
                        .cloned()
                        .into_iter()
                        .flat_map(|x| x
                            .clone()
                            .into_iter()
                            .map(|y| y.destination))
                        .collect::<BTreeSet<_>>())
                    .ok(),
                Some($reach)
            );
        }};
    }

    macro_rules! assert_reach {
        ($r:expr) => {{
            assert_peer_reach!(s1, $r.s1.clone());
            assert_peer_reach!(s2, $r.s2.clone());
            assert_peer_reach!(s3, $r.s3.clone());
            assert_peer_reach!(s4, $r.s4.clone());
        }};
    }

    //
    // Initialize announcements for each server peer
    //

    let s1_origin: Vec<Ipv6Net> = [ip6_net!("fd00:1::/64")].into();
    let s2_origin: Vec<Ipv6Net> = [ip6_net!("fd00:2::/64")].into();
    let s3_origin: Vec<Ipv6Net> = [ip6_net!("fd00:3::/64")].into();
    let s4_origin: Vec<Ipv6Net> = [ip6_net!("fd00:4::/64")].into();

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
    // Going down to the first peer should result in three peering sessions
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
            // rack).
            let mut reach = PeerReachablePrefixes {
                s1: s2_origin.iter().cloned().collect(),
                s2: s1_origin.iter().cloned().collect(),
                s3: s4_origin.iter().cloned().collect(),
                s4: s3_origin.iter().cloned().collect(),
            };
            // If there is any peering between transit routers, each server router
            // should see prefixes originated from the router adjacent to their
            // transit router.
            if counts.t1 > 2 && counts.t2 > 2 {
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
    }

    Ok(())
}

async fn prefix_count(c: &Client) -> Result<usize> {
    Ok(c.get_prefixes()
        .await?
        .values()
        .map(|x| x.len())
        .sum::<usize>())
}

async fn tunnel_endpoint_count(c: &Client) -> Result<usize> {
    Ok(c.get_tunnel_endpoints().await?.len())
}

async fn tunnel_originated_endpoint_count(c: &Client) -> Result<usize> {
    Ok(c.get_originated_tunnel_endpoints().await?.len())
}

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, slog::o!())
}
