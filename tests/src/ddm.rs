// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Result};
use ddm_admin_client::types::TunnelOrigin;
use ddm_admin_client::Client;
use slog::{Drain, Logger};
use std::env;
use std::net::Ipv6Addr;
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

const ZONE_BRAND: &str = "sparse";

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
        let softnpu_mount = format!("/tmp/softnpu/{}", testname);
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
            &format!("tests/conf/softnpu-{}.toml", self.testname),
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
}

impl Drop for SoftnpuZone<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.zone.zexec("pkill softnpu") {
            eprintln!("failed to stop softnpu: {}", e);
        }
        if let Err(e) = self.zfs.copy_from_zone(
            &self.zone.name,
            "opt/softnpu.log",
            &format!("/work/{}-softnpu.log", self.zone.name),
        ) {
            eprintln!(
                "failed to copy zone log file for {}: {}",
                self.zone.name, e,
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
}

impl<'a> RouterZone<'a> {
    fn server(
        name: &str,
        zfs: &'a Zfs,
        mgmt: &'a str,
        rtr_ifx: &[&'a str],
    ) -> Result<Self> {
        Self::new(name, zfs, mgmt, rtr_ifx, false, "")
    }

    fn transit(
        name: &str,
        zfs: &'a Zfs,
        mgmt: &'a str,
        rtr_ifx: &[&'a str],
        testname: &str,
    ) -> Result<Self> {
        Self::new(name, zfs, mgmt, rtr_ifx, true, testname)
    }

    fn new(
        name: &str,
        zfs: &'a Zfs,
        mgmt: &'a str,
        rtr_ifx: &[&'a str],
        transit: bool,
        testname: &str,
    ) -> Result<Self> {
        let mut ifx = vec![mgmt];
        ifx.extend_from_slice(rtr_ifx);

        let fs = if transit {
            let softnpu_mount = format!("/tmp/softnpu/{}", testname);
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
        })
    }

    fn stop_router(&self) -> Result<String> {
        self.zone.zexec("pkill ddmd")
    }

    fn start_router(&self) -> Result<()> {
        let addrs = self.ifx[1..]
            .iter()
            .map(|x| format!("-a {}/v6", x))
            .collect::<Vec<String>>()
            .join(" ");

        let ddm = "/opt/ddmd";
        let extra_args = format!(
            "--rack-uuid {} --sled-uuid {}",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );

        if self.transit {
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
            self.zone.zexec(
                "svccfg -s dendrite setprop config/port_config = /opt/dpd-ports.toml")?;
            self.zone.zexec(&format!(
                "svccfg -s dendrite setprop config/rear_ports = {}",
                self.ifx.len() - 1
            ))?;
            self.zone.zexec("svcadm refresh dendrite:default")?;
            self.zone.zexec("svcadm enable dendrite:default")?;
            // wait for dendrite to come up
            println!("wait 10s for dendrite to come up ...");
            sleep(Duration::from_secs(10));
            self.zone
                .zexec("svccfg -s tfport setprop config/pkt_source = none")?;
            self.zone
                .zexec("svccfg -s tfport setprop config/flags = --sync-only")?;
            self.zone.zexec("svcadm refresh tfport:default")?;
            self.zone.zexec("svcadm enable tfport")?;
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
        println!("running zone {} setup", self.zone.name);

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

        for ifx in &self.ifx[1..] {
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
            println!("waiting 3s for copy of files to zone to complete ...");
            sleep(Duration::from_secs(3));
        }

        self.zfs.copy_bin_to_zone(&self.zone.name, "ddmd")?;
        self.zfs.copy_bin_to_zone(&self.zone.name, "ddmadm")?;

        self.start_router()?;

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
            eprintln!("failed to stop ddmd: {}", e);
        }
        if let Err(e) = self.zfs.copy_from_zone(
            &self.zone.name,
            "opt/ddmd.log",
            &format!("/work/{}.log", self.zone.name),
        ) {
            eprintln!(
                "failed to copy zone log file for {}: {}",
                self.zone.name, e,
            );
        }
        if self.transit {
            if let Err(e) = self.zfs.copy_from_zone(
                &self.zone.name,
                "var/svc/log/system-illumos-dendrite:default.log",
                &format!("/work/{}-dpd.log", self.zone.name),
            ) {
                eprintln!(
                    "failed to copy zone dpd log file for {}: {}",
                    self.zone.name, e,
                );
            }
        }
    }
}

macro_rules! run_topo {
    ($fn:expr) => {
        if env::var("TEST_INTERACTIVE").is_err() {
            $fn
        } else {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
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

    println!("start zone s1");
    let s1 = RouterZone::server("s1.trio", &zfs, &mg2.name, &[&sl0_sw0.end_a])?;
    println!("start zone s2");
    let s2 = RouterZone::server("s2.trio", &zfs, &mg3.name, &[&sl1_sw1.end_a])?;
    println!("start zone t1");
    let t1 = RouterZone::transit(
        "t1.trio",
        &zfs,
        &mg1.name,
        &[&tf0_sr0.end_a, &tf1_sr1.end_a],
        "trio",
    )?;

    println!("waiting for zones to come up");
    sleep(Duration::from_secs(10));

    sidecar.setup()?;
    s1.setup(1)?;
    s2.setup(2)?;
    t1.setup(3)?;

    run_topo!(run_trio_tests(&s1, &s2, &t1).await?);

    Ok(())
}

async fn run_trio_tests(
    zs1: &RouterZone<'_>,
    zs2: &RouterZone<'_>,
    zt1: &RouterZone<'_>,
) -> Result<()> {
    let log = init_logger();
    let s1 = Client::new("http://10.0.0.1:8000", log.clone());
    let s2 = Client::new("http://10.0.0.2:8000", log.clone());
    let t1 = Client::new("http://10.0.0.3:8000", log.clone());

    // If we never get a response from a server, return 99 as a sentinel value.
    wait_for_eq!(s1.get_peers().await.map_or(99, |x| x.len()), 1);
    wait_for_eq!(s2.get_peers().await.map_or(99, |x| x.len()), 1);
    wait_for_eq!(t1.get_peers().await.map_or(99, |x| x.len()), 2);

    println!("initial peering test passed");

    s1.advertise_prefixes(&vec!["fd00:1::/64".parse().unwrap()])
        .await?;

    wait_for_eq!(prefix_count(&s1).await?, 0);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await?, 1);

    println!("advertise from one passed");

    s2.advertise_prefixes(&vec!["fd00:2::/64".parse().unwrap()])
        .await?;

    wait_for_eq!(prefix_count(&s1).await?, 1);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await?, 2);

    println!("advertise from two passed");

    retry_cmd!(zs1.zexec("ping fd00:2::1"), 1, 10);
    retry_cmd!(zs2.zexec("ping fd00:1::1"), 1, 10);

    println!("connectivity test passed");

    zt1.stop_router()?;
    wait_for_eq!(prefix_count(&s1).await?, 0);
    wait_for_eq!(prefix_count(&s2).await?, 0);
    zt1.start_router()?;
    wait_for_eq!(prefix_count(&s1).await?, 1);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await.unwrap_or(99), 2);
    retry_cmd!(zs1.zexec("ping fd00:2::1"), 1, 10);
    retry_cmd!(zs2.zexec("ping fd00:1::1"), 1, 10);

    println!("transit router restart passed");

    zs1.stop_router()?;
    wait_for_eq!(prefix_count(&s2).await?, 0);
    wait_for_eq!(prefix_count(&t1).await?, 1);
    zs1.start_router()?;

    wait_for_eq!(prefix_count(&s1).await.unwrap_or(99), 1);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await?, 2);

    s1.advertise_prefixes(&vec!["fd00:1::/64".parse().unwrap()])
        .await?;

    wait_for_eq!(prefix_count(&s1).await?, 1);
    wait_for_eq!(prefix_count(&s2).await?, 1);
    wait_for_eq!(prefix_count(&t1).await?, 2);

    retry_cmd!(zs2.zexec("netstat -nr -f inet6"), 1, 10);
    retry_cmd!(zs2.zexec("ndp -na"), 1, 10);
    retry_cmd!(zt1.zexec("/opt/oxide/dendrite/bin/swadm route list"), 1, 10);
    retry_cmd!(zt1.zexec("/opt/oxide/dendrite/bin/swadm arp list"), 1, 10);
    retry_cmd!(zt1.zexec("/opt/oxide/dendrite/bin/swadm addr list"), 1, 10);
    retry_cmd!(
        zs1.zexec("ndp -na; netstat -nr -f inet6; ping -ns fd00:2::1 60 2"),
        1,
        10
    );
    retry_cmd!(zs2.zexec("ping fd00:1::1"), 1, 10);

    println!("server router restart passed");

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

    println!("peer expiration recovery passed");

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

    println!("redundant advertise passed");

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

    println!("tunnel endpoint advertise passed");

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

    println!("redundant tunnel endpoint advertise passed");

    zs1.stop_router()?;
    sleep(Duration::from_secs(5));
    zs1.start_router()?;
    sleep(Duration::from_secs(5));
    let s1 = Client::new("http://10.0.0.1:8000", log.clone());
    wait_for_eq!(tunnel_endpoint_count(&s1).await?, 1);

    println!("tunnel router restart passed");

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

    println!("tunnel endpoint withdraw passed");

    Ok(())
}

#[tokio::test]
async fn test_quartet() -> Result<()> {
    // A quartet of servers in a star topology.
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

    println!("start zone s1");
    let s1 =
        RouterZone::server("s1.quartet", &zfs, &mgs1.name, &[&sl0_sw0.end_a])?;
    println!("start zone s2");
    let s2 =
        RouterZone::server("s2.quartet", &zfs, &mgs2.name, &[&sl1_sw1.end_a])?;
    println!("start zone s3");
    let s3 =
        RouterZone::server("s3.quartet", &zfs, &mgs3.name, &[&sl2_sw2.end_a])?;
    println!("start zone t1");
    let t1 = RouterZone::transit(
        "t1.quartet",
        &zfs,
        &mgt1.name,
        &[&tf0_sr0.end_a, &tf1_sr1.end_a, &tf2_sr2.end_a],
        "quartet",
    )?;

    println!("waiting for zones to come up");
    sleep(Duration::from_secs(10));

    sidecar.setup()?;
    s1.setup(1)?;
    s2.setup(2)?;
    s3.setup(3)?;
    t1.setup(4)?;

    run_topo!(run_quartet_tests(&s1, &s2, &s3, &t1).await?);

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

    println!("initial peering test passed");

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
