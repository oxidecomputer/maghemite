use crate::machinery::*;
use crate::wait_for_eq;
use anyhow::{anyhow, Result};
use ddm_admin_client::types::Ipv6Prefix;
use ddm_admin_client::Client;
use slog::{Drain, Logger};
use std::net::Ipv6Addr;
use std::thread::sleep;
use std::time::Duration;
use zone::Zlogin;

struct RouterZone<'a> {
    ifx: Vec<&'a str>,
    zfs: &'a Zfs,
    zone: Zone,
    transit: bool,
}

impl<'a> RouterZone<'a> {
    fn server(
        name: &str,
        zfs: &'a Zfs,
        mgmt: &'a str,
        rtr_ifx: &[&'a str],
    ) -> Result<Self> {
        Self::new(name, zfs, mgmt, rtr_ifx, false)
    }

    fn transit(
        name: &str,
        zfs: &'a Zfs,
        mgmt: &'a str,
        rtr_ifx: &[&'a str],
    ) -> Result<Self> {
        Self::new(name, zfs, mgmt, rtr_ifx, true)
    }

    fn new(
        name: &str,
        zfs: &'a Zfs,
        mgmt: &'a str,
        rtr_ifx: &[&'a str],
        transit: bool,
    ) -> Result<Self> {
        let mut ifx = vec![mgmt];
        ifx.extend_from_slice(rtr_ifx);
        let zone = Zone::new(name, zfs, &ifx)?;
        Ok(Self {
            ifx,
            zfs,
            zone,
            transit,
        })
    }

    fn zcmd(&self, z: &Zlogin, cmd: &str) -> Result<String> {
        println!("[{}] {}", self.zone.name, cmd);
        match z.exec_blocking(cmd) {
            Ok(out) => {
                println!("{}", out);
                Ok(out)
            }
            Err(e) => {
                println!("{}", e);
                Err(anyhow!("{}", e))
            }
        }
    }

    fn zexec(&self, cmd: &str) -> Result<String> {
        let z = Zlogin::new(&self.zone.name);
        self.zcmd(&z, cmd)
    }

    fn stop_router(&self) -> Result<String> {
        self.zexec("pkill ddmd")
    }

    fn start_router(&self) -> Result<()> {
        let addrs = self.ifx[1..]
            .iter()
            .map(|x| format!("-a {}/v6", x))
            .collect::<Vec<String>>()
            .join(" ");

        let kind = if self.transit { "transit" } else { "server" };
        self.zexec(&format!(
            "{} /opt/ddmd --kind {} {} &> /opt/ddmd.log &",
            "RUST_LOG=trace RUST_BACKTRACE=1", kind, addrs
        ))?;
        Ok(())
    }

    fn setup(&self, index: u8) -> Result<()> {
        println!("running zone {} setup", self.zone.name);

        let z = Zlogin::new(&self.zone.name);
        while !self.zcmd(&z, "svcs milestone/network")?.contains("online") {
            sleep(Duration::from_secs(1));
        }
        self.zcmd(&z, "dladm")?;
        self.zcmd(
            &z,
            &format!(
                "ipadm create-addr -t -T static -a 10.0.0.{}/24 {}/v4",
                index, self.ifx[0],
            ),
        )?;

        for ifx in &self.ifx[1..] {
            self.zcmd(
                &z,
                &format!("ipadm create-addr -t -T addrconf {}/v6", ifx),
            )?;
        }

        self.zcmd(
            &z,
            &format!(
                "ipadm create-addr -t -T static -a fd00:{}::1/64 lo0/u6",
                index,
            ),
        )?;

        if self.transit {
            self.zcmd(&z, "routeadm -e ipv6-forwarding")?;
            self.zcmd(&z, "routeadm -u")?;
        }

        self.zfs.copy_bin_to_zone(&self.zone.name, "ddmd")?;
        self.zfs.copy_bin_to_zone(&self.zone.name, "ddmadm")?;

        self.start_router()?;

        Ok(())
    }
}

impl<'a> Drop for RouterZone<'a> {
    fn drop(&mut self) {
        if let Err(e) = self.zexec("pkill ddmd") {
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
    }
}

#[tokio::test]
async fn test_trio() -> Result<()> {
    // A trio. Two server routers and one transit router.
    //
    //   +----+  +----+  +----+
    //   | s1 |--| t1 |--| s2 |     zones
    //   +----+  +----+  +----+
    //     |       |       |
    //   +--------------------+
    //   |        mgmt        |     etherstub
    //   +--------------------+
    //

    let s1_t1 = SimnetLink::new("s1t1", "t1s1")?;
    let s2_t1 = SimnetLink::new("s2t1", "t1s2")?;

    let mgmt0 = Etherstub::new("mgmt0")?;

    let mg0 = Vnic::new("mg0", &mgmt0.name)?;
    let mgs1 = Vnic::new("mgs1", &mgmt0.name)?;
    let mgs2 = Vnic::new("mgs2", &mgmt0.name)?;
    let mgt1 = Vnic::new("mgt1", &mgmt0.name)?;

    let _mgip = Ip::new("10.0.0.254/24", &mg0.name, "test")?;

    let zfs = Zfs::new("mgtest")?;

    println!("start zone s1");
    let s1 = RouterZone::server("s1", &zfs, &mgs1.name, &[&s1_t1.end_a])?;
    println!("start zone s2");
    let s2 = RouterZone::server("s2", &zfs, &mgs2.name, &[&s2_t1.end_a])?;
    println!("start zone t1");
    let t1 = RouterZone::transit(
        "t1",
        &zfs,
        &mgt1.name,
        &[&s1_t1.end_b, &s2_t1.end_b],
    )?;

    println!("waiting for zones to come up");
    sleep(Duration::from_secs(10));

    s1.setup(1)?;
    s2.setup(2)?;
    t1.setup(3)?;

    run_trio_tests(&s1, &s2, &t1).await?;

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

    s1.advertise_prefixes(&vec![Ipv6Prefix {
        addr: "fd00:1::".parse().unwrap(),
        len: 64,
    }])
    .await?;

    wait_for_eq!(s1.get_prefixes().await?.len(), 0);
    wait_for_eq!(s2.get_prefixes().await?.len(), 1);
    wait_for_eq!(t1.get_prefixes().await?.len(), 1);

    println!("advertise from one passed");

    s2.advertise_prefixes(&vec![Ipv6Prefix {
        addr: "fd00:2::".parse().unwrap(),
        len: 64,
    }])
    .await?;

    wait_for_eq!(s1.get_prefixes().await?.len(), 1);
    wait_for_eq!(s2.get_prefixes().await?.len(), 1);
    wait_for_eq!(t1.get_prefixes().await?.len(), 2);

    println!("advertise from two passed");

    zs1.zexec("ping fd00:2::1")?;
    zs2.zexec("ping fd00:1::1")?;

    println!("connectivity test passed");

    zt1.stop_router()?;
    wait_for_eq!(s1.get_prefixes().await?.len(), 0);
    wait_for_eq!(s2.get_prefixes().await?.len(), 0);
    zt1.start_router()?;
    wait_for_eq!(s1.get_prefixes().await?.len(), 1);
    wait_for_eq!(s2.get_prefixes().await?.len(), 1);
    wait_for_eq!(t1.get_prefixes().await.map_or(99, |x| x.len()), 2);
    zs1.zexec("ping fd00:2::1")?;
    zs2.zexec("ping fd00:1::1")?;

    println!("transit router restart passed");

    zs1.stop_router()?;
    wait_for_eq!(s2.get_prefixes().await?.len(), 0);
    wait_for_eq!(t1.get_prefixes().await?.len(), 1);
    zs1.start_router()?;

    wait_for_eq!(s1.get_prefixes().await.map_or(99, |x| x.len()), 1);
    wait_for_eq!(s2.get_prefixes().await?.len(), 0);
    wait_for_eq!(t1.get_prefixes().await?.len(), 1);

    s1.advertise_prefixes(&vec![Ipv6Prefix {
        addr: "fd00:1::".parse().unwrap(),
        len: 64,
    }])
    .await?;

    wait_for_eq!(s1.get_prefixes().await?.len(), 1);
    wait_for_eq!(s2.get_prefixes().await?.len(), 1);
    wait_for_eq!(t1.get_prefixes().await?.len(), 2);

    zs1.zexec("ping fd00:2::1")?;
    zs2.zexec("ping fd00:1::1")?;

    println!("server router restart passed");

    let peers = t1.get_peers().await?;
    let p0: Ipv6Addr = peers
        .values()
        .next()
        .ok_or(anyhow!("expected transit peer"))?
        .addr;

    t1.expire_peer(&p0).await?;
    wait_for_eq!(s1.get_prefixes().await?.len(), 1);
    wait_for_eq!(s2.get_prefixes().await?.len(), 1);
    wait_for_eq!(t1.get_prefixes().await?.len(), 2);

    s2.withdraw_prefixes(&vec![Ipv6Prefix {
        addr: "fd00:2::".parse().unwrap(),
        len: 64,
    }])
    .await?;

    wait_for_eq!(s1.get_prefixes().await?.len(), 0);
    wait_for_eq!(s2.get_prefixes().await?.len(), 1);
    wait_for_eq!(t1.get_prefixes().await?.len(), 1);

    s2.advertise_prefixes(&vec![Ipv6Prefix {
        addr: "fd00:2::".parse().unwrap(),
        len: 64,
    }])
    .await?;

    wait_for_eq!(s1.get_prefixes().await?.len(), 1);
    wait_for_eq!(s2.get_prefixes().await?.len(), 1);
    wait_for_eq!(t1.get_prefixes().await?.len(), 2);

    println!("peer expiration recovery passed");

    Ok(())
}

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, slog::o!())
}
