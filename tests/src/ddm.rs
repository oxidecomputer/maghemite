use anyhow::{anyhow, Result};
use ddm_admin_client::types::Ipv6Prefix;
use ddm_admin_client::Client;
use slog::{Drain, Logger};
use std::env;
use std::net::Ipv6Addr;
use std::thread::sleep;
use std::time::Duration;
use zone::Zlogin;
use ztest::*;

const ZONE_BRAND: &str = "sparse";

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
        let zone = Zone::new(name, ZONE_BRAND, zfs, &ifx)?;
        Ok(Self {
            ifx,
            zfs,
            zone,
            transit,
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

        let kind = if self.transit { "transit" } else { "server" };
        self.zone.zexec(&format!(
            "{} /opt/ddmd --kind {} {} &> /opt/ddmd.log &",
            "RUST_LOG=trace RUST_BACKTRACE=1", kind, addrs
        ))?;
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
            self.zone.zcmd(&z, "routeadm -e ipv6-forwarding")?;
            self.zone.zcmd(&z, "routeadm -u")?;
        }

        self.zfs.copy_bin_to_zone(&self.zone.name, "ddmd")?;
        self.zfs.copy_bin_to_zone(&self.zone.name, "ddmadm")?;

        self.start_router()?;

        Ok(())
    }
}

impl<'a> std::ops::Deref for RouterZone<'a> {
    type Target = Zone;
    fn deref(&self) -> &Zone {
        &self.zone
    }
}

impl<'a> Drop for RouterZone<'a> {
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
    let s1 = RouterZone::server("trio.s1", &zfs, &mgs1.name, &[&s1_t1.end_a])?;
    println!("start zone s2");
    let s2 = RouterZone::server("trio.s2", &zfs, &mgs2.name, &[&s2_t1.end_a])?;
    println!("start zone t1");
    let t1 = RouterZone::transit(
        "trio.t1",
        &zfs,
        &mgt1.name,
        &[&s1_t1.end_b, &s2_t1.end_b],
    )?;

    println!("waiting for zones to come up");
    sleep(Duration::from_secs(10));

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

#[tokio::test]
async fn test_quartet() -> Result<()> {
    // A quartet of servers in a star topology.
    //
    //               +----+
    //  +------------| s1 |
    //  |            +----+
    //  |               |
    //  |   +----+   +----+   +----+
    //  |   | s2 |---| t1 |---| s3 |
    //  |   +----+   +----+   +----+
    //  |      |        |       |
    //  |    +--------------------+
    //  +----|        mgmt        |     etherstub
    //       +--------------------+

    let s1_t1 = SimnetLink::new("s1t1", "t1s1")?;
    let s2_t1 = SimnetLink::new("s2t1", "t1s2")?;
    let s3_t1 = SimnetLink::new("s3t1", "t1s3")?;

    let mgmt0 = Etherstub::new("mgmt0")?;

    let mg0 = Vnic::new("mg0", &mgmt0.name)?;
    let mgs1 = Vnic::new("mgs1", &mgmt0.name)?;
    let mgs2 = Vnic::new("mgs2", &mgmt0.name)?;
    let mgs3 = Vnic::new("mgs3", &mgmt0.name)?;
    let mgt1 = Vnic::new("mgt1", &mgmt0.name)?;

    let _mgip = Ip::new("10.0.0.254/24", &mg0.name, "test")?;

    let zfs = Zfs::new("mgtest")?;

    println!("start zone s1");
    let s1 =
        RouterZone::server("quartet.s1", &zfs, &mgs1.name, &[&s1_t1.end_a])?;
    println!("start zone s2");
    let s2 =
        RouterZone::server("quartet.s2", &zfs, &mgs2.name, &[&s2_t1.end_a])?;
    println!("start zone s3");
    let s3 =
        RouterZone::server("quartet.s3", &zfs, &mgs3.name, &[&s3_t1.end_a])?;
    println!("start zone t1");
    let t1 = RouterZone::transit(
        "quartet.t1",
        &zfs,
        &mgt1.name,
        &[&s1_t1.end_b, &s2_t1.end_b, &s3_t1.end_b],
    )?;

    println!("waiting for zones to come up");
    sleep(Duration::from_secs(10));

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

    s1.advertise_prefixes(&vec![Ipv6Prefix {
        addr: "fd00:1::".parse().unwrap(),
        len: 64,
    }])
    .await?;

    s3.advertise_prefixes(&vec![Ipv6Prefix {
        addr: "fd00:3::".parse().unwrap(),
        len: 64,
    }])
    .await?;

    // s1/s3 should now have 1 prefixe
    wait_for_eq!(
        s1.get_prefixes()
            .await?
            .values()
            .map(|x| x.len())
            .sum::<usize>(),
        1
    );
    wait_for_eq!(
        s3.get_prefixes()
            .await?
            .values()
            .map(|x| x.len())
            .sum::<usize>(),
        1
    );

    // s3 should be able to ping s1
    zs3.zexec("ping fd00:1::1")?;

    s2.advertise_prefixes(&vec![Ipv6Prefix {
        addr: "fd00:1::".parse().unwrap(),
        len: 64,
    }])
    .await?;

    // s3 should now have 2 prefixes
    wait_for_eq!(
        s3.get_prefixes()
            .await?
            .values()
            .map(|x| x.len())
            .sum::<usize>(),
        2
    );

    s2.withdraw_prefixes(&vec![Ipv6Prefix {
        addr: "fd00:1::".parse().unwrap(),
        len: 64,
    }])
    .await?;

    // s3 should still have 1 prefix left
    wait_for_eq!(
        s3.get_prefixes()
            .await?
            .values()
            .map(|x| x.len())
            .sum::<usize>(),
        1
    );

    // s3 should be able to ping s1 even after s2 withdrew s1's prefix
    zs3.zexec("ping fd00:1::1")?;

    Ok(())
}

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, slog::o!())
}
