use crate::machinery::*;
use anyhow::{anyhow, Result};
use ddm_admin_client::types::Ipv6Prefix;
use ddm_admin_client::Client;
use slog::{Drain, Logger};
use std::thread::sleep;
use std::time::Duration;
use zone::Zlogin;

struct RouterZone<'a> {
    ifx: Vec<&'a str>,
    zfs: &'a Zfs,
    zone: Zone,
}

impl<'a> RouterZone<'a> {
    fn new(
        name: &str,
        zfs: &'a Zfs,
        mgmt: &'a str,
        rtr_ifx: &[&'a str],
    ) -> Result<Self> {
        let mut ifx = vec![mgmt];
        ifx.extend_from_slice(rtr_ifx);
        let zone = Zone::new(name, zfs, &ifx)?;
        Ok(Self { ifx, zfs, zone })
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

    fn setup(&self, index: u8, transit: bool) -> Result<()> {
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

        let addrs = self.ifx[1..]
            .iter()
            .map(|x| format!("-a {}/v6", x))
            .collect::<Vec<String>>()
            .join(" ");

        let kind = if transit { "transit" } else { "server" };

        self.zfs.copy_bin_to_zone(&self.zone.name, "ddmd")?;
        self.zfs.copy_bin_to_zone(&self.zone.name, "ddmadm")?;
        self.zcmd(&z, &format!("/opt/ddmd --kind {} {} &", kind, addrs))?;
        Ok(())
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
    let s1 = RouterZone::new("s1", &zfs, &mgs1.name, &[&s1_t1.end_a])?;
    println!("start zone s2");
    let s2 = RouterZone::new("s2", &zfs, &mgs2.name, &[&s2_t1.end_a])?;
    println!("start zone t1");
    let t1 =
        RouterZone::new("t1", &zfs, &mgt1.name, &[&s1_t1.end_b, &s2_t1.end_b])?;

    println!("waiting for zones to come up");
    sleep(Duration::from_secs(10));

    s1.setup(1, false)?;
    s2.setup(2, false)?;
    t1.setup(3, true)?;

    run_trio_tests().await?;

    Ok(())
}

macro_rules! wait_for_eq {
    ($lhs:expr, $rhs:expr, $period:expr, $count:expr) => {
        for _ in 0..$count {
            if $lhs == $rhs {
                break;
            }
            sleep(Duration::from_secs($period));
        }
        assert_eq!($lhs, $rhs);
    };
    ($lhs:expr, $rhs:expr) => {
        wait_for_eq!($lhs, $rhs, 1, 10);
    };
}

async fn run_trio_tests() -> Result<()> {
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
        addr: "fd00:1701:d::".parse().unwrap(),
        len: 64,
    }])
    .await?;

    wait_for_eq!(s2.get_prefixes().await?.len(), 0);
    wait_for_eq!(s2.get_prefixes().await?.len(), 1);
    wait_for_eq!(t1.get_prefixes().await?.len(), 1);

    println!("advertise from one passed");

    s2.advertise_prefixes(&vec![Ipv6Prefix {
        addr: "fd00:1701:e::".parse().unwrap(),
        len: 64,
    }])
    .await?;

    wait_for_eq!(s2.get_prefixes().await?.len(), 1);
    wait_for_eq!(s2.get_prefixes().await?.len(), 1);
    wait_for_eq!(t1.get_prefixes().await?.len(), 2);

    println!("advertise from two passed");

    Ok(())
}

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, slog::o!())
}
