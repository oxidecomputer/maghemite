use anyhow::{anyhow, Result};
use libnet::{
    connect_simnet_peers, create_ipaddr, create_simnet_link, create_vnic_link,
    get_ipaddr_info, DropIp, DropLink, Ipv4Prefix, LinkFlags, LinkHandle,
};
use std::net::{IpAddr, Ipv4Addr};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use zone::{Adm, Config, CreationOptions, IpType, Net};

const PFEXEC: &str = "/bin/pfexec";

pub struct SimnetLink {
    pub end_a: String,
    pub end_b: String,
    _link_a: DropLink,
    _link_b: DropLink,
}

impl SimnetLink {
    pub fn new(end_a: &str, end_b: &str) -> Result<Self> {
        let a = create_simnet_link(end_a, LinkFlags::Active)?;
        let b = create_simnet_link(end_b, LinkFlags::Active)?;
        let _link_a = DropLink { info: a.clone() };
        let _link_b = DropLink { info: b.clone() };
        connect_simnet_peers(&LinkHandle::Id(a.id), &LinkHandle::Id(b.id))?;
        Ok(Self {
            end_a: end_a.into(),
            end_b: end_b.into(),
            _link_a,
            _link_b,
        })
    }
}

pub struct Vnic {
    pub name: String,
    _link: DropLink,
}

impl Vnic {
    pub fn new(name: &str, link: &str) -> Result<Self> {
        let link = create_vnic_link(
            name,
            &LinkHandle::Name(link.into()),
            None,
            LinkFlags::Active,
        )?;
        Ok(Self {
            name: name.into(),
            _link: DropLink { info: link },
        })
    }
}

pub struct Etherstub {
    pub name: String,
}

impl Etherstub {
    pub fn new(name: &str) -> Result<Self> {
        std::process::Command::new(PFEXEC)
            .env_clear()
            .arg("dladm")
            .arg("create-etherstub")
            .arg("-t")
            .arg(name)
            .output()?;

        Ok(Etherstub { name: name.into() })
    }
}

impl Drop for Etherstub {
    fn drop(&mut self) {
        if let Err(e) = std::process::Command::new(PFEXEC)
            .env_clear()
            .arg("dladm")
            .arg("delete-etherstub")
            .arg(&self.name)
            .output()
        {
            eprintln!("etherstub delete failed: {}", e);
        }
    }
}

pub struct Ip {
    pub ip: IpAddr,
    _ip: DropIp,
}

impl Ip {
    pub fn new(addr: &str, ifname: &str, name: &str) -> Result<Self> {
        let (addr, mask) =
            addr.split_once('/').ok_or(anyhow!("bad ip address"))?;
        let addr: Ipv4Addr = addr.parse()?;
        let mask: u8 = mask.parse()?;
        let addrname = format!("{}/{}", ifname, name);
        create_ipaddr(&addrname, Ipv4Prefix { addr, mask }.into())?;
        let info = get_ipaddr_info(&addrname)?;
        Ok(Self {
            ip: addr.into(),
            _ip: DropIp { info },
        })
    }
}

pub struct Zfs {
    pub name: String,
}

impl Zfs {
    pub fn new(name: &str) -> Result<Self> {
        std::process::Command::new(PFEXEC)
            .env_clear()
            .arg("zfs")
            .arg("create")
            .arg("-p")
            .arg("-o")
            .arg(&format!("mountpoint=/{}", name))
            .arg(&format!("rpool/{}", name))
            .output()?;
        Ok(Self { name: name.into() })
    }

    pub fn path_for(&self, name: &str) -> PathBuf {
        PathBuf::from(&format!("/{}/{}", self.name, name))
    }

    pub fn copy_from_zone(
        &self,
        name: &str,
        from: &str,
        to: &str,
    ) -> Result<()> {
        let from = format!("/{}/{}/root/{}", self.name, name, from);
        println!("cp {} {}", from, to);
        std::process::Command::new(PFEXEC)
            .env_clear()
            .arg("cp")
            .arg(from)
            .arg(to)
            .output()?;
        Ok(())
    }

    pub fn copy_to_zone(&self, name: &str, from: &str, to: &str) -> Result<()> {
        let to = format!("/{}/{}/root/{}", self.name, name, to);
        println!("cp {} {}", from, to);
        std::process::Command::new(PFEXEC)
            .env_clear()
            .arg("cp")
            .arg(from)
            .arg(to)
            .output()?;
        Ok(())
    }

    pub fn copy_bin_to_zone(&self, name: &str, bin: &str) -> Result<()> {
        let from = match env!("CARGO_WORKSPACE_DIR") {
            "" => format!("target/debug/{}", bin),
            path => format!("{}target/debug/{}", path, bin),
        };
        let to = format!("opt/{}", bin);
        self.copy_to_zone(name, &from, &to)
    }
}

impl Drop for Zfs {
    fn drop(&mut self) {
        if let Err(e) = std::process::Command::new(PFEXEC)
            .env_clear()
            .arg("zfs")
            .arg("destroy")
            .arg("-rf")
            .arg(&format!("rpool/{}", self.name))
            .output()
        {
            eprintln!("zfs drop failed: {}", e);
        }
    }
}

pub struct ZoneConfig {
    pub name: String,
    pub config: Config,
}

impl ZoneConfig {
    pub fn new(name: &str, zfs: &Zfs) -> Self {
        let mut config = Config::create(name, true, CreationOptions::Default);
        config
            .get_global()
            .set_path(zfs.path_for(name))
            .set_autoboot(true)
            .set_brand("sparse")
            .set_ip_type(IpType::Exclusive);
        Self {
            name: name.into(),
            config,
        }
    }
    fn add_phy(&mut self, name: &str) {
        self.add_net(&Net {
            physical: name.into(),
            ..Default::default()
        });
    }
}

impl Deref for ZoneConfig {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl DerefMut for ZoneConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

impl Drop for ZoneConfig {
    fn drop(&mut self) {
        if let Err(e) = self.config.delete(true).run_blocking() {
            eprintln!("zone config drop failed: {}", e);
        }
    }
}

pub struct ZoneInstall {
    pub name: String,
}

impl ZoneInstall {
    pub fn new(name: &str) -> Result<Self> {
        Adm::new(name).install_blocking(&[])?;
        Ok(Self { name: name.into() })
    }
}

impl Drop for ZoneInstall {
    fn drop(&mut self) {
        if let Err(e) = Adm::new(&self.name).uninstall_blocking(true) {
            eprintln!("uninstall zone failed: {}", e);
        }
    }
}

pub struct ZoneBoot {
    pub name: String,
}

impl ZoneBoot {
    pub fn new(name: &str) -> Result<Self> {
        Adm::new(name).boot_blocking()?;
        Ok(Self { name: name.into() })
    }
}

impl Drop for ZoneBoot {
    fn drop(&mut self) {
        if let Err(e) = Adm::new(&self.name).halt_blocking() {
            eprintln!("halt zone failed: {}", e);
        }
    }
}

pub struct Zone {
    pub name: String,
    pub config: Option<ZoneConfig>,
    pub install: Option<ZoneInstall>,
    pub boot: Option<ZoneBoot>,
}

impl Zone {
    pub fn new(name: &str, zfs: &Zfs, phys: &[&str]) -> Result<Self> {
        // init config
        println!("configure zone");
        let mut config = ZoneConfig::new(name, zfs);
        for phy in phys {
            config.add_phy(phy);
        }
        config.run_blocking()?;

        // install zone
        println!("install zone");
        let install = ZoneInstall::new(name)?;

        // boot zone
        println!("boot zone");
        let boot = ZoneBoot::new(name)?;

        Ok(Self {
            name: name.into(),
            config: Some(config),
            install: Some(install),
            boot: Some(boot),
        })
    }
}

impl Drop for Zone {
    fn drop(&mut self) {
        drop(self.boot.take());
        drop(self.install.take());
        drop(self.config.take());
    }
}

#[macro_export]
macro_rules! wait_for_eq {
    ($lhs:expr, $rhs:expr, $period:expr, $count:expr) => {
        let mut ok = false;
        for _ in 0..$count {
            if $lhs == $rhs {
                ok = true;
                break;
            }
            sleep(Duration::from_secs($period));
        }
        if !ok {
            assert_eq!($lhs, $rhs);
        }
    };
    ($lhs:expr, $rhs:expr) => {
        wait_for_eq!($lhs, $rhs, 1, 10);
    };
}
