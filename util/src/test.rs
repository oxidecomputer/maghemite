use std::net::{IpAddr, Ipv6Addr};

use anyhow::Result;
use libnet::{
    connect_simnet_peers, create_simnet_link, enable_v6_link_local,
    get_ipaddr_info, DropIp, DropLink, LinkFlags,
};
use slog::{self, Drain, Logger};

pub struct LabInterface {
    pub name: String,
    pub link: DropLink,
    pub addr: DropIp,
}

impl LabInterface {
    pub fn new(name: &str) -> Result<LabInterface> {
        let link = DropLink {
            info: create_simnet_link(name, LinkFlags::Active)?,
        };
        enable_v6_link_local(name, "v6")?;
        let addr = DropIp {
            info: get_ipaddr_info(&format!("{}/v6", name))?,
        };
        Ok(LabInterface {
            name: name.into(),
            link,
            addr,
        })
    }
    pub fn v6addr(&self) -> Option<Ipv6Addr> {
        match self.addr.info.addr {
            IpAddr::V6(a) => Some(a),
            _ => None,
        }
    }
}

pub fn testlab_x2(name: &str) -> Result<Vec<LabInterface>> {
    let if0 = LabInterface::new(&format!("test_{}_sim0", name))?;
    let if1 = LabInterface::new(&format!("test_{}_sim1", name))?;
    connect_simnet_peers(&if0.link.handle(), &if1.link.handle())?;

    Ok(vec![if0, if1])
}

pub fn testlab_1x2(name: &str) -> Result<Vec<LabInterface>> {
    let if0 = LabInterface::new(&format!("test_{}_sim0", name))?;
    let if1 = LabInterface::new(&format!("test_{}_sim1", name))?;
    let if2 = LabInterface::new(&format!("test_{}_sim2", name))?;
    let if3 = LabInterface::new(&format!("test_{}_sim3", name))?;
    connect_simnet_peers(&if0.link.handle(), &if1.link.handle())?;
    connect_simnet_peers(&if2.link.handle(), &if3.link.handle())?;

    Ok(vec![if0, if1, if2, if3])
}

pub fn logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain)
        .chan_size(0x2000)
        .build()
        .fuse();
    slog::Logger::root(drain, slog::o!())
}
