//! Linux machinery

#![allow(dead_code)]

use anyhow::{Context, Result};
use libfalcon::{NodeRef, Runner};
use serde::Deserialize;
use std::net::IpAddr;

#[derive(Copy, Clone)]
pub struct LinuxNode(pub NodeRef);

impl LinuxNode {
    pub async fn ip(&self, d: &Runner, link: &str) -> Result<Vec<IpAddr>> {
        let json = d.exec(self.0, &format!("ip j addr show {link}")).await?;
        let ipaddr: IpAddrInfo =
            serde_json::from_str(&json).context("parse ip addr json")?;

        Ok(ipaddr.addr_info.iter().map(|x| x.local).collect())
    }
}

#[derive(Deserialize)]
struct IpAddrInfo {
    addr_info: Vec<AddrInfo>,
}

#[derive(Deserialize)]
struct AddrInfo {
    local: IpAddr,
}
