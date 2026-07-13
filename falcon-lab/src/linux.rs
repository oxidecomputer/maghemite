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

    /// Capture host-side Linux network state for container-backed routers.
    pub async fn collect_diagnostics(
        &self,
        d: &Runner,
        topo: &str,
        node_name: &str,
    ) {
        for (suffix, cmd) in Self::diagnostic_commands() {
            crate::diagnostics::capture(
                d,
                self.0,
                topo,
                &format!("{node_name}-{suffix}"),
                cmd,
            )
            .await;
        }
    }

    /// Capture container-side Linux network state for container-backed routers.
    ///
    /// Each command is executed separately to keep command runtime bounded and
    /// make timeout/failure diagnostics specific to a single snapshot.
    pub async fn collect_container_diagnostics(
        &self,
        d: &Runner,
        topo: &str,
        node_name: &str,
        container_name: &str,
    ) {
        for (suffix, cmd) in Self::diagnostic_commands() {
            crate::diagnostics::capture(
                d,
                self.0,
                topo,
                &format!("{node_name}-{container_name}-{suffix}"),
                &format!("docker exec {container_name} {cmd}"),
            )
            .await;
        }
    }

    fn diagnostic_commands() -> [(&'static str, &'static str); 5] {
        [
            ("ip-link", "ip -d -s link show"),
            ("ip-addr", "ip -d -s addr show"),
            ("ip-neigh", "ip -d -s neigh show"),
            ("ip-nexthop", "ip -d -s nexthop show"),
            ("ip-route", "ip -d -s route show table all"),
        ]
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
