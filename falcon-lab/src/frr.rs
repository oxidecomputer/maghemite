//! FRR machinery

#![allow(dead_code)]

use crate::linux::LinuxNode;
use anyhow::{Context, Result};
use colored::Colorize;
use libfalcon::{NodeRef, Runner};
use oxnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;
use slog::info;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Copy, Clone)]
pub struct FrrNode(pub NodeRef);

impl FrrNode {
    pub fn name(&self, d: &Runner) -> String {
        d.get_node(self.0).name.clone()
    }

    pub async fn enable_daemons(
        &self,
        d: &Runner,
        daemons: &[&str],
    ) -> Result<()> {
        for name in daemons {
            info!(d.log, "{}: enabling frr daemon {name}", self.name(d));
            d.exec(
                self.0,
                &format!("sed -i 's/{name}=no/{name}=yes/g' /etc/frr/daemons"),
            )
            .await?;
        }
        d.exec(self.0, "systemctl restart frr").await?;
        // XXX do better than arbitrary wait
        sleep(Duration::from_secs(5)).await;
        Ok(())
    }

    pub async fn install(&self, d: &Runner) -> Result<()> {
        info!(d.log, "{}: installing frr", self.name(d));
        d.exec(self.0, "apt-get -y update && apt-get -y install frr")
            .await
            .context("apt install frr failed")?;
        Ok(())
    }

    pub fn linux(&self) -> LinuxNode {
        LinuxNode(self.0)
    }

    /// Execute a vtysh command and return the output.
    pub async fn shell(&self, d: &Runner, script: &str) -> Result<String> {
        info!(
            d.log,
            "{}: executing frr script {}",
            self.name(d),
            script.dimmed()
        );
        let args = script
            .lines()
            .map(|l| format!("-c '{l}'"))
            .collect::<Vec<_>>()
            .join(" ");
        let output = d
            .exec(self.0, &format!("vtysh {args}"))
            .await
            .context("vtysh shell failed")?;
        Ok(output)
    }

    /// Get BGP IPv4 imported prefixes from FRR.
    pub async fn bgp_ipv4_imported(
        &self,
        d: &Runner,
    ) -> Result<FrrBgpIpv4Response> {
        let output = self.shell(d, "show ip bgp json").await?;
        let response: FrrBgpIpv4Response = serde_json::from_str(&output)?;
        Ok(response)
    }

    /// Get BGP IPv6 imported prefixes from FRR.
    pub async fn bgp_ipv6_imported(
        &self,
        d: &Runner,
    ) -> Result<FrrBgpIpv6Response> {
        let output = self.shell(d, "show bgp json").await?;
        let response: FrrBgpIpv6Response = serde_json::from_str(&output)?;
        Ok(response)
    }
}

/// Minimal representation of FRR `show ip bgp json` output.
/// Only captures destination prefix and nexthop.
#[derive(Debug, Deserialize)]
pub struct FrrBgpIpv4Response {
    pub routes: HashMap<Ipv4Net, Vec<FrrBgpRoutePath>>,
}

impl FrrBgpIpv4Response {
    /// Returns all imported routes (those with a non-unspecified nexthop) from the response.
    pub fn all(&self) -> impl Iterator<Item = (&Ipv4Net, &FrrBgpNexthop)> {
        self.routes.iter().flat_map(|(prefix, paths)| {
            paths.iter().flat_map(move |path| {
                path.nexthops
                    .iter()
                    .filter(|nh| !nh.ip.is_unspecified())
                    .map(move |nh| (prefix, nh))
            })
        })
    }
}

/// Minimal representation of FRR `show bgp json` output (IPv6).
/// Only captures destination prefix and nexthop.
#[derive(Debug, Deserialize)]
pub struct FrrBgpIpv6Response {
    pub routes: HashMap<Ipv6Net, Vec<FrrBgpRoutePath>>,
}

impl FrrBgpIpv6Response {
    /// Returns all imported routes (those with a non-unspecified nexthop) from the response.
    pub fn all(&self) -> impl Iterator<Item = (&Ipv6Net, &FrrBgpNexthop)> {
        self.routes.iter().flat_map(|(prefix, paths)| {
            paths.iter().flat_map(move |path| {
                path.nexthops
                    .iter()
                    .filter(|nh| !nh.ip.is_unspecified())
                    .map(move |nh| (prefix, nh))
            })
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct FrrBgpRoutePath {
    #[serde(default)]
    pub nexthops: Vec<FrrBgpNexthop>,
}

#[derive(Debug, Deserialize)]
pub struct FrrBgpNexthop {
    pub ip: IpAddr,
}
