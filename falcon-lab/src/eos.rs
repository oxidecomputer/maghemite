//! Arista EOS machinery

#![allow(dead_code)]

use crate::linux::LinuxNode;
use anyhow::{Result, anyhow};
use colored::Colorize;
use libfalcon::{NodeRef, Runner};
use oxnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;
use slog::info;
use std::collections::HashMap;

#[derive(Copy, Clone)]
pub struct EosNode(pub NodeRef);

impl EosNode {
    pub fn name(&self, d: &Runner) -> String {
        d.get_node(self.0).name.clone()
    }

    pub async fn wait_for_init(&self, d: &Runner) -> Result<()> {
        info!(d.log, "waiting for ceos to initialize");
        let mut retries = 60usize;
        loop {
            if retries == 0 {
                break;
            }
            retries = retries.saturating_sub(1);
            let status = d
                .exec(
                    self.0,
                    "docker inspect ceos --format '{{.State.Status}}'",
                )
                .await?;

            let version = self.shell(d, "show version").await?;

            if status.contains("running") && version.contains("Arista cEOSLab")
            {
                return Ok(());
            }
        }
        Err(anyhow!("ceos wait for init timeout"))
    }

    pub async fn shell(&self, d: &Runner, script: &str) -> Result<String> {
        info!(
            d.log,
            "{}: executing eos script {}",
            self.name(d),
            script.dimmed()
        );

        let response = d
            .exec(self.0, &format!("docker exec ceos Cli -c '{script}'"))
            .await?;

        Ok(response)
    }

    pub fn linux(&self) -> LinuxNode {
        LinuxNode(self.0)
    }

    /// Get BGP IPv4 imported prefixes from EOS.
    pub async fn bgp_ipv4_imported(
        &self,
        d: &Runner,
    ) -> Result<BgpIpv4Response> {
        let output = self.shell(d, "show ip bgp | json").await?;
        let response: BgpIpv4Response = serde_json::from_str(&output)?;
        Ok(response)
    }

    /// Get BGP IPv6 imported prefixes from EOS.
    pub async fn bgp_ipv6_imported(
        &self,
        d: &Runner,
    ) -> Result<BgpIpv6Response> {
        let output = self.shell(d, "show ipv6 bgp | json").await?;
        let response: BgpIpv6Response = serde_json::from_str(&output)?;
        Ok(response)
    }
}

/// Minimal representation of `show ip bgp | json` output.
/// Only captures destination prefix and nexthop.
#[derive(Debug, Deserialize)]
pub struct BgpIpv4Response {
    pub vrfs: HashMap<String, BgpIpv4Vrf>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BgpIpv4Vrf {
    pub bgp_route_entries: HashMap<Ipv4Net, BgpIpv4RouteEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BgpIpv4RouteEntry {
    pub bgp_route_paths: Vec<BgpIpv4RoutePath>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BgpIpv4RoutePath {
    #[serde(default)]
    pub next_hop: String,
}

impl BgpIpv4Response {
    /// Returns all imported routes (those with a non-empty nexthop) from all VRFs.
    pub fn all(&self) -> impl Iterator<Item = (&Ipv4Net, &BgpIpv4RoutePath)> {
        self.vrfs.values().flat_map(|vrf| {
            vrf.bgp_route_entries.iter().flat_map(|(prefix, entry)| {
                entry
                    .bgp_route_paths
                    .iter()
                    .filter(|path| !path.next_hop.is_empty())
                    .map(move |path| (prefix, path))
            })
        })
    }
}

/// Minimal representation of `show ipv6 bgp | json` output.
/// Only captures destination prefix and nexthop.
#[derive(Debug, Deserialize)]
pub struct BgpIpv6Response {
    pub vrfs: HashMap<String, BgpIpv6Vrf>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BgpIpv6Vrf {
    pub bgp_route_entries: HashMap<Ipv6Net, BgpIpv6RouteEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BgpIpv6RouteEntry {
    pub bgp_route_paths: Vec<BgpIpv6RoutePath>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BgpIpv6RoutePath {
    #[serde(default)]
    pub next_hop: String,
}

impl BgpIpv6Response {
    /// Returns all imported routes (those with a non-empty nexthop) from all VRFs.
    pub fn all(&self) -> impl Iterator<Item = (&Ipv6Net, &BgpIpv6RoutePath)> {
        self.vrfs.values().flat_map(|vrf| {
            vrf.bgp_route_entries.iter().flat_map(|(prefix, entry)| {
                entry
                    .bgp_route_paths
                    .iter()
                    .filter(|path| !path.next_hop.is_empty())
                    .map(move |path| (prefix, path))
            })
        })
    }
}
