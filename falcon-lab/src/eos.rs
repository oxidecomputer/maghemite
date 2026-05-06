//! Arista EOS machinery

#![allow(dead_code)]

use crate::linux::LinuxNode;
use anyhow::{Context, Result, anyhow};
use colored::Colorize;
use libfalcon::{NodeRef, Runner};
use oxnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;
use slog::info;
use std::collections::HashMap;
use std::net::IpAddr;

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

    /// Freeze the ceos container. BFD packets stop being processed without
    /// tearing down running-config, so `unpause` restores the session.
    pub async fn pause(&self, d: &Runner) -> Result<()> {
        info!(d.log, "{}: pausing ceos", self.name(d));
        d.exec(self.0, "docker pause ceos").await?;
        Ok(())
    }

    pub async fn unpause(&self, d: &Runner) -> Result<()> {
        info!(d.log, "{}: unpausing ceos", self.name(d));
        d.exec(self.0, "docker unpause ceos").await?;
        Ok(())
    }

    /// Query ceos for the local status of a BFD session to `peer`. Returns
    /// `true` iff EOS reports any per-interface peerStats entry under this
    /// peer with status `up`. The nested shape is:
    ///   vrfs.<vrf>.ipv4Neighbors.<peer>.peers.<iface>.types.normal.peerStats.<local>.status
    pub async fn bfd_peer_up(&self, d: &Runner, peer: IpAddr) -> Result<bool> {
        let output = self.shell(d, "show bfd peers | json").await?;
        let resp: EosBfdResponse = serde_json::from_str(&output)
            .context("parse eos bfd peers json")?;
        let key = peer.to_string();
        for vrf in resp.vrfs.values() {
            let neighbors = match peer {
                IpAddr::V4(_) => &vrf.ipv4_neighbors,
                IpAddr::V6(_) => &vrf.ipv6_neighbors,
            };
            let Some(neighbor) = neighbors.get(&key) else {
                continue;
            };
            for if_peer in neighbor.peers.values() {
                let Some(normal) = if_peer.types.normal.as_ref() else {
                    continue;
                };
                for stats in normal.peer_stats.values() {
                    if stats.status.eq_ignore_ascii_case("up") {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
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

/// Subset of `show bfd peers | json` output. Neighbor keys are raw IP
/// strings; we compare after normalizing via `IpAddr::to_string()`. The
/// schema is deeply nested:
/// `vrfs.<vrf>.ipv[46]Neighbors.<peer>.peers.<iface>.types.normal.peerStats.<local>.status`.
#[derive(Debug, Deserialize)]
pub struct EosBfdResponse {
    pub vrfs: HashMap<String, EosBfdVrf>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EosBfdVrf {
    #[serde(default)]
    pub ipv4_neighbors: HashMap<String, EosBfdNeighbor>,
    #[serde(default)]
    pub ipv6_neighbors: HashMap<String, EosBfdNeighbor>,
}

#[derive(Debug, Deserialize)]
pub struct EosBfdNeighbor {
    #[serde(default)]
    pub peers: HashMap<String, EosBfdIfPeer>,
}

#[derive(Debug, Deserialize)]
pub struct EosBfdIfPeer {
    pub types: EosBfdTypes,
}

#[derive(Debug, Deserialize)]
pub struct EosBfdTypes {
    #[serde(default)]
    pub normal: Option<EosBfdNormal>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EosBfdNormal {
    pub peer_stats: HashMap<String, EosBfdStats>,
}

#[derive(Debug, Deserialize)]
pub struct EosBfdStats {
    pub status: String,
}
