//! Baked BIRD 2 peer: explicit networking, configuration, and CLI assertions.

use anyhow::{Context, Result, ensure};
use libfalcon::{NodeRef, Runner};
use serde::Deserialize;
use std::{
    fs,
    net::{IpAddr, Ipv6Addr},
    time::Duration,
};

use crate::{linux::LinuxNode, wait_for_eq};

mod config;
pub use config::{ASN, BgpLink, MD5_KEY, bgp_config};
use config::{bfd_config, bfd_peers_up, protocol_established, route_imported};

#[derive(Copy, Clone)]
pub struct BirdNode(pub NodeRef);

impl BirdNode {
    /// Match data interfaces by the MAC assigned by Falcon, not Debian's PCI
    /// naming/order (the management NIC must never participate in discovery).
    pub fn data_mac(index: usize) -> String {
        format!("a8:40:25:01:00:{index:02x}")
    }

    async fn checked(&self, d: &Runner, command: &str) -> Result<String> {
        let output = d
            .exec(
                self.0,
                &format!("({command}) && printf '\\nFALCON_BIRD_OK\\n'"),
            )
            .await?;
        ensure!(
            output.lines().any(|l| l.trim() == "FALCON_BIRD_OK"),
            "BIRD guest command failed: {command}: {output}"
        );
        Ok(output)
    }

    pub async fn data_interface(
        &self,
        d: &Runner,
        index: usize,
    ) -> Result<String> {
        #[derive(Deserialize)]
        struct Link {
            ifname: String,
            address: String,
        }
        let output = d.exec(self.0, "ip -j link show").await?;
        let links: Vec<Link> = serde_json::from_str(&output)
            .context("parse BIRD interface inventory")?;
        let mac = Self::data_mac(index);
        let mut matching = links.iter().filter(|l| l.address == mac);
        let interface = matching.next().context("BIRD data MAC missing")?;
        ensure!(matching.next().is_none(), "duplicate BIRD data MAC {mac}");
        ensure!(
            interface
                .ifname
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "unexpected BIRD interface name: {}",
            interface.ifname
        );
        self.checked(d, &format!(
            "sysctl -w net.ipv6.conf.{}.disable_ipv6=0 && ip link set dev {} up",
            interface.ifname, interface.ifname
        )).await?;
        Ok(interface.ifname.clone())
    }

    pub async fn link_local(
        &self,
        d: &Runner,
        interface: &str,
    ) -> Result<Ipv6Addr> {
        #[derive(Deserialize)]
        struct Interface {
            addr_info: Vec<Address>,
        }
        #[derive(Deserialize)]
        struct Address {
            local: Ipv6Addr,
            #[serde(default)]
            tentative: bool,
            #[serde(default)]
            dadfailed: bool,
        }
        for _ in 0..20 {
            let output = d
                .exec(
                    self.0,
                    &format!("ip -j -6 addr show dev {interface} scope link"),
                )
                .await?;
            let interfaces: Vec<Interface> = serde_json::from_str(&output)
                .context("parse BIRD IPv6 addresses")?;
            if let Some(address) =
                interfaces.iter().flat_map(|i| &i.addr_info).find(|a| {
                    a.local.is_unicast_link_local()
                        && !a.tentative
                        && !a.dadfailed
                })
            {
                return Ok(address.local);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        anyhow::bail!(
            "BIRD {interface}: no usable link-local address after DAD"
        )
    }

    pub async fn apply(&self, d: &Runner, config: &str) -> Result<()> {
        let name = format!("{}-bird.conf", d.get_node(self.0).name);
        fs::create_dir_all("cargo-bay")?;
        fs::write(format!("cargo-bay/{name}"), config)?;
        // Clear the marker ourselves as well: even a missing voxel-init must
        // not let an earlier successful invocation masquerade as readiness.
        self.checked(d, &format!(
            "rm -f /run/voxel-bird-ready && /opt/oxide/voxel-init bird --config /opt/cargo-bay/{name} && test -f /run/voxel-bird-ready && birdc show status"
        )).await?;
        Ok(())
    }

    pub async fn setup_bfd(&self, d: &Runner) -> Result<()> {
        let interface = self.data_interface(d, 0).await?;
        self.link_local(d, &interface).await?;
        self.checked(d, &format!(
            "ip addr replace 10.0.4.2/24 dev {interface} && ip -6 addr replace fd00:5::2/64 dev {interface}"
        )).await?;
        self.apply(d, &bfd_config(&interface)).await
    }

    pub async fn stop(&self, d: &Runner) -> Result<()> {
        self.checked(d, "systemctl stop bird && rm -f /run/voxel-bird-ready && test \"$(systemctl is-active bird)\" = inactive").await?;
        Ok(())
    }

    pub async fn start(&self, d: &Runner) -> Result<()> {
        self.checked(d, "systemctl reset-failed bird && systemctl start bird")
            .await?;
        wait_for_eq!(
            self.checked(d, "birdc show status").await.is_ok(),
            true,
            "BIRD control socket ready"
        );
        Ok(())
    }

    pub async fn bgp_established(
        &self,
        d: &Runner,
        index: usize,
    ) -> Result<bool> {
        let name = format!("dut{index}");
        let output = d
            .exec(self.0, &format!("birdc show protocols {name}"))
            .await?;
        Ok(protocol_established(&output, &name))
    }

    pub async fn bgp_imported(
        &self,
        d: &Runner,
        index: usize,
        prefix: &str,
    ) -> Result<bool> {
        let name = format!("dut{index}");
        let table = if prefix.contains(':') {
            "master6"
        } else {
            "master4"
        };
        let output = d.exec(self.0, &format!(
            "birdc 'show route table {table} for {prefix} protocol {name} all'"
        )).await?;
        Ok(route_imported(&output, &name, prefix))
    }

    pub async fn bfd_peers_up(
        &self,
        d: &Runner,
        wanted: &[IpAddr],
    ) -> Result<bool> {
        let output = d.exec(self.0, "birdc show bfd sessions").await?;
        Ok(bfd_peers_up(&output, wanted))
    }

    pub async fn collect_diagnostics(&self, d: &Runner, topo: &str) {
        let name = &d.get_node(self.0).name;
        for (suffix, command) in [
            ("image", "cat /var/voxel-image-ready"),
            ("status", "birdc show status"),
            ("protocols", "birdc show protocols all"),
            ("routes4", "birdc show route table master4 all"),
            ("routes6", "birdc show route table master6 all"),
            ("bfd", "birdc show bfd sessions"),
            ("journal", "journalctl -u bird --no-pager -n 200"),
        ] {
            crate::diagnostics::capture(
                d,
                self.0,
                topo,
                &format!("{name}-{suffix}"),
                command,
            )
            .await;
        }
        LinuxNode(self.0).collect_diagnostics(d, topo, name).await;
    }
}
