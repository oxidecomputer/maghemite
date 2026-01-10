//! illumos machinery

use anyhow::{Result, anyhow};
use libfalcon::{NodeRef, Runner};
use slog::{debug, error};
use std::{net::IpAddr, time::Duration};
use tokio::time::{Instant, sleep};

#[derive(Copy, Clone)]
pub struct IllumosNode(pub NodeRef);

impl IllumosNode {
    pub async fn ip(&self, d: &Runner, addrobj: &str) -> Result<IpAddr> {
        let ip = d
            .exec(self.0, &format!("ipadm show-addr {addrobj} -p -o addr"))
            .await?;
        // handle link locals with percent scopes
        if let Some((ip, _)) = ip.split_once("%") {
            return ip.parse().map_err(|e| anyhow!("invalid ip: {ip}: {e}"));
        }
        let ipnet: oxnet::IpNet =
            ip.parse().map_err(|e| anyhow!("invalid ip: {ip}: {e}"))?;
        Ok(ipnet.addr())
    }

    pub async fn dhcp(&self, d: &Runner, addrobj: &str) -> Result<IpAddr> {
        d.exec(self.0, &format!("ipadm create-addr -T dhcp {addrobj}"))
            .await?;
        d.exec(self.0, "echo 'nameserver 1.1.1.1' > /etc/resolv.conf")
            .await?;
        let mut retries = 10usize;
        loop {
            match self.ip(d, addrobj).await {
                Ok(addr) => return Ok(addr),
                Err(e) => {
                    if retries > 0 {
                        debug!(d.log, "error waiting for dhcp address: {e}");
                        retries = retries.saturating_sub(1);
                        sleep(Duration::from_secs(1)).await;
                    } else {
                        error!(d.log, "error waiting for dhcp address: {e}");
                        break;
                    }
                }
            }
        }
        Err(anyhow!("dhcp timed out"))
    }

    pub async fn addrconf(&self, d: &Runner, addrobj: &str) -> Result<IpAddr> {
        d.exec(self.0, &format!("ipadm create-addr -T addrconf {addrobj}"))
            .await?;
        let mut retries = 10usize;
        loop {
            match self.ip(d, addrobj).await {
                Ok(addr) => return Ok(addr),
                Err(e) => {
                    if retries > 0 {
                        debug!(
                            d.log,
                            "error waiting for addrconf address: {e}"
                        );
                        retries = retries.saturating_sub(1);
                        sleep(Duration::from_secs(1)).await;
                    } else {
                        error!(
                            d.log,
                            "error waiting for addrconf address: {e}"
                        );
                        break;
                    }
                }
            }
        }
        Err(anyhow!("addrconf timed out"))
    }

    pub async fn wait_for_link(
        &self,
        d: &Runner,
        name: &str,
        timeout: Duration,
    ) -> Result<()> {
        let start = Instant::now();
        loop {
            let result = d
                .exec(self.0, &format!("dladm show-link {name} -p -o link"))
                .await
                .map_err(|e| anyhow!("error showing link {name}: {e}"))?;
            if result.as_str() == name {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                break;
            }
            sleep(Duration::from_secs(1)).await
        }
        Err(anyhow!("timeout waiting for link {name}"))
    }
}
