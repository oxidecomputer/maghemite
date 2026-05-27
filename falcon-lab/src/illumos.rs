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

    pub async fn staticaddr(
        &self,
        d: &Runner,
        addrobj: &str,
        cidr: &str,
    ) -> Result<IpAddr> {
        let cmd = format!("ipadm create-addr -T static -a {cidr} {addrobj}");
        let out = d.exec(self.0, &cmd).await?;
        ensure_ipadm_ok(&out, &cmd)?;
        self.ip(d, addrobj).await
    }

    pub async fn addrconf(&self, d: &Runner, addrobj: &str) -> Result<IpAddr> {
        let cmd = format!("ipadm create-addr -T addrconf {addrobj}");
        let out = d.exec(self.0, &cmd).await?;
        ensure_ipadm_ok(&out, &cmd)?;
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

    /// Resolve the SMF log file for `svc` via `svcs -L` and return its
    /// contents along with the resolved path. Avoids hard-coding the log file.
    pub async fn svc_log(
        &self,
        d: &Runner,
        svc: &str,
    ) -> Result<(String, String)> {
        let path = d.exec(self.0, &format!("svcs -L {svc}")).await?;
        let path = path.trim();
        if path.is_empty() {
            return Err(anyhow!("`svcs -L {svc}` returned empty path"));
        }
        let contents = d.exec(self.0, &format!("cat {path}")).await?;
        Ok((path.to_string(), contents))
    }

    /// Fetch the full contents of a file on the node.
    pub async fn read_file(&self, d: &Runner, path: &str) -> Result<String> {
        d.exec(self.0, &format!("cat {path}"))
            .await
            .map_err(|e| anyhow!("cat {path}: {e}"))
    }

    /// Capture SMF status plus the standard illumos network-state snapshots
    /// (ipadm / dladm / netstat) for this node. Each lands as its own
    /// `/work/<topo>-<node>-<suffix>.log` artifact.
    pub async fn collect_diagnostics(&self, d: &Runner, topo: &str) {
        let name = d.get_node(self.0).name.clone();
        for (suffix, cmd) in [
            ("svcs-xv", "svcs -xv"),
            ("ipadm", "ipadm show-addr"),
            ("dladm", "dladm show-link"),
            ("netstat", "netstat -nr"),
        ] {
            crate::diagnostics::capture(
                d,
                self.0,
                topo,
                &format!("{name}-{suffix}"),
                cmd,
            )
            .await;
        }
    }
}

/// Treat `ipadm` output as success unless it contains an error line and the
/// error is not an "already assigned / already exists" idempotency case.
/// ipadm prefixes error messages with `ipadm:` and is otherwise silent on
/// success.
fn ensure_ipadm_ok(output: &str, cmd: &str) -> Result<()> {
    let lower = output.to_lowercase();
    if lower.contains("ipadm:") && !lower.contains("already") {
        return Err(anyhow!("'{cmd}' failed: {}", output.trim()));
    }
    Ok(())
}
