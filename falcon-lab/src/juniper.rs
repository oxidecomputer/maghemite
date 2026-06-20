//! Juniper cRPD machinery.

use crate::{diagnostics::ProtocolDiagnostics, linux::LinuxNode};
use anyhow::{Context, Result, anyhow};
use colored::Colorize;
use libfalcon::{NodeRef, Runner};
use serde::Deserialize;
use slog::info;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

const CRPD_CONTAINER: &str = "crpd1";
const CARGO_BAY: &str = "cargo-bay";
const LICENSE_PATH: &str = "falcon-juniper-license.key";
const CONFIG_SUFFIX: &str = "-junos.set";

#[derive(Copy, Clone)]
pub struct JuniperNode(pub NodeRef);

/// Remove non-secret Junos topology configs from previous runs.
///
/// The Junos image's guest-side apply service starts during boot and consumes
/// the first `/opt/cargo-bay/*-junos.set` it sees. CI runs multiple Junos
/// topologies against one cargo-bay, so stale config must be removed before a
/// new Junos VM can boot and observe it.
pub fn clear_staged_routing_configs() -> Result<()> {
    let dir = Path::new(CARGO_BAY);
    if !dir.exists() {
        return Ok(());
    }
    for entry in
        fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("read {} entry", dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.ends_with(CONFIG_SUFFIX) {
            fs::remove_file(&path)
                .with_context(|| format!("remove stale {}", path.display()))?;
        }
    }
    Ok(())
}

impl JuniperNode {
    pub fn name(&self, d: &Runner) -> String {
        d.get_node(self.0).name.clone()
    }

    pub fn linux(&self) -> LinuxNode {
        LinuxNode(self.0)
    }

    async fn exec_step(
        &self,
        d: &Runner,
        step: &str,
        command: &str,
    ) -> Result<String> {
        d.exec(self.0, command)
            .await
            .with_context(|| format!("{step}: {command}"))
    }

    /// Freeze the cRPD container. BFD packets stop being processed without
    /// tearing down committed config, so `unpause` restores the session.
    pub async fn pause(&self, d: &Runner) -> Result<()> {
        info!(d.log, "{}: pausing {CRPD_CONTAINER}", self.name(d));
        self.exec_step(
            d,
            "pause Juniper cRPD container",
            &format!("docker pause {CRPD_CONTAINER}"),
        )
        .await?;
        Ok(())
    }

    pub async fn unpause(&self, d: &Runner) -> Result<()> {
        info!(d.log, "{}: unpausing {CRPD_CONTAINER}", self.name(d));
        self.exec_step(
            d,
            "unpause Juniper cRPD container",
            &format!("docker unpause {CRPD_CONTAINER}"),
        )
        .await?;
        Ok(())
    }

    /// Stage non-secret topology config and verify that the runtime license is
    /// present for the guest-side systemd services to consume.
    pub async fn setup(&self, d: &Runner, routing_config: &str) -> Result<()> {
        // Falcon-lab only stages files. The Junos image is expected to run
        // guest-side systemd services that mount cargo-bay, install the
        // license, and apply `<node>-junos.set`; see falcon-lab/README.md.
        self.stage_routing_config(d, routing_config)?;
        self.stage_license()?;
        info!(
            d.log,
            "{}: staged Juniper config and license for guest systemd services",
            self.name(d)
        );
        Ok(())
    }

    fn stage_routing_config(
        &self,
        d: &Runner,
        routing_config: &str,
    ) -> Result<PathBuf> {
        let node_name = self.name(d);
        let dir = Path::new(CARGO_BAY);
        fs::create_dir_all(dir)
            .with_context(|| format!("create {}", dir.display()))?;
        let path = dir.join(format!("{node_name}{CONFIG_SUFFIX}"));
        let routing_config = routing_config
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, format!("configure\n{routing_config}\ncommit\n"))
            .with_context(|| format!("write {}", path.display()))?;
        Ok(path)
    }

    fn stage_license(&self) -> Result<PathBuf> {
        let path = Path::new(CARGO_BAY).join(LICENSE_PATH);
        let metadata = fs::metadata(&path).with_context(|| {
            format!(
                "Juniper license missing at {}; fetch it into cargo-bay before running falcon-lab",
                path.display()
            )
        })?;
        if !metadata.is_file() {
            return Err(anyhow!(
                "Juniper license path is not a file: {}",
                path.display()
            ));
        }
        Ok(path)
    }

    pub async fn shell(&self, d: &Runner, script: &str) -> Result<String> {
        info!(
            d.log,
            "{}: executing juniper script {}",
            self.name(d),
            script.dimmed()
        );
        d.exec(
            self.0,
            &format!(
                "docker exec {CRPD_CONTAINER} cli -c {}",
                shell_quote(script)
            ),
        )
        .await
        .context("juniper cli failed")
    }

    /// Returns true iff Junos has installed `prefix` from BGP.
    pub async fn bgp_route_imported(
        &self,
        d: &Runner,
        prefix: &str,
    ) -> Result<bool> {
        let output = self
            .shell(d, &format!("show route {prefix} protocol bgp"))
            .await?;
        Ok(output.contains(prefix) && output.contains("BGP"))
    }

    /// Query cRPD for the local status of a BFD session to `peer`. Returns
    /// true iff Junos reports the session as `Up`.
    pub async fn bfd_peer_up(&self, d: &Runner, peer: IpAddr) -> Result<bool> {
        let output = self.shell(d, "show bfd session | display json").await?;
        let resp: JunosBfdResponse = serde_json::from_str(&output)
            .context("parse juniper bfd session json")?;
        let peer = peer.to_string();
        Ok(resp
            .bfd_session_information
            .into_iter()
            .flat_map(|info| info.bfd_session)
            .any(|session| session.is_up_for(&peer)))
    }

    /// Capture non-secret Juniper diagnostics. Do not add `show configuration`
    /// directly or Junos/container logs here: the committed configuration
    /// contains the license key, and logs may include secret-bearing
    /// configuration activity.
    pub async fn collect_diagnostics(
        &self,
        d: &Runner,
        topo: &str,
        protocols: ProtocolDiagnostics,
    ) {
        let name = self.name(d);
        let mut commands = vec![
            ("docker-ps", "docker ps -a"),
            ("docker-inspect", "docker inspect crpd1"),
            (
                "show-configuration-redacted",
                "docker exec crpd1 cli -c 'show configuration | display set | no-more' \
                    | sed -E 's/(set system license keys key ).*/\\1<redacted>/'",
            ),
            (
                "show-version",
                "docker exec crpd1 cli -c 'show version | no-more'",
            ),
            (
                "show-interfaces-terse",
                "docker exec crpd1 cli -c 'show interfaces terse | no-more'",
            ),
        ];
        if protocols.bgp() {
            commands.extend([
                (
                    "show-bgp-summary",
                    "docker exec crpd1 cli -c 'show bgp summary | no-more'",
                ),
                (
                    "show-bgp-neighbors-auto-discovered",
                    "docker exec crpd1 cli -c 'show bgp neighbors auto-discovered | no-more'",
                ),
            ]);
        }
        if protocols.bfd() {
            commands.push((
                "show-bfd-session-detail",
                "docker exec crpd1 cli -c 'show bfd session detail | no-more'",
            ));
        }
        for (suffix, command) in commands {
            crate::diagnostics::capture(
                d,
                self.0,
                topo,
                &format!("{name}-{suffix}"),
                &format!("timeout 5s {command} || true"),
            )
            .await;
        }
        for (suffix, command) in [
            (
                "junos-apply-status",
                "cat /run/falcon-junos-apply.status 2>/dev/null || true",
            ),
            (
                "junos-apply-output",
                "cat /var/run/juniper/falcon-lab/apply.out 2>/dev/null || true",
            ),
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
        self.linux().collect_diagnostics(d, topo, &name).await;
        self.linux()
            .collect_container_diagnostics(d, topo, &name, CRPD_CONTAINER)
            .await;
    }

    /// Capture cRPD setup diagnostics for boot failures. Keep these strictly
    /// non-secret: do not collect generated config, setup transcripts, or logs
    /// that may include the Juniper license.
    pub async fn collect_boot_diagnostics(&self, d: &Runner, topo: &str) {
        let name = self.name(d);
        const COMMANDS: [(&str, &str); 4] = [
            ("docker-ps", "docker ps -a"),
            ("docker-inspect", "docker inspect crpd1"),
            (
                "show-version",
                "timeout 5s docker exec crpd1 cli -c 'show version | no-more' || true",
            ),
            (
                "show-interfaces-terse",
                "timeout 5s docker exec crpd1 cli -c 'show interfaces terse | no-more' || true",
            ),
        ];
        for (suffix, command) in COMMANDS {
            crate::diagnostics::capture(
                d,
                self.0,
                topo,
                &format!("{name}-{suffix}"),
                command,
            )
            .await;
        }
        for (suffix, command) in [
            (
                "junos-apply-status",
                "cat /run/falcon-junos-apply.status 2>/dev/null || true",
            ),
            (
                "junos-apply-output",
                "cat /var/run/juniper/falcon-lab/apply.out 2>/dev/null || true",
            ),
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
    }
}

#[derive(Deserialize)]
struct JunosBfdResponse {
    #[serde(rename = "bfd-session-information", default)]
    bfd_session_information: Vec<JunosBfdSessionInformation>,
}

#[derive(Deserialize)]
struct JunosBfdSessionInformation {
    #[serde(rename = "bfd-session", default)]
    bfd_session: Vec<JunosBfdSession>,
}

#[derive(Deserialize)]
struct JunosBfdSession {
    #[serde(rename = "session-neighbor", default)]
    session_neighbor: Vec<JunosData>,
    #[serde(rename = "session-state", default)]
    session_state: Vec<JunosData>,
}

impl JunosBfdSession {
    fn is_up_for(&self, peer: &str) -> bool {
        self.session_neighbor
            .first()
            .is_some_and(|neighbor| neighbor.data == peer)
            && self
                .session_state
                .first()
                .is_some_and(|state| state.data.eq_ignore_ascii_case("up"))
    }
}

#[derive(Deserialize)]
struct JunosData {
    data: String,
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
