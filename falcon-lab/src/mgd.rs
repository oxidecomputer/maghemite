//! MGD machinery

use crate::{ddm::DdmNode, dendrite::DendriteNode, illumos::IllumosNode};
use anyhow::{Result, anyhow};
use libfalcon::{NodeRef, Runner};
use mg_admin_client::Client;
use slog::{Logger, debug};
use std::{net::IpAddr, time::Duration};
use tokio::time::{Instant, sleep};

/// Path to the mgd binary inside the ox VM (staged from `cargo-bay/` on
/// the host).
const MGD_BIN: &str = "/opt/cargo-bay/mgd";

/// File mgd's stdout/stderr is redirected to. Used by both `run_mgd` (the
/// shell redirect) and `collect_diagnostics` (the failure-time fetch); keep
/// these in sync via this single constant.
const MGD_LOG: &str = "/tmp/mgd.log";

#[derive(Copy, Clone)]
pub struct MgdNode(pub NodeRef);

impl MgdNode {
    pub async fn run_mgd(&self, d: &Runner) -> Result<()> {
        d.exec(
            self.0,
            &format!("chmod +x {MGD_BIN} && {MGD_BIN} run &> {MGD_LOG} &"),
        )
        .await?;
        Ok(())
    }

    pub async fn client(&self, d: &Runner, addr: IpAddr) -> Result<Client> {
        Ok(Client::new(&format!("http://{addr}:4676"), d.log.clone()))
    }

    pub fn illumos(&self) -> IllumosNode {
        IllumosNode(self.0)
    }

    pub fn dendrite(&self) -> DendriteNode {
        DendriteNode(self.0)
    }

    pub fn ddm(&self) -> DdmNode {
        DdmNode(self.0)
    }

    /// Capture the mgd log. Currently, falcon-lab launches mgd manually with
    /// stdout/stderr redirected to `MGD_LOG`.
    pub async fn collect_diagnostics(&self, d: &Runner, topo: &str) {
        let name = d.get_node(self.0).name.clone();
        let label = format!("{name}-mgd");
        match self.illumos().read_file(d, MGD_LOG).await {
            Ok(contents) => crate::diagnostics::write_artifact(
                d,
                topo,
                &label,
                Some(MGD_LOG),
                &contents,
            ),
            Err(e) => slog::warn!(d.log, "diagnostics {label}: {e}"),
        }
    }
}

pub async fn wait_for_mgd(
    c: &Client,
    timeout: Duration,
    log: &Logger,
) -> Result<()> {
    let start = Instant::now();
    loop {
        match c.read_routers().await {
            Ok(_) => return Ok(()),
            Err(e) => debug!(log, "wait for mgd: {e}"),
        }
        if start.elapsed() >= timeout {
            break;
        }
        sleep(Duration::from_secs(1)).await
    }
    Err(anyhow!("timeout waiting for mgd"))
}
