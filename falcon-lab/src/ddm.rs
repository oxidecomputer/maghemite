//! DDM machinery

#![allow(dead_code)]

use crate::{dendrite::DendriteNode, illumos::IllumosNode};
use anyhow::Result;
use ddm_admin_client::Client;
use libfalcon::{NodeRef, Runner};
use std::net::IpAddr;

/// Path to the ddmd binary inside the helios VM
const DDMD_BIN: &str = "/opt/cargo-bay/ddmd";

/// File ddmd's stdout/stderr is redirected to inside the helios VM
const DDM_LOG: &str = "/tmp/ddm.log";

#[derive(Copy, Clone)]
pub struct DdmNode(pub NodeRef);

impl DdmNode {
    pub async fn run_ddm(&self, d: &Runner) -> Result<()> {
        d.exec(
            self.0,
            &format!("chmod +x {DDMD_BIN} && {DDMD_BIN} &> {DDM_LOG} &"),
        )
        .await?;
        Ok(())
    }

    pub async fn client(&self, d: &Runner, addr: IpAddr) -> Result<Client> {
        Ok(Client::new(&format!("http://{addr}:8000"), d.log.clone()))
    }

    pub fn illumos(&self) -> IllumosNode {
        IllumosNode(self.0)
    }

    pub fn dendrite(&self) -> DendriteNode {
        DendriteNode(self.0)
    }

    /// Capture the ddmd log. Currently, falcon-lab launches ddm manually with
    /// stdout/stderr redirected to `DDM_LOG`.
    pub async fn collect_diagnostics(&self, d: &Runner, topo: &str) {
        let name = d.get_node(self.0).name.clone();
        let label = format!("{name}-ddm");
        match self.illumos().read_file(d, DDM_LOG).await {
            Ok(contents) => crate::diagnostics::write_artifact(
                d,
                topo,
                &label,
                Some(DDM_LOG),
                &contents,
            ),
            Err(e) => slog::warn!(d.log, "diagnostics {label}: {e}"),
        }
    }
}
