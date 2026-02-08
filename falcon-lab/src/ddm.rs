//! DDM machinery

#![allow(dead_code)]

use crate::{dendrite::DendriteNode, illumos::IllumosNode};
use anyhow::Result;
use ddm_admin_client::Client;
use libfalcon::{NodeRef, Runner};
use std::net::IpAddr;

#[derive(Copy, Clone)]
pub struct DdmNode(pub NodeRef);

impl DdmNode {
    pub async fn run_ddm(&self, d: &Runner) -> Result<()> {
        d.exec(
            self.0,
            "chmod +x /opt/cargo-bay/ddmd && \
            /opt/cargo-bay/ddmd &> /tmp/ddm.log &",
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
}
