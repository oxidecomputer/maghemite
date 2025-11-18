//! MGD machinery

use crate::{ddm::DdmNode, dendrite::DendriteNode, illumos::IllumosNode};
use anyhow::Result;
use libfalcon::{NodeRef, Runner};
use mg_admin_client::Client;
use std::net::IpAddr;

#[derive(Copy, Clone)]
pub struct MgdNode(pub NodeRef);

impl MgdNode {
    pub async fn run_mgd(&self, d: &Runner) -> Result<()> {
        d.exec(
            self.0,
            "chmod +x /opt/cargo-bay/mgd && \
            /opt/cargo-bay/mgd run &> /tmp/mgd.log &",
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
}
