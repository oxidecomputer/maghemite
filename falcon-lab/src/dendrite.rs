//! Dendrite machinery

#![allow(dead_code)]

use crate::illumos::IllumosNode;
use anyhow::Result;
use dpd_client::{
    Client,
    types::{LinkCreate, LinkId, PortId, PortSpeed},
};
use libfalcon::{NodeRef, Runner};
use slog::info;
use std::{net::IpAddr, sync::Arc};

#[derive(Copy, Clone)]
pub struct DendriteNode(pub NodeRef);

impl DendriteNode {
    pub fn name(&self, d: &Runner) -> String {
        d.get_node(self.0).name.clone()
    }

    pub async fn client(&self, d: &Runner, addr: IpAddr) -> Result<Client> {
        let client_state = dpd_client::ClientState {
            tag: String::default(),
            log: d.log.clone(),
        };
        Ok(Client::new(
            &format!("http://{addr}:{}", dpd_client::default_port()),
            client_state,
        ))
    }

    pub async fn npuvm(
        self,
        d: Arc<Runner>,
        front_ports: usize,
        rear_ports: usize,
        npuvm_commit: String,
        dendrite_commit: Option<String>,
    ) -> Result<()> {
        const BUILDOMAT_URL: &str =
            "https://buildomat.eng.oxide.computer/public/file/oxidecomputer/";
        info!(d.log, "{}: setting up npuvm", self.name(&d));
        d.exec(
            self.0,
            &format!(
                "curl --retry 5 -OL \
                {BUILDOMAT_URL}/softnpu/image/{npuvm_commit}/npuvm"
            ),
        )
        .await?;
        d.exec(self.0, "chmod +x npuvm").await?;
        d.exec(
            self.0,
            &format!(
                "./npuvm install \
                    --front-ports {front_ports} \
                    --rear-ports {rear_ports} \
                    --pkt-source vioif0 \
                    {}",
                dendrite_commit
                    .map(|x| format!("--dendrite-commit {x}"))
                    .unwrap_or_default()
            ),
        )
        .await?;
        d.exec(
            self.0,
            "/root/scadm propolis load-program /root/libsidecar_lite.so",
        )
        .await?;
        Ok(())
    }

    pub fn illumos(&self) -> IllumosNode {
        IllumosNode(self.0)
    }
}

pub async fn softnpu_link_create(c: &Client, name: &str) -> Result<()> {
    let port = PortId::Qsfp(name.parse()?);
    let link = LinkId(0);
    c.link_create(
        &port,
        &LinkCreate {
            autoneg: false,
            fec: None,
            kr: false,
            lane: Some(link),
            speed: PortSpeed::Speed100G,
            tx_eq: None,
        },
    )
    .await?;
    c.link_enabled_set(&port, &link, true).await?;
    Ok(())
}
