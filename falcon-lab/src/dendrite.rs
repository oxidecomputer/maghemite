//! Dendrite machinery

#![allow(dead_code)]

use crate::illumos::IllumosNode;
use anyhow::{Result, anyhow};
use dpd_client::{
    Client,
    types::{LinkCreate, LinkId, PortId, PortSpeed},
};
use libfalcon::{NodeRef, Runner};
use slog::{Logger, debug, info};
use std::{error::Error as StdError, net::IpAddr, sync::Arc, time::Duration};
use tokio::time::{Instant, sleep};

/// Format an error along with its full `source()` chain. The default `Display`
/// for `dpd_client::Error` / `reqwest::Error` only prints the top frame
/// ("error sending request for url ..."), which hides the actual cause
/// (connection refused, dns failure, tls error, ...).
pub fn fmt_error_chain(err: &(dyn StdError + 'static)) -> String {
    let mut out = err.to_string();
    let mut src = err.source();
    while let Some(s) = src {
        out.push_str(": ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

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
        sidecar_lite_commit: Option<String>,
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
        // Capture install stdout to land in the buildomat log. Without this
        // they're only visible inside the softnpu VM and lost on teardown.
        let install_out = d
            .exec(
                self.0,
                &format!(
                    "./npuvm install \
                        --front-ports {front_ports} \
                        --rear-ports {rear_ports} \
                        --pkt-source vioif0 \
                        {} {}",
                    dendrite_commit
                        .map(|x| format!("--dendrite-commit {x}"))
                        .unwrap_or_default(),
                    sidecar_lite_commit
                        .map(|x| format!("--sidecar-lite-commit {x}"))
                        .unwrap_or_default(),
                ),
            )
            .await?;
        info!(
            d.log,
            "{}: npuvm install output:\n{install_out}",
            self.name(&d)
        );
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

    /// Capture the dpd SMF service log.
    pub async fn collect_diagnostics(&self, d: &Runner, topo: &str) {
        let name = self.name(d);
        match self.illumos().svc_log(d, "dendrite").await {
            Ok((path, contents)) => crate::diagnostics::write_artifact(
                d,
                topo,
                &format!("{name}-dendrite"),
                Some(&path),
                &contents,
            ),
            Err(e) => {
                slog::warn!(d.log, "diagnostics {name}-dendrite: {e}")
            }
        }
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

pub async fn wait_for_dpd(
    c: &Client,
    timeout: Duration,
    log: &Logger,
) -> Result<()> {
    let start = Instant::now();
    loop {
        match c.dpd_uptime().await {
            Ok(_) => return Ok(()),
            Err(e) => {
                let chain = fmt_error_chain(&e);
                debug!(log, "wait for dpd: {chain}");
                if start.elapsed() >= timeout {
                    return Err(anyhow!(
                        "timeout waiting for dpd after {timeout:?}; \
                         last error: {chain}"
                    ));
                }
            }
        }
        sleep(Duration::from_secs(1)).await
    }
}
