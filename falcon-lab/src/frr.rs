//! FRR machinery

#![allow(dead_code)]

use std::time::Duration;

use crate::linux::LinuxNode;
use anyhow::{Context, Result};
use libfalcon::{NodeRef, Runner};
use slog::info;
use tokio::time::sleep;

#[derive(Copy, Clone)]
pub struct FrrNode(pub NodeRef);

impl FrrNode {
    pub fn name(&self, d: &Runner) -> String {
        d.get_node(self.0).name.clone()
    }

    pub async fn enable_daemon(&self, d: &Runner, name: &str) -> Result<()> {
        info!(d.log, "{}: enabling frr daemon {name}", self.name(d));
        d.exec(
            self.0,
            &format!("sed -i 's/{name}=no/{name}=yes/g' /etc/frr/daemons"),
        )
        .await?;
        d.exec(self.0, "systemctl restart frr").await?;
        // XXX do better than arbitrary wait
        sleep(Duration::from_secs(5)).await;
        Ok(())
    }

    pub async fn install(&self, d: &Runner) -> Result<()> {
        info!(d.log, "{}: installing frr", self.name(d));
        d.exec(self.0, "apt-get -y update && apt-get -y install frr")
            .await
            .context("apt install frr failed")?;
        Ok(())
    }

    pub async fn shell(&self, d: &Runner, script: &str) -> Result<()> {
        info!(d.log, "{}: executing frr script {script}", self.name(d));
        let args = script
            .lines()
            .map(|l| format!("'{l}'"))
            .collect::<Vec<_>>()
            .join(" -c ");
        d.exec(self.0, &format!("vtysh {args}"))
            .await
            .context("vtysh shell failed")?;

        Ok(())
    }

    pub fn linux(&self) -> LinuxNode {
        LinuxNode(self.0)
    }
}
