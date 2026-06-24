//! Failure-time diagnostics: run a command (or hand over already-collected
//! text) and persist it under `/work/<topo>-<label>.log` so buildomat can
//! upload it as a job artifact. Each artifact is also echoed via `warn!`
//! so it lands in the console output even if the disk write fails.

use libfalcon::{NodeRef, Runner};
use slog::{info, warn};
use std::path::Path;

#[derive(Copy, Clone)]
pub enum ProtocolDiagnostics {
    Bgp,
    Bfd,
}

impl ProtocolDiagnostics {
    pub fn bgp(self) -> bool {
        matches!(self, Self::Bgp)
    }

    pub fn bfd(self) -> bool {
        matches!(self, Self::Bfd)
    }
}

/// Run `cmd` on `node`, capture stdout, and persist it as an artifact
/// labelled `<topo>-<label>.log`.
pub async fn capture(
    d: &Runner,
    node: NodeRef,
    topo: &str,
    label: &str,
    cmd: &str,
) {
    match d.exec(node, cmd).await {
        Ok(out) => write_artifact(d, topo, label, Some(cmd), &out),
        Err(e) => warn!(d.log, "diagnostics {label}: exec failed: {e}"),
    }
}

/// Persist a labelled blob and echo it to the runner log. `source` is an
/// optional descriptor (file path or command string) included in the
/// inline header to make it clear where the contents came from.
pub fn write_artifact(
    d: &Runner,
    topo: &str,
    label: &str,
    source: Option<&str>,
    contents: &str,
) {
    let header = match source {
        Some(s) => format!("=== {topo} {label} ({s}) ==="),
        None => format!("=== {topo} {label} ==="),
    };
    info!(d.log, "{header}\n{contents}");
    let path = Path::new("/work").join(format!("{topo}-{label}.log"));
    if let Err(e) = std::fs::write(&path, contents) {
        warn!(d.log, "diagnostics {label}: write {path:?}: {e}");
    }
}
