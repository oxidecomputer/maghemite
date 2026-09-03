//! Falcon test lab

use crate::dendrite::NpuvmCommits;
use crate::scenario::{
    InteropScenario, MgdDuoScenario, Scenario, ScenarioOptions,
};
use clap::{Args, Parser, Subcommand, ValueEnum};

mod bgp;
mod ddm;
mod dendrite;
mod diagnostics;
mod eos;
mod frr;
mod illumos;
mod juniper;
mod linux;
mod mgd;
mod scenario;
mod topo;
mod util;

const DEFAULT_NPUVM_COMMIT: &str = "fd2c726815cdb03c2687e1bf2912a9184905557b";

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run(TopologyRun),
    Cleanup(TopologyCleanup),
    Serial(Serial),
}

#[derive(Debug, Args)]
struct TopologyRun {
    #[command(subcommand)]
    topology: RunTopology,
}

#[derive(Debug, Subcommand)]
enum RunTopology {
    MgdDuo(ScenarioRun<MgdDuoScenario>),
    Interop(ScenarioRun<InteropScenario>),
}

#[derive(Debug, Args)]
struct ScenarioRun<S: ValueEnum + Send + Sync + 'static> {
    #[arg(value_enum)]
    scenario: S,
    #[command(flatten)]
    options: RunOptions,
}

#[derive(Debug, Args)]
struct RunOptions {
    #[arg(long)]
    no_cleanup: bool,
    #[arg(long)]
    no_diag_on_fail: bool,
    #[arg(long, default_value = DEFAULT_NPUVM_COMMIT)]
    npuvm_commit: String,
    #[arg(long)]
    dendrite_commit: Option<String>,
    #[arg(long)]
    sidecar_lite_commit: Option<String>,
}

impl RunOptions {
    fn scenario_options(self) -> ScenarioOptions {
        let commits = NpuvmCommits {
            npuvm: self.npuvm_commit,
            dendrite: self.dendrite_commit,
            sidecar_lite: self.sidecar_lite_commit,
        };
        ScenarioOptions::new(self.no_cleanup, !self.no_diag_on_fail, commits)
    }
}

#[derive(Debug, Args)]
struct TopologyCleanup {
    #[command(subcommand)]
    topology: CleanupTopology,
}

#[derive(Debug, Subcommand)]
enum CleanupTopology {
    MgdDuo(ScenarioCleanup<MgdDuoScenario>),
    Interop(ScenarioCleanup<InteropScenario>),
}

#[derive(Debug, Args)]
struct ScenarioCleanup<S: ValueEnum + Send + Sync + 'static> {
    #[arg(value_enum)]
    scenario: S,
}

#[derive(Debug, Args)]
struct Serial {
    node: String,
}

fn main() -> anyhow::Result<()> {
    oxide_tokio_rt::run(run())
}

async fn run() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Run(cmd) => match cmd.topology {
            RunTopology::MgdDuo(cmd) => {
                cmd.scenario.run(cmd.options.scenario_options()).await?;
            }
            RunTopology::Interop(cmd) => {
                cmd.scenario.run(cmd.options.scenario_options()).await?;
            }
        },
        Command::Cleanup(cmd) => match cmd.topology {
            CleanupTopology::MgdDuo(cmd) => {
                cmd.scenario.cleanup()?;
            }
            CleanupTopology::Interop(cmd) => {
                cmd.scenario.cleanup()?;
            }
        },
        Command::Serial(cmd) => {
            libfalcon::cli::console(&cmd.node, ".falcon".into()).await?
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_options_follow_scenario() {
        let cli = Cli::try_parse_from([
            "falcon-lab",
            "run",
            "interop",
            "bare",
            "--no-cleanup",
        ])
        .expect("parse interop bare scenario");

        assert!(matches!(
            cli.command,
            Command::Run(TopologyRun {
                topology: RunTopology::Interop(ScenarioRun {
                    scenario: InteropScenario::Bare,
                    options: RunOptions {
                        no_cleanup: true,
                        ..
                    },
                }),
            })
        ));
    }

    #[test]
    fn cleanup_uses_topology_and_scenario() {
        let cli = Cli::try_parse_from([
            "falcon-lab",
            "cleanup",
            "mgd-duo",
            "bgp-unnumbered",
        ])
        .expect("parse mgd-duo cleanup scenario");

        assert!(matches!(
            cli.command,
            Command::Cleanup(TopologyCleanup {
                topology: CleanupTopology::MgdDuo(ScenarioCleanup {
                    scenario: MgdDuoScenario::BgpUnnumbered,
                }),
            })
        ));
    }

    #[test]
    fn scenario_is_rejected_by_wrong_topology() {
        assert!(
            Cli::try_parse_from([
                "falcon-lab",
                "run",
                "mgd-duo",
                "bfd-static-routing",
            ])
            .is_err()
        );
    }
}
