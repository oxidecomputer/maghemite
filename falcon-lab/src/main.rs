//! Falcon test lab

use crate::test::{cleanup_unnumbered_test, run_trio_unnumbered_test};
use clap::{Parser, Subcommand};

mod bgp;
mod ddm;
mod dendrite;
mod eos;
mod frr;
mod illumos;
mod linux;
mod mgd;
mod test;
mod topo;
mod util;

#[derive(Debug, Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run(Run),
    Cleanup(Cleanup),
    Serial(Serial),
}

#[derive(Debug, Parser)]
struct Run {
    #[clap(subcommand)]
    command: TestCommand,

    #[clap(long)]
    no_cleanup: bool,

    #[clap(long, default_value = "fd2c726815cdb03c2687e1bf2912a9184905557b")]
    npuvm_commit: String,

    #[clap(long)]
    dendrite_commit: Option<String>,

    #[clap(long)]
    sidecar_lite_commit: Option<String>,
}

#[derive(Debug, Parser)]
struct Cleanup {
    #[clap(subcommand)]
    command: TestCommand,
}

#[derive(Debug, Parser)]
struct Serial {
    node: String,
}

#[derive(Debug, Subcommand)]
enum TestCommand {
    TrioUnnumbered,
}

fn main() -> anyhow::Result<()> {
    oxide_tokio_rt::run(run())
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(cmd) => match cmd.command {
            TestCommand::TrioUnnumbered => {
                run_trio_unnumbered_test(
                    cmd.no_cleanup,
                    cmd.npuvm_commit.clone(),
                    cmd.dendrite_commit,
                    cmd.sidecar_lite_commit,
                )
                .await?
            }
        },
        Command::Cleanup(cmd) => match cmd.command {
            TestCommand::TrioUnnumbered => cleanup_unnumbered_test().await?,
        },
        Command::Serial(cmd) => {
            libfalcon::cli::console(&cmd.node, ".falcon".into()).await?
        }
    }
    Ok(())
}
