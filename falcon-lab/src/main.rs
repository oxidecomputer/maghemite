//! Falcon test lab

use crate::dendrite::NpuvmCommits;
use crate::test::{
    cleanup_mgd_unnumbered_test, cleanup_quartet_bfd_static_test,
    cleanup_quartet_unnumbered_test, run_mgd_unnumbered_test,
    run_quartet_bfd_static_test, run_quartet_unnumbered_test,
};
use clap::{Parser, Subcommand};

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

    #[clap(long)]
    no_diag_on_fail: bool,

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
    MgdUnnumbered,
    QuartetUnnumbered,
    QuartetBfdStaticRouting,
}

fn main() -> anyhow::Result<()> {
    oxide_tokio_rt::run(run())
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(cmd) => {
            let commits = NpuvmCommits {
                npuvm: cmd.npuvm_commit,
                dendrite: cmd.dendrite_commit,
                sidecar_lite: cmd.sidecar_lite_commit,
            };
            match cmd.command {
                TestCommand::MgdUnnumbered => {
                    run_mgd_unnumbered_test(
                        cmd.no_cleanup,
                        !cmd.no_diag_on_fail,
                    )
                    .await?
                }
                TestCommand::QuartetUnnumbered => {
                    run_quartet_unnumbered_test(
                        cmd.no_cleanup,
                        !cmd.no_diag_on_fail,
                        commits,
                    )
                    .await?
                }
                TestCommand::QuartetBfdStaticRouting => {
                    run_quartet_bfd_static_test(
                        cmd.no_cleanup,
                        !cmd.no_diag_on_fail,
                        commits,
                    )
                    .await?
                }
            }
        }
        Command::Cleanup(cmd) => match cmd.command {
            TestCommand::MgdUnnumbered => cleanup_mgd_unnumbered_test().await?,
            TestCommand::QuartetUnnumbered => {
                cleanup_quartet_unnumbered_test().await?
            }
            TestCommand::QuartetBfdStaticRouting => {
                cleanup_quartet_bfd_static_test().await?
            }
        },
        Command::Serial(cmd) => {
            libfalcon::cli::console(&cmd.node, ".falcon".into()).await?
        }
    }
    Ok(())
}
