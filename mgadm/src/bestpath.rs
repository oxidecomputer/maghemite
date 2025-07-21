// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::num::NonZeroU8;

use anyhow::Result;
use clap::{Args, Subcommand};
use mg_admin_client::types;
use mg_admin_client::Client;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Fanout configuration commands.
    Fanout(FanoutCommand),
}

#[derive(Debug, Args)]
pub struct FanoutCommand {
    #[command(subcommand)]
    command: FanoutCmd,
}

#[derive(Subcommand, Debug)]
pub enum FanoutCmd {
    /// Read the current fanout setting.
    Read,

    /// Update the fanout setting.
    Update {
        /// Maximum number of equal-cost paths for ECMP forwarding
        fanout: NonZeroU8,
    },
}

pub async fn commands(command: Commands, c: Client) -> Result<()> {
    match command {
        Commands::Fanout(fanout_cmd) => match fanout_cmd.command {
            FanoutCmd::Read => read_bestpath_fanout(c).await?,
            FanoutCmd::Update { fanout } => {
                update_bestpath_fanout(fanout, c).await?
            }
        },
    }
    Ok(())
}

async fn read_bestpath_fanout(c: Client) -> Result<()> {
    let result = c.read_bestpath_fanout().await?;
    println!("{}", result.into_inner().fanout);
    Ok(())
}

async fn update_bestpath_fanout(fanout: NonZeroU8, c: Client) -> Result<()> {
    c.update_bestpath_fanout(&types::BestpathFanoutRequest { fanout })
        .await?;
    println!("Updated bestpath fanout to: {}", fanout);
    Ok(())
}
