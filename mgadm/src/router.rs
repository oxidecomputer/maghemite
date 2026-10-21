// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::Subcommand;
use colored::*;
use mg_admin_client::Client;
use mg_api_types::router::MultiRouterApplyRequest;
use std::io::Write;
use tabwriter::TabWriter;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List the routers on this system.
    List,

    /// Apply a full multi-router configuration from a JSON file.
    ///
    /// The file contains a MultiRouterApplyRequest: the complete desired
    /// set of routers. Routers absent from the file are torn down.
    Apply {
        /// Path to a JSON file containing a MultiRouterApplyRequest.
        file: String,
    },
}

pub async fn commands(command: Commands, c: Client) -> Result<()> {
    match command {
        Commands::List => {
            let routers = c.list_routers().await?.into_inner();
            let mut tw = TabWriter::new(std::io::stdout());
            writeln!(
                &mut tw,
                "{}\t{}\t{}",
                "Name".dimmed(),
                "Id".dimmed(),
                "TEP".dimmed(),
            )?;
            for r in routers {
                writeln!(&mut tw, "{}\t{}\t{}", r.name, r.id, r.tep)?;
            }
            tw.flush()?;
        }
        Commands::Apply { file } => {
            let contents = std::fs::read_to_string(&file)?;
            let rq: MultiRouterApplyRequest = serde_json::from_str(&contents)?;
            c.multi_router_apply(&rq).await?;
        }
    }
    Ok(())
}
