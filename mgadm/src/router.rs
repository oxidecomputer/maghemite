// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::Subcommand;
use client_common::println_nopipe;
use colored::*;
use mg_admin_client::Client;
use mg_api_types::router::ApplyRoutersRequest;
use std::io::Write;
use tabwriter::TabWriter;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List the routers on this system.
    List,

    /// Apply the complete set of routers from a JSON file.
    Apply {
        /// Path to a JSON file containing a ApplyRoutersRequest.
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
            let rq: ApplyRoutersRequest = serde_json::from_str(&contents)?;
            let response = c.apply_routers(&rq).await?.into_inner();
            for r in &response.not_applied {
                println_nopipe!(
                    "not applied: {} ({}): {}",
                    r.name,
                    r.id,
                    r.reason
                );
            }
        }
    }
    Ok(())
}
