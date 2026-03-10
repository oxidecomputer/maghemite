// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use mg_admin_client::types::BestpathFanoutRequest;
use mg_admin_client::{Client, print_rib};
use mg_common::println_nopipe;
use rdb::types::{AddressFamily, ProtocolFilter};
use std::num::NonZeroU8;

#[derive(Clone, Debug, ValueEnum)]
#[allow(non_camel_case_types)]
pub enum RibDisplayMode {
    /// Display summary information (default).
    summary,
    /// Display detailed information.
    detail,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// View RIB state
    Status(StatusCommand),

    /// Fanout configuration commands.
    Fanout(FanoutCommand),
}

#[derive(Debug, Args)]
pub struct StatusCommand {
    #[command(subcommand)]
    command: StatusCmd,
}

#[derive(Subcommand, Debug)]
pub enum StatusCmd {
    /// Get the unified adj-rib-in table. Contains routes from all
    /// protocols (e.g. BGP and static routing).
    Imported {
        /// Address family to filter by
        #[arg(value_enum)]
        address_family: Option<AddressFamily>,
        /// Protocol filter (optional)
        #[arg(value_enum)]
        protocol: Option<ProtocolFilter>,
        /// Exact-match prefix filter (e.g. 10.0.0.0/24)
        prefix: Option<String>,
        /// Display mode: summary (default) or detail.
        /// Defaults to detail when a prefix is specified.
        #[clap(long, value_enum)]
        mode: Option<RibDisplayMode>,
    },

    /// Get the loc-rib table. Contains only valid routes and their
    /// best paths.
    Selected {
        /// Address family to filter by
        #[arg(value_enum)]
        address_family: Option<AddressFamily>,
        /// Protocol filter (optional)
        #[arg(value_enum)]
        protocol: Option<ProtocolFilter>,
        /// Exact-match prefix filter (e.g. 10.0.0.0/24)
        prefix: Option<String>,
        /// Display mode: summary (default) or detail.
        /// Defaults to detail when a prefix is specified.
        #[clap(long, value_enum)]
        mode: Option<RibDisplayMode>,
    },
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
        Commands::Status(status_cmd) => match status_cmd.command {
            StatusCmd::Imported {
                address_family,
                protocol,
                prefix,
                mode,
            } => {
                let detail = match mode {
                    Some(m) => matches!(m, RibDisplayMode::detail),
                    None => prefix.is_some(),
                };
                get_imported(c, address_family, protocol, detail, prefix)
                    .await?
            }
            StatusCmd::Selected {
                address_family,
                protocol,
                prefix,
                mode,
            } => {
                let detail = match mode {
                    Some(m) => matches!(m, RibDisplayMode::detail),
                    None => prefix.is_some(),
                };
                get_selected(c, address_family, protocol, detail, prefix)
                    .await?
            }
        },
    }
    Ok(())
}

async fn get_imported(
    c: Client,
    address_family: Option<AddressFamily>,
    protocol: Option<ProtocolFilter>,
    detail: bool,
    prefix: Option<String>,
) -> Result<()> {
    let imported = c
        .get_rib_imported_v3(
            address_family.as_ref(),
            prefix.as_deref(),
            protocol.as_ref(),
        )
        .await?
        .into_inner();

    print_rib(imported, detail);
    Ok(())
}

async fn get_selected(
    c: Client,
    address_family: Option<AddressFamily>,
    protocol: Option<ProtocolFilter>,
    detail: bool,
    prefix: Option<String>,
) -> Result<()> {
    let selected = c
        .get_rib_selected_v3(
            address_family.as_ref(),
            prefix.as_deref(),
            protocol.as_ref(),
        )
        .await?
        .into_inner();

    print_rib(selected, detail);
    Ok(())
}

async fn read_bestpath_fanout(c: Client) -> Result<()> {
    let result = c.read_rib_bestpath_fanout().await?;
    println_nopipe!("{}", result.into_inner().fanout);
    Ok(())
}

async fn update_bestpath_fanout(fanout: NonZeroU8, c: Client) -> Result<()> {
    c.update_rib_bestpath_fanout(&BestpathFanoutRequest { fanout })
        .await?;
    println_nopipe!("Updated bestpath fanout to: {}", fanout);
    Ok(())
}
