// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::num::NonZeroU8;

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use mg_admin_client::types::BestpathFanoutRequest;
use mg_admin_client::{Client, print_rib};
use rdb::types::{AddressFamily, ProtocolFilter};

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

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum AddressFamilyArg {
    /// IPv4 routes only
    Ipv4,
    /// IPv6 routes only
    Ipv6,
    /// All routes (IPv4 and IPv6)
    All,
}

impl From<AddressFamilyArg> for AddressFamily {
    fn from(arg: AddressFamilyArg) -> Self {
        match arg {
            AddressFamilyArg::Ipv4 => AddressFamily::Ipv4,
            AddressFamilyArg::Ipv6 => AddressFamily::Ipv6,
            AddressFamilyArg::All => AddressFamily::All,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum StatusCmd {
    /// Get the unified adj-rib-in table. Contains routes from all
    /// protocols (e.g. BGP and static routing).
    Imported {
        /// Address family to filter by
        #[arg(value_enum, default_value_t = AddressFamilyArg::All)]
        address_family: AddressFamilyArg,
        /// Protocol filter (optional)
        #[arg(value_enum)]
        protocol: Option<ProtocolFilter>,
    },

    /// Get the loc-rib table. Contains only valid routes and their
    /// best paths.
    Selected {
        /// Address family to filter by
        #[arg(value_enum, default_value_t = AddressFamilyArg::All)]
        address_family: AddressFamilyArg,
        /// Protocol filter (optional)
        #[arg(value_enum)]
        protocol: Option<ProtocolFilter>,
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
            } => get_imported(c, address_family.into(), protocol).await?,
            StatusCmd::Selected {
                address_family,
                protocol,
            } => get_selected(c, address_family.into(), protocol).await?,
        },
    }
    Ok(())
}

async fn get_imported(
    c: Client,
    address_family: AddressFamily,
    protocol: Option<ProtocolFilter>,
) -> Result<()> {
    let imported = c
        .get_rib_imported(Some(&address_family), protocol.as_ref())
        .await?
        .into_inner();

    print_rib(imported, address_family, protocol);
    Ok(())
}

async fn get_selected(
    c: Client,
    address_family: AddressFamily,
    protocol: Option<ProtocolFilter>,
) -> Result<()> {
    let selected = c
        .get_rib_selected(Some(&address_family), protocol.as_ref())
        .await?
        .into_inner();

    print_rib(selected, address_family, protocol);
    Ok(())
}

async fn read_bestpath_fanout(c: Client) -> Result<()> {
    let result = c.read_rib_bestpath_fanout().await?;
    println!("{}", result.into_inner().fanout);
    Ok(())
}

async fn update_bestpath_fanout(fanout: NonZeroU8, c: Client) -> Result<()> {
    c.update_rib_bestpath_fanout(&BestpathFanoutRequest { fanout })
        .await?;
    println!("Updated bestpath fanout to: {}", fanout);
    Ok(())
}
