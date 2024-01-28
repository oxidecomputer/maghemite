// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use colored::Colorize;
use mg_admin_client::{
    types::{BfdPeerConfig, SessionMode},
    Client,
};
use std::io::Write;
use std::net::IpAddr;
use tabwriter::TabWriter;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Mode {
    SingleHop,
    MultiHop,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Get the list of configured peers.
    GetPeers,

    /// Add a peer.
    AddPeer {
        /// Address of the peer.
        peer: IpAddr,
        /// Address to listen on.
        listen: IpAddr,
        /// Acceptable time between control messages in microseconds.
        required_rx: u64,
        /// Detection threshold for connectivity as a multipler to required_rx
        detection_threshold: u8,
        /// Session mode is either single-hop or multi-hop
        mode: Mode,
    },

    /// Remove a peer.
    RemovePeer {
        /// Address of the peer.
        peer: IpAddr,
    },
}

pub async fn commands(command: Commands, client: Client) -> Result<()> {
    match command {
        Commands::GetPeers => {
            let msg = client.get_bfd_peers().await?;
            let mut tw = TabWriter::new(std::io::stdout());
            writeln!(
                &mut tw,
                "{}\t{}\t{}\t{}\t{}\t{}",
                "Peer".dimmed(),
                "Listen".dimmed(),
                "Required Rx".dimmed(),
                "Detection Threshold".dimmed(),
                "Mode".dimmed(),
                "Status".dimmed(),
            )?;
            for info in &msg.into_inner() {
                writeln!(
                    &mut tw,
                    "{}\t{}\t{}\t{}\t{:?}\t{:?}",
                    info.config.peer,
                    info.config.listen,
                    info.config.required_rx,
                    info.config.detection_threshold,
                    info.config.mode,
                    info.state,
                )?;
            }
            tw.flush()?;
        }
        Commands::AddPeer {
            peer,
            listen,
            required_rx,
            detection_threshold,
            mode,
        } => {
            client
                .add_bfd_peer(&BfdPeerConfig {
                    peer,
                    listen,
                    required_rx,
                    detection_threshold,
                    mode: match mode {
                        Mode::SingleHop => SessionMode::SingleHop,
                        Mode::MultiHop => SessionMode::MultiHop,
                    },
                })
                .await?;
        }
        Commands::RemovePeer { peer } => {
            client.remove_bfd_peer(&peer).await?;
        }
    }

    Ok(())
}
