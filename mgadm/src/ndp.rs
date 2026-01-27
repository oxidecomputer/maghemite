// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;
use mg_admin_client::Client;
use std::io::{Write, stdout};
use tabwriter::TabWriter;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List all interfaces with NDP discovery state
    List {
        #[clap(env)]
        asn: u32,
    },

    /// Get detailed NDP state for a specific interface
    Status {
        #[clap(env)]
        asn: u32,
        interface: String,
    },
}

pub async fn commands(command: Commands, c: Client) -> Result<()> {
    match command {
        Commands::List { asn } => ndp_list(asn, c).await?,
        Commands::Status { asn, interface } => {
            ndp_status(asn, interface, c).await?
        }
    }
    Ok(())
}

async fn ndp_list(asn: u32, c: Client) -> Result<()> {
    let interfaces = c.get_ndp_interfaces(asn).await?.into_inner();

    if interfaces.is_empty() {
        println!("No NDP-managed interfaces found for ASN {}", asn);
        return Ok(());
    }

    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}",
        "Interface".dimmed(),
        "Local Address".dimmed(),
        "Scope ID".dimmed(),
        "Discovered Peer".dimmed(),
        "Reachable".dimmed(),
    )?;

    for iface in interfaces {
        let (peer_str, reachable_str) = match &iface.discovered_peer {
            Some(peer) => {
                let addr_str = format!("{}%{}", peer.address, iface.interface);
                let reachable = if peer.expired {
                    "No (expired)".red()
                } else {
                    "Yes".green()
                };
                (addr_str, reachable)
            }
            None => ("None".to_string(), "N/A".dimmed()),
        };

        writeln!(
            &mut tw,
            "{}\t{}\t{}\t{}\t{}",
            iface.interface,
            iface.local_address,
            iface.scope_id,
            peer_str,
            reachable_str,
        )?;
    }

    tw.flush()?;
    Ok(())
}

async fn ndp_status(asn: u32, interface: String, c: Client) -> Result<()> {
    let detail = c
        .get_ndp_interface_detail(asn, &interface)
        .await?
        .into_inner();

    println!("{}", "=".repeat(80));
    println!("NDP State: {}", interface);
    println!("{}", "=".repeat(80));
    println!();

    println!("Interface Information:");
    println!("  Name: {}", detail.interface);
    println!("  Local Address: {}", detail.local_address);
    println!("  Scope ID: {}", detail.scope_id);
    println!(
        "  Router Lifetime (advertised): {}s",
        detail.router_lifetime
    );
    println!();

    if let Some(peer) = detail.discovered_peer {
        if peer.expired {
            println!("{}", "Discovered Peer (EXPIRED):".red());
        } else {
            println!("Discovered Peer:");
        }

        println!("  Address: {}", peer.address);
        println!("  Discovered At: {}", peer.discovered_at);
        println!("  Last Advertisement: {}", peer.last_advertisement);
        println!("  Router Lifetime: {}s", peer.router_lifetime);
        println!("  Reachable Time: {}ms", peer.reachable_time);
        println!("  Retrans Timer: {}ms", peer.retrans_timer);

        if peer.expired {
            println!("  Expired: {}", "Yes".red());
            if let Some(time_since) = peer.time_until_expiry {
                println!("  Time Since Expiry: {}", time_since);
            }
        } else {
            println!("  Expired: {}", "No".green());
            if let Some(time_until) = peer.time_until_expiry {
                println!("  Time Until Expiry: {}", time_until);
            }
        }
    } else {
        println!("Discovered Peer: None");
    }

    Ok(())
}
