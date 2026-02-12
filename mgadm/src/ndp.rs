// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Args, Subcommand};
use colored::Colorize;
use mg_admin_client::Client;
use mg_common::println_nopipe;
use std::io::{Write, stdout};
use tabwriter::TabWriter;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// View NDP status
    Status(StatusArgs),
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    #[command(subcommand)]
    command: StatusCmd,
}

#[derive(Subcommand, Debug)]
pub enum StatusCmd {
    /// Show NDP manager state
    Manager {
        #[clap(env)]
        asn: u32,
    },

    /// List all NDP-managed interfaces
    Interfaces {
        #[clap(env)]
        asn: u32,
    },

    /// Show detailed state for a specific interface
    Interface {
        interface: String,
        #[clap(env)]
        asn: u32,
    },
}

pub async fn commands(command: Commands, c: Client) -> Result<()> {
    match command {
        Commands::Status(args) => match args.command {
            StatusCmd::Manager { asn } => ndp_manager_status(asn, c).await?,
            StatusCmd::Interfaces { asn } => ndp_interfaces(asn, c).await?,
            StatusCmd::Interface { asn, interface } => {
                ndp_interface_detail(asn, interface, c).await?
            }
        },
    }
    Ok(())
}

async fn ndp_manager_status(asn: u32, c: Client) -> Result<()> {
    let state = c.get_ndp_manager_state(asn).await?.into_inner();

    println_nopipe!("NDP Manager State (ASN {})", asn);
    println_nopipe!("{}", "=".repeat(60));
    println_nopipe!();

    // Monitor thread status
    let monitor_status = if state.monitor_thread_running {
        "Running".green()
    } else {
        "Stopped".red()
    };
    println_nopipe!("Monitor Thread: {}", monitor_status);
    println_nopipe!();

    // Pending interfaces
    println_nopipe!(
        "Pending Interfaces (configured, waiting for system): {}",
        state.pending_interfaces.len()
    );
    if state.pending_interfaces.is_empty() {
        println_nopipe!("  (none)");
    } else {
        for pending in &state.pending_interfaces {
            println_nopipe!(
                "  {} (router_lifetime: {}s)",
                pending.interface,
                pending.router_lifetime
            );
        }
    }
    println_nopipe!();

    // Active interfaces
    println_nopipe!("Active Interfaces: {}", state.active_interfaces.len());
    if state.active_interfaces.is_empty() {
        println_nopipe!("  (none)");
    } else {
        for iface in &state.active_interfaces {
            println_nopipe!("  {}", iface);
        }
    }

    Ok(())
}

async fn ndp_interfaces(asn: u32, c: Client) -> Result<()> {
    let interfaces = c.get_ndp_interfaces(asn).await?.into_inner();

    if interfaces.is_empty() {
        println_nopipe!("No NDP-managed interfaces found for ASN {}", asn);
        return Ok(());
    }

    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        "Interface".dimmed(),
        "Local Address".dimmed(),
        "Scope".dimmed(),
        "Discovered Peer".dimmed(),
        "TX".dimmed(),
        "RX".dimmed(),
        "Reachable".dimmed(),
    )?;

    for iface in interfaces {
        let (peer_str, reachable_str) = match &iface.discovered_peer {
            Some(peer) => {
                let addr_str = format!("{}%{}", peer.address, iface.interface);
                let reachable = if peer.expired {
                    "No".red()
                } else {
                    "Yes".green()
                };
                (addr_str, reachable)
            }
            None => ("None".to_string(), "N/A".dimmed()),
        };

        let (tx_str, rx_str) = match &iface.thread_state {
            Some(ts) => {
                let tx = if ts.tx_running {
                    "Run".green()
                } else {
                    "Stop".red()
                };
                let rx = if ts.rx_running {
                    "Run".green()
                } else {
                    "Stop".red()
                };
                (tx, rx)
            }
            None => ("N/A".dimmed(), "N/A".dimmed()),
        };

        writeln!(
            &mut tw,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            iface.interface,
            iface.local_address,
            iface.scope_id,
            peer_str,
            tx_str,
            rx_str,
            reachable_str,
        )?;
    }

    tw.flush()?;
    Ok(())
}

async fn ndp_interface_detail(
    asn: u32,
    interface: String,
    c: Client,
) -> Result<()> {
    let detail = c
        .get_ndp_interface_detail(asn, &interface)
        .await?
        .into_inner();

    println_nopipe!("NDP State: {}", interface);
    println_nopipe!("{}", "=".repeat(60));
    println_nopipe!();

    println_nopipe!("Interface Information:");
    println_nopipe!("  Name: {}", detail.interface);
    println_nopipe!("  Local Address: {}", detail.local_address);
    println_nopipe!("  Scope ID: {}", detail.scope_id);
    println_nopipe!(
        "  Router Lifetime (advertised): {}s",
        detail.router_lifetime
    );
    println_nopipe!();

    // Thread state
    println_nopipe!("Thread State:");
    if let Some(ts) = &detail.thread_state {
        let tx_status = if ts.tx_running {
            "Running".green()
        } else {
            "Stopped".red()
        };
        let rx_status = if ts.rx_running {
            "Running".green()
        } else {
            "Stopped".red()
        };
        println_nopipe!("  TX Loop: {}", tx_status);
        println_nopipe!("  RX Loop: {}", rx_status);
    } else {
        println_nopipe!("  TX Loop: {}", "Unknown".dimmed());
        println_nopipe!("  RX Loop: {}", "Unknown".dimmed());
    }
    println_nopipe!();

    if let Some(peer) = detail.discovered_peer {
        if peer.expired {
            println_nopipe!("{}", "Discovered Peer (EXPIRED):".red());
        } else {
            println_nopipe!("Discovered Peer:");
        }

        println_nopipe!("  Address: {}", peer.address);
        println_nopipe!("  Discovered At: {}", peer.discovered_at);
        println_nopipe!("  Last Advertisement: {}", peer.last_advertisement);
        println_nopipe!("  Router Lifetime: {}s", peer.router_lifetime);
        println_nopipe!("  Reachable Time: {}ms", peer.reachable_time);
        println_nopipe!("  Retrans Timer: {}ms", peer.retrans_timer);

        if peer.expired {
            println_nopipe!("  Expired: {}", "Yes".red());
            if let Some(time_since) = peer.time_until_expiry {
                println_nopipe!("  Time Since Expiry: {}", time_since);
            }
        } else {
            println_nopipe!("  Expired: {}", "No".green());
            if let Some(time_until) = peer.time_until_expiry {
                println_nopipe!("  Time Until Expiry: {}", time_until);
            }
        }
    } else {
        println_nopipe!("Discovered Peer: None");
    }

    Ok(())
}
