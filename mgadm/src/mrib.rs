// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! MRIB (Multicast RIB) inspection commands.
//!
//! This module provides read-only inspection of multicast routing state.
//! Omicron is the source of truth for multicast group membership and
//! programs the MRIB via the mg-api. Administrative writes are not
//! exposed here to avoid conflicts with Omicron-managed state.

use std::net::IpAddr;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use client_common::println_nopipe;
use mg_admin_client::Client;
use mg_api_types::mrib::{
    MulticastAddr, MulticastRoute, RouteOriginFilter, Vni,
};
use mg_api_types::rdb::rib::AddressFamily;

fn parse_route_origin(s: &str) -> Result<RouteOriginFilter, String> {
    match s.to_lowercase().as_str() {
        "static" => Ok(RouteOriginFilter::Static),
        "dynamic" => Ok(RouteOriginFilter::Dynamic),
        _ => Err(format!(
            "invalid origin: {s} (expected 'static' or 'dynamic')"
        )),
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// View MRIB state.
    Status(StatusCommand),
}

#[derive(Debug, Args)]
pub struct StatusCommand {
    #[command(subcommand)]
    command: StatusCmd,
}

#[derive(Subcommand, Debug)]
pub enum StatusCmd {
    /// Get the mrib_in table. Contains all configured multicast routes.
    Imported {
        /// Address family to filter by.
        #[arg(value_enum)]
        address_family: Option<AddressFamily>,

        /// Multicast group address (if omitted, lists all routes).
        #[arg(short, long, conflicts_with = "address_family")]
        group: Option<IpAddr>,

        /// Source address (omit for any-source (*,G)).
        #[arg(short, long, conflicts_with = "address_family")]
        source: Option<IpAddr>,

        /// VNI to filter by (if omitted, matches every VNI).
        #[arg(short, long)]
        vni: Option<Vni>,

        /// Filter by route origin ("static" or "dynamic").
        #[arg(long, value_parser = parse_route_origin)]
        origin: Option<RouteOriginFilter>,
    },

    /// Get the mrib_loc table. Contains (*,G) routes and (S,G) routes whose
    /// source is reachable in the unicast loc-rib.
    Selected {
        /// Address family to filter by.
        #[arg(value_enum)]
        address_family: Option<AddressFamily>,

        /// Multicast group address (if omitted, lists all routes).
        #[arg(short, long, conflicts_with = "address_family")]
        group: Option<IpAddr>,

        /// Source address (omit for any-source (*,G)).
        #[arg(short, long, conflicts_with = "address_family")]
        source: Option<IpAddr>,

        /// VNI to filter by (if omitted, matches every VNI).
        #[arg(short, long)]
        vni: Option<Vni>,

        /// Filter by route origin ("static" or "dynamic").
        #[arg(long, value_parser = parse_route_origin)]
        origin: Option<RouteOriginFilter>,
    },
}

pub async fn commands(command: Commands, c: Client) -> Result<()> {
    let Commands::Status(status_cmd) = command;
    let (selected, address_family, group, source, vni, origin) =
        match status_cmd.command {
            StatusCmd::Imported {
                address_family,
                group,
                source,
                vni,
                origin,
            } => (false, address_family, group, source, vni, origin),
            StatusCmd::Selected {
                address_family,
                group,
                source,
                vni,
                origin,
            } => (true, address_family, group, source, vni, origin),
        };

    let group = group
        .map(MulticastAddr::try_from)
        .transpose()
        .context("invalid multicast group")?;

    let res = if selected {
        c.get_mrib_selected(
            address_family.as_ref(),
            group.as_ref(),
            origin.as_ref(),
            source.as_ref(),
            vni.as_ref(),
        )
        .await
    } else {
        c.get_mrib_imported(
            address_family.as_ref(),
            group.as_ref(),
            origin.as_ref(),
            source.as_ref(),
            vni.as_ref(),
        )
        .await
    };
    let routes = res.context("get MRIB routes")?.into_inner();

    let filtered = group.is_some()
        || source.is_some()
        || vni.is_some()
        || address_family.is_some()
        || origin.is_some();
    if routes.is_empty() && filtered {
        println_nopipe!("No multicast routes match the given filters");
        return Ok(());
    }
    print_routes(&routes);
    Ok(())
}

fn print_routes(routes: &[MulticastRoute]) {
    if routes.is_empty() {
        println_nopipe!("No multicast routes");
        return;
    }
    for route in routes {
        let source = route
            .key
            .source()
            .map_or_else(|| "*".to_string(), |s| s.to_string());

        println_nopipe!(
            "({source},{}) vni={} underlay={} source={:?}",
            route.key.group(),
            route.key.vni(),
            route.underlay_group,
            route.source,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Wrapper to test subcommand parsing
    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(subcommand)]
        command: Commands,
    }

    #[test]
    fn test_status_imported_specific_route() {
        let cli = TestCli::try_parse_from([
            "test",
            "status",
            "imported",
            "-g",
            "225.1.2.3",
        ])
        .unwrap();

        let Commands::Status(cmd) = cli.command;
        match cmd.command {
            StatusCmd::Imported {
                group, source, vni, ..
            } => {
                assert_eq!(
                    group,
                    Some(IpAddr::V4(Ipv4Addr::new(225, 1, 2, 3)))
                );
                assert_eq!(source, None);
                assert_eq!(vni, None);
            }
            _ => panic!("expected Imported"),
        }
    }

    #[test]
    fn test_status_imported_specific_route_all_flags() {
        let cli = TestCli::try_parse_from([
            "test",
            "status",
            "imported",
            "-g",
            "225.1.2.3",
            "-s",
            "10.0.0.1",
            "-v",
            "100",
        ])
        .unwrap();

        let Commands::Status(cmd) = cli.command;
        match cmd.command {
            StatusCmd::Imported {
                group, source, vni, ..
            } => {
                assert_eq!(
                    group,
                    Some(IpAddr::V4(Ipv4Addr::new(225, 1, 2, 3)))
                );
                assert_eq!(
                    source,
                    Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
                );
                assert_eq!(vni, Some(Vni::new(100).unwrap()));
            }
            _ => panic!("expected Imported"),
        }
    }

    #[test]
    fn test_status_selected_specific_route_ipv6() {
        let cli = TestCli::try_parse_from([
            "test",
            "status",
            "selected",
            "--group",
            "ff0e::1",
            "--source",
            "2001:db8::1",
            "--vni",
            "42",
        ])
        .unwrap();

        let Commands::Status(cmd) = cli.command;
        match cmd.command {
            StatusCmd::Selected {
                group, source, vni, ..
            } => {
                assert_eq!(
                    group,
                    Some(IpAddr::V6(Ipv6Addr::new(
                        0xff0e, 0, 0, 0, 0, 0, 0, 1
                    )))
                );
                assert_eq!(
                    source,
                    Some(IpAddr::V6(Ipv6Addr::new(
                        0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
                    )))
                );
                assert_eq!(vni, Some(Vni::new(42).unwrap()));
            }
            _ => panic!("expected Selected"),
        }
    }

    #[test]
    fn test_status_imported_list_with_af() {
        let cli =
            TestCli::try_parse_from(["test", "status", "imported", "ipv4"])
                .unwrap();

        let Commands::Status(cmd) = cli.command;
        match cmd.command {
            StatusCmd::Imported {
                group,
                address_family,
                ..
            } => {
                assert_eq!(group, None);
                assert_eq!(address_family, Some(AddressFamily::Ipv4));
            }
            _ => panic!("expected Imported"),
        }
    }

    #[test]
    fn test_status_imported_list_with_origin() {
        let cli = TestCli::try_parse_from([
            "test", "status", "imported", "--origin", "dynamic",
        ])
        .unwrap();

        let Commands::Status(cmd) = cli.command;
        match cmd.command {
            StatusCmd::Imported { group, origin, .. } => {
                assert_eq!(group, None);
                assert_eq!(origin, Some(RouteOriginFilter::Dynamic));
            }
            _ => panic!("expected Imported"),
        }
    }

    #[test]
    fn test_status_selected_list_all() {
        let cli =
            TestCli::try_parse_from(["test", "status", "selected"]).unwrap();

        let Commands::Status(cmd) = cli.command;
        match cmd.command {
            StatusCmd::Selected {
                group,
                address_family,
                origin,
                ..
            } => {
                assert_eq!(group, None);
                assert_eq!(address_family, None);
                assert_eq!(origin, None);
            }
            _ => panic!("expected Selected"),
        }
    }

    #[test]
    fn test_status_filter_combinations() {
        let parses = |table, args: &[&str]| {
            let argv = ["test", "status", table]
                .into_iter()
                .chain(args.iter().copied());
            TestCli::try_parse_from(argv).is_ok()
        };
        for table in ["imported", "selected"] {
            for args in [
                &["-g", "239.1.1.1", "ipv4"][..],
                &["-s", "10.0.0.1", "ipv4"],
                &["-v", "16777216"],
                &["-v", "not-a-vni"],
            ] {
                assert!(!parses(table, args), "{table} {args:?} should fail");
            }
            for args in [
                &["-g", "239.1.1.1", "--origin", "dynamic"][..],
                &["-s", "10.0.0.1"],
                &["-v", "100"],
                &["-v", "100", "--origin", "static", "ipv6"],
            ] {
                assert!(parses(table, args), "{table} {args:?} should parse");
            }
        }
    }
}
