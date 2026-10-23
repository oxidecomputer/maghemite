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

const DEFAULT_VNI: u32 = Vni::DEFAULT_MULTICAST.as_u32();

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
        #[arg(short, long, conflicts_with_all = ["address_family", "origin"])]
        group: Option<IpAddr>,

        /// Source address (omit for any-source (*,G)).
        #[arg(short, long, requires = "group")]
        source: Option<IpAddr>,

        /// VNI (defaults to Vni::DEFAULT_MULTICAST for fleet-scoped multicast).
        #[arg(short, long, requires = "group", default_value_t = DEFAULT_VNI, value_parser = clap::value_parser!(u32).range(0..=(Vni::MAX_VNI as i64)))]
        vni: u32,

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
        #[arg(short, long, conflicts_with_all = ["address_family", "origin"])]
        group: Option<IpAddr>,

        /// Source address (omit for any-source (*,G)).
        #[arg(short, long, requires = "group")]
        source: Option<IpAddr>,

        /// VNI (defaults to Vni::DEFAULT_MULTICAST for fleet-scoped multicast).
        #[arg(short, long, requires = "group", default_value_t = DEFAULT_VNI, value_parser = clap::value_parser!(u32).range(0..=(Vni::MAX_VNI as i64)))]
        vni: u32,

        /// Filter by route origin ("static" or "dynamic").
        #[arg(long, value_parser = parse_route_origin)]
        origin: Option<RouteOriginFilter>,
    },
}

pub async fn commands(command: Commands, c: Client) -> Result<()> {
    match command {
        Commands::Status(status_cmd) => match status_cmd.command {
            StatusCmd::Imported {
                group,
                source,
                vni,
                address_family,
                origin,
            } => {
                if let Some(g) = group {
                    get_route(c, g, source, Vni::new(vni)?).await?
                } else {
                    get_imported(c, address_family, origin).await?
                }
            }
            StatusCmd::Selected {
                group,
                source,
                vni,
                address_family,
                origin,
            } => {
                if let Some(g) = group {
                    get_route_selected(c, g, source, Vni::new(vni)?).await?
                } else {
                    get_selected(c, address_family, origin).await?
                }
            }
        },
    }
    Ok(())
}

async fn get_imported(
    c: Client,
    address_family: Option<AddressFamily>,
    origin: Option<RouteOriginFilter>,
) -> Result<()> {
    let routes = c
        .get_mrib_imported(
            address_family.as_ref(),
            None,
            origin.as_ref(),
            None,
            None,
        )
        .await
        .context("get imported MRIB routes")?
        .into_inner();
    print_routes(&routes);
    Ok(())
}

async fn get_selected(
    c: Client,
    address_family: Option<AddressFamily>,
    origin: Option<RouteOriginFilter>,
) -> Result<()> {
    let routes = c
        .get_mrib_selected(
            address_family.as_ref(),
            None,
            origin.as_ref(),
            None,
            None,
        )
        .await
        .context("get selected MRIB routes")?
        .into_inner();
    print_routes(&routes);
    Ok(())
}

async fn get_route(
    c: Client,
    group: IpAddr,
    source: Option<IpAddr>,
    vni: Vni,
) -> Result<()> {
    let group =
        MulticastAddr::try_from(group).context("invalid multicast group")?;
    let route = c
        .get_mrib_imported(
            None,
            Some(&group),
            None,
            source.as_ref(),
            Some(&vni),
        )
        .await
        .with_context(|| format!("look up imported MRIB route for {group}"))?
        .into_inner()
        .into_iter()
        .next()
        .context("route not found")?;

    println_nopipe!("{route:#?}");

    Ok(())
}

async fn get_route_selected(
    c: Client,
    group: IpAddr,
    source: Option<IpAddr>,
    vni: Vni,
) -> Result<()> {
    let group =
        MulticastAddr::try_from(group).context("invalid multicast group")?;
    let route = c
        .get_mrib_selected(
            None,
            Some(&group),
            None,
            source.as_ref(),
            Some(&vni),
        )
        .await
        .with_context(|| format!("look up selected MRIB route for {group}"))?
        .into_inner()
        .into_iter()
        .next()
        .context("route not found in mrib_loc")?;

    println_nopipe!("{route:#?}");

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
                assert_eq!(vni, DEFAULT_VNI);
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
                assert_eq!(vni, 100);
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
                assert_eq!(vni, 42);
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
    fn test_status_rejects_ignored_selectors() {
        for table in ["imported", "selected"] {
            for args in [
                &["-g", "239.1.1.1", "--origin", "dynamic"][..],
                &["-g", "239.1.1.1", "ipv4"],
                &["-s", "10.0.0.1"],
                &["-v", "100"],
            ] {
                let argv = ["test", "status", table]
                    .into_iter()
                    .chain(args.iter().copied());
                assert!(
                    TestCli::try_parse_from(argv).is_err(),
                    "{table} {args:?} should be rejected"
                );
            }
        }
    }
}
