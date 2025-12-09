// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! MRIB (Multicast RIB) administration commands.
//!
//! This module provides read-only inspection of multicast routing state.
//! Omicron is the source of truth for multicast group membership and
//! programs the MRIB via the mg-api. Administrative writes are not
//! exposed here to avoid conflicts with Omicron-managed state.

use std::net::IpAddr;

use anyhow::Result;
use clap::{Args, Subcommand};

use mg_admin_client::Client;
use mg_admin_client::types::{
    MribRpfRebuildIntervalRequest, MulticastRoute, MulticastRouteKey,
    RouteOriginFilter,
};
use rdb::types::{AddressFamily, DEFAULT_MULTICAST_VNI};

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

    /// RPF (Reverse Path Forwarding) table configuration and lookup.
    Rpf(RpfCommand),
}

#[derive(Debug, Args)]
pub struct StatusCommand {
    #[command(subcommand)]
    command: StatusCmd,
}

#[derive(Subcommand, Debug)]
pub enum StatusCmd {
    /// Get imported multicast routes (`mrib_in`).
    ///
    /// Lists all routes, or gets a specific route with `-g`.
    ///
    /// Usage: `mrib status imported [ipv4|ipv6] [-g group] [-s source] [-v vni]`
    Imported {
        /// Address family to filter by.
        #[arg(value_enum)]
        address_family: Option<AddressFamily>,

        /// Multicast group address (if omitted, lists all routes).
        #[arg(short, long)]
        group: Option<IpAddr>,

        /// Source address (omit for any-source (*,G)).
        #[arg(short, long)]
        source: Option<IpAddr>,

        /// VNI (defaults to DEFAULT_MULTICAST_VNI for fleet-scoped multicast).
        #[arg(short, long, default_value_t = DEFAULT_MULTICAST_VNI)]
        vni: u32,

        /// Filter by route origin ("static" or "dynamic").
        #[arg(long, value_parser = parse_route_origin)]
        origin: Option<RouteOriginFilter>,
    },

    /// Get selected multicast routes (`mrib_loc`, RPF-validated).
    ///
    /// Lists all routes, or gets a specific route with `-g`.
    ///
    /// Usage: `mrib status selected [ipv4|ipv6] [-g group] [-s source] [-v vni]`
    Selected {
        /// Address family to filter by.
        #[arg(value_enum)]
        address_family: Option<AddressFamily>,

        /// Multicast group address (if omitted, lists all routes).
        #[arg(short, long)]
        group: Option<IpAddr>,

        /// Source address (omit for any-source (*,G)).
        #[arg(short, long)]
        source: Option<IpAddr>,

        /// VNI (defaults to DEFAULT_MULTICAST_VNI for fleet-scoped multicast).
        #[arg(short, long, default_value_t = DEFAULT_MULTICAST_VNI)]
        vni: u32,

        /// Filter by route origin ("static" or "dynamic").
        #[arg(long, value_parser = parse_route_origin)]
        origin: Option<RouteOriginFilter>,
    },
}

#[derive(Debug, Args)]
pub struct RpfCommand {
    #[command(subcommand)]
    command: RpfCmd,
}

#[derive(Subcommand, Debug)]
pub enum RpfCmd {
    /// Get RPF rebuild interval.
    GetInterval,

    /// Set RPF rebuild interval.
    SetInterval {
        /// Rebuild interval in milliseconds
        interval_ms: u64,
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
                    get_route(c, g, source, vni).await?
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
                    get_route_selected(c, g, source, vni).await?
                } else {
                    get_selected(c, address_family, origin).await?
                }
            }
        },
        Commands::Rpf(rpf_cmd) => match rpf_cmd.command {
            RpfCmd::GetInterval => get_rpf_interval(c).await?,
            RpfCmd::SetInterval { interval_ms } => {
                set_rpf_interval(c, interval_ms).await?
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
        .get_mrib_imported(address_family.as_ref(), None, origin, None, None)
        .await?
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
        .get_mrib_selected(address_family.as_ref(), None, origin, None, None)
        .await?
        .into_inner();
    print_routes(&routes);
    Ok(())
}

async fn get_route(
    c: Client,
    group: IpAddr,
    source: Option<IpAddr>,
    vni: u32,
) -> Result<()> {
    let routes = c
        .get_mrib_imported(None, Some(&group), None, source.as_ref(), Some(vni))
        .await?
        .into_inner();
    if let Some(route) = routes.first() {
        println!("{route:#?}");
    } else {
        anyhow::bail!("route not found");
    }
    Ok(())
}

async fn get_route_selected(
    c: Client,
    group: IpAddr,
    source: Option<IpAddr>,
    vni: u32,
) -> Result<()> {
    let routes = c
        .get_mrib_selected(None, Some(&group), None, source.as_ref(), Some(vni))
        .await?
        .into_inner();
    if let Some(route) = routes.first() {
        println!("{route:#?}");
    } else {
        anyhow::bail!("route not found in mrib_loc");
    }
    Ok(())
}

async fn get_rpf_interval(c: Client) -> Result<()> {
    let result = c.read_mrib_rpf_rebuild_interval().await?.into_inner();
    println!("RPF rebuild interval: {}ms", result.interval_ms);
    Ok(())
}

async fn set_rpf_interval(c: Client, interval_ms: u64) -> Result<()> {
    c.update_mrib_rpf_rebuild_interval(&MribRpfRebuildIntervalRequest {
        interval_ms,
    })
    .await?;
    println!("Updated RPF rebuild interval to: {interval_ms}ms");
    Ok(())
}

fn print_routes(routes: &[MulticastRoute]) {
    if routes.is_empty() {
        println!("No multicast routes");
        return;
    }
    for route in routes {
        let (source_str, group_str, vni) = match &route.key {
            MulticastRouteKey::V4(k) => {
                let src = k.source.map_or("*".to_string(), |s| s.to_string());
                let grp = k.group.to_string();
                (src, grp, k.vni)
            }
            MulticastRouteKey::V6(k) => {
                let src = k.source.map_or("*".to_string(), |s| s.to_string());
                let grp = k.group.to_string();
                (src, grp, k.vni)
            }
        };
        println!(
            "({source_str},{group_str}) vni={vni} underlay={} rpf={:?} nexthops={} source={:?}",
            route.underlay_group,
            route.rpf_neighbor,
            route.underlay_nexthops.len(),
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

        match cli.command {
            Commands::Status(cmd) => match cmd.command {
                StatusCmd::Imported {
                    group, source, vni, ..
                } => {
                    assert_eq!(
                        group,
                        Some(IpAddr::V4(Ipv4Addr::new(225, 1, 2, 3)))
                    );
                    assert_eq!(source, None);
                    assert_eq!(vni, DEFAULT_MULTICAST_VNI);
                }
                _ => panic!("expected Imported"),
            },
            _ => panic!("expected Status command"),
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

        match cli.command {
            Commands::Status(cmd) => match cmd.command {
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
            },
            _ => panic!("expected Status command"),
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

        match cli.command {
            Commands::Status(cmd) => match cmd.command {
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
            },
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn test_status_imported_list_with_af() {
        let cli =
            TestCli::try_parse_from(["test", "status", "imported", "ipv4"])
                .unwrap();

        match cli.command {
            Commands::Status(cmd) => match cmd.command {
                StatusCmd::Imported {
                    group,
                    address_family,
                    ..
                } => {
                    assert_eq!(group, None);
                    assert_eq!(address_family, Some(AddressFamily::Ipv4));
                }
                _ => panic!("expected Imported"),
            },
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn test_status_imported_list_with_origin() {
        let cli = TestCli::try_parse_from([
            "test", "status", "imported", "--origin", "dynamic",
        ])
        .unwrap();

        match cli.command {
            Commands::Status(cmd) => match cmd.command {
                StatusCmd::Imported { group, origin, .. } => {
                    assert_eq!(group, None);
                    assert_eq!(origin, Some(RouteOriginFilter::Dynamic));
                }
                _ => panic!("expected Imported"),
            },
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn test_status_selected_list_all() {
        let cli =
            TestCli::try_parse_from(["test", "status", "selected"]).unwrap();

        match cli.command {
            Commands::Status(cmd) => match cmd.command {
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
            },
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn test_rpf_set_interval() {
        let cli =
            TestCli::try_parse_from(["test", "rpf", "set-interval", "500"])
                .unwrap();

        match cli.command {
            Commands::Rpf(cmd) => match cmd.command {
                RpfCmd::SetInterval { interval_ms } => {
                    assert_eq!(interval_ms, 500);
                }
                _ => panic!("expected SetInterval"),
            },
            _ => panic!("expected Rpf command"),
        }
    }
}
