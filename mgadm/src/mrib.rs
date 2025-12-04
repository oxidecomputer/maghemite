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
use clap::{Args, Subcommand, ValueEnum};

use mg_admin_client::Client;
use mg_admin_client::types::{
    MribRpfRebuildIntervalRequest, MulticastAddr, MulticastRoute,
    RouteOriginFilter,
};
use rdb::types::AddressFamily;

/// Filter for route origin.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum RouteOrigin {
    /// Static routes only (manually configured).
    Static,
    /// Dynamic routes only (learned via IGMP, MLD, etc.).
    Dynamic,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// View MRIB state.
    Status(StatusCommand),

    /// Get a specific multicast route by key.
    Get(GetCommand),

    /// Get a specific installed multicast route (mrib_loc).
    GetInstalled(GetCommand),

    /// RPF rebuild configuration.
    Rpf(RpfCommand),

    /// Static multicast route management.
    Static(StaticCommand),
}

#[derive(Debug, Args)]
pub struct StatusCommand {
    #[command(subcommand)]
    command: StatusCmd,
}

#[derive(Subcommand, Debug)]
pub enum StatusCmd {
    /// Get all imported multicast routes (`mrib_in`).
    Imported {
        /// Filter by address family.
        #[arg(short, long, value_enum)]
        af: Option<AddressFamily>,

        /// Filter by route origin ("static" or "dynamic").
        #[arg(long, value_enum)]
        origin: Option<RouteOrigin>,
    },

    /// Get installed multicast routes (`mrib_loc`, RPF-validated).
    Installed {
        /// Filter by address family.
        #[arg(short, long, value_enum)]
        af: Option<AddressFamily>,

        /// Filter by route origin ("static" or "dynamic").
        #[arg(long, value_enum)]
        origin: Option<RouteOrigin>,
    },
}

#[derive(Debug, Args)]
pub struct GetCommand {
    /// Multicast group address.
    #[arg(short, long)]
    group: IpAddr,

    /// Source address (omit for any-source (*,G)).
    #[arg(short, long)]
    source: Option<IpAddr>,

    /// VNI (defaults to 77 for fleet-scoped multicast).
    #[arg(short, long, default_value_t = 77)]
    vni: u32,
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

#[derive(Debug, Args)]
pub struct StaticCommand {
    #[command(subcommand)]
    command: StaticRouteCmd,
}

#[derive(Subcommand, Debug)]
pub enum StaticRouteCmd {
    /// List all static multicast routes.
    List,
}

pub async fn commands(command: Commands, c: Client) -> Result<()> {
    match command {
        Commands::Status(status_cmd) => match status_cmd.command {
            StatusCmd::Imported { af, origin } => {
                get_imported(c, af, origin).await?
            }
            StatusCmd::Installed { af, origin } => {
                get_installed(c, af, origin).await?
            }
        },
        Commands::Get(get_cmd) => {
            get_route(c, get_cmd.group, get_cmd.source, get_cmd.vni).await?
        }
        Commands::GetInstalled(get_cmd) => {
            get_route_installed(c, get_cmd.group, get_cmd.source, get_cmd.vni)
                .await?
        }
        Commands::Rpf(rpf_cmd) => match rpf_cmd.command {
            RpfCmd::GetInterval => get_rpf_interval(c).await?,
            RpfCmd::SetInterval { interval_ms } => {
                set_rpf_interval(c, interval_ms).await?
            }
        },
        Commands::Static(static_cmd) => match static_cmd.command {
            StaticRouteCmd::List => static_list(c).await?,
        },
    }
    Ok(())
}

async fn get_imported(
    c: Client,
    af: Option<AddressFamily>,
    origin: Option<RouteOrigin>,
) -> Result<()> {
    let origin_filter = origin.map(|o| match o {
        RouteOrigin::Static => RouteOriginFilter::Static,
        RouteOrigin::Dynamic => RouteOriginFilter::Dynamic,
    });
    let routes = c
        .mrib_status_imported(af.as_ref(), origin_filter)
        .await?
        .into_inner();
    print_routes(&routes);
    Ok(())
}

async fn get_installed(
    c: Client,
    af: Option<AddressFamily>,
    origin: Option<RouteOrigin>,
) -> Result<()> {
    let origin_filter = origin.map(|o| match o {
        RouteOrigin::Static => RouteOriginFilter::Static,
        RouteOrigin::Dynamic => RouteOriginFilter::Dynamic,
    });
    let routes = c
        .mrib_status_installed(af.as_ref(), origin_filter)
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
    let route = c
        .mrib_get_route(&group, source.as_ref(), Some(vni))
        .await?
        .into_inner();
    println!("{route:#?}");
    Ok(())
}

async fn get_route_installed(
    c: Client,
    group: IpAddr,
    source: Option<IpAddr>,
    vni: u32,
) -> Result<()> {
    let route = c
        .mrib_get_selected_route(&group, source.as_ref(), Some(vni))
        .await?
        .into_inner();
    println!("{route:#?}");
    Ok(())
}

async fn get_rpf_interval(c: Client) -> Result<()> {
    let result = c.mrib_get_rpf_rebuild_interval().await?.into_inner();
    println!("RPF rebuild interval: {}ms", result.interval_ms);
    Ok(())
}

async fn set_rpf_interval(c: Client, interval_ms: u64) -> Result<()> {
    c.mrib_set_rpf_rebuild_interval(&MribRpfRebuildIntervalRequest {
        interval_ms,
    })
    .await?;
    println!("Updated RPF rebuild interval to: {interval_ms}ms");
    Ok(())
}

async fn static_list(c: Client) -> Result<()> {
    let routes = c.mrib_static_list().await?.into_inner();
    if routes.is_empty() {
        println!("No static multicast routes");
    } else {
        print_routes(&routes);
    }
    Ok(())
}

fn print_routes(routes: &[MulticastRoute]) {
    if routes.is_empty() {
        println!("No multicast routes");
        return;
    }
    for route in routes {
        let key = &route.key;
        let source_str = match &key.source {
            Some(s) => s.to_string(),
            None => "*".to_string(),
        };
        let group_str = match &key.group {
            MulticastAddr::V4(v4) => v4.to_string(),
            MulticastAddr::V6(v6) => v6.to_string(),
        };
        println!(
            "({source_str},{group_str}) vni={} underlay={} rpf={:?} nexthops={} source={:?}",
            key.vni,
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
    fn test_get_command_group_only() {
        let cli = TestCli::try_parse_from(["test", "get", "-g", "225.1.2.3"])
            .unwrap();

        match cli.command {
            Commands::Get(cmd) => {
                assert_eq!(cmd.group, IpAddr::V4(Ipv4Addr::new(225, 1, 2, 3)));
                assert_eq!(cmd.source, None);
                assert_eq!(cmd.vni, 77); // default
            }
            _ => panic!("expected Get command"),
        }
    }

    #[test]
    fn test_get_command_all_flags() {
        let cli = TestCli::try_parse_from([
            "test",
            "get",
            "-g",
            "225.1.2.3",
            "-s",
            "10.0.0.1",
            "-v",
            "100",
        ])
        .unwrap();

        match cli.command {
            Commands::Get(cmd) => {
                assert_eq!(cmd.group, IpAddr::V4(Ipv4Addr::new(225, 1, 2, 3)));
                assert_eq!(
                    cmd.source,
                    Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
                );
                assert_eq!(cmd.vni, 100);
            }
            _ => panic!("expected Get command"),
        }
    }

    #[test]
    fn test_get_command_ipv6() {
        let cli = TestCli::try_parse_from([
            "test",
            "get",
            "--group",
            "ff0e::1",
            "--source",
            "2001:db8::1",
            "--vni",
            "42",
        ])
        .unwrap();

        match cli.command {
            Commands::Get(cmd) => {
                assert_eq!(
                    cmd.group,
                    IpAddr::V6(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 1))
                );
                assert_eq!(
                    cmd.source,
                    Some(IpAddr::V6(Ipv6Addr::new(
                        0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
                    )))
                );
                assert_eq!(cmd.vni, 42);
            }
            _ => panic!("expected Get command"),
        }
    }

    #[test]
    fn test_status_imported_with_af() {
        let cli = TestCli::try_parse_from([
            "test", "status", "imported", "-a", "ipv4",
        ])
        .unwrap();

        match cli.command {
            Commands::Status(cmd) => match cmd.command {
                StatusCmd::Imported { af, origin } => {
                    assert_eq!(af, Some(AddressFamily::Ipv4));
                    assert_eq!(origin, None);
                }
                _ => panic!("expected Imported"),
            },
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn test_status_imported_with_origin() {
        let cli = TestCli::try_parse_from([
            "test", "status", "imported", "--origin", "dynamic",
        ])
        .unwrap();

        match cli.command {
            Commands::Status(cmd) => match cmd.command {
                StatusCmd::Imported { af, origin } => {
                    assert_eq!(af, None);
                    assert_eq!(origin, Some(RouteOrigin::Dynamic));
                }
                _ => panic!("expected Imported"),
            },
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn test_status_installed_no_af() {
        let cli =
            TestCli::try_parse_from(["test", "status", "installed"]).unwrap();

        match cli.command {
            Commands::Status(cmd) => match cmd.command {
                StatusCmd::Installed { af, origin } => {
                    assert_eq!(af, None);
                    assert_eq!(origin, None);
                }
                _ => panic!("expected Installed"),
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

    #[test]
    fn test_static_list() {
        let cli = TestCli::try_parse_from(["test", "static", "list"]).unwrap();

        match cli.command {
            Commands::Static(cmd) => {
                assert!(matches!(cmd.command, StaticRouteCmd::List));
            }
            _ => panic!("expected Static command"),
        }
    }
}
