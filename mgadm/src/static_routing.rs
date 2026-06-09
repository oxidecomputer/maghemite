// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use anyhow::Result;
use clap::{Args, Subcommand};
use client_common::println_nopipe;
use mg_admin_client::{Client, types};
use mg_api_types::rdb::DEFAULT_RIB_PRIORITY_STATIC;
use mg_api_types::rdb::prefix::{Prefix4, Prefix6};
use oxnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv6Addr};

#[derive(Subcommand, Debug)]
pub enum Commands {
    // Unicast static routes
    GetV4Routes,
    AddV4Route(StaticRoute4),
    RemoveV4Routes(StaticRoute4),
    GetV6Routes,
    AddV6Route(StaticRoute6),
    RemoveV6Routes(StaticRoute6),

    // Multicast static routes (read-only -> Omicron is source of truth)
    GetMroutes,
}

#[derive(Debug, Args)]
pub struct StaticRoute4 {
    pub destination: Ipv4Net,
    pub nexthop: IpAddr,
    #[clap(long)]
    pub vlan_id: Option<u16>,
    #[clap(long, default_value_t = DEFAULT_RIB_PRIORITY_STATIC)]
    pub rib_priority: u8,
}

#[derive(Debug, Args)]
pub struct StaticRoute6 {
    pub destination: Ipv6Net,
    pub nexthop: Ipv6Addr,
    #[clap(long)]
    pub vlan_id: Option<u16>,
    #[clap(long, default_value_t = DEFAULT_RIB_PRIORITY_STATIC)]
    pub rib_priority: u8,
}

pub async fn commands(command: Commands, client: Client) -> Result<()> {
    match command {
        Commands::GetV4Routes => {
            let routes = client.static_list_v4_routes().await?;
            println_nopipe!("{:#?}", routes);
        }
        Commands::AddV4Route(route) => {
            let arg = mg_api_types::static_routes::AddStaticRoute4Request {
                routes: mg_api_types::static_routes::StaticRoute4List {
                    list: vec![mg_api_types::static_routes::StaticRoute4 {
                        prefix: Prefix4::new(
                            route.destination.addr(),
                            route.destination.width(),
                        ),
                        nexthop: route.nexthop,
                        vlan_id: route.vlan_id,
                        rib_priority: route.rib_priority,
                    }],
                },
            };
            client.static_add_v4_route(&arg).await?;
        }
        Commands::RemoveV4Routes(route) => {
            let arg = mg_api_types::static_routes::DeleteStaticRoute4Request {
                routes: mg_api_types::static_routes::StaticRoute4List {
                    list: vec![mg_api_types::static_routes::StaticRoute4 {
                        prefix: Prefix4::new(
                            route.destination.addr(),
                            route.destination.width(),
                        ),
                        nexthop: route.nexthop,
                        vlan_id: route.vlan_id,
                        rib_priority: route.rib_priority,
                    }],
                },
            };
            client.static_remove_v4_route(&arg).await?;
        }
        Commands::GetV6Routes => {
            let routes = client.static_list_v6_routes().await?;
            println_nopipe!("{:#?}", routes);
        }
        Commands::AddV6Route(route) => {
            let arg = mg_api_types::static_routes::AddStaticRoute6Request {
                routes: mg_api_types::static_routes::StaticRoute6List {
                    list: vec![mg_api_types::static_routes::StaticRoute6 {
                        prefix: Prefix6 {
                            value: route.destination.addr(),
                            length: route.destination.width(),
                        },
                        nexthop: route.nexthop,
                        vlan_id: route.vlan_id,
                        rib_priority: route.rib_priority,
                    }],
                },
            };
            client.static_add_v6_route(&arg).await?;
        }
        Commands::RemoveV6Routes(route) => {
            let arg = mg_api_types::static_routes::DeleteStaticRoute6Request {
                routes: mg_api_types::static_routes::StaticRoute6List {
                    list: vec![mg_api_types::static_routes::StaticRoute6 {
                        prefix: Prefix6 {
                            value: route.destination.addr(),
                            length: route.destination.width(),
                        },
                        nexthop: route.nexthop,
                        vlan_id: route.vlan_id,
                        rib_priority: route.rib_priority,
                    }],
                },
            };
            client.static_remove_v6_route(&arg).await?;
        }
        Commands::GetMroutes => {
            let routes = client.static_list_mcast_routes().await?.into_inner();
            if routes.is_empty() {
                println_nopipe!("No static multicast routes");
            } else {
                print_mroutes(&routes);
            }
        }
    }
    Ok(())
}

fn print_mroutes(routes: &[types::MulticastRoute]) {
    for route in routes {
        let (source_str, group_str, vni) = match &route.key {
            types::MulticastRouteKey::V4(k) => {
                let src = k.source.map_or("*".to_string(), |s| s.to_string());
                let grp = k.group.to_string();
                (src, grp, k.vni.clone())
            }
            types::MulticastRouteKey::V6(k) => {
                let src = k.source.map_or("*".to_string(), |s| s.to_string());
                let grp = k.group.to_string();
                (src, grp, k.vni.clone())
            }
        };
        println_nopipe!(
            "({source_str}, {group_str}) vni={vni} underlay={}",
            route.underlay_group,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_route_conversion_to_api_types() {
        // IPv4-over-IPv4 case
        let route4 = StaticRoute4 {
            destination: Ipv4Net::from_str("192.168.0.0/16").unwrap(),
            nexthop: IpAddr::V4(Ipv4Addr::from_str("10.0.0.1").unwrap()),
            vlan_id: Some(100),
            rib_priority: 50,
        };

        let api_route4 = mg_api_types::static_routes::StaticRoute4 {
            prefix: Prefix4::new(
                route4.destination.addr(),
                route4.destination.width(),
            ),
            nexthop: route4.nexthop,
            vlan_id: route4.vlan_id,
            rib_priority: route4.rib_priority,
        };

        assert_eq!(
            api_route4.prefix.value,
            Ipv4Addr::from_str("192.168.0.0").unwrap()
        );
        assert_eq!(api_route4.prefix.length, 16);
        assert_eq!(api_route4.nexthop, route4.nexthop);
        assert_eq!(api_route4.vlan_id, route4.vlan_id);
        assert_eq!(api_route4.rib_priority, route4.rib_priority);

        // IPv4-over-IPv6 case
        let route4_v6nh = StaticRoute4 {
            destination: Ipv4Net::from_str("192.168.0.0/16").unwrap(),
            nexthop: IpAddr::V6(Ipv6Addr::from_str("fe80::1").unwrap()),
            vlan_id: None,
            rib_priority: 50,
        };

        let api_route4_v6nh = mg_api_types::static_routes::StaticRoute4 {
            prefix: Prefix4::new(
                route4_v6nh.destination.addr(),
                route4_v6nh.destination.width(),
            ),
            nexthop: route4_v6nh.nexthop,
            vlan_id: route4_v6nh.vlan_id,
            rib_priority: route4_v6nh.rib_priority,
        };
        assert_eq!(api_route4_v6nh.nexthop, route4_v6nh.nexthop);

        // IPv6 test case
        let route6 = StaticRoute6 {
            destination: Ipv6Net::from_str("fd00::/8").unwrap(),
            nexthop: Ipv6Addr::from_str("fe80::1").unwrap(),
            vlan_id: Some(300),
            rib_priority: 75,
        };

        let api_route6 = mg_api_types::static_routes::StaticRoute6 {
            prefix: Prefix6::new(
                route6.destination.addr(),
                route6.destination.width(),
            ),
            nexthop: route6.nexthop,
            vlan_id: route6.vlan_id,
            rib_priority: route6.rib_priority,
        };

        assert_eq!(
            api_route6.prefix.value,
            Ipv6Addr::from_str("fd00::").unwrap()
        );
        assert_eq!(api_route6.prefix.length, 8);
        assert_eq!(api_route6.nexthop, route6.nexthop);
        assert_eq!(api_route6.vlan_id, route6.vlan_id);
        assert_eq!(api_route6.rib_priority, route6.rib_priority);
    }
}
