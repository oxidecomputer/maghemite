// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Args, Subcommand};
use mg_admin_client::types;
use mg_admin_client::Client;
use oxnet::{Ipv4Net, Ipv6Net};
use rdb::DEFAULT_RIB_PRIORITY_STATIC;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Subcommand, Debug)]
pub enum Commands {
    GetV4Routes,
    AddV4Route(StaticRoute4),
    RemoveV4Routes(StaticRoute4),
    GetV6Routes,
    AddV6Route(StaticRoute6),
    RemoveV6Routes(StaticRoute6),
}

#[derive(Debug, Args)]
pub struct StaticRoute4 {
    pub destination: Ipv4Net,
    pub nexthop: Ipv4Addr,
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
            println!("{:#?}", routes);
        }
        Commands::AddV4Route(route) => {
            let arg = types::AddStaticRoute4Request {
                routes: types::StaticRoute4List {
                    list: vec![types::StaticRoute4 {
                        prefix: types::Prefix4 {
                            value: route.destination.addr(),
                            length: route.destination.width(),
                        },
                        nexthop: route.nexthop,
                        vlan_id: route.vlan_id,
                        rib_priority: route.rib_priority,
                    }],
                },
            };
            client.static_add_v4_route(&arg).await?;
        }
        Commands::RemoveV4Routes(route) => {
            let arg = types::DeleteStaticRoute4Request {
                routes: types::StaticRoute4List {
                    list: vec![types::StaticRoute4 {
                        prefix: types::Prefix4 {
                            value: route.destination.addr(),
                            length: route.destination.width(),
                        },
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
            println!("{:#?}", routes);
        }
        Commands::AddV6Route(route) => {
            let arg = types::AddStaticRoute6Request {
                routes: types::StaticRoute6List {
                    list: vec![types::StaticRoute6 {
                        prefix: types::Prefix6 {
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
            let arg = types::DeleteStaticRoute6Request {
                routes: types::StaticRoute6List {
                    list: vec![types::StaticRoute6 {
                        prefix: types::Prefix6 {
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
    }
    Ok(())
}
