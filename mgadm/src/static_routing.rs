// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Args, Subcommand};
use mg_admin_client::types;
use mg_admin_client::Client;
use rdb::DEFAULT_RIB_PRIORITY_STATIC;
use std::net::{AddrParseError, Ipv4Addr};
use std::num::ParseIntError;
use thiserror::Error;

#[derive(Subcommand, Debug)]
pub enum Commands {
    GetV4Routes,
    AddV4Route(StaticRoute4),
    RemoveV4Routes(StaticRoute4),
}

#[derive(Debug, Error)]
pub enum Ipv4NetParseError {
    #[error("expected CIDR representation <addr>/<mask>")]
    Cidr,

    #[error("address parse error: {0}")]
    Addr(#[from] AddrParseError),

    #[error("mask parse error: {0}")]
    Mask(#[from] ParseIntError),
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

#[derive(Debug, Clone, Copy)]
pub struct Ipv4Net {
    pub addr: Ipv4Addr,
    pub len: u8,
}

impl std::str::FromStr for Ipv4Net {
    type Err = Ipv4NetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() < 2 {
            return Err(Ipv4NetParseError::Cidr);
        }

        Ok(Ipv4Net {
            addr: Ipv4Addr::from_str(parts[0])?,
            len: u8::from_str(parts[1])?,
        })
    }
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
                            value: route.destination.addr,
                            length: route.destination.len,
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
                            value: route.destination.addr,
                            length: route.destination.len,
                        },
                        nexthop: route.nexthop,
                        vlan_id: route.vlan_id,
                        rib_priority: route.rib_priority,
                    }],
                },
            };
            client.static_remove_v4_route(&arg).await?;
        }
    }
    Ok(())
}
