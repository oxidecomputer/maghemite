// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_admin_client::types::TunnelOrigin;
use ddm_admin_client::Client;
use dpd_client::Cidr;
use oxnet::Ipv6Net;
use rdb::db::Rib;
use rdb::{Prefix, Prefix4, Prefix6, DEFAULT_ROUTE_PRIORITY};
use slog::{error, info, Logger};
use std::{collections::HashSet, net::Ipv6Addr, sync::Arc};

use crate::dendrite::RouteHash;

const BOUNDARY_SERVICES_VNI: u32 = 99;

pub(crate) fn update_tunnel_endpoints(
    tep: Ipv6Addr, // tunnel endpoint address
    client: &Client,
    routes: &Rib,
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    let current: HashSet<TunnelOrigin> = match rt
        .block_on(async { client.get_originated_tunnel_endpoints().await })
        .map(|x| x.into_inner())
    {
        Ok(x) => x,
        Err(e) => {
            error!(log, "get originated tunnel endpoints: {e}");
            return;
        }
    }
    .into_iter()
    .collect();

    let target: HashSet<TunnelOrigin> = routes
        .iter()
        .map(|(prefix, _path)| route_to_tunnel(tep, prefix))
        .collect();

    let to_add = target.difference(&current);
    let to_remove = current.difference(&target);

    add_tunnel_endpoints(tep, client, to_add.into_iter(), &rt, log);
    remove_tunnel_endpoints(client, to_remove.into_iter(), &rt, log);
}

fn ensure_tep_underlay_origin(
    client: &Client,
    tep: Ipv6Addr,
    rt: &Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    let current: Vec<Ipv6Net> = match rt
        .block_on(async { client.get_originated().await })
        .map(|x| x.into_inner())
    {
        Ok(x) => x,
        Err(e) => {
            error!(log, "get originated endpoints: {e}");
            return;
        }
    }
    .into_iter()
    .collect();

    let target = Ipv6Net::new(tep, 64).unwrap();

    if current.contains(&target) {
        return;
    }

    if let Err(e) =
        rt.block_on(async { client.advertise_prefixes(&vec![target]).await })
    {
        error!(log, "get originated endpoints: {e}");
    };
}

fn route_to_tunnel(tep: Ipv6Addr, prefix: &Prefix) -> TunnelOrigin {
    match prefix {
        Prefix::V4(p) => {
            TunnelOrigin {
                overlay_prefix: oxnet::Ipv4Net::new(p.value, p.length)
                    .unwrap()
                    .into(),
                boundary_addr: tep,
                vni: BOUNDARY_SERVICES_VNI,     //TODO?
                metric: DEFAULT_ROUTE_PRIORITY, //TODO
            }
        }
        Prefix::V6(p) => {
            TunnelOrigin {
                overlay_prefix: oxnet::Ipv6Net::new(p.value, p.length)
                    .unwrap()
                    .into(),
                boundary_addr: tep,
                vni: BOUNDARY_SERVICES_VNI,     //TODO?
                metric: DEFAULT_ROUTE_PRIORITY, //TODO
            }
        }
    }
}

pub(crate) fn add_tunnel_routes(
    tep: Ipv6Addr, // tunnel endpoint address
    client: &Client,
    routes: &HashSet<RouteHash>,
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    let teps: Vec<TunnelOrigin> = routes
        .iter()
        .map(|rt| {
            let pfx = match rt.cidr {
                Cidr::V4(p) => Prefix4 {
                    value: p.prefix,
                    length: p.prefix_len,
                }
                .into(),
                Cidr::V6(p) => Prefix6 {
                    value: p.prefix,
                    length: p.prefix_len,
                }
                .into(),
            };
            route_to_tunnel(tep, &pfx)
        })
        .collect();
    add_tunnel_endpoints(tep, client, teps.iter(), &rt, log)
}

pub(crate) fn add_tunnel_endpoints<'a, I: Iterator<Item = &'a TunnelOrigin>>(
    tep: Ipv6Addr, // tunnel endpoint address
    client: &Client,
    routes: I,
    rt: &Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    let routes: Vec<TunnelOrigin> = routes.cloned().collect();
    if routes.is_empty() {
        return;
    }
    ensure_tep_underlay_origin(client, tep, rt, log);
    let resp =
        rt.block_on(async { client.advertise_tunnel_endpoints(&routes).await });
    if let Err(e) = resp {
        error!(log, "advertise tunnel endpoints: {e}");
    }
}

pub(crate) fn remove_tunnel_routes(
    tep: Ipv6Addr, // tunnel endpoint address
    client: &Client,
    routes: &HashSet<RouteHash>,
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    let teps: Vec<TunnelOrigin> = routes
        .iter()
        .map(|rt| {
            let pfx = match rt.cidr {
                Cidr::V4(p) => Prefix4 {
                    value: p.prefix,
                    length: p.prefix_len,
                }
                .into(),
                Cidr::V6(p) => Prefix6 {
                    value: p.prefix,
                    length: p.prefix_len,
                }
                .into(),
            };
            route_to_tunnel(tep, &pfx)
        })
        .collect();
    remove_tunnel_endpoints(client, teps.iter(), &rt, log)
}

pub(crate) fn remove_tunnel_endpoints<
    'a,
    I: Iterator<Item = &'a TunnelOrigin>,
>(
    client: &Client,
    routes: I,
    rt: &Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    let routes: Vec<TunnelOrigin> = routes.cloned().collect();
    if routes.is_empty() {
        return;
    }
    let resp =
        rt.block_on(async { client.withdraw_tunnel_endpoints(&routes).await });
    match resp {
        Err(e) => error!(log, "withdraw tunnel endpoints: {e}"),
        Ok(_) => info!(log, "withdrew tunnel endpoints: {:#?}", routes),
    }
}

pub(crate) fn new_ddm_client(log: &Logger) -> Client {
    Client::new("http://localhost:8000", log.clone())
}
