// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_admin_client::{Client, TunnelOrigin};
use rdb::Route4ImportKey;
use slog::{error, Logger};
use std::{collections::HashSet, net::Ipv6Addr, sync::Arc};

pub(crate) fn update_tunnel_endpoints(
    tep: Ipv6Addr, // tunnel endpoint address
    client: &Client,
    routes: &[Route4ImportKey],
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

    let target: HashSet<TunnelOrigin> =
        routes.iter().map(|x| route_to_tunnel(tep, x)).collect();

    let to_add = target.difference(&current);
    let to_remove = current.difference(&target);

    add_tunnel_endpoints(client, to_add.into_iter(), &rt, log);
    remove_tunnel_endpoints(client, to_remove.into_iter(), &rt, log);
}

const BOUNDARY_SERVICES_VNI: u32 = 99;

fn route_to_tunnel(tep: Ipv6Addr, x: &Route4ImportKey) -> TunnelOrigin {
    TunnelOrigin {
        overlay_prefix: ddm_admin_client::IpPrefix::V4(
            ddm_admin_client::Ipv4Prefix {
                addr: x.prefix.value,
                len: x.prefix.length,
            },
        ),
        boundary_addr: tep,
        vni: BOUNDARY_SERVICES_VNI, //TODO?
    }
}

pub(crate) fn add_tunnel_routes(
    tep: Ipv6Addr, // tunnel endpoint address
    client: &Client,
    routes: &[Route4ImportKey],
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    let teps: Vec<TunnelOrigin> =
        routes.iter().map(|x| route_to_tunnel(tep, x)).collect();
    add_tunnel_endpoints(client, teps.iter(), &rt, log)
}

pub(crate) fn add_tunnel_endpoints<'a, I: Iterator<Item = &'a TunnelOrigin>>(
    client: &Client,
    routes: I,
    rt: &Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    let routes = routes.cloned().collect();
    let resp =
        rt.block_on(async { client.advertise_tunnel_endpoints(&routes).await });
    if let Err(e) = resp {
        error!(log, "advertise tunnel endpoints: {e}");
    }
}

pub(crate) fn remove_tunnel_routes(
    tep: Ipv6Addr, // tunnel endpoint address
    client: &Client,
    routes: &[Route4ImportKey],
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    let teps: Vec<TunnelOrigin> =
        routes.iter().map(|x| route_to_tunnel(tep, x)).collect();
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
    let routes = routes.cloned().collect();
    let resp =
        rt.block_on(async { client.withdraw_tunnel_endpoints(&routes).await });
    if let Err(e) = resp {
        error!(log, "withdraw tunnel endpoints: {e}");
    }
}

pub(crate) fn new_ddm_client(log: &Logger) -> Client {
    Client::new("http://localhost:8000", log.clone())
}
