// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_admin_client::types::TunnelOrigin;
use ddm_admin_client::Client;
use oxnet::Ipv6Net;
use slog::{error, info, Logger};
use std::{collections::HashSet, net::Ipv6Addr, sync::Arc};

pub(crate) const BOUNDARY_SERVICES_VNI: u32 = 99;

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

pub(crate) fn add_tunnel_routes(
    tep: Ipv6Addr, // tunnel endpoint address
    client: &Client,
    routes: &HashSet<TunnelOrigin>,
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    add_tunnel_endpoints(tep, client, routes.iter(), &rt, log)
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
    client: &Client,
    routes: &HashSet<TunnelOrigin>,
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    remove_tunnel_endpoints(client, routes.iter(), &rt, log)
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
