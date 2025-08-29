// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::log::ddm_log;
use ddm_admin_client::types::TunnelOrigin;
use ddm_admin_client::Client;
use oxnet::Ipv6Net;
use slog::Logger;
use std::{net::Ipv6Addr, sync::Arc};

pub(crate) const BOUNDARY_SERVICES_VNI: u32 = 99;
const UNIT_DDM: &str = "ddm";

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
            ddm_log!(
                log,
                error,
                "failed to get originated endpoints: {e}";
                "error" => format!("{e}")
            );
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
        ddm_log!(log,
            error,
            "advertise prefixes error: {e}";
            "error" => format!("{e}"),
            "prefixes" => format!("{target:#?}")
        );
    };
}

pub(crate) fn add_tunnel_routes<'a, I: Iterator<Item = &'a TunnelOrigin>>(
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
        ddm_log!(log,
            error,
            "advertise prefixes error: {e}";
            "error" => format!("{e}"),
            "prefixes" => format!("{routes:#?}")
        );
    }
}

pub(crate) fn remove_tunnel_routes<'a, I: Iterator<Item = &'a TunnelOrigin>>(
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
        Err(e) => ddm_log!(log,
            error,
            "withdraw tunnel endpoints error: {e}";
            "prefixes" => format!("{routes:#?}")
        ),
        Ok(_) => ddm_log!(log,
            info,
            "withdrew tunnel endpoints";
            "prefixes" => format!("{routes:#?}")
        ),
    }
}

pub(crate) fn new_ddm_client(log: &Logger) -> Client {
    Client::new("http://localhost:8000", log.clone())
}
