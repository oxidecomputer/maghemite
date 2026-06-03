// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::log::ddm_log;
#[cfg(target_os = "illumos")]
use ddm_admin_client::Client;
use ddm_api_types_versions::latest::net::{MulticastOrigin, TunnelOrigin};
use oxnet::Ipv6Net;
use slog::Logger;
use std::{
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
};

use crate::platform::Ddm;

pub(crate) const BOUNDARY_SERVICES_VNI: u32 = 99;
const UNIT_DDM: &str = "ddm";

fn ensure_tep_underlay_origin(
    client: &impl Ddm,
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
    client: &impl Ddm,
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
    client: &impl Ddm,
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

/// Create a new DDM admin client.
///
/// In production the lower half runs in the same zone as DDM, so `addr` is
/// `None` and the client targets the default `localhost:8000`. Tests pass an
/// explicit `addr` to reach a DDM listening elsewhere (for example a
/// dynamically assigned port in an integration harness).
#[cfg(target_os = "illumos")]
pub fn new_ddm_client(log: &Logger, addr: Option<SocketAddr>) -> Client {
    let host = match addr {
        Some(addr) => format!("http://{addr}"),
        None => "http://localhost:8000".to_string(),
    };
    Client::new(&host, log.clone())
}

pub(crate) fn add_multicast_routes<
    'a,
    I: Iterator<Item = &'a MulticastOrigin>,
>(
    client: &impl Ddm,
    routes: I,
    rt: &Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    let routes: Vec<MulticastOrigin> = routes.cloned().collect();
    if routes.is_empty() {
        return;
    }
    let resp =
        rt.block_on(async { client.advertise_multicast_groups(&routes).await });
    if let Err(e) = resp {
        ddm_log!(log,
            error,
            "advertise multicast groups error: {e}";
            "error" => format!("{e}"),
            "groups" => format!("{routes:#?}")
        );
    }
}

pub(crate) fn remove_multicast_routes<
    'a,
    I: Iterator<Item = &'a MulticastOrigin>,
>(
    client: &impl Ddm,
    routes: I,
    rt: &Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    let routes: Vec<MulticastOrigin> = routes.cloned().collect();
    if routes.is_empty() {
        return;
    }
    let resp =
        rt.block_on(async { client.withdraw_multicast_groups(&routes).await });
    match resp {
        Err(e) => ddm_log!(log,
            error,
            "withdraw multicast groups error: {e}";
            "groups" => format!("{routes:#?}")
        ),
        Ok(_) => ddm_log!(log,
            debug,
            "withdrew multicast groups";
            "groups" => format!("{routes:#?}")
        ),
    }
}
