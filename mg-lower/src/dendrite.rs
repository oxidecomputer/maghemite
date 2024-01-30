// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Error;
use crate::MG_LOWER_TAG;
use dendrite_common::network::Cidr;
use dendrite_common::ports::PortId;
use dendrite_common::ports::QsfpPort;
use dpd_client::types;
use dpd_client::Client as DpdClient;
use http::StatusCode;
use libnet::{get_route, IpPrefix, Ipv4Prefix};
use rdb::Route4ImportKey;
use slog::{error, warn, Logger};
use std::collections::HashSet;
use std::hash::Hash;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::sync::Arc;

const TFPORT_QSFP_DEVICE_PREFIX: &str = "tfportqsfp";

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RouteHash {
    cidr: Cidr,
    port_id: PortId,
    link_id: types::LinkId,
    nexthop: IpAddr,
}

impl RouteHash {
    pub fn new(
        cidr: Cidr,
        port_id: PortId,
        link_id: types::LinkId,
        nexthop: IpAddr,
    ) -> Result<Self, &'static str> {
        match (cidr, nexthop) {
            (Cidr::V4(_), IpAddr::V4(_)) | (Cidr::V6(_), IpAddr::V6(_)) => {
                Ok(RouteHash {
                    cidr,
                    port_id,
                    link_id,
                    nexthop,
                })
            }
            _ => Err("mismatched subnet and target"),
        }
    }
}

pub(crate) fn ensure_tep_addr(
    tep: Ipv6Addr,
    dpd: &DpdClient,
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    if let Err(e) = rt.block_on(async {
        dpd.loopback_ipv6_create(&types::Ipv6Entry {
            tag: MG_LOWER_TAG.into(),
            addr: tep,
        })
        .await
    }) {
        if e.status() != Some(StatusCode::CONFLICT) {
            warn!(log, "failed to ensure TEP address {tep} on ASIC: {e}");
        }
    }
}

/// Perform a set of route additions and deletions via the Dendrite API.
pub(crate) fn update_dendrite<'a, I>(
    to_add: I,
    to_del: I,
    dpd: &DpdClient,
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) -> Result<(), Error>
where
    I: Iterator<Item = &'a RouteHash>,
{
    for r in to_add {
        let cidr = r.cidr;
        let tag = dpd.inner().tag.clone();
        let port_id = r.port_id;
        let link_id = r.link_id;

        let target = match (r.cidr, r.nexthop) {
            (Cidr::V4(_), IpAddr::V4(tgt_ip)) => types::Ipv4Route {
                tag,
                port_id,
                link_id,
                tgt_ip,
            }
            .into(),
            (Cidr::V6(_), IpAddr::V6(tgt_ip)) => types::Ipv6Route {
                tag,
                port_id,
                link_id,
                tgt_ip,
            }
            .into(),
            _ => {
                error!(
                    log,
                    "mismatched subnet {} and target {}", r.cidr, r.nexthop
                );
                continue;
            }
        };

        let add = types::RouteAdd { cidr, target };
        if let Err(e) = rt.block_on(async { dpd.route_ipv4_add(&add).await }) {
            error!(log, "failed to create route {:?}: {}", r, e);
            Err(e)?;
        }
    }
    for r in to_del {
        let port_id = r.port_id;
        let link_id = r.link_id;

        let cidr = match r.cidr {
            Cidr::V4(cidr) => cidr,
            Cidr::V6(_) => continue,
        };
        let target = match r.nexthop {
            IpAddr::V4(tgt_ip) => tgt_ip,
            IpAddr::V6(_) => continue,
        };
        if let Err(e) = rt.block_on(async {
            dpd.route_ipv4_delete_target(&cidr, &port_id, &link_id, &target)
                .await
        }) {
            error!(log, "failed to create route {:?}: {}", r, e);
            Err(e)?;
        }
    }
    Ok(())
}

fn get_port_and_link(
    r: &Route4ImportKey,
) -> Result<(PortId, types::LinkId), String> {
    let sys_route = match get_route(IpPrefix::V4(Ipv4Prefix {
        addr: r.nexthop,
        mask: 32,
    })) {
        Ok(r) => r,
        Err(e) => {
            return Err(format!("Unable to get route for {r:?}: {e:?}"));
        }
    };

    let ifname = match sys_route.ifx {
        Some(name) => name,
        None => {
            return Err(format!(
                "No interface associated with route for {:?}: {:?}",
                r, sys_route,
            ));
        }
    };

    // TODO this is gross, use link type properties rather than futzing
    // around with strings.
    let Some(egress_port_num) = ifname
        .strip_prefix(TFPORT_QSFP_DEVICE_PREFIX)
        .and_then(|x| x.strip_suffix("_0"))
        .map(|x| x.trim())
        .and_then(|x| x.parse::<u8>().ok())
    else {
        return Err(format!(
            "expected {}$M_0, got {}",
            TFPORT_QSFP_DEVICE_PREFIX, ifname
        ));
    };

    let port_id = match QsfpPort::try_from(egress_port_num) {
        Ok(qsfp) => PortId::Qsfp(qsfp),
        Err(e) => return Err(format!("bad port name: {e}")),
    };

    // TODO breakout considerations
    let link_id = dpd_client::types::LinkId(0);
    Ok((port_id, link_id))
}

/// Translate a vector of RIB route data structures to a HashSet of RouteHashes
pub(crate) fn db_route_to_dendrite_route(
    rs: Vec<Route4ImportKey>,
    log: &Logger,
    _dpd: &DpdClient,
) -> HashSet<RouteHash> {
    let mut result = HashSet::new();

    for r in &rs {
        let (port_id, link_id) = match get_port_and_link(r) {
            Ok((p, l)) => (p, l),
            Err(e) => {
                error!(log, "failed to get port for {r:?}: {e:?}");
                continue;
            }
        };

        let cidr = dpd_client::Ipv4Cidr {
            prefix: r.prefix.value,
            prefix_len: r.prefix.length,
        };

        match RouteHash::new(cidr.into(), port_id, link_id, r.nexthop.into()) {
            Ok(route) => {
                let _ = result.insert(route);
            }
            Err(e) => error!(log, "bad route: {e}"),
        };
    }

    result
}

/// Create a new Dendrite/dpd client. The lower half always runs on the same
/// host/zone as the underlying platform.
pub(crate) fn new_dpd_client(log: &Logger) -> DpdClient {
    let client_state = dpd_client::ClientState {
        tag: MG_LOWER_TAG.into(),
        log: log.clone(),
    };
    DpdClient::new(
        &format!("http://localhost:{}", dpd_client::default_port()),
        client_state,
    )
}
