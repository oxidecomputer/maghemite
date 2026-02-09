// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    Error, MG_LOWER_TAG,
    log::dpd_log,
    platform::{Dpd, SwitchZone},
};
#[cfg(target_os = "illumos")]
use dpd_client::Client as DpdClient;
use dpd_client::types::{self, LinkState, Route};
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
use rdb::{Path, Prefix};
use slog::Logger;
use std::{
    collections::{BTreeSet, HashSet},
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

const TFPORT_QSFP_DEVICE_PREFIX: &str = "tfportqsfp";
const UNIT_DPD: &str = "dpd";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RouteHash {
    pub(crate) cidr: IpNet,
    pub(crate) port_id: types::PortId,
    pub(crate) link_id: types::LinkId,
    pub(crate) nexthop: IpAddr,
    pub(crate) vlan_id: Option<u16>,
}

impl RouteHash {
    pub fn new(
        cidr: IpNet,
        port_id: types::PortId,
        link_id: types::LinkId,
        nexthop: IpAddr,
        vlan_id: Option<u16>,
    ) -> Result<Self, &'static str> {
        if matches!(cidr, IpNet::V6(_)) && matches!(nexthop, IpAddr::V4(_)) {
            return Err("mismatched subnet and target");
        }
        Ok(RouteHash {
            cidr,
            port_id,
            link_id,
            nexthop,
            vlan_id,
        })
    }

    pub fn for_prefix_path(
        sw: &impl SwitchZone,
        prefix: Prefix,
        path: Path,
    ) -> Result<RouteHash, Error> {
        let (port_id, link_id) = get_port_and_link(sw, &path)?;

        let cidr = match prefix {
            Prefix::V4(p) => Ipv4Net::new(p.value, p.length)?.into(),
            Prefix::V6(p) => Ipv6Net::new(p.value, p.length)?.into(),
        };

        RouteHash::new(cidr, port_id, link_id, path.nexthop, path.vlan_id)
            .map_err(|e| Error::AddressFamilyMismatch(e.to_string()))
    }
}

pub(crate) fn ensure_tep_addr(
    tep: Ipv6Addr,
    dpd: &impl Dpd,
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    if let Err(e) = rt.block_on(async {
        dpd.loopback_ipv6_create(&types::Ipv6Entry {
            tag: MG_LOWER_TAG.into(),
            addr: tep,
        })
        .await
    }) && e.status() != Some(reqwest::StatusCode::CONFLICT)
    {
        dpd_log!(
            log,
            warn,
            "failed to ensure TEP address {tep} on ASIC: {e}";
            "error" => format!("{e}"),
            "prefix" => format!("{tep}")
        );
    }
}

pub(crate) fn link_is_up(
    dpd: &impl Dpd,
    port_id: &types::PortId,
    link_id: &types::LinkId,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<bool, Error> {
    let link_info =
        rt.block_on(async { dpd.link_get(port_id, link_id).await })?;

    Ok(link_info.link_state == LinkState::Up)
}

fn get_local_addrs(
    dpd: &impl Dpd,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<(BTreeSet<Ipv4Addr>, BTreeSet<Ipv6Addr>), Error> {
    let links = rt
        .block_on(async { dpd.link_list_all(None).await })?
        .into_inner();

    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();

    for link in links {
        let addrs = rt
            .block_on(async {
                dpd.link_ipv4_list(&link.port_id, &link.link_id, None, None)
                    .await
            })?
            .into_inner()
            .items;
        v4.extend(addrs.into_iter().map(|x| x.addr));

        let addrs = rt
            .block_on(async {
                dpd.link_ipv6_list(&link.port_id, &link.link_id, None, None)
                    .await
            })?
            .into_inner()
            .items;
        v6.extend(addrs.into_iter().map(|x| x.addr));
    }

    Ok((v4, v6))
}

/// Perform a set of route additions and deletions via the Dendrite API.
pub(crate) fn update_dendrite<'a, I>(
    to_add: I,
    to_del: I,
    dpd: &impl Dpd,
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) -> Result<(), Error>
where
    I: Iterator<Item = &'a RouteHash>,
{
    let (local_v4_addrs, local_v6_addrs) = get_local_addrs(dpd, &rt)?;

    for r in to_add {
        let tag = dpd.tag();
        let port_id = r.port_id.clone();
        let link_id = r.link_id;
        let vlan_id = r.vlan_id;

        match (r.cidr, r.nexthop) {
            (IpNet::V4(c), IpAddr::V4(tgt_ip)) => {
                if c.width() == 32 && local_v4_addrs.contains(&c.prefix()) {
                    dpd_log!(log,
                        warn,
                        "skipping data plane installation for martian prefix {c:?}";
                        "prefix" => format!("{c}")
                    );
                    continue;
                }
                if local_v4_addrs.contains(&tgt_ip) {
                    dpd_log!(log,
                        warn,
                        "skipping data plane installation for martian nexthop {tgt_ip:?}";
                        "nexthop" => format!("{tgt_ip}")
                    );
                    continue;
                }

                let target = types::RouteTarget::V4(types::Ipv4Route {
                    tag,
                    port_id,
                    link_id,
                    tgt_ip,
                    vlan_id,
                });

                let update = types::Ipv4RouteUpdate {
                    cidr: c,
                    target,
                    replace: false,
                };
                if let Err(e) =
                    rt.block_on(async { dpd.route_ipv4_add(&update).await })
                {
                    dpd_log!(log,
                        error,
                        "failed to create route {r:?} {e}";
                        "error" => format!("{e}")
                    );
                    return Err(e.into());
                }
            }
            (IpNet::V6(c), IpAddr::V6(tgt_ip)) => {
                if c.width() == 128 && local_v6_addrs.contains(&c.prefix()) {
                    dpd_log!(log,
                        warn,
                        "skipping data plane installation for martian prefix {c:?}";
                        "prefix" => format!("{c}")
                    );
                    continue;
                }
                if local_v6_addrs.contains(&tgt_ip) {
                    dpd_log!(log,
                        warn,
                        "skipping data plane installation for martian nexthop {tgt_ip:?}";
                        "nexthop" => format!("{tgt_ip}")
                    );
                    continue;
                }

                let target = types::Ipv6Route {
                    tag,
                    port_id,
                    link_id,
                    tgt_ip,
                    vlan_id,
                };

                let update = types::Ipv6RouteUpdate {
                    cidr: c,
                    target,
                    replace: false,
                };
                if let Err(e) =
                    rt.block_on(async { dpd.route_ipv6_add(&update).await })
                {
                    dpd_log!(log,
                        error,
                        "failed to create route {r:?} {e}";
                        "error" => format!("{e}")
                    );
                    return Err(e.into());
                }
            }
            (IpNet::V4(c), IpAddr::V6(tgt_ip)) => {
                let target = types::RouteTarget::V6(types::Ipv6Route {
                    tag,
                    port_id,
                    link_id,
                    tgt_ip,
                    vlan_id,
                });

                let update = types::Ipv4RouteUpdate {
                    cidr: c,
                    target,
                    replace: false,
                };
                if let Err(e) =
                    rt.block_on(async { dpd.route_ipv4_add(&update).await })
                {
                    dpd_log!(log,
                        error,
                        "failed to create route {r:?} {e}";
                        "error" => format!("{e}")
                    );
                    return Err(e.into());
                }
            }
            _ => {
                dpd_log!(log,
                    error,
                    "mismatched address-family for subnet {} and target {}", r.cidr, r.nexthop;
                    "prefix" => format!("{}", r.cidr),
                    "nexthop" => format!("{}", r.nexthop)
                );
                continue;
            }
        };
    }
    for r in to_del {
        let port_id = r.port_id.clone();
        let link_id = r.link_id;

        match (r.cidr, r.nexthop) {
            (IpNet::V4(cidr), tgt_ip) => {
                if let Err(e) = rt.block_on(async {
                    dpd.route_ipv4_delete_target(
                        &cidr, &port_id, &link_id, &tgt_ip,
                    )
                    .await
                }) {
                    dpd_log!(log,
                        error,
                        "failed to delete route in ASIC {r:?} via {}: {e}", r.nexthop;
                        "error" => format!("{e}"),
                        "prefix" => format!("{}", r.cidr),
                        "nexthop" => format!("{}", r.nexthop)
                    );
                    Err(e)?;
                }
            }
            (IpNet::V6(cidr), IpAddr::V6(tgt_ip)) => {
                if let Err(e) = rt.block_on(async {
                    dpd.route_ipv6_delete_target(
                        &cidr, &port_id, &link_id, &tgt_ip,
                    )
                    .await
                }) {
                    dpd_log!(log,
                        error,
                        "failed to delete route in ASIC {r:?} via {}: {e}", r.nexthop;
                        "error" => format!("{e}"),
                        "prefix" => format!("{}", r.cidr),
                        "nexthop" => format!("{}", r.nexthop)
                    );
                    Err(e)?;
                }
            }
            (IpNet::V6(_), IpAddr::V4(_)) => {
                dpd_log!(log,
                    error,
                    "v6-over-v4 routes are not supported: subnet {} target {}",
                    r.cidr, r.nexthop;
                    "prefix" => format!("{}", r.cidr),
                    "nexthop" => format!("{}", r.nexthop)
                );
                continue;
            }
        }
    }
    Ok(())
}

// Translate a tfport name into the underlying (port, link, vlan) tuple.
//    tfportqsfp10_0 would translate to (10, 0, None)
//    tfportqsfp10_0.100 would translate to (10, 0, Some(100))
// TODO this is gross, use link type properties rather than futzing
// around with strings.
fn parse_tfport_name(name: &str) -> Result<(u8, u8, Option<u16>), Error> {
    let body =
        name.strip_prefix(TFPORT_QSFP_DEVICE_PREFIX)
            .ok_or(Error::Tfport(format!(
                "{} missing expected prefix {}",
                name, TFPORT_QSFP_DEVICE_PREFIX
            )))?;
    let fields: Vec<&str> = body.split('.').collect();
    let (port, link) = fields[0]
        .split_once('_')
        .ok_or(Error::Tfport(format!("{} has no link id", name)))?;

    let port = port.parse::<u8>().map_err(|_| {
        Error::Tfport(format!("{} has invalid port {}", name, port))
    })?;

    let link = link.parse::<u8>().map_err(|_| {
        Error::Tfport(format!("{} has invalid link id {}", name, link))
    })?;

    let vlan = match fields.len() {
        1 => Ok(None),
        2 => fields[1].parse::<u16>().map(Some).map_err(|_| {
            Error::Tfport(format!("{} has invalid vlan {}", name, fields[1]))
        }),
        _ => Err(Error::Tfport(format!(
            "{} has multiple vlan deliminators",
            name
        ))),
    }?;

    Ok((port, link, vlan))
}

#[test]
fn test_tfport_parser() {
    // Test valid names
    assert_eq!(parse_tfport_name("tfportqsfp10_0").unwrap(), (10, 0, None));
    assert_eq!(
        parse_tfport_name("tfportqsfp10_0.100").unwrap(),
        (10, 0, Some(100))
    );
    assert_eq!(parse_tfport_name("tfportqsfp1_1").unwrap(), (1, 1, None));

    // test malformed names
    assert!(parse_tfport_name("fportqsfp10_0").is_err());
    assert!(parse_tfport_name("10_0").is_err());
    assert!(parse_tfport_name("tfportqsfp10").is_err());
    assert!(parse_tfport_name("tfportqsfp_10").is_err());
    assert!(parse_tfport_name("tfportqsfp0_").is_err());
    assert!(parse_tfport_name("tfportqsfp10_10_10").is_err());
    assert!(parse_tfport_name("tfportqsfp10.100_0").is_err());

    // test invalid components
    assert!(parse_tfport_name("tfportqsfp1X_0.100").is_err());
    assert!(parse_tfport_name("tfportqsfp10_X.100").is_err());
    assert!(parse_tfport_name("tfportqsfp10_0.X").is_err());
}

fn get_port_and_link(
    sw: &impl SwitchZone,
    path: &Path,
) -> Result<(types::PortId, types::LinkId), Error> {
    // If path has interface binding (unnumbered peer), use it directly
    if let IpAddr::V6(nh6) = path.nexthop
        && nh6.is_unicast_link_local()
        && let Some(ref iface) = path.nexthop_interface
    {
        let (port, link, _vlan) = parse_tfport_name(iface)?;
        let port_name = format!("qsfp{port}");
        let port_id = types::Qsfp::try_from(&port_name)
            .map(types::PortId::Qsfp)
            .map_err(|e| {
                Error::Tfport(format!(
                    "bad port name ifname: {iface}  port name: {port_name}: {e}",
                ))
            })?;
        // TODO breakout considerations
        let link_id = types::LinkId(link);
        return Ok((port_id, link_id));
    }

    // Standard nexthop resolution for numbered peers
    resolve_port_and_link(sw, path.nexthop)
}

fn resolve_port_and_link(
    sw: &impl SwitchZone,
    nexthop: IpAddr,
) -> Result<(types::PortId, types::LinkId), Error> {
    let prefix = IpNet::host_net(nexthop);
    let sys_route = sw.get_route(prefix, Some(Duration::from_secs(1)))?;

    let ifname = match sys_route.ifx {
        Some(name) => name,
        None => {
            return Err(Error::NoNexthopRoute(format!(
                "No interface associated with route for {:?}: {:?}",
                prefix, sys_route,
            )));
        }
    };

    let (port, link, _vlan) = parse_tfport_name(&ifname)?;
    let port_name = format!("qsfp{port}");
    let port_id = types::Qsfp::try_from(&port_name)
        .map(types::PortId::Qsfp)
        .map_err(|e| {
            Error::Tfport(format!(
                "bad port name ifname: {ifname}  port name: {port_name}: {e}"
            ))
        })?;

    // TODO breakout considerations
    let link_id = types::LinkId(link);
    Ok((port_id, link_id))
}

pub(crate) fn get_routes_for_prefix(
    dpd: &impl Dpd,
    prefix: &Prefix,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<HashSet<RouteHash>, Error> {
    let result = match prefix {
        Prefix::V4(p) => {
            let cidr = Ipv4Net::new(p.value, p.length)?;
            let dpd_routes =
                match rt.block_on(async { dpd.route_ipv4_get(&cidr).await }) {
                    Ok(routes) => routes,
                    Err(e) => {
                        if e.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                            return Ok(HashSet::new());
                        }
                        return Err(e.into());
                    }
                }
                .into_inner();

            let mut result: Vec<RouteHash> = Vec::new();
            for r in dpd_routes.iter() {
                let (tag, port_id, link_id, tgt_ip, vlan_id) = match r {
                    Route::V4(v4) => (
                        &v4.tag,
                        v4.port_id.clone(),
                        v4.link_id,
                        IpAddr::V4(v4.tgt_ip),
                        v4.vlan_id,
                    ),
                    Route::V6(v6) => (
                        &v6.tag,
                        v6.port_id.clone(),
                        v6.link_id,
                        IpAddr::V6(v6.tgt_ip),
                        v6.vlan_id,
                    ),
                };
                if tag != MG_LOWER_TAG {
                    continue;
                }
                match RouteHash::new(
                    cidr.into(),
                    port_id.clone(),
                    link_id,
                    tgt_ip,
                    vlan_id,
                ) {
                    Ok(rh) => result.push(rh),
                    Err(e) => {
                        dpd_log!(log,
                            error,
                            "route hash creation failed for {prefix} (port: {}, link: {}, tgt_ip: {}, vlan_id: {:?}): {e}",
                            port_id, link_id, tgt_ip, vlan_id;
                            "error" => format!("{e}"),
                            "prefix" => format!("r:?")
                        );
                        continue;
                    }
                };
            }

            result
        }
        Prefix::V6(p) => {
            let cidr = Ipv6Net::new(p.value, p.length)?;
            let dpd_routes =
                match rt.block_on(async { dpd.route_ipv6_get(&cidr).await }) {
                    Ok(routes) => routes,
                    Err(e) => {
                        if e.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                            return Ok(HashSet::new());
                        }
                        return Err(e.into());
                    }
                }
                .into_inner();

            let mut result: Vec<RouteHash> = Vec::new();
            for r in dpd_routes.iter() {
                if r.tag != MG_LOWER_TAG {
                    continue;
                }
                match RouteHash::new(
                    cidr.into(),
                    r.port_id.clone(),
                    r.link_id,
                    r.tgt_ip.into(),
                    r.vlan_id,
                ) {
                    Ok(rh) => result.push(rh),
                    Err(e) => {
                        dpd_log!(log,
                            error,
                            "route hash creation failed for {prefix} (port: {}, link: {}, tgt_ip: {}, vlan_id: {:?}): {e}",
                            r.port_id.clone(), r.link_id, r.tgt_ip, r.vlan_id;
                            "error" => format!("{e}"),
                            "prefix" => format!("r:?")
                        );
                        continue;
                    }
                };
            }
            result
        }
    };
    Ok(result.into_iter().collect())
}

/// Create a new Dendrite/dpd client. The lower half always runs on the same
/// host/zone as the underlying platform.
#[cfg(target_os = "illumos")]
pub fn new_dpd_client(log: &Logger) -> DpdClient {
    let client_state = dpd_client::ClientState {
        tag: MG_LOWER_TAG.into(),
        log: log.clone(),
    };
    DpdClient::new(
        &format!("http://localhost:{}", dpd_client::default_port()),
        client_state,
    )
}
