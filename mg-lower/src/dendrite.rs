// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Error;
use crate::MG_LOWER_TAG;
use dendrite_common::network::Cidr;
use dendrite_common::ports::PortId;
use dendrite_common::ports::QsfpPort;
use dpd_client::types;
use dpd_client::types::LinkId;
use dpd_client::types::LinkState;
use dpd_client::Client as DpdClient;
use dpd_client::Ipv4Cidr;
use dpd_client::Ipv6Cidr;
use http::StatusCode;
use libnet::Ipv6Prefix;
use libnet::{get_route, IpPrefix, Ipv4Prefix};
use rdb::Path;
use rdb::Prefix;
use slog::{error, warn, Logger};
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

const TFPORT_QSFP_DEVICE_PREFIX: &str = "tfportqsfp";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RouteHash {
    pub(crate) cidr: Cidr,
    pub(crate) port_id: PortId,
    pub(crate) link_id: types::LinkId,
    pub(crate) nexthop: IpAddr,
    pub(crate) vlan_id: Option<u16>,
}

impl RouteHash {
    pub fn new(
        cidr: Cidr,
        port_id: PortId,
        link_id: types::LinkId,
        nexthop: IpAddr,
        vlan_id: Option<u16>,
    ) -> Result<Self, &'static str> {
        match (cidr, nexthop) {
            (Cidr::V4(_), IpAddr::V4(_)) | (Cidr::V6(_), IpAddr::V6(_)) => {
                Ok(RouteHash {
                    cidr,
                    port_id,
                    link_id,
                    nexthop,
                    vlan_id,
                })
            }
            _ => Err("mismatched subnet and target"),
        }
    }

    pub fn for_prefix_path(
        prefix: Prefix,
        path: Path,
    ) -> Result<RouteHash, Error> {
        let (port_id, link_id) = get_port_and_link(path.nexthop)?;

        // XXX: verify that the link vlan ID matches the route's vlan ID?
        let rh = RouteHash {
            cidr: match prefix {
                Prefix::V4(p) => Ipv4Cidr {
                    prefix: p.value,
                    prefix_len: p.length,
                }
                .into(),
                Prefix::V6(p) => Ipv6Cidr {
                    prefix: p.value,
                    prefix_len: p.length,
                }
                .into(),
            },
            port_id,
            link_id,
            nexthop: path.nexthop,
            vlan_id: path.vlan_id,
        };

        Ok(rh)
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

pub(crate) fn link_is_up(
    dpd: &DpdClient,
    port_id: PortId,
    link_id: LinkId,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<bool, Error> {
    let link_info =
        rt.block_on(async { dpd.link_get(&port_id, &link_id).await })?;

    Ok(link_info.link_state == LinkState::Up)
}

fn get_local_addrs(
    dpd: &DpdClient,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<(BTreeSet<Ipv4Addr>, BTreeSet<Ipv6Addr>), Error> {
    let links = rt
        .block_on(async { dpd.link_list_all().await })?
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
    dpd: &DpdClient,
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) -> Result<(), Error>
where
    I: Iterator<Item = &'a RouteHash>,
{
    let (local_v4_addrs, local_v6_addrs) = get_local_addrs(dpd, &rt)?;

    for r in to_add {
        let cidr = r.cidr;
        let tag = dpd.inner().tag.clone();
        let port_id = r.port_id;
        let link_id = r.link_id;
        let vlan_id = r.vlan_id;

        let target = match (r.cidr, r.nexthop) {
            (Cidr::V4(c), IpAddr::V4(tgt_ip)) => {
                if c.prefix_len == 32 && local_v4_addrs.contains(&c.prefix) {
                    warn!(
                        log,
                        "martian detected: prefix={c:?}, \
                        skipping data plane installation"
                    );
                    continue;
                }
                if local_v4_addrs.contains(&tgt_ip) {
                    warn!(
                        log,
                        "martian detected: nexthop={tgt_ip:?}, \
                        skipping data plane installation"
                    );
                    continue;
                }

                types::Ipv4Route {
                    tag,
                    port_id,
                    link_id,
                    tgt_ip,
                    vlan_id,
                }
                .into()
            }
            (Cidr::V6(c), IpAddr::V6(tgt_ip)) => {
                if c.prefix_len == 128 && local_v6_addrs.contains(&c.prefix) {
                    warn!(
                        log,
                        "martian detected: prefix={c:?}, \
                        skipping data plane installation"
                    );
                    continue;
                }
                if local_v6_addrs.contains(&tgt_ip) {
                    warn!(
                        log,
                        "martian detected: nexthop={tgt_ip:?}, \
                        skipping data plane installation"
                    );
                    continue;
                }

                types::Ipv6Route {
                    tag,
                    port_id,
                    link_id,
                    tgt_ip,
                    vlan_id,
                }
                .into()
            }
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
    nexthop: IpAddr,
) -> Result<(PortId, types::LinkId), Error> {
    let prefix = match nexthop {
        IpAddr::V4(addr) => IpPrefix::V4(Ipv4Prefix { addr, mask: 32 }),
        IpAddr::V6(addr) => IpPrefix::V6(Ipv6Prefix { addr, mask: 128 }),
    };
    let sys_route = get_route(prefix, Some(Duration::from_secs(1)))?;

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
    let port_id = match QsfpPort::try_from(port) {
        Ok(qsfp) => PortId::Qsfp(qsfp),
        Err(e) => return Err(Error::Tfport(format!("bad port name: {e}"))),
    };

    // TODO breakout considerations
    let link_id = dpd_client::types::LinkId(link);
    Ok((port_id, link_id))
}

pub(crate) fn get_routes_for_prefix(
    dpd: &DpdClient,
    prefix: &Prefix,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> Result<HashSet<RouteHash>, Error> {
    let result = match prefix {
        Prefix::V4(p) => {
            let cidr = Ipv4Cidr {
                prefix: p.value,
                prefix_len: p.length,
            };
            let dpd_routes =
                match rt.block_on(async { dpd.route_ipv4_get(&cidr).await }) {
                    Ok(routes) => routes,
                    Err(e) => {
                        if e.status() == Some(StatusCode::NOT_FOUND) {
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
                match link_is_up(dpd, r.port_id, r.link_id, &rt) {
                    Err(e) => {
                        error!(
                            log,
                            "nexthop: {} failed to get link state for {:?}/{:?}: {e}",
                            r.tgt_ip,
                            r.port_id,
                            r.link_id
                        );
                        continue;
                    }
                    Ok(false) => {
                        warn!(
                            log,
                            "nexthop: {} link {:?}/{:?} is not up, \
                            not installing route for {:?}",
                            r.tgt_ip,
                            r.port_id,
                            r.link_id,
                            prefix,
                        );
                        continue;
                    }
                    Ok(true) => {}
                }
                match RouteHash::new(
                    cidr.into(),
                    r.port_id,
                    r.link_id,
                    r.tgt_ip.into(),
                    r.vlan_id,
                ) {
                    Ok(rh) => result.push(rh),
                    Err(e) => {
                        error!(
                            log,
                            "route hash creation failed for {:?}: {e}", prefix
                        );
                        continue;
                    }
                };
            }

            dpd_routes
                .into_iter()
                .map(|r| {
                    RouteHash::new(
                        cidr.into(),
                        r.port_id,
                        r.link_id,
                        r.tgt_ip.into(),
                        r.vlan_id,
                    )
                    .unwrap()
                })
                .collect()
        }
        Prefix::V6(p) => {
            let cidr = Ipv6Cidr {
                prefix: p.value,
                prefix_len: p.length,
            };
            let dpd_routes = rt
                .block_on(async { dpd.route_ipv6_get(&cidr).await })?
                .into_inner();

            dpd_routes
                .into_iter()
                .map(|r| {
                    RouteHash::new(
                        cidr.into(),
                        r.port_id,
                        r.link_id,
                        r.tgt_ip.into(),
                        r.vlan_id,
                    )
                    .unwrap()
                })
                .collect()
        }
    };
    Ok(result)
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
