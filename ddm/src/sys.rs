// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::sm::{Config, DpdConfig};
use crate::{dbg, err, inf, wrn};
use ddm_api_types::db::TunnelRoute;
use dpd_client::Client;
use dpd_client::ClientState;
use dpd_client::types;
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use types::PortId;

#[cfg(target_os = "illumos")]
use ::{
    opte_ioctl::OpteHdl, oxide_vpc::api::TunnelEndpoint,
    std::collections::HashMap,
};

const DDM_DPD_TAG: &str = "ddmd";

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Route {
    pub dest: IpAddr,
    pub prefix_len: u8,
    pub gw: IpAddr,
    pub egress_port: u16,
    pub ifname: String,
}

impl Route {
    pub fn new(dest: IpAddr, prefix_len: u8, gw: IpAddr) -> Self {
        Self {
            dest,
            prefix_len,
            gw,
            egress_port: 0,
            ifname: String::new(),
        }
    }
}

impl From<crate::db::Route> for Route {
    fn from(r: crate::db::Route) -> Self {
        Self {
            dest: r.destination.addr().into(),
            prefix_len: r.destination.width(),
            gw: r.nexthop.into(),
            egress_port: 0,
            ifname: r.ifname,
        }
    }
}

impl From<libnet::route::Route> for Route {
    fn from(r: libnet::route::Route) -> Self {
        Self {
            dest: r.dest,
            prefix_len: r.mask.try_into().unwrap(),
            gw: r.gw,
            egress_port: 0,
            ifname: r.ifx.unwrap_or_default(),
        }
    }
}

impl From<Route> for libnet::route::Route {
    fn from(r: Route) -> libnet::route::Route {
        libnet::route::Route {
            dest: r.dest,
            mask: r.prefix_len as u32,
            gw: r.gw,
            delay: 0,
            ifx: if !r.ifname.is_empty() {
                Some(r.ifname)
            } else {
                None
            },
        }
    }
}

impl From<Route> for IpNet {
    fn from(r: Route) -> IpNet {
        match r.dest {
            IpAddr::V4(a) => Ipv4Net::new(a, r.prefix_len).unwrap().into(),
            IpAddr::V6(a) => Ipv6Net::new(a, r.prefix_len).unwrap().into(),
        }
    }
}

pub fn add_underlay_routes(
    log: &Logger,
    config: &Config,
    routes: Vec<Route>,
    rt: &tokio::runtime::Handle,
) {
    match &config.dpd {
        Some(dpd) => {
            inf!(
                log,
                config.if_name,
                "sending {} routes to dendrite",
                routes.len(),
            );
            add_routes_dendrite(
                routes,
                &dpd.host,
                dpd.port,
                &config.if_name,
                rt,
                log,
            );
        }
        None => {
            inf!(
                log,
                config.if_name,
                "sending {} routes to illumos",
                routes.len(),
            );
            add_routes_illumos(log, routes, &config.if_name);
        }
    }
}

pub fn add_routes_dendrite(
    routes: Vec<Route>,
    host: &str,
    port: u16,
    ifname: &str,
    rt: &tokio::runtime::Handle,
    log: &Logger,
) {
    dbg!(log, ifname, "sending to dpd host={} port={}", host, port);

    let client_state = ClientState {
        tag: DDM_DPD_TAG.into(),
        log: log.clone(),
    };
    let client = Client::new(&format!("http://{host}:{port}"), client_state);

    // Map the system interface name (e.g. "tfportrear0_0") to the Dendrite
    // switch port and link it fronts.
    let Some((port_id, link_id)) = tfport_to_dpd(ifname) else {
        err!(log, ifname, "cannot derive switch port from interface name");
        return;
    };

    // Underlay routes belong only on rack-interior links. Unlike the old
    // tfportrear name check, the uplink attribute also handles multi-rack port
    // layouts without assuming a particular physical port type.
    match rt.block_on({
        let client = client.clone();
        let port_id = port_id.clone();
        async move { client.link_uplink_get(&port_id, &link_id).await }
    }) {
        Ok(response) => {
            if response.into_inner() {
                inf!(
                    log,
                    ifname,
                    "skipping route install on uplink port {port_id}/{link_id}"
                );
                return;
            }
        }
        Err(error) => {
            err!(log, ifname, "failed to query uplink property: {error}");
            return;
        }
    }

    for r in routes {
        let cidr = match r.dest {
            IpAddr::V6(addr) => match Ipv6Net::new(addr, r.prefix_len) {
                Ok(cidr) => cidr,
                Err(e) => {
                    err!(
                        log,
                        ifname,
                        "error forming cidr: {}/{} {:?}",
                        addr,
                        r.prefix_len,
                        e
                    );
                    continue;
                }
            },
            _ => {
                err!(log, ifname, "unsupported dst: {:?}", r.dest);
                continue;
            }
        };

        let gw = match r.gw {
            IpAddr::V6(gw) => gw,
            _ => {
                err!(log, ifname, "unsupported gw: {:?}", r.gw);
                continue;
            }
        };

        inf!(
            log,
            ifname,
            "adding route {} -> {} on port {port_id}/{link_id}",
            r.dest,
            r.gw,
        );

        let target = types::Ipv6Route {
            tag: DDM_DPD_TAG.into(),
            port_id: port_id.clone(),
            link_id,
            tgt_ip: gw,
            vlan_id: None,
        };
        let route_set = types::Ipv6RouteUpdate {
            cidr,
            target,
            replace: false,
        };

        let client = client.clone();

        if let Err(e) =
            rt.block_on(async move { client.route_ipv6_set(&route_set).await })
        {
            err!(log, ifname, "dpd route create: {e}");
        }
    }
}

/// Derive the Dendrite switch port and link fronted by a tfport interface.
///
/// Tfport interfaces are named `tfport<port>_<link>`, such as
/// `tfportrear0_0` or `tfportqsfp10_1`.
fn tfport_to_dpd(ifname: &str) -> Option<(PortId, types::LinkId)> {
    let (port, link) = ifname.strip_prefix("tfport")?.rsplit_once('_')?;
    let port_id = port.parse::<PortId>().ok()?;
    let link_id = types::LinkId(link.parse::<u8>().ok()?);
    Some((port_id, link_id))
}

#[cfg(target_os = "illumos")]
fn tunnel_route_update_map(
    routes: &HashSet<TunnelRoute>,
) -> HashMap<IpNet, Vec<TunnelEndpoint>> {
    let mut m: HashMap<IpNet, Vec<TunnelEndpoint>> = HashMap::new();
    for r in routes {
        let pfx = r.origin.overlay_prefix;
        let tep = TunnelEndpoint {
            ip: r.origin.boundary_addr.into(),
            vni: oxide_vpc::api::Vni::new(r.origin.vni).unwrap(),
        };
        match m.get_mut(&pfx) {
            Some(entry) => {
                entry.push(tep);
            }
            None => {
                m.insert(pfx, vec![tep]);
            }
        }
    }
    m
}

#[cfg(not(target_os = "illumos"))]
pub fn add_tunnel_routes(
    _log: &Logger,
    _ifname: &str,
    _routes: &HashSet<TunnelRoute>,
) -> Result<(), String> {
    todo!();
}

#[cfg(target_os = "illumos")]
pub fn add_tunnel_routes(
    log: &Logger,
    ifname: &str,
    routes: &HashSet<TunnelRoute>,
) -> Result<(), String> {
    use oxide_vpc::api::{
        IpCidr, Ipv4Cidr, Ipv4PrefixLen, Ipv6Cidr, Ipv6PrefixLen,
        SetVirt2BoundaryReq,
    };
    let hdl = OpteHdl::open().map_err(|e| e.to_string())?;

    for (pfx, tep) in tunnel_route_update_map(routes) {
        for t in &tep {
            inf!(
                log,
                ifname,
                "adding tunnel route {} -[{}]-> {}",
                pfx,
                t.vni,
                t.ip,
            );
        }
        let vip = match pfx {
            IpNet::V4(p) => IpCidr::Ip4(Ipv4Cidr::new(
                p.addr().into(),
                Ipv4PrefixLen::new(p.width()).unwrap(),
            )),
            IpNet::V6(p) => IpCidr::Ip6(Ipv6Cidr::new(
                p.addr().into(),
                Ipv6PrefixLen::new(p.width()).unwrap(),
            )),
        };
        let req = SetVirt2BoundaryReq { vip, tep };
        if let Err(e) = hdl.set_v2b(&req) {
            err!(log, ifname, "failed to set v2p route: {:?}: {}", req, e);
        }
    }

    Ok(())
}

#[cfg(not(target_os = "illumos"))]
pub fn remove_tunnel_routes(
    _log: &Logger,
    _ifname: &str,
    _routes: &HashSet<TunnelRoute>,
) -> Result<(), String> {
    todo!()
}

#[cfg(target_os = "illumos")]
pub fn remove_tunnel_routes(
    log: &Logger,
    ifname: &str,
    routes: &HashSet<TunnelRoute>,
) -> Result<(), String> {
    use oxide_vpc::api::{
        ClearVirt2BoundaryReq, IpCidr, Ipv4Cidr, Ipv4PrefixLen, Ipv6Cidr,
        Ipv6PrefixLen,
    };
    let hdl = OpteHdl::open().map_err(|e| e.to_string())?;
    for (pfx, tep) in tunnel_route_update_map(routes) {
        for t in &tep {
            inf!(
                log,
                ifname,
                "removing tunnel route {} -[{}]-> {}",
                pfx,
                t.vni,
                t.ip,
            );
        }
        let vip = match pfx {
            IpNet::V4(p) => IpCidr::Ip4(Ipv4Cidr::new(
                p.addr().into(),
                Ipv4PrefixLen::new(p.width()).unwrap(),
            )),
            IpNet::V6(p) => IpCidr::Ip6(Ipv6Cidr::new(
                p.addr().into(),
                Ipv6PrefixLen::new(p.width()).unwrap(),
            )),
        };
        let req = ClearVirt2BoundaryReq { vip, tep };
        if let Err(e) = hdl.clear_v2b(&req) {
            err!(log, ifname, "failed to clear v2p route: {:?}: {}", req, e);
        }
    }

    Ok(())
}

pub fn remove_underlay_routes(
    log: &Logger,
    ifname: &str,
    dpd: &Option<DpdConfig>,
    routes: Vec<Route>,
    rt: &tokio::runtime::Handle,
) {
    match dpd {
        Some(dpd) => {
            inf!(
                log,
                ifname,
                "removing routes {} from dendrite",
                routes.len(),
            );
            // TODO seems like this should take an egress port, if there is a
            // destination prefix with two different destination egress ports,
            // we want to be able to delete one but not the other. Looks like
            // this would be an update to the dpd api.
            remove_routes_dendrite(
                routes, &dpd.host, dpd.port, rt, ifname, log,
            );
        }
        None => {
            inf!(log, ifname, "removing {} routes from illumos", routes.len(),);
            remove_routes_illumos(log, ifname, routes);
        }
    }
}

pub fn remove_routes_dendrite(
    routes: Vec<Route>,
    host: &str,
    port: u16,
    rt: &tokio::runtime::Handle,
    ifname: &str,
    log: &Logger,
) {
    let client_state = ClientState {
        tag: DDM_DPD_TAG.into(),
        log: log.clone(),
    };
    let client = Client::new(&format!("http://{host}:{port}"), client_state);

    for r in routes {
        let cidr = match r.dest {
            IpAddr::V6(addr) => match Ipv6Net::new(addr, r.prefix_len) {
                Ok(cidr) => cidr,
                Err(e) => {
                    err!(
                        log,
                        ifname,
                        "failed to create cidr for {}/{}: {}",
                        addr,
                        r.prefix_len,
                        e
                    );
                    continue;
                }
            },
            _ => {
                wrn!(
                    log,
                    ifname,
                    "route remove: non-ipv6 routes not supported"
                );
                continue;
            }
        };

        let client = client.clone();

        if let Err(e) =
            rt.block_on(async move { client.route_ipv6_delete(&cidr).await })
        {
            err!(log, ifname, "dpd route delete: {e}");
            continue;
        }
    }
}

pub fn get_routes_dendrite(
    host: String,
    port: u16,
    rt: &tokio::runtime::Handle,
    log: Logger,
) -> Result<Vec<Route>, String> {
    let client_state = ClientState {
        tag: DDM_DPD_TAG.into(),
        log: log.clone(),
    };
    let client = Client::new(&format!("http://{host}:{port}"), client_state);

    let routes = rt
        .block_on(async { client.route_ipv6_list(None, None).await })
        .map_err(|e| format!("dpd route list: {}", e))?
        .items
        .to_vec();

    let mut result = Vec::new();

    for r in routes {
        for target in r.targets {
            let egress_port = match &target.port_id {
                PortId::Rear(rear) => match rear.parse::<u16>() {
                    Ok(p) => p,
                    Err(e) => {
                        slog::warn!(
                            log,
                            "Found invalid rear port ({}): {:?}",
                            target.port_id,
                            e
                        );
                        continue;
                    }
                },
                _ => continue,
            };

            result.push(Route {
                dest: r.cidr.prefix().into(),
                prefix_len: r.cidr.width(),
                gw: target.tgt_ip.into(),
                egress_port,
                ifname: String::new(),
            });
        }
    }

    Ok(result)
}

pub fn get_routes_illumos() -> Result<Vec<Route>, String> {
    let mut result = Vec::new();

    let routes = match libnet::get_routes() {
        Ok(rs) => rs,
        Err(e) => return Err(format!("get routes: {}", e)),
    };

    for r in routes {
        result.push(r.into());
    }

    Ok(result)
}

pub fn add_routes_illumos(log: &Logger, routes: Vec<Route>, ifname: &str) {
    for r in routes {
        let gw = r.gw;

        inf!(log, ifname, "adding route {} -> {}", r.dest, r.gw,);

        // don't add with a local destination or gateway
        if let Ok(true) = addr_is_local(gw) {
            continue;
        }
        if let Ok(true) = addr_is_local(r.dest) {
            continue;
        }

        let dst = match IpNet::new(r.dest, r.prefix_len) {
            Ok(dst) => dst,
            Err(e) => {
                err!(
                    log,
                    ifname,
                    "error forming route destination: {:?}, {}",
                    r,
                    e
                );
                continue;
            }
        };

        if let Err(e) =
            libnet::ensure_route_present(dst, gw, Some(ifname.into()))
        {
            err!(log, ifname, "set route: {}", e);
        }
    }
}

/// Resolve the IPv6 link-local address configured on the interface `ifname`.
///
/// Addresses on logical interfaces (`ifname:N`) count as belonging to
/// `ifname`. Returns the interface index and address. If more than one
/// link-local address is present the first is used and the rest are logged.
pub fn link_local_addr(
    log: &Logger,
    ifname: &str,
) -> Result<(u32, Ipv6Addr), String> {
    let addrinfo = libnet::get_ipaddrs().map_err(|e| e.to_string())?;
    let mut candidates = addrinfo
        .into_iter()
        .filter(|(lif, _)| {
            lif.strip_prefix(ifname)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
        })
        .flat_map(|(_, infos)| infos)
        .filter_map(|info| match info.addr {
            IpAddr::V6(addr) if addr.is_unicast_link_local() => {
                Some((info.index as u32, addr))
            }
            _ => None,
        });

    let Some(selected) = candidates.next() else {
        return Err(format!(
            "no IPv6 link-local address found on interface {ifname}"
        ));
    };

    let others = candidates.map(|(_, addr)| addr).collect::<Vec<_>>();
    if !others.is_empty() {
        wrn!(
            log,
            ifname,
            "more than one link-local address on interface; using {}, also found {}",
            selected.1,
            others
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }

    Ok(selected)
}

fn addr_is_local(gw: IpAddr) -> Result<bool, String> {
    let addrinfo = libnet::get_ipaddrs().map_err(|e| format!("{}", e))?;
    for (_, infos) in addrinfo {
        for info in infos {
            if gw == info.addr {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn remove_routes_illumos(log: &Logger, ifname: &str, routes: Vec<Route>) {
    for r in routes {
        let gw = r.gw;
        inf!(log, ifname, "removing route {} -> {}", r.dest, r.gw,);
        let dst = match IpNet::new(r.dest, r.prefix_len) {
            Ok(dst) => dst,
            Err(e) => {
                err!(
                    log,
                    ifname,
                    "error forming route destination: {:?}, {}",
                    r,
                    e
                );
                continue;
            }
        };
        if let Err(e) = libnet::delete_route(dst, gw, Some(r.ifname.clone())) {
            err!(log, ifname, "set route: {e}");
            continue;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tfport_to_dpd;

    #[test]
    fn tfport_to_dpd_parses_port_type_and_link() {
        let (port, link) = tfport_to_dpd("tfportqsfp10_1").unwrap();
        assert_eq!(port.to_string(), "qsfp10");
        assert_eq!(link.0, 1);
    }

    #[test]
    fn tfport_to_dpd_rejects_invalid_names() {
        assert!(tfport_to_dpd("qsfp10_1").is_none());
        assert!(tfport_to_dpd("tfportqsfp10").is_none());
        assert!(tfport_to_dpd("tfportqsfp10_invalid").is_none());
    }
}
