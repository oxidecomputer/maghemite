use crate::sm::{Config, DpdConfig};
use crate::{dbg, err, inf, wrn};
use dendrite_common::network::{Cidr, Ipv6Cidr};
use dpd_client::types;
use dpd_client::Client;
use dpd_client::ClientState;
use libnet::{IpPrefix, Ipv4Prefix, Ipv6Prefix};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

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
            dest: r.destination.addr.into(),
            //TODO libnet should return a u8, as nothing > 128 is a valid mask
            prefix_len: r.destination.len,
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
            //TODO libnet should return a u8, as nothing > 128 is a valid mask
            prefix_len: r.mask.try_into().unwrap(),
            gw: r.gw,
            egress_port: 0,
            ifname: match r.ifx {
                Some(ifx) => ifx,
                None => String::new(),
            },
        }
    }
}

impl From<Route> for libnet::route::Route {
    fn from(r: Route) -> libnet::route::Route {
        libnet::route::Route {
            dest: r.dest,
            //TODO libnet should return a u8 as nothing > 128 is a valid mask
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

impl From<Route> for IpPrefix {
    fn from(r: Route) -> IpPrefix {
        match r.dest {
            IpAddr::V4(a) => IpPrefix::V4(Ipv4Prefix {
                addr: a,
                mask: r.prefix_len,
            }),
            IpAddr::V6(a) => IpPrefix::V6(Ipv6Prefix {
                addr: a,
                mask: r.prefix_len,
            }),
        }
    }
}

pub fn add_routes(
    log: &Logger,
    config: &Config,
    routes: Vec<Route>,
    rt: &Arc<tokio::runtime::Handle>,
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
    rt: &Arc<tokio::runtime::Handle>,
    log: &Logger,
) {
    dbg!(log, ifname, "sending to dpd host={} port={}", host, port);

    let client_state = ClientState {
        tag: DDM_DPD_TAG.into(),
        log: log.clone(),
    };
    let client = Client::new(&format!("http://{host}:{port}"), client_state);

    for r in routes {
        let cidr = match r.dest {
            IpAddr::V6(addr) => Ipv6Cidr {
                prefix: addr,
                prefix_len: r.prefix_len,
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

        // TODO this is gross, use link type properties rather than futzing
        // around with strings.
        let Some(egress_port_num) = ifname
            .strip_prefix("tfportrear")
            .and_then(|x| x.strip_suffix("_0"))
            .map(|x| x.trim())
            .and_then(|x| x.parse::<usize>().ok())
        else {
            err!(log, ifname, "expected tfportrear");
            continue;
        };

        // TODO this assumes ddm only operates on rear ports, which will not be
        // true for multi-rack deployments.
        let switch_port = match types::PortId::from_str(&format!(
            "rear{}",
            egress_port_num
        )) {
            Ok(swp) => swp,
            Err(e) => {
                err!(log, ifname, "bad port name: {e}");
                continue;
            }
        };

        inf!(
            log,
            ifname,
            "adding route {} -> {} on port {:?}/{}",
            r.dest,
            r.gw,
            switch_port,
            0,
        );

        // TODO breakout considerations
        let link = types::LinkId(0);

        let route = types::Route {
            tag: DDM_DPD_TAG.into(),
            cidr: cidr.into(),
            switch_port,
            link,
            nexthop: gw.into(),
        };

        let client = client.clone();

        if let Err(e) =
            rt.block_on(async move { client.route_ipv6_set(&route).await })
        {
            err!(log, ifname, "dpd route create: {e}");
        }
    }
}

pub fn remove_routes(
    log: &Logger,
    ifname: &str,
    dpd: &Option<DpdConfig>,
    routes: Vec<Route>,
    rt: &Arc<tokio::runtime::Handle>,
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
    rt: &Arc<tokio::runtime::Handle>,
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
            IpAddr::V6(addr) => Ipv6Cidr {
                prefix: addr,
                prefix_len: r.prefix_len,
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
    rt: &Arc<tokio::runtime::Handle>,
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
        let gw = match r.nexthop {
            IpAddr::V6(addr) => addr.into(),
            _ => Ipv6Addr::UNSPECIFIED.into(),
        };
        let (dest, prefix_len) = match r.cidr {
            Cidr::V6(cidr) => (cidr.prefix.into(), cidr.prefix_len),
            _ => continue,
        };

        let egress_port = match r.switch_port {
            types::PortId::Rear(port) => port
                .to_string()
                .parse::<u16>()
                .expect("RearPort(n) is a u8, so should always parse"),
            _ => continue,
        };

        result.push(Route {
            dest,
            prefix_len,
            gw,
            egress_port,
            ifname: String::new(),
        });
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

        if let Err(e) =
            libnet::ensure_route_present(r.into(), gw, Some(ifname.into()))
        {
            err!(log, ifname, "set route: {}", e);
        }
    }
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
        if let Err(e) =
            libnet::delete_route(r.clone().into(), gw, Some(r.ifname.clone()))
        {
            err!(log, ifname, "set route: {e}");
            continue;
        }
    }
}
