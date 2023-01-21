use crate::sm::{Config, DpdConfig};
use dendrite_common::network::{Cidr, Ipv6Cidr};
use libnet::{IpPrefix, Ipv4Prefix, Ipv6Prefix};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{debug, info, warn, Logger};
use std::net::{IpAddr, Ipv6Addr};

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
            ifname: String::new(), //TODO
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
) -> Result<(), String> {
    match &config.dpd {
        Some(dpd) => {
            info!(log, "sending {} routes to dendrite", routes.len());
            add_routes_dendrite(
                routes,
                &dpd.host,
                dpd.port,
                &config.if_name,
                log,
            )
        }
        None => {
            info!(log, "sending {} routes to illumos", routes.len());
            add_routes_illumos(routes, &config.if_name)
        }
    }
}

pub fn add_routes_dendrite(
    routes: Vec<Route>,
    host: &str,
    port: u16,
    if_name: &str,
    log: &Logger,
) -> Result<(), String> {
    debug!(log, "sending to dpd host={} port={}", host, port);

    let dpd_api = dpd_api::Api::new(DDM_DPD_TAG, host, port)
        .map_err(|e| format!("dpdapi new: {}", e))?;

    for r in routes {
        let cidr = match r.dest {
            IpAddr::V6(addr) => Ipv6Cidr {
                prefix: addr,
                prefix_len: r.prefix_len,
            },
            _ => {
                return Err(format!("unsupported dst: {:?}", r.dest));
            }
        };

        let gw = match r.gw {
            IpAddr::V6(gw) => gw,
            _ => {
                return Err(format!("unsupported gw: {:?}", r.gw));
            }
        };

        // TODO this is gross, use link type properties rather than futzing
        // around with strings.
        let egress_port_num = if_name
            .strip_prefix("tfport")
            .ok_or(format!("expected tfport prefix {}", if_name))?
            .strip_suffix("_0")
            .ok_or(format!("expected _0 suffix {}", if_name))?
            .trim()
            .parse::<usize>()
            .map_err(|_| format!("expected tofino port number {}", if_name))?;

        let egress_port = format!("{}:0", egress_port_num);

        if let Err(e) = dpd_api.route_ipv6_add(&cidr, egress_port, Some(gw)) {
            // If this comes back as 409 conflict, that just means the route is
            // already there.
            if e.to_string().contains("409") {
                warn!(log, "attempt to add route that exists {}", cidr);
            } else {
                return Err(format!("dpd route add: {}", e));
            }
        }
    }

    Ok(())
}

pub fn remove_routes(
    log: &Logger,
    dpd: &Option<DpdConfig>,
    routes: Vec<Route>,
) -> Result<(), String> {
    match dpd {
        Some(dpd) => {
            info!(log, "removing routes {} from dendrite", routes.len());
            // TODO seems like this should take an egress port, if there is a
            // destination prefix with two different destination egress ports,
            // we want to be able to delete one but not the other. Looks like
            // this would be an update to the dpd api.
            remove_routes_dendrite(routes, &dpd.host, dpd.port, log)
        }
        None => {
            info!(log, "removing {} routes from illumos", routes.len());
            remove_routes_illumos(routes)
        }
    }
}

pub fn remove_routes_dendrite(
    routes: Vec<Route>,
    host: &str,
    port: u16,
    log: &Logger,
) -> Result<(), String> {
    let dpd_api = dpd_api::Api::new(DDM_DPD_TAG, host, port)
        .map_err(|e| format!("dpd api new: {}", e))?;

    for r in routes {
        let cidr = match r.dest {
            IpAddr::V6(addr) => Ipv6Cidr {
                prefix: addr,
                prefix_len: r.prefix_len,
            },
            _ => {
                warn!(log, "route remove: non-ipv6 routes not supported");
                continue;
            }
        };

        dpd_api
            .route_ipv6_del(&cidr)
            .map_err(|e| format!("dpd route del: {}", e))?;
    }

    Ok(())
}

pub fn get_routes_dendrite(
    host: String,
    port: u16,
) -> Result<Vec<Route>, String> {
    let api = dpd_api::Api::new(DDM_DPD_TAG, host, port)
        .map_err(|e| format!("dpd api new: {}", e))?;

    let mut cookie = "".to_string();
    let routes = api
        .route_ipv6_get_range(None, &mut cookie)
        .map_err(|e| format!("dpd get routes: {}", e))?;
    let mut result = Vec::new();

    for r in routes {
        let gw = match r.nexthop {
            Some(IpAddr::V6(addr)) => addr.into(),
            _ => Ipv6Addr::UNSPECIFIED.into(),
        };
        let (dest, prefix_len) = match r.cidr {
            Cidr::V6(cidr) => (cidr.prefix.into(), cidr.prefix_len),
            _ => continue,
        };
        let parts: Vec<&str> = r.egress_port.split(':').collect();
        if parts.is_empty() {
            return Err(format!(
                "expected port format M:N, got {}",
                r.egress_port
            ));
        }
        let egress_port = match parts[0].parse::<u16>() {
            Ok(n) => n,
            Err(e) => {
                return Err(format!(
                    "expected port format M:N, got {}: {}",
                    r.egress_port, e,
                ))
            }
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

pub fn add_routes_illumos(
    routes: Vec<Route>,
    ifname: &str,
) -> Result<(), String> {
    for r in routes {
        let gw = r.gw;

        // don't add with a local destination or gateway
        if addr_is_local(gw)? || addr_is_local(r.dest)? {
            continue;
        }
        match libnet::ensure_route_present(r.into(), gw, Some(ifname.into())) {
            Ok(_) => {}
            Err(e) => return Err(format!("set route: {}", e)),
        }
    }

    Ok(())
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

pub fn remove_routes_illumos(routes: Vec<Route>) -> Result<(), String> {
    for r in routes {
        let gw = r.gw;
        match libnet::delete_route(r.clone().into(), gw, Some(r.ifname.clone()))
        {
            Ok(_) => {}
            Err(e) => return Err(format!("set route: {}", e)),
        }
    }

    Ok(())
}
