use std::net::{IpAddr, Ipv6Addr};

use dendrite_common::{Cidr, Ipv6Cidr};
use libnet::{IpPrefix, Ipv4Prefix, Ipv6Prefix};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{debug, warn, Logger};

use crate::router::Config;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Route {
    pub dest: IpAddr,
    pub prefix_len: u8,
    pub gw: IpAddr,
    pub egress_port: u16,
}

impl From<libnet::route::Route> for Route {
    fn from(r: libnet::route::Route) -> Self {
        Self {
            dest: r.dest,
            //TODO libnet should return a u8, as nothing > 128 is a valid mask
            prefix_len: r.mask.try_into().unwrap(),
            gw: r.gw,
            egress_port: 0,
        }
    }
}

impl Into<libnet::route::Route> for Route {
    fn into(self) -> libnet::route::Route {
        libnet::route::Route {
            dest: self.dest,
            //TODO libnet should return a u8 as nothing > 128 is a valid mask
            mask: self.prefix_len as u32,
            gw: self.gw,
        }
    }
}

impl Into<IpPrefix> for Route {
    fn into(self) -> IpPrefix {
        match self.dest {
            IpAddr::V4(a) => IpPrefix::V4(Ipv4Prefix {
                addr: a,
                mask: self.prefix_len,
            }),
            IpAddr::V6(a) => IpPrefix::V6(Ipv6Prefix {
                addr: a,
                mask: self.prefix_len,
            }),
        }
    }
}

pub fn add_routes(
    log: &Logger,
    config: &Config,
    routes: Vec<Route>,
) -> Result<(), String> {
    match &config.protod {
        Some(protod) => {
            add_routes_dendrite(routes, &protod.host, protod.port, log)
        }
        None => add_routes_illumos(routes),
    }
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

pub fn add_routes_illumos(routes: Vec<Route>) -> Result<(), String> {
    for r in routes {
        let gw = r.gw;

        // don't add with a local destination or gateway
        if addr_is_local(gw)? || addr_is_local(r.dest)? {
            continue;
        }
        match libnet::ensure_route_present(r.into(), gw) {
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

pub fn remote_routes_illumos(routes: Vec<Route>) -> Result<(), String> {
    for r in routes {
        let gw = r.gw;
        match libnet::delete_route(r.into(), gw) {
            Ok(_) => {}
            Err(e) => return Err(format!("set route: {}", e)),
        }
    }

    Ok(())
}

pub fn get_routes_dendrite(
    host: String,
    port: u16,
) -> Result<Vec<Route>, String> {
    let api = protod_api::Api::new(host.clone(), port)
        .map_err(|e| format!("protod api new: {}", e))?;

    let mut cookie = "".to_string();
    let routes = api
        .route_ipv6_get_range(None, &mut cookie)
        .map_err(|e| format!("protod get routes: {}", e))?;
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
        let egress_port = r.egress_port;
        result.push(Route {
            dest,
            prefix_len,
            gw,
            egress_port,
        });
    }

    Ok(result)
}

pub fn add_routes_dendrite(
    routes: Vec<Route>,
    host: &str,
    port: u16,
    log: &Logger,
) -> Result<(), String> {
    let protod_api = protod_api::Api::new(host.into(), port)
        .map_err(|e| format!("protod api new: {}", e))?;

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

        let egress_port = match protod_api.ndp_get(gw) {
            Ok(nbr) => {
                debug!(
                    log,
                    "found neighbor port: {:?} -> {:?}", gw, nbr.port_id
                );
                nbr.port_id
            }
            Err(e) => {
                // TODO(ry) there are a number of reasons why an ndp entry may
                // be transiently unavailable, there should be some (possibly
                // asynchronous) retry logic here.
                return Err(format!("ndp get{:?}", e));
            }
        };

        protod_api
            .route_ipv6_add(&cidr, egress_port, Some(gw))
            .map_err(|e| format!("protod route add: {}", e))?;
    }

    Ok(())
}

pub fn remove_routes_dendrite(
    routes: Vec<Route>,
    host: String,
    port: u16,
    log: Logger,
) -> Result<(), String> {
    let protod_api = protod_api::Api::new(host.clone(), port)
        .map_err(|e| format!("protod api new: {}", e))?;

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

        protod_api
            .route_ipv6_del(&cidr)
            .map_err(|e| format!("protod route del: {}", e))?;
    }

    Ok(())
}
