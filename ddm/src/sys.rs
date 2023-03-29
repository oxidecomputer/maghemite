use crate::sm::{Config, DpdConfig};
use dendrite_common::network::{Cidr, Ipv6Cidr};
use dpd_client::types;
use dpd_client::Client;
use dpd_client::ClientState;
use libnet::{IpPrefix, Ipv4Prefix, Ipv6Prefix};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{debug, info, warn, Logger};
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
) -> Result<(), String> {
    match &config.dpd {
        Some(dpd) => {
            info!(log, "sending {} routes to dendrite", routes.len());
            add_routes_dendrite(
                routes,
                &dpd.host,
                dpd.port,
                &config.if_name,
                rt,
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
    rt: &Arc<tokio::runtime::Handle>,
    log: &Logger,
) -> Result<(), String> {
    debug!(log, "sending to dpd host={} port={}", host, port);

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

        // TODO this assumes ddm only operates on rear ports, which will not be
        // true for multi-rack deployments.
        let switch_port =
            types::PortId::from_str(&format!("rear{}/0", egress_port_num - 1))?;

        // TODO breakout considerations
        let link = types::LinkId(0);

        let route = types::Route {
            tag: DDM_DPD_TAG.into(),
            cidr: cidr.into(),
            switch_port,
            link,
            nexthop: Some(gw.into()),
        };

        let client = client.clone();

        rt.spawn(async move {
            client.route_ipv6_create(&route).await.unwrap(); //TODO unwrap
        });
    }

    Ok(())
}

pub fn remove_routes(
    log: &Logger,
    dpd: &Option<DpdConfig>,
    routes: Vec<Route>,
    rt: &Arc<tokio::runtime::Handle>,
) -> Result<(), String> {
    match dpd {
        Some(dpd) => {
            info!(log, "removing routes {} from dendrite", routes.len());
            // TODO seems like this should take an egress port, if there is a
            // destination prefix with two different destination egress ports,
            // we want to be able to delete one but not the other. Looks like
            // this would be an update to the dpd api.
            remove_routes_dendrite(routes, &dpd.host, dpd.port, rt, log)
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
    rt: &Arc<tokio::runtime::Handle>,
    log: &Logger,
) -> Result<(), String> {
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
                warn!(log, "route remove: non-ipv6 routes not supported");
                continue;
            }
        };

        let client = client.clone();

        rt.spawn(async move {
            client.route_ipv6_delete(&cidr).await.unwrap(); //TODO unwrap
        });
    }

    Ok(())
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

    let routes = rt.block_on(async {
        //TODO unwrap
        client
            .route_ipv6_list(None, None)
            .await
            .unwrap()
            .items
            .to_vec()
    });
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
        let parts: Vec<&str> = r.switch_port.split(':').collect();
        if parts.is_empty() {
            return Err(format!(
                "expected port format M:N, got {}",
                r.switch_port.as_str()
            ));
        }
        let egress_port = match parts[0].parse::<u16>() {
            Ok(n) => n,
            Err(e) => {
                return Err(format!(
                    "expected port format M:N, got {}: {}",
                    r.switch_port.as_str(),
                    e,
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
