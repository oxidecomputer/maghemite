use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use libnet::{IpPrefix, Ipv4Prefix, Ipv6Prefix};

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
            IpAddr::V4(a) => {
                IpPrefix::V4(Ipv4Prefix{
                    addr: a,
                    mask: self.prefix_len,
                })
            }
            IpAddr::V6(a) => {
                IpPrefix::V6(Ipv6Prefix{
                    addr: a,
                    mask: self.prefix_len,
                })
            }
        }
    }
}

pub fn  get_routes_illumos() -> Result<Vec<Route>, String> {

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

pub fn  add_routes_illumos(routes: Vec<Route>) -> Result<(), String> {

    for r in routes {
        let gw = r.gw;
        match libnet::ensure_route_present(r.into(), gw) {
            Ok(_) => {},
            Err(e) => return Err(format!("set route: {}", e)),
        }
    }

    Ok(())

}

pub fn  remote_routes_illumos(routes: Vec<Route>) -> Result<(), String> {

    for r in routes {
        let gw = r.gw;
        match libnet::delete_route(r.into(), gw) {
            Ok(_) => {},
            Err(e) => return Err(format!("set route: {}", e)),
        }
    }

    Ok(())

}

pub fn  get_routes_dendrite(
    host: String,
    port: u16,
) -> Result<Vec<Route>, String> {

    todo!();

}

pub fn  add_routes_dendrite(
    routes: Vec<Route>,
    host: String,
    port: u16,
) -> Result<(), String> {

    todo!();

}

pub fn  remove_routes_dendrite(
    routes: Vec<Route>,
    host: String,
    port: u16,
) -> Result<(), String> {

    todo!();

}
