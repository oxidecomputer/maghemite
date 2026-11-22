// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The illumos backend for ddm-lower

use crate::{InterfaceName, Route};
use ddm_api_types::net::TunnelOrigin;
use opte_ioctl::{self, OpteHdl};
use oxide_vpc::api::{
    ClearVirt2BoundaryReq, IpCidr, Ipv4Cidr, Ipv4PrefixLen, Ipv6Cidr,
    Ipv6PrefixLen, NoResp, SetVirt2BoundaryReq, TunnelEndpoint, Vni,
};
use oxnet::IpNet;
use slog::Logger;
use slog::{error, info, o};
use slog_error_chain::{InlineErrorChain, SlogInlineError};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, Ipv6Addr};

#[derive(thiserror::Error, Debug, SlogInlineError)]
pub enum Error {
    #[error("failed to get ip addresses from illumos")]
    GetIpAddrs(#[source] libnet::Error),

    #[error("failed to add route to illumos: {route:?}")]
    AddRoute {
        route: Route,
        #[source]
        err: libnet::route::Error,
    },

    #[error("failed to remove route from illumos: {route:?}")]
    RemoveRoute {
        route: Route,
        #[source]
        err: libnet::route::Error,
    },

    #[error("failed to open OpteHdl")]
    OpteOpenHdl(#[source] opte_ioctl::Error),

    #[error("failed to create VNI: value must fit in 24 bits: origin = {0:?}")]
    VniTooLarge(TunnelOrigin),

    #[error("failed to set tunnel routes for {req:?}")]
    OpteSetV2B {
        req: SetVirt2BoundaryReq,
        #[source]
        err: opte_ioctl::Error,
    },

    #[error("failed to clear tunnel routes for {req:?}")]
    OpteClearV2B {
        req: ClearVirt2BoundaryReq,
        #[source]
        err: opte_ioctl::Error,
    },
}

/// The illumos backend for ddm-lower
pub struct IllumosBackend {
    log: Logger,
}

impl IllumosBackend {
    // Create a new [`IllumosBackend`]
    pub fn new(log: &Logger) -> Self {
        Self {
            log: log.new(o!("backend" => "illumos")),
        }
    }
    /// Add underlay routes to illumos, returning any errors encountered.
    ///
    /// We log any errors inside here, but we also return them so that they can
    /// be used by the reconciler for statistics and external reporting.
    pub fn add_underlay_routes(
        &self,
        mut routes: Vec<Route>,
    ) -> Result<(), Vec<Error>> {
        // Filter out all local routes.
        // An error here is fatal. We'll try again on the next reconciliation.
        let local_addrs = Self::read_local_addrs().map_err(|e| vec![e])?;
        routes.retain(|r| !Self::route_is_local(r, &local_addrs));

        let mut errors = vec![];
        for r in routes {
            info!(
                self.log,
                "[{}] adding route {} -> {}", r.ifname, r.dest, r.gw,
            );
            match libnet::ensure_route_present(
                IpNet::V6(r.dest),
                IpAddr::V6(r.gw),
                Some(r.ifname.as_str().to_string()),
            ) {
                Ok(()) => {
                    info!(
                        self.log,
                        "[{}] successfully added route {} -> {}",
                        r.ifname,
                        r.dest,
                        r.gw,
                    );
                }
                Err(err) => {
                    error!(
                        self.log,
                        "[{}] failed to add route {} -> {}: {}",
                        r.ifname,
                        r.dest,
                        r.gw,
                        err
                    );
                    errors.push(Error::AddRoute { route: r, err });
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Remove underlay routes from illumos, returning any errors encountered.
    ///
    /// We log any errors inside here, but we also return them so that they can
    /// be used by the reconciler for statistics and external reporting.
    pub fn remove_underlay_routes(
        &self,
        routes: Vec<Route>,
    ) -> Result<(), Vec<Error>> {
        let mut errors = vec![];

        for r in routes {
            info!(
                self.log,
                "[{}] removing route {} -> {}", r.ifname, r.dest, r.gw,
            );

            match libnet::delete_route(
                IpNet::V6(r.dest),
                IpAddr::V6(r.gw),
                Some(r.ifname.as_str().to_string()),
            ) {
                Ok(()) => {
                    info!(
                        self.log,
                        "[{}] successfully removed route {} -> {}",
                        r.ifname,
                        r.dest,
                        r.gw,
                    );
                }
                // The routing socket returns ESRCH when the route is already
                // gone; don't report it as a failure or callers will keep
                // retrying the removal. ESRCH has no stable io::ErrorKind
                // mapping, so match on the raw errno.
                Err(libnet::route::Error::IoError(e))
                    if e.raw_os_error() == Some(libc::ESRCH) =>
                {
                    info!(
                        self.log,
                        "[{}] route {} -> {} already removed",
                        r.ifname,
                        r.dest,
                        r.gw,
                    );
                }
                Err(err) => {
                    error!(
                        self.log,
                        "[{}] failed to remove route {} -> {}: {}",
                        r.ifname,
                        r.dest,
                        r.gw,
                        err
                    );
                    errors.push(Error::RemoveRoute { route: r, err });
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Add tunnel routes to OPTE
    ///
    /// We log any errors inside here, but we also return them so that they can
    /// be used by the reconciler for statistics and external reporting.
    pub fn add_tunnel_routes(
        &self,
        ifname: InterfaceName,
        origins: &HashSet<TunnelOrigin>,
    ) -> Result<(), Vec<Error>> {
        // An error here is fatal. We'll try again on the next reconciliation.
        let hdl = OpteHdl::open().map_err(|e| vec![Error::OpteOpenHdl(e)])?;
        let (tunnel_routes, mut errors) = create_tunnel_routes(origins);

        for (vip, tep) in tunnel_routes {
            info!(
                self.log,
                "[{}] adding tunnel routes", ifname;
                "prefix" => %vip,
                "tunnel_endpoints" => ?tep
            );
            let req = SetVirt2BoundaryReq { vip, tep };
            match hdl.set_v2b(&req) {
                Ok(NoResp { .. }) => {
                    info!(
                        self.log,
                        "[{}] successfully added tunnel routes", ifname;
                        "prefix" => %vip,
                        "tunnel_endpoints" => ?req.tep
                    );
                }
                Err(err) => {
                    error!(self.log,
                        "[{}] failed to add tunnel routes", ifname;
                        "prefix" => %vip,
                        "tunnel_endpoints" => ?req.tep,
                        "error" => InlineErrorChain::new(&err));
                    errors.push(Error::OpteSetV2B { req, err });
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Remove tunnel routes from OPTE
    ///
    /// We log any errors inside here, but we also return them so that they can
    /// be used by the reconciler for statistics and external reporting.
    pub fn remove_tunnel_routes(
        &self,
        ifname: InterfaceName,
        origins: &HashSet<TunnelOrigin>,
    ) -> Result<(), Vec<Error>> {
        // An error here is fatal. We'll try again on the next reconciliation.
        let hdl = OpteHdl::open().map_err(|e| vec![Error::OpteOpenHdl(e)])?;
        let (tunnel_routes, mut errors) = create_tunnel_routes(origins);

        for (vip, tep) in tunnel_routes {
            info!(
                self.log,
                "[{}] removing tunnel routes", ifname;
                "prefix" => %vip,
                "tunnel_endpoints" => ?tep
            );
            let req = ClearVirt2BoundaryReq { vip, tep };
            match hdl.clear_v2b(&req) {
                Ok(NoResp { .. }) => {
                    info!(
                        self.log,
                        "[{}] successfully removed tunnel routes", ifname;
                        "prefix" => %vip,
                        "tunnel_endpoints" => ?req.tep
                    );
                }
                Err(err) => {
                    error!(self.log,
                        "[{}] failed to remove tunnel routes", ifname;
                        "prefix" => %vip,
                        "tunnel_endpoints" => ?req.tep,
                        "error" => InlineErrorChain::new(&err));
                    errors.push(Error::OpteClearV2B { req, err });
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Read all the IP addresses known to illumos
    fn read_local_addrs() -> Result<BTreeSet<Ipv6Addr>, Error> {
        let local_addrs = libnet::get_ipaddrs()
            .map_err(Error::GetIpAddrs)?
            .values()
            .flat_map(|infos| infos.iter().map(|info| info.addr))
            .filter_map(|addr| match addr {
                IpAddr::V4(_) => None,
                IpAddr::V6(v6_addr) => Some(v6_addr),
            })
            .collect();
        Ok(local_addrs)
    }

    /// Return true if a route refers to a local address, false otherwise.
    fn route_is_local(route: &Route, local_addrs: &BTreeSet<Ipv6Addr>) -> bool {
        local_addrs.contains(&route.gw)
            || local_addrs.contains(&route.dest.addr())
    }
}

// Create and return the set of valid tunnel routes
//
// Returns valid tunnel routes along with any errors.
fn create_tunnel_routes(
    origins: &HashSet<TunnelOrigin>,
) -> (
    impl Iterator<Item = (IpCidr, Vec<TunnelEndpoint>)>,
    Vec<Error>,
) {
    let mut errors = vec![];
    let mut prefix_map = BTreeMap::<IpNet, Vec<TunnelEndpoint>>::new();
    for o in origins {
        let Ok(vni) = Vni::new(o.vni) else {
            errors.push(Error::VniTooLarge(*o));
            continue;
        };
        let tep = TunnelEndpoint {
            ip: o.boundary_addr.into(),
            vni,
        };
        prefix_map
            .entry(o.overlay_prefix)
            .and_modify(|endpoints| endpoints.push(tep))
            .or_insert(vec![tep]);
    }
    let tunnel_routes = prefix_map.into_iter().map(|(pfx, endpoints)| {
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
        (vip, endpoints)
    });
    (tunnel_routes, errors)
}
