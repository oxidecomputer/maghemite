// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The illumos backend for ddm-lower

use crate::{InterfaceName, Route};
use slog::Logger;
use slog::{error, info, o};
use slog_error_chain::SlogInlineError;
use std::collections::BTreeSet;
use std::net::IpAddr;

/// The illumos platform for ddm-lower
pub struct IllumosPlatform {
    log: Logger,
}

impl IllumosPlatform {
    pub fn new(log: &Logger) -> Self {
        Self {
            log: log.new(o!("backend" => "illumos")),
        }
    }
}

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
}

impl IllumosPlatform {
    ///  Add routes to illumos, returning any errors encountered.
    ///
    /// We log any errors inside here, but we also return them so that they can
    /// be used by the reconciler for statistics and external reporting.
    pub fn add_routes(&self, mut routes: Vec<Route>) -> Result<(), Vec<Error>> {
        // Filter out all local routes.
        // An error here is fatal. We'll try again on the next reconciliation.
        let local_addrs = Self::read_local_addrs().map_err(|e| vec![e])?;
        routes.retain(|r| !Self::route_is_local(&r, &local_addrs));

        let mut errors = vec![];
        for r in routes {
            info!(
                self.log,
                "[{}] adding route {} -> {}", r.ifname, r.dest, r.gw,
            );
            match libnet::ensure_route_present(
                r.dest,
                r.gw,
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

    /// Remove routes from illumos, returning any errors encountered.
    ///
    /// We log any errors inside here, but we also return them so that they can
    /// be used by the reconciler for statistics and external reporting.
    pub fn remove_routes(&self, routes: Vec<Route>) -> Result<(), Vec<Error>> {
        let mut errors = vec![];

        for r in routes {
            info!(
                self.log,
                "[{}] removing route {} -> {}", r.ifname, r.dest, r.gw,
            );

            match libnet::delete_route(
                r.dest,
                r.gw,
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

    /// Read all the IP addresses known to illumos
    fn read_local_addrs() -> Result<BTreeSet<IpAddr>, Error> {
        let local_addrs = libnet::get_ipaddrs()
            .map_err(Error::GetIpAddrs)?
            .values()
            .flat_map(|infos| infos.iter().map(|info| info.addr))
            .collect();
        Ok(local_addrs)
    }

    /// Return true if a route refers to a local address, false otherwise.
    fn route_is_local(route: &Route, local_addrs: &BTreeSet<IpAddr>) -> bool {
        local_addrs.contains(&route.gw)
            || local_addrs.contains(&route.dest.addr())
    }
}
