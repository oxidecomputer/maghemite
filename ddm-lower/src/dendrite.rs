// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The dendrite backend for ddm-lower

use crate::{InterfaceName, Route};
use dpd_client::Error as ProgenitorError;
use dpd_client::types::error::ConversionError;
use dpd_client::types::{
    Ipv6Route, Ipv6RouteUpdate, LinkId, PortId, Qsfp, Rear,
};
use dpd_client::{Client, ClientState};
use slog::Logger;
use slog::{debug, error, info, o};
use slog_error_chain::SlogInlineError;
use std::net::SocketAddrV6;

const DDM_DPD_TAG: &str = "ddmd";

#[derive(thiserror::Error, Debug, SlogInlineError)]
pub enum Error {
    #[error("invalid port prefix: expected tfportrear or tfportqsfp, got {0}")]
    InvalidPortPrefix(InterfaceName),
    #[error("invalid rear port name {port_name} for interface {ifname}")]
    InvalidRearPortName {
        ifname: InterfaceName,
        port_name: String,
        #[source]
        err: ConversionError,
    },
    #[error("invalid front port name {port_name} for interface {ifname}")]
    InvalidFrontPortName {
        ifname: InterfaceName,
        port_name: String,
        #[source]
        err: ConversionError,
    },
    #[error("failed to add route to dendrite: {route:?}")]
    AddRoute {
        route: Route,
        #[source]
        err: ProgenitorError<dpd_client::types::Error>,
    },
    #[error("failed to remove route from dendrite: {route:?}")]
    RemoveRoute {
        route: Route,
        #[source]
        err: ProgenitorError<dpd_client::types::Error>,
    },
}

/// The dendrite backend for ddm-lower
pub struct DendriteBackend {
    log: Logger,
}

impl DendriteBackend {
    pub fn new(log: &Logger) -> Self {
        Self {
            log: log.new(o!("backend" => "dendrite")),
        }
    }

    /// Add underlay routes to dendrite, returning any errors encountered.
    ///
    /// We log any errors inside here, but we also return them so that they can
    /// be used by the reconciler for statistics and external reporting.
    pub async fn add_underlay_routes(
        &self,
        dpd_addr: SocketAddrV6,
        routes: Vec<Route>,
    ) -> Result<(), Vec<Error>> {
        if routes.is_empty() {
            return Ok(());
        }

        // All interfaces must be the same for a given set of routes
        let ifname = routes.first().unwrap().ifname.clone();
        assert!(
            routes.iter().all(|r| r.ifname == ifname),
            "all routes must be for the same interface"
        );

        debug!(self.log, "[{ifname}] sending route add to dpd: {dpd_addr}");

        let client_state = ClientState {
            tag: DDM_DPD_TAG.into(),
            log: self.log.clone(),
        };

        let client = Client::new(&format!("http://{dpd_addr}"), client_state);

        let mut errors = vec![];
        for r in routes {
            info!(
                self.log,
                "[{}] adding route {} -> {}", r.ifname, r.dest, r.gw,
            );

            // TODO this is gross, use link type properties rather than futzing
            // around with strings.
            let port_id = {
                if let Some(egress_port_num) = ifname
                    .as_str()
                    .strip_prefix("tfportrear")
                    .and_then(|x| x.strip_suffix("_0"))
                    .map(|x| x.trim())
                    .and_then(|x| x.parse::<u8>().ok())
                {
                    let port_name = format!("rear{}", egress_port_num);
                    match Rear::try_from(&port_name) {
                        Ok(rear) => PortId::Rear(rear),
                        Err(err) => {
                            let error = Error::InvalidRearPortName {
                                ifname: ifname.clone(),
                                port_name,
                                err,
                            };
                            error!(
                                self.log,
                                "failed to parse ifname to add route";
                                &error
                            );
                            errors.push(error);
                            continue;
                        }
                    }
                } else if let Some(egress_port_num) = ifname
                    .as_str()
                    .strip_prefix("tfportqsfp")
                    .and_then(|x| x.strip_suffix("_0"))
                    .map(|x| x.trim())
                    .and_then(|x| x.parse::<u8>().ok())
                {
                    let port_name = format!("qsfp{}", egress_port_num);
                    match Qsfp::try_from(&port_name) {
                        Ok(qsfp) => PortId::Qsfp(qsfp),
                        Err(err) => {
                            let error = Error::InvalidFrontPortName {
                                ifname: ifname.clone(),
                                port_name,
                                err,
                            };
                            error!(
                                self.log,
                                "failed to parse ifname to add route";
                                &error
                            );
                            errors.push(error);
                            continue;
                        }
                    }
                } else {
                    let error = Error::InvalidPortPrefix(ifname.clone());
                    error!(
                        self.log,
                        "failed to parse ifname to add route";
                        &error
                    );
                    errors.push(error);
                    continue;
                }
            };

            // TODO breakout considerations
            let link_id = LinkId(0);

            let target = Ipv6Route {
                tag: DDM_DPD_TAG.into(),
                port_id,
                link_id,
                tgt_ip: r.gw,
                vlan_id: None,
            };
            let route_set = Ipv6RouteUpdate {
                cidr: r.dest,
                target,
                replace: false,
            };

            match client.route_ipv6_set(&route_set).await {
                Ok(_) => {
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

    /// Remove underlay routes from dendrite, returning any errors encountered.
    ///
    /// We log any errors inside here, but we also return them so that they can
    /// be used by the reconciler for statistics and external reporting.
    ///
    // TODO: seems like this should take an egress port, if there is a
    // destination prefix with two different destination egress ports, we want
    // to be able to delete one but not the other. Looks like this would be an
    // update to the dpd api.
    pub async fn remove_underlay_routes(
        &self,
        dpd_addr: SocketAddrV6,
        routes: Vec<Route>,
    ) -> Result<(), Vec<Error>> {
        if routes.is_empty() {
            return Ok(());
        }

        // All interfaces must be the same for a given set of routes
        let ifname = routes.first().unwrap().ifname.clone();
        assert!(
            routes.iter().all(|r| r.ifname == ifname),
            "all routes must be for the same interface"
        );

        debug!(
            self.log,
            "[{ifname}] sending route delete to dpd: {dpd_addr}"
        );

        let client_state = ClientState {
            tag: DDM_DPD_TAG.into(),
            log: self.log.clone(),
        };

        let client = Client::new(&format!("http://{dpd_addr}"), client_state);

        let mut errors = vec![];
        for r in routes {
            info!(
                self.log,
                "[{}] adding route {} -> {}", r.ifname, r.dest, r.gw,
            );
            match client.route_ipv6_delete(&r.dest).await {
                Ok(_) => {
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
}
