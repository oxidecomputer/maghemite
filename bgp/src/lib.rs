// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod clock;
pub mod config;
pub mod connection;
pub mod connection_tcp;
pub mod dispatcher;
pub mod error;
pub mod fanout;
pub mod log;
pub mod messages;
pub mod policy;
pub mod router;
pub mod session;

mod rhai_integration;

#[cfg(test)]
mod proptest;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
mod test;

#[cfg(test)]
pub mod connection_channel;

pub const BGP_PORT: u16 = 179;
pub const COMPONENT_BGP: &str = "bgp";
pub const MOD_ROUTER: &str = "router";
pub const MOD_NEIGHBOR: &str = "neighbor";
pub const MOD_CLOCK: &str = "clock";
pub const MOD_POLICY: &str = "policy";

// XXX: Make this configurable
pub const IO_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(100);
