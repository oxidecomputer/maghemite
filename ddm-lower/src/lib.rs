// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This is the DDM lower half responsible for applying DDM routes from the
//! in-memory database in ddm/src/db.rs to the underlying platform.
//!
//!  The underlying platform is either dendrite or illumos.

use derive_more::Display;
use oxnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[cfg(target_os = "illumos")]
mod illumos;

// An illumos ifname
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Display)]
pub struct InterfaceName(String);

impl InterfaceName {
    pub fn new(name: impl Into<String>) -> InterfaceName {
        InterfaceName(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// A route that can be installed in the underlying platform
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Route {
    pub dest: IpNet,
    pub gw: IpAddr,
    pub ifname: InterfaceName,
}
