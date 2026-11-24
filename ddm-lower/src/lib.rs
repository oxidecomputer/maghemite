// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This is the DDM lower half responsible for applying DDM routes from the
//! in-memory database in ddm/src/db.rs to the underlying platform.
//!
//!  The underlying platform is either dendrite or illumos.

use derive_more::Display;
use oxnet::Ipv6Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

pub mod dendrite;
#[cfg(target_os = "illumos")]
pub mod illumos;

// An illumos ifname
#[derive(
    Debug,
    Clone,
    Deserialize,
    Serialize,
    JsonSchema,
    Display,
    PartialEq,
    Eq,
    Hash,
)]
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
#[derive(
    Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash,
)]
pub struct Route {
    pub dest: Ipv6Net,
    pub gw: Ipv6Addr,
    pub ifname: InterfaceName,
}
