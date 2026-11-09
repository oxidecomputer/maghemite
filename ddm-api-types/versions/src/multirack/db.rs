// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;

use crate::v1;
use crate::v1::net::TunnelOrigin;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A tunnel route imported from a peer.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelRoute {
    pub origin: TunnelOrigin,

    /// The routers the route was advertised through, starting with its
    /// originator and ending with the peer it was learned from.
    pub path: Vec<String>,

    /// The address of the peer the route was learned from.
    pub nexthop: Ipv6Addr,
}

impl From<TunnelRoute> for v1::db::TunnelRoute {
    fn from(value: TunnelRoute) -> Self {
        // compilation barrier. a new field must be considered here.
        let TunnelRoute {
            origin,
            path: _,
            nexthop,
        } = value;
        Self { origin, nexthop }
    }
}
