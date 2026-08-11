// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;

use crate::v3::net::TunnelOrigin;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelRoute {
    pub origin: TunnelOrigin,

    // The nexthop is only used to associate the route with a peer allowing us
    // to remove the route if the peer expires. It does not influence what goes
    // into the underlaying underlay routing platform. Tunnel routes only
    // influence the state of the underlying encapsulation service.
    pub nexthop: Ipv6Addr,
}

impl From<TunnelRoute> for TunnelOrigin {
    fn from(x: TunnelRoute) -> Self {
        x.origin
    }
}

impl From<TunnelRoute> for crate::v1::db::TunnelRoute {
    fn from(x: TunnelRoute) -> Self {
        Self {
            // router_id is dropped: the v1 wire shape cannot represent it.
            origin: x.origin.into(),
            nexthop: x.nexthop,
        }
    }
}
