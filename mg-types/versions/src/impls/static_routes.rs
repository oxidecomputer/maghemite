// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::latest;
use rdb::StaticRouteKey;

impl From<latest::static_routes::StaticRoute4> for StaticRouteKey {
    fn from(val: latest::static_routes::StaticRoute4) -> Self {
        StaticRouteKey {
            prefix: val.prefix.into(),
            nexthop: val.nexthop,
            nexthop_interface: val.nexthop_interface,
            vlan_id: val.vlan_id,
            rib_priority: val.rib_priority,
        }
    }
}

impl From<latest::static_routes::StaticRoute6> for StaticRouteKey {
    fn from(val: latest::static_routes::StaticRoute6) -> Self {
        StaticRouteKey {
            prefix: val.prefix.into(),
            nexthop: val.nexthop,
            nexthop_interface: val.nexthop_interface,
            vlan_id: val.vlan_id,
            rib_priority: val.rib_priority,
        }
    }
}
