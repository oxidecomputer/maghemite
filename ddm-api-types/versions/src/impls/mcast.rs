// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::Ipv6Addr;

use crate::latest::db::MulticastRoute;
use crate::latest::net::MulticastOrigin;

impl MulticastRoute {
    /// Origin and peer identity shared by equality and hashing.
    fn identity(&self) -> (&MulticastOrigin, &Ipv6Addr) {
        (&self.origin, &self.nexthop)
    }
}

impl PartialEq for MulticastRoute {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl Eq for MulticastRoute {}

impl std::hash::Hash for MulticastRoute {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity().hash(state);
    }
}

impl From<MulticastRoute> for MulticastOrigin {
    fn from(x: MulticastRoute) -> Self {
        x.origin
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};
    use std::net::Ipv6Addr;

    use crate::latest::db::MulticastRoute;
    use crate::latest::exchange::MulticastPathHop;
    use crate::latest::net::{
        MulticastOrigin, OverlayMulticast, UnderlayMulticastIpv6, Vni,
    };

    fn origin(overlay: &str) -> MulticastOrigin {
        MulticastOrigin::new(
            OverlayMulticast::new(overlay.parse().unwrap()).unwrap(),
            UnderlayMulticastIpv6::new("ff04::1".parse().unwrap()).unwrap(),
            Vni::new(77).unwrap(),
            None,
        )
        .unwrap()
    }

    /// Use the same initial hasher state for each route comparison.
    fn hash_of(route: &MulticastRoute) -> u64 {
        let mut hasher = DefaultHasher::new();
        route.hash(&mut hasher);
        hasher.finish()
    }

    /// Route identity is the origin and nexthop, and excludes the path.
    #[test]
    fn route_identity_is_origin_and_nexthop() {
        let base = MulticastRoute {
            origin: origin("233.252.0.1"),
            nexthop: Ipv6Addr::LOCALHOST,
            path: vec![MulticastPathHop::new(
                "router-1".into(),
                Ipv6Addr::LOCALHOST,
            )],
        };

        let mut other_path = base.clone();
        other_path.path = vec![
            MulticastPathHop::new("router-1".into(), Ipv6Addr::LOCALHOST),
            MulticastPathHop::new("router-2".into(), Ipv6Addr::LOCALHOST),
        ];
        assert_eq!(base, other_path);
        assert_eq!(hash_of(&base), hash_of(&other_path));

        let other_origin = MulticastRoute {
            origin: origin("233.252.0.2"),
            nexthop: Ipv6Addr::LOCALHOST,
            path: vec![],
        };
        let other_nexthop = MulticastRoute {
            origin: origin("233.252.0.1"),
            nexthop: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            path: vec![],
        };
        assert_ne!(base, other_origin);
        assert_ne!(base, other_nexthop);
    }
}
