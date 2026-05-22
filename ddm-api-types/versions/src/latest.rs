// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Re-exports of the latest versions of types.

pub mod admin {
    pub use crate::v1::admin::EnableStatsRequest;
    pub use crate::v1::admin::ExpirePathParams;
    pub use crate::v1::admin::PrefixMap;
}

pub mod db {
    pub use crate::v1::db::RouterKind;
    pub use crate::v1::db::TunnelRoute;
    pub use crate::v2::db::PeerStatus;
    pub use crate::v3::db::MulticastRoute;
    pub use crate::v3::db::PeerInfo;
}

pub mod exchange {
    pub use crate::v1::exchange::PathVector;
    pub use crate::v1::exchange::PathVectorV2;
    pub use crate::v3::exchange::MulticastPathHop;
    pub use crate::v3::exchange::MulticastPathVector;
}

pub mod net {
    pub use crate::v1::net::IpPrefix;
    pub use crate::v1::net::Ipv4Prefix;
    pub use crate::v1::net::Ipv6Prefix;
    pub use crate::v1::net::TunnelOrigin;
    pub use crate::v3::net::MulticastOrigin;
    pub use crate::v3::net::UnderlayMulticastIpv6;
    pub use crate::v3::net::Vni;
}
