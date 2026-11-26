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

    pub use crate::v4::db::PeerStatus;

    pub use crate::v5::db::MulticastRoute;
    pub use crate::v5::db::PeerInfo;
}

pub mod exchange {
    pub use crate::v1::exchange::PathVector;

    pub use crate::v5::exchange::MulticastPathHop;
    pub use crate::v5::exchange::MulticastPathVector;
    pub use crate::v5::exchange::RouterId;
}

pub mod net {
    pub use crate::v1::net::TunnelOrigin;

    pub use crate::v5::net::MulticastOrigin;
    pub use crate::v5::net::MulticastOriginError;
    pub use crate::v5::net::OverlayMulticast;
    pub use crate::v5::net::OverlayMulticastError;
    pub use crate::v5::net::UnderlayMulticastError;
    pub use crate::v5::net::UnderlayMulticastIpv6;
    pub use crate::v5::net::Vni;
    pub use crate::v5::net::VniError;
}

pub mod external_peers {
    pub use crate::v3::external_peers::ExternalPeers;
}
