// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Re-exports of the latest versions of types.

pub mod bfd {
    pub use crate::v1::bfd::BfdPeerInfo;
    pub use crate::v1::bfd::DeleteBfdPeerPathParams;
}

pub mod bgp {
    pub use crate::v1::bgp::AsnSelector;
    pub use crate::v1::bgp::CheckerSource;
    pub use crate::v1::bgp::ShaperSource;

    pub use crate::v2::bgp::FsmEventBuffer;
    pub use crate::v2::bgp::MessageDirection;

    pub use crate::v4::bgp::DynamicTimerInfo;
    pub use crate::v4::bgp::Ipv4UnicastConfig;
    pub use crate::v4::bgp::Ipv6UnicastConfig;
    pub use crate::v4::bgp::JitterRange;
    pub use crate::v4::bgp::NeighborResetRequest;

    pub use crate::v5::bgp::ExportedSelector;
    pub use crate::v5::bgp::FsmHistoryRequest;
    pub use crate::v5::bgp::FsmHistoryResponse;
    pub use crate::v5::bgp::MessageHistoryRequest;
    pub use crate::v5::bgp::MessageHistoryResponse;
    pub use crate::v5::bgp::NeighborSelector;
    pub use crate::v5::bgp::UnnumberedNeighborResetRequest;
    pub use crate::v5::bgp::UnnumberedNeighborSelector;

    pub use crate::v8::bgp::ApplyRequest;
    pub use crate::v8::bgp::BgpPeerConfig;
    pub use crate::v8::bgp::BgpPeerParameters;
    pub use crate::v8::bgp::Neighbor;
    pub use crate::v8::bgp::UnnumberedBgpPeerConfig;
    pub use crate::v8::bgp::UnnumberedNeighbor;
}

pub mod ndp {
    pub use crate::v5::ndp::NdpInterface;
    pub use crate::v5::ndp::NdpInterfaceSelector;
    pub use crate::v5::ndp::NdpManagerState;
    pub use crate::v5::ndp::NdpPeer;
    pub use crate::v5::ndp::NdpPendingInterface;
    pub use crate::v5::ndp::NdpThreadState;
}

pub mod rib {
    pub use crate::v1::rib::BestpathFanoutRequest;
    pub use crate::v1::rib::BestpathFanoutResponse;

    pub use crate::v2::rib::RibQuery;

    pub use crate::v5::rib::GetRibResult;
    pub use crate::v5::rib::Rib;
}

pub mod static_routes {
    pub use crate::v1::static_routes::AddStaticRoute4Request;
    pub use crate::v1::static_routes::DeleteStaticRoute4Request;
    pub use crate::v1::static_routes::StaticRoute4;
    pub use crate::v1::static_routes::StaticRoute4List;

    pub use crate::v2::static_routes::AddStaticRoute6Request;
    pub use crate::v2::static_routes::DeleteStaticRoute6Request;
    pub use crate::v2::static_routes::StaticRoute6;
    pub use crate::v2::static_routes::StaticRoute6List;
}

pub mod switch {
    pub use crate::v3::switch::SwitchIdentifiers;
}
