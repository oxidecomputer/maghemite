// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Re-exports of the latest versions of types.

pub mod bfd {
    pub use crate::v1::bfd::DeleteBfdPeerPathParams;
}

pub mod bgp {
    pub use crate::v1::bgp::{
        AsnSelector, CheckerSource, Origin4, Router, ShaperSource,
    };
    pub use crate::v2::bgp::{FsmEventBuffer, MessageDirection, Origin6};
    pub use crate::v4::bgp::{
        AfiSafi, BgpCapability, DynamicTimerInfo, Ipv4UnicastConfig,
        Ipv6UnicastConfig, JitterRange, NeighborResetRequest, PeerCounters,
        StaticTimerInfo,
    };
    pub use crate::v5::bgp::{
        ExportedSelector, FsmHistoryRequest, FsmHistoryResponse,
        MessageHistoryRequest, MessageHistoryResponse, NeighborSelector,
        PeerInfo, PeerTimers, UnnumberedNeighborResetRequest,
        UnnumberedNeighborSelector,
    };
    pub use crate::v8::bgp::{
        ApplyRequest, BgpPeerConfig, BgpPeerParameters, Neighbor,
        UnnumberedBgpPeerConfig, UnnumberedNeighbor,
    };
}

pub mod ndp {
    pub use crate::v5::ndp::{
        NdpInterface, NdpInterfaceSelector, NdpManagerState, NdpPeer,
        NdpPendingInterface, NdpThreadState,
    };
}

pub mod rib {
    pub use crate::v1::rib::{BestpathFanoutRequest, BestpathFanoutResponse};
    pub use crate::v2::rib::RibQuery;
    pub use crate::v5::rib::{GetRibResult, Rib};
}

pub mod static_routes {
    pub use crate::v1::static_routes::{
        AddStaticRoute4Request, DeleteStaticRoute4Request, StaticRoute4,
        StaticRoute4List,
    };
    pub use crate::v2::static_routes::{
        AddStaticRoute6Request, DeleteStaticRoute6Request, StaticRoute6,
        StaticRoute6List,
    };
}

pub mod switch {
    pub use crate::v3::switch::SwitchIdentifiers;
}
