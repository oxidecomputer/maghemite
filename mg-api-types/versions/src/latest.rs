// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Re-exports of the latest versions of types.

pub mod bfd {
    pub use crate::v1::bfd::{
        BfdPeerConfig, BfdPeerInfo, BfdPeerState, DeleteBfdPeerPathParams,
        SessionMode,
    };
}

pub mod bgp {
    pub use crate::v1::bgp::config::{
        AsnSelector, CheckerSource, Origin4, Router, ShaperSource,
    };
    pub use crate::v2::bgp::history::{
        FsmEventBuffer, MessageDirection, Origin6,
    };
    pub use crate::v4::bgp::config::{
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

    pub mod messages {
        pub use crate::v1::bgp::messages::{
            AS_TRANS, AddPathElement, AsPathType, BGP4, Capability,
            CapabilityCode, CeaseErrorSubcode, Community, ErrorCode,
            ErrorSubcode, Header, HeaderErrorSubcode, MAX_MESSAGE_SIZE,
            MessageKind, MessageType, NotificationMessage, OpenErrorSubcode,
            OpenMessage, OptionalParameter, OptionalParameterCode, PathOrigin,
            RouteRefreshMessage, Safi, Tlv, UpdateErrorSubcode,
        };

        pub use crate::v4::bgp::messages::{
            Afi, Aggregator, As4Aggregator, As4PathSegment, BgpNexthop,
            ExtendedNexthopElement, Ipv6DoubleNexthop, Message,
            MpReachIpv4Unicast, MpReachIpv6Unicast, MpReachNlri,
            MpUnreachIpv4Unicast, MpUnreachIpv6Unicast, MpUnreachNlri,
            PathAttribute, PathAttributeType, PathAttributeTypeCode,
            PathAttributeValue, UpdateMessage, path_attribute_flags,
        };
    }

    pub mod session {
        pub use crate::v2::bgp::session::{
            ConnectionDirection, ConnectionId, FsmEventCategory,
            FsmEventRecord, FsmStateKind, MAX_MESSAGE_HISTORY, MessageHistory,
            MessageHistoryEntry,
        };
    }
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
