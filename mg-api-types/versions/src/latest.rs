// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Re-exports of the latest versions of types.

pub mod bfd {
    pub use crate::v1::bfd::BfdPeerConfig;
    pub use crate::v1::bfd::BfdPeerInfo;
    pub use crate::v1::bfd::BfdPeerState;
    pub use crate::v1::bfd::DeleteBfdPeerPathParams;
    pub use crate::v1::bfd::SessionMode;
}

pub mod bgp {
    pub use crate::v1::bgp::config::AsnSelector;
    pub use crate::v1::bgp::config::CheckerSource;
    pub use crate::v1::bgp::config::Origin4;
    pub use crate::v1::bgp::config::Router;
    pub use crate::v1::bgp::config::ShaperSource;
    pub use crate::v1::bgp::peer::PeerId;

    pub use crate::v2::bgp::history::FsmEventBuffer;
    pub use crate::v2::bgp::history::MessageDirection;
    pub use crate::v2::bgp::history::Origin6;

    pub use crate::v4::bgp::config::AfiSafi;
    pub use crate::v4::bgp::config::BgpCapability;
    pub use crate::v4::bgp::config::DynamicTimerInfo;
    pub use crate::v4::bgp::config::Ipv4UnicastConfig;
    pub use crate::v4::bgp::config::Ipv6UnicastConfig;
    pub use crate::v4::bgp::config::JitterRange;
    pub use crate::v4::bgp::config::NeighborResetOp;
    pub use crate::v4::bgp::config::NeighborResetRequest;
    pub use crate::v4::bgp::config::PeerCounters;
    pub use crate::v4::bgp::config::PeerInfo;
    pub use crate::v4::bgp::config::PeerTimers;
    pub use crate::v4::bgp::config::StaticTimerInfo;
    pub use crate::v4::bgp::policy::ImportExportPolicy;
    pub use crate::v4::bgp::policy::ImportExportPolicy4;
    pub use crate::v4::bgp::policy::ImportExportPolicy6;

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

    pub use crate::impls::bgp::error;
    pub use crate::impls::bgp::parse;

    pub mod messages {
        pub use crate::v1::bgp::messages::AS_TRANS;
        pub use crate::v1::bgp::messages::AddPathElement;
        pub use crate::v1::bgp::messages::AsPathType;
        pub use crate::v1::bgp::messages::BGP4;
        pub use crate::v1::bgp::messages::Capability;
        pub use crate::v1::bgp::messages::CapabilityCode;
        pub use crate::v1::bgp::messages::CeaseErrorSubcode;
        pub use crate::v1::bgp::messages::Community;
        pub use crate::v1::bgp::messages::ErrorCode;
        pub use crate::v1::bgp::messages::ErrorSubcode;
        pub use crate::v1::bgp::messages::Header;
        pub use crate::v1::bgp::messages::HeaderErrorSubcode;
        pub use crate::v1::bgp::messages::MAX_MESSAGE_SIZE;
        pub use crate::v1::bgp::messages::MessageKind;
        pub use crate::v1::bgp::messages::MessageType;
        pub use crate::v1::bgp::messages::NotificationMessage;
        pub use crate::v1::bgp::messages::OpenErrorSubcode;
        pub use crate::v1::bgp::messages::OpenMessage;
        pub use crate::v1::bgp::messages::OptionalParameter;
        pub use crate::v1::bgp::messages::OptionalParameterCode;
        pub use crate::v1::bgp::messages::PathOrigin;
        pub use crate::v1::bgp::messages::RouteRefreshMessage;
        pub use crate::v1::bgp::messages::Safi;
        pub use crate::v1::bgp::messages::Tlv;
        pub use crate::v1::bgp::messages::UpdateErrorSubcode;

        pub use crate::v4::bgp::messages::Afi;
        pub use crate::v4::bgp::messages::Aggregator;
        pub use crate::v4::bgp::messages::As4Aggregator;
        pub use crate::v4::bgp::messages::As4PathSegment;
        pub use crate::v4::bgp::messages::BgpNexthop;
        pub use crate::v4::bgp::messages::ExtendedNexthopElement;
        pub use crate::v4::bgp::messages::Ipv6DoubleNexthop;
        pub use crate::v4::bgp::messages::Message;
        pub use crate::v4::bgp::messages::MpReachIpv4Unicast;
        pub use crate::v4::bgp::messages::MpReachIpv6Unicast;
        pub use crate::v4::bgp::messages::MpReachNlri;
        pub use crate::v4::bgp::messages::MpUnreachIpv4Unicast;
        pub use crate::v4::bgp::messages::MpUnreachIpv6Unicast;
        pub use crate::v4::bgp::messages::MpUnreachNlri;
        pub use crate::v4::bgp::messages::PathAttribute;
        pub use crate::v4::bgp::messages::PathAttributeType;
        pub use crate::v4::bgp::messages::PathAttributeTypeCode;
        pub use crate::v4::bgp::messages::PathAttributeValue;
        pub use crate::v4::bgp::messages::UpdateMessage;
        pub use crate::v4::bgp::messages::path_attribute_flags;
    }

    pub mod session {
        pub use crate::v2::bgp::session::ConnectionDirection;
        pub use crate::v2::bgp::session::ConnectionId;
        pub use crate::v2::bgp::session::FsmEventCategory;
        pub use crate::v2::bgp::session::FsmEventRecord;
        pub use crate::v2::bgp::session::FsmStateKind;
        pub use crate::v2::bgp::session::MAX_MESSAGE_HISTORY;
        pub use crate::v2::bgp::session::MessageHistory;
        pub use crate::v2::bgp::session::MessageHistoryEntry;
    }
}

pub mod rdb {
    pub use crate::v1::rdb::AddressFamily;
    pub use crate::v1::rdb::ProtocolFilter;

    pub mod neighbor {
        pub use crate::v4::rdb::neighbor::BgpNeighborInfo;
        pub use crate::v4::rdb::neighbor::BgpNeighborParameters;
        pub use crate::v4::rdb::neighbor::BgpUnnumberedNeighborInfo;
    }

    pub mod path {
        pub use crate::v5::rdb::path::BgpPathProperties;
        pub use crate::v5::rdb::path::Path;
    }

    pub mod prefix {
        pub use crate::v1::rdb::prefix::Prefix;
        pub use crate::v1::rdb::prefix::Prefix4;
        pub use crate::v1::rdb::prefix::Prefix6;
    }

    pub mod router {
        pub use crate::v1::rdb::router::BgpRouterInfo;
    }
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
