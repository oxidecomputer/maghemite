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
        Ipv6UnicastConfig, JitterRange, NeighborResetOp, NeighborResetRequest,
        PeerCounters, StaticTimerInfo,
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

pub mod rdb {
    use std::collections::{BTreeMap, BTreeSet};

    pub use crate::v1::rdb::{AddressFamily, ProtocolFilter};

    /// Runtime IPv4+IPv6 routing-information-base shape used by `rdb`.
    /// Defined here (rather than in `rdb`) so cross-version conversions
    /// can live in `mg-api-types-versions` without forcing it to depend
    /// on the `rdb` business-logic crate.
    pub type Rib = BTreeMap<prefix::Prefix, BTreeSet<path::Path>>;
    /// Runtime IPv4-only RIB.
    pub type Rib4 = BTreeMap<prefix::Prefix4, BTreeSet<path::Path>>;
    /// Runtime IPv6-only RIB.
    pub type Rib6 = BTreeMap<prefix::Prefix6, BTreeSet<path::Path>>;

    /// Drop paths from `rib` whose protocol does not match
    /// `protocol_filter`. `None` is a pass-through.
    pub fn filter_rib_by_protocol(
        rib: Rib,
        protocol_filter: Option<ProtocolFilter>,
    ) -> Rib {
        match protocol_filter {
            None => rib,
            Some(filter) => {
                let mut filtered = BTreeMap::new();

                for (prefix, paths) in rib {
                    let filtered_paths: BTreeSet<_> = paths
                        .into_iter()
                        .filter(|path| match filter {
                            ProtocolFilter::Bgp => path.bgp.is_some(),
                            ProtocolFilter::Static => path.bgp.is_none(),
                        })
                        .collect();

                    if !filtered_paths.is_empty() {
                        filtered.insert(prefix, filtered_paths);
                    }
                }

                filtered
            }
        }
    }

    pub mod neighbor {
        pub use crate::v4::rdb::neighbor::{
            BgpNeighborInfo, BgpNeighborParameters, BgpUnnumberedNeighborInfo,
        };
    }

    pub mod path {
        pub use crate::v5::rdb::path::{BgpPathProperties, Path};
    }

    pub mod peer {
        pub use crate::v1::rdb::peer::PeerId;
    }

    pub mod policy {
        pub use crate::v4::rdb::policy::{
            ImportExportPolicy, ImportExportPolicy4, ImportExportPolicy6,
        };
    }

    pub mod prefix {
        pub use crate::v1::rdb::prefix::{Prefix, Prefix4, Prefix6};
    }

    pub mod router {
        pub use crate::v1::rdb::router::BgpRouterInfo;
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
