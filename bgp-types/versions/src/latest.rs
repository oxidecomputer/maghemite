// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Re-exports of the latest versions of types.

pub mod messages {
    pub use crate::v1::messages::{
        AS_TRANS, AddPathElement, AsPathType, BGP4, Capability, CapabilityCode,
        CeaseErrorSubcode, Community, ErrorCode, ErrorSubcode, Header,
        HeaderErrorSubcode, MAX_MESSAGE_SIZE, MessageKind, MessageType,
        NotificationMessage, OpenErrorSubcode, OpenMessage, OptionalParameter,
        OptionalParameterCode, PathOrigin, RouteRefreshMessage, Safi, Tlv,
        UpdateErrorSubcode,
    };

    pub use crate::v4::messages::{
        Afi, Aggregator, As4Aggregator, As4PathSegment, BgpNexthop,
        ExtendedNexthopElement, Ipv6DoubleNexthop, Message, MpReachIpv4Unicast,
        MpReachIpv6Unicast, MpReachNlri, MpUnreachIpv4Unicast,
        MpUnreachIpv6Unicast, MpUnreachNlri, PathAttribute, PathAttributeType,
        PathAttributeTypeCode, PathAttributeValue, UpdateMessage,
        path_attribute_flags,
    };
}
