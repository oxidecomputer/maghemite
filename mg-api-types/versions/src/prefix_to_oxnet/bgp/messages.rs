// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v1;
use crate::v4;
use oxnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// IPv4 Unicast MP_REACH_NLRI contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MpReachIpv4Unicast {
    pub nexthop: v4::bgp::messages::BgpNexthop,
    pub reserved: u8,
    pub nlri: Vec<Ipv4Net>,
}

/// IPv6 Unicast MP_REACH_NLRI contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MpReachIpv6Unicast {
    pub nexthop: v4::bgp::messages::BgpNexthop,
    pub reserved: u8,
    pub nlri: Vec<Ipv6Net>,
}

/// MP_REACH_NLRI path attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "afi_safi", rename_all = "snake_case")]
pub enum MpReachNlri {
    Ipv4Unicast(MpReachIpv4Unicast),
    Ipv6Unicast(MpReachIpv6Unicast),
}

/// IPv4 Unicast MP_UNREACH_NLRI contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MpUnreachIpv4Unicast {
    pub withdrawn: Vec<Ipv4Net>,
}

/// IPv6 Unicast MP_UNREACH_NLRI contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MpUnreachIpv6Unicast {
    pub withdrawn: Vec<Ipv6Net>,
}

/// MP_UNREACH_NLRI path attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "afi_safi", rename_all = "snake_case")]
pub enum MpUnreachNlri {
    Ipv4Unicast(MpUnreachIpv4Unicast),
    Ipv6Unicast(MpUnreachIpv6Unicast),
}

/// The value encoding of a path attribute.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathAttributeValue {
    Origin(v1::bgp::messages::PathOrigin),
    AsPath(Vec<v1::bgp::messages::As4PathSegment>),
    NextHop(Ipv4Addr),
    MultiExitDisc(u32),
    LocalPref(u32),
    Aggregator(v4::bgp::messages::Aggregator),
    Communities(Vec<v1::bgp::messages::Community>),
    AtomicAggregate,
    As4Path(Vec<v1::bgp::messages::As4PathSegment>),
    As4Aggregator(v4::bgp::messages::As4Aggregator),
    MpReachNlri(MpReachNlri),
    MpUnreachNlri(MpUnreachNlri),
}

/// A self-describing BGP path attribute.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PathAttribute {
    pub typ: v4::bgp::messages::PathAttributeType,
    pub value: PathAttributeValue,
}

/// BGP UPDATE message.
#[derive(
    Debug, PartialEq, Eq, Clone, Default, Serialize, Deserialize, JsonSchema,
)]
pub struct UpdateMessage {
    pub withdrawn: Vec<Ipv4Net>,
    pub path_attributes: Vec<PathAttribute>,
    pub nlri: Vec<Ipv4Net>,
    #[serde(skip, default)]
    #[schemars(skip)]
    pub errors: Vec<(
        crate::impls::bgp::parse::UpdateParseErrorReason,
        crate::impls::bgp::parse::AttributeAction,
    )>,
}

/// Holds a BGP message.
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Message {
    Open(v1::bgp::messages::OpenMessage),
    Update(UpdateMessage),
    Notification(v1::bgp::messages::NotificationMessage),
    KeepAlive,
    RouteRefresh(v1::bgp::messages::RouteRefreshMessage),
}

// ---------------------------------------------------------------------------
// Downgrade conversions: v10 → v4
// ---------------------------------------------------------------------------

fn ipv4net_to_prefix4(n: Ipv4Net) -> v1::rdb::prefix::Prefix4 {
    v1::rdb::prefix::Prefix4 { value: n.addr(), length: n.width() }
}

fn ipv6net_to_prefix6(n: Ipv6Net) -> v1::rdb::prefix::Prefix6 {
    v1::rdb::prefix::Prefix6 { value: n.addr(), length: n.width() }
}

impl From<MpReachIpv4Unicast> for v4::bgp::messages::MpReachIpv4Unicast {
    fn from(v: MpReachIpv4Unicast) -> Self {
        Self {
            nexthop: v.nexthop,
            reserved: v.reserved,
            nlri: v.nlri.into_iter().map(ipv4net_to_prefix4).collect(),
        }
    }
}

impl From<MpReachIpv6Unicast> for v4::bgp::messages::MpReachIpv6Unicast {
    fn from(v: MpReachIpv6Unicast) -> Self {
        Self {
            nexthop: v.nexthop,
            reserved: v.reserved,
            nlri: v.nlri.into_iter().map(ipv6net_to_prefix6).collect(),
        }
    }
}

impl From<MpReachNlri> for v4::bgp::messages::MpReachNlri {
    fn from(v: MpReachNlri) -> Self {
        match v {
            MpReachNlri::Ipv4Unicast(i) => Self::Ipv4Unicast(i.into()),
            MpReachNlri::Ipv6Unicast(i) => Self::Ipv6Unicast(i.into()),
        }
    }
}

impl From<MpUnreachIpv4Unicast> for v4::bgp::messages::MpUnreachIpv4Unicast {
    fn from(v: MpUnreachIpv4Unicast) -> Self {
        Self { withdrawn: v.withdrawn.into_iter().map(ipv4net_to_prefix4).collect() }
    }
}

impl From<MpUnreachIpv6Unicast> for v4::bgp::messages::MpUnreachIpv6Unicast {
    fn from(v: MpUnreachIpv6Unicast) -> Self {
        Self { withdrawn: v.withdrawn.into_iter().map(ipv6net_to_prefix6).collect() }
    }
}

impl From<MpUnreachNlri> for v4::bgp::messages::MpUnreachNlri {
    fn from(v: MpUnreachNlri) -> Self {
        match v {
            MpUnreachNlri::Ipv4Unicast(i) => Self::Ipv4Unicast(i.into()),
            MpUnreachNlri::Ipv6Unicast(i) => Self::Ipv6Unicast(i.into()),
        }
    }
}

impl From<PathAttributeValue> for v4::bgp::messages::PathAttributeValue {
    fn from(v: PathAttributeValue) -> Self {
        match v {
            PathAttributeValue::Origin(x) => Self::Origin(x),
            PathAttributeValue::AsPath(x) => Self::AsPath(x),
            PathAttributeValue::NextHop(x) => Self::NextHop(x),
            PathAttributeValue::MultiExitDisc(x) => Self::MultiExitDisc(x),
            PathAttributeValue::LocalPref(x) => Self::LocalPref(x),
            PathAttributeValue::Aggregator(x) => Self::Aggregator(x),
            PathAttributeValue::Communities(x) => Self::Communities(x),
            PathAttributeValue::AtomicAggregate => Self::AtomicAggregate,
            PathAttributeValue::As4Path(x) => Self::As4Path(x),
            PathAttributeValue::As4Aggregator(x) => Self::As4Aggregator(x),
            PathAttributeValue::MpReachNlri(x) => Self::MpReachNlri(x.into()),
            PathAttributeValue::MpUnreachNlri(x) => {
                Self::MpUnreachNlri(x.into())
            }
        }
    }
}

impl From<PathAttribute> for v4::bgp::messages::PathAttribute {
    fn from(v: PathAttribute) -> Self {
        Self { typ: v.typ, value: v.value.into() }
    }
}

impl From<UpdateMessage> for v4::bgp::messages::UpdateMessage {
    fn from(v: UpdateMessage) -> Self {
        Self {
            withdrawn: v.withdrawn.into_iter().map(ipv4net_to_prefix4).collect(),
            path_attributes: v
                .path_attributes
                .into_iter()
                .map(v4::bgp::messages::PathAttribute::from)
                .collect(),
            nlri: v.nlri.into_iter().map(ipv4net_to_prefix4).collect(),
            errors: v.errors,
        }
    }
}

impl From<Message> for v4::bgp::messages::Message {
    fn from(v: Message) -> Self {
        match v {
            Message::Open(x) => Self::Open(x),
            Message::Update(x) => Self::Update(x.into()),
            Message::Notification(x) => Self::Notification(x),
            Message::KeepAlive => Self::KeepAlive,
            Message::RouteRefresh(x) => Self::RouteRefresh(x),
        }
    }
}
