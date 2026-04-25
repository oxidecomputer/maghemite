// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v1::peer::PeerId;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq)]
pub struct Path {
    pub nexthop: IpAddr,

    /// Interface binding for nexthop resolution.
    ///
    /// This field is only populated for BGP unnumbered sessions where the nexthop
    /// is a link-local IPv6 address. For numbered peers, this is always None.
    ///
    /// Added in API version 5.0.0 (UNNUMBERED).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nexthop_interface: Option<String>,

    pub shutdown: bool,
    pub rib_priority: u8,
    pub bgp: Option<BgpPathProperties>,
    pub vlan_id: Option<u16>,
}

// BgpPathProperties intentionally does not implement Ord — Path::Ord
// compares only the `peer` field for BGP path identity. All other
// fields are attributes, not identity.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq)]
pub struct BgpPathProperties {
    pub origin_as: u32,
    pub id: u32,
    pub peer: PeerId,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub as_path: Vec<u32>,
    pub stale: Option<DateTime<Utc>>,
}

impl From<crate::v1::path::Path> for Path {
    fn from(value: crate::v1::path::Path) -> Self {
        Self {
            nexthop: value.nexthop,
            nexthop_interface: None,
            shutdown: value.shutdown,
            rib_priority: value.rib_priority,
            bgp: value.bgp.map(BgpPathProperties::from),
            vlan_id: value.vlan_id,
        }
    }
}

impl From<Path> for crate::v1::path::Path {
    fn from(value: Path) -> Self {
        Self {
            nexthop: value.nexthop,
            shutdown: value.shutdown,
            rib_priority: value.rib_priority,
            bgp: value.bgp.map(crate::v1::path::BgpPathProperties::from),
            vlan_id: value.vlan_id,
        }
    }
}

impl From<crate::v1::path::BgpPathProperties> for BgpPathProperties {
    fn from(value: crate::v1::path::BgpPathProperties) -> Self {
        Self {
            origin_as: value.origin_as,
            id: value.id,
            peer: PeerId::Ip(value.peer),
            med: value.med,
            local_pref: value.local_pref,
            as_path: value.as_path,
            stale: value.stale,
        }
    }
}

impl From<BgpPathProperties> for crate::v1::path::BgpPathProperties {
    fn from(value: BgpPathProperties) -> Self {
        Self {
            origin_as: value.origin_as,
            id: value.id,
            // PeerId::Interface has no IpAddr representation; fall back to
            // IPv6 unspecified. Pre-UNNUMBERED clients can't have produced
            // interface peers, so this branch is only hit when downgrading.
            peer: match value.peer {
                PeerId::Ip(ip) => ip,
                PeerId::Interface(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            med: value.med,
            local_pref: value.local_pref,
            as_path: value.as_path,
            stale: value.stale,
        }
    }
}
