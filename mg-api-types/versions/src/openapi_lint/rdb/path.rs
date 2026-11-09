// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::super::bgp::peer::PeerId;
use crate::v5;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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

impl From<Path> for v5::rdb::path::Path {
    fn from(new: Path) -> Self {
        let Path {
            nexthop,
            nexthop_interface,
            shutdown,
            rib_priority,
            bgp,
            vlan_id,
        } = new;
        Self {
            nexthop,
            nexthop_interface,
            shutdown,
            rib_priority,
            bgp: bgp.map(Into::into),
            vlan_id,
        }
    }
}

impl From<BgpPathProperties> for v5::rdb::path::BgpPathProperties {
    fn from(new: BgpPathProperties) -> Self {
        let BgpPathProperties {
            origin_as,
            id,
            peer,
            med,
            local_pref,
            as_path,
            stale,
        } = new;
        Self {
            origin_as,
            id,
            peer: peer.into(),
            med,
            local_pref,
            as_path,
            stale,
        }
    }
}
