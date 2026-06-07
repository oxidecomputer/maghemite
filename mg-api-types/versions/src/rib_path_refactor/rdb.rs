// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v1::bgp::messages::{As4PathSegment, AsPathType};
use crate::v1::bgp::peer::PeerId;
use crate::v4::bgp::messages::{PathAttributeValue, PathAttribute, PathAttributeTypeCode};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub type BgpPathAttributeSet = HashSet<PathAttribute>;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq)]
pub struct BgpPathProperties {
    pub origin_as: u32,
    pub bgp_id: u32,
    pub peer: PeerId,
    pub stale: Option<DateTime<Utc>>,
    pub attrs: Arc<BgpPathAttributeSet>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq)]
pub enum ProtocolPathProperties {
    Static,
    Bgp(BgpPathProperties),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq)]
pub struct Nexthop {
    pub ip: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub interface: Option<String>,
    pub vlan_id: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq)]
pub struct Path {
    pub nexthop: Nexthop,
    pub shutdown: bool,
    pub rib_priority: u8,
    pub proto: ProtocolPathProperties,
}

impl From<crate::v5::rdb::path::BgpPathProperties> for BgpPathProperties {
    fn from(value: crate::v5::rdb::path::BgpPathProperties) -> Self {
        let crate::v5::rdb::path::BgpPathProperties {
            origin_as,
            id,
            peer,
            med,
            local_pref,
            as_path,
            stale,
        } = value;

        let mut set = BgpPathAttributeSet::new();
        if let Some(med) = med {
            set.insert(PathAttribute::from(PathAttributeValue::MultiExitDisc(med)));
        }
        if let Some(pref) = local_pref {
            set.insert(PathAttribute::from(PathAttributeValue::LocalPref(pref)));
        }
        set.insert(PathAttribute::from(PathAttributeValue::Origin(
            crate::v1::bgp::messages::PathOrigin::Incomplete,
        )));
        set.insert(PathAttribute::from(
            PathAttributeValue::AsPath(vec![As4PathSegment {
            typ: AsPathType::AsSequence,
            value: as_path,
        }])));

        Self {
            origin_as,
            bgp_id: id,
            peer,
            stale,
            attrs: Arc::new(set),
        }
    }
}

impl From<BgpPathProperties> for crate::v5::rdb::path::BgpPathProperties {
    fn from(value: BgpPathProperties) -> Self {
        let BgpPathProperties {
            origin_as,
            bgp_id,
            peer,
            stale,
            attrs,
        } = value;

        let med = attrs.get(PathAttributeTypeCode::MultiExitDisc);

        Self {
            origin_as,
            id: bgp_id,
            peer,
            med:,
            local_pref: todo!(),
            as_path: todo!(),
            stale,
        }
    }
}

impl From<crate::v5::rdb::path::Path> for Path {
    fn from(value: crate::v5::rdb::path::Path) -> Self {
        let crate::v5::rdb::path::Path {
            nexthop,
            nexthop_interface,
            shutdown,
            rib_priority,
            bgp,
            vlan_id,
        } = value;

        Self {
            nexthop: Nexthop {
                ip: nexthop,
                interface: nexthop_interface,
                vlan_id,
            },
            shutdown,
            rib_priority,
            proto: match bgp {
                Some(b) => ProtocolPathProperties::Bgp(Arc::new(b)),
                None => ProtocolPathProperties::Static,
            },
        }
    }
}

impl From<Path> for crate::v5::rdb::path::Path {
    fn from(value: Path) -> Self {
        let Path {
            nexthop,
            shutdown,
            rib_priority,
            proto,
        } = value;

        Self {
            nexthop: nexthop.ip,
            nexthop_interface: nexthop.interface,
            shutdown,
            rib_priority,
            bgp: match proto {
                ProtocolPathProperties::Static => None,
                ProtocolPathProperties::Bgp(b) => Some(b.as_ref().clone()),
            },
            vlan_id: nexthop.vlan_id,
        }
    }
}
