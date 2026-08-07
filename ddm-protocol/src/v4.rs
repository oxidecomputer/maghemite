// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ALL TYPES IN THIS FILE ARE FOR DDM PROTOCOL VERSION 4. THEY SHALL NEVER
//! CHANGE. THESE TYPES CAN BE REMOVED WHEN DDMV4 CLIENTS AND SERVERS NO LONGER
//! EXIST BUT THEIR DEFINITIONS SHALL NEVER CHANGE.
//!
//! Version 4 extends version 3 with multicast group subscription propagation
//! (RFD 488). The underlay and tunnel halves are unchanged from version 3 and
//! are reused directly. The multicast wire types are defined here as plain,
//! self-contained structures: this crate must stay free of `omicron-common`,
//! so the validated forms (`UnderlayMulticastIpv6`, `Vni`) used by the admin
//! and database layers are converted to and from these wire types at the
//! exchange boundary.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv6Addr},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v3;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct Update {
    pub underlay: Option<v3::UnderlayUpdate>,
    pub tunnel: Option<v3::TunnelUpdate>,
    pub multicast: Option<MulticastUpdate>,
}

impl Update {
    /// Build an `Update` whose halves carry the announcements from the
    /// [`PullResponse`] `pr`.
    pub fn announce(pr: PullResponse) -> Self {
        Self {
            underlay: pr.underlay.map(v3::UnderlayUpdate::announce),
            tunnel: pr.tunnel.map(v3::TunnelUpdate::announce),
            multicast: pr.multicast.map(MulticastUpdate::announce),
        }
    }
}

impl From<v3::UnderlayUpdate> for Update {
    fn from(u: v3::UnderlayUpdate) -> Self {
        Update {
            underlay: Some(u),
            tunnel: None,
            multicast: None,
        }
    }
}

impl From<v3::TunnelUpdate> for Update {
    fn from(t: v3::TunnelUpdate) -> Self {
        Update {
            underlay: None,
            tunnel: Some(t),
            multicast: None,
        }
    }
}

impl From<MulticastUpdate> for Update {
    fn from(m: MulticastUpdate) -> Self {
        Update {
            underlay: None,
            tunnel: None,
            multicast: Some(m),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct PullResponse {
    pub underlay: Option<HashSet<v3::PathVector>>,
    pub tunnel: Option<HashSet<v3::TunnelOrigin>>,
    pub multicast: Option<HashSet<MulticastPathVector>>,
}

/// Multicast group subscription updates.
///
/// Each entry carries a [`MulticastPathVector`] with the group origin and the
/// path vector used for loop detection.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct MulticastUpdate {
    pub announce: HashSet<MulticastPathVector>,
    pub withdraw: HashSet<MulticastPathVector>,
}

impl MulticastUpdate {
    pub fn announce(groups: HashSet<MulticastPathVector>) -> Self {
        Self {
            announce: groups,
            ..Default::default()
        }
    }
    pub fn withdraw(groups: HashSet<MulticastPathVector>) -> Self {
        Self {
            withdraw: groups,
            ..Default::default()
        }
    }

    /// Add a hop to all path vectors in this update.
    pub fn with_hop(&self, hop: MulticastPathHop) -> Self {
        Self {
            announce: self
                .announce
                .iter()
                .map(|pv| pv.with_hop(hop.clone()))
                .collect(),
            withdraw: self
                .withdraw
                .iter()
                .map(|pv| pv.with_hop(hop.clone()))
                .collect(),
        }
    }
}

/// Wire form of a multicast group origin.
///
/// The validated counterpart (`ddm_api_types::net::MulticastOrigin`) carries an
/// `UnderlayMulticastIpv6` and a `Vni`. As a frozen wire type this form stays
/// unvalidated, a plain `Ipv6Addr` for the underlay group and a plain `u32` for
/// the VNI. Validation happens when converting into that counterpart at the
/// exchange boundary.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct MulticastOrigin {
    /// The overlay multicast group address (IPv4 or IPv6).
    pub overlay_group: IpAddr,

    /// The underlay multicast group address (ff04::X on the wire).
    pub underlay_group: Ipv6Addr,

    /// VNI identifying the VPC/network context for this group.
    #[serde(default)]
    pub vni: u32,

    /// Metric for path selection (lower is better). Excluded from identity so
    /// that metric changes update an existing entry rather than duplicating it.
    #[serde(default)]
    pub metric: u64,

    /// Optional source address for Source-Specific Multicast (S,G) routes.
    /// `None` for Any-Source Multicast (*,G) routes.
    #[serde(default)]
    pub source: Option<IpAddr>,
}

impl MulticastOrigin {
    /// Identity used for equality and hashing: the group, its underlay mapping,
    /// VNI, and source. Excludes `metric`, a mutable path-selection attribute,
    /// matching the validated `MulticastOrigin`. Routing both `PartialEq` and
    /// `Hash` through this accessor keeps the field set defined once so the two
    /// cannot drift.
    fn identity(&self) -> (&IpAddr, &Ipv6Addr, &u32, &Option<IpAddr>) {
        (
            &self.overlay_group,
            &self.underlay_group,
            &self.vni,
            &self.source,
        )
    }
}

impl PartialEq for MulticastOrigin {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl Eq for MulticastOrigin {}

impl std::hash::Hash for MulticastOrigin {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity().hash(state);
    }
}

/// A single hop in the multicast path, carrying metadata for replication
/// optimization (RFD 488).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct MulticastPathHop {
    /// Router identifier (hostname).
    pub router_id: String,

    /// The underlay address of this router (for replication targeting).
    pub underlay_addr: Ipv6Addr,

    /// Number of downstream subscribers reachable via this hop.
    #[serde(default)]
    pub downstream_subscriber_count: u32,
}

impl MulticastPathHop {
    /// Create a hop with the given router identity and a zero subscriber count.
    pub fn new(router_id: String, underlay_addr: Ipv6Addr) -> Self {
        Self {
            router_id,
            underlay_addr,
            downstream_subscriber_count: 0,
        }
    }
}

/// Multicast group subscription announcement propagating through DDM.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct MulticastPathVector {
    /// The multicast group origin information.
    pub origin: MulticastOrigin,

    /// The path from the original subscriber to the current router, ordered
    /// from subscriber outward (subscriber router first).
    pub path: Vec<MulticastPathHop>,
}

impl MulticastPathVector {
    /// Append a hop to this path vector.
    pub fn with_hop(&self, hop: MulticastPathHop) -> Self {
        let mut path = self.path.clone();
        path.push(hop);
        Self {
            origin: self.origin.clone(),
            path,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Write out the JSON schema for the DDMv4 protocol to a file for
    // validation. This should not change.
    #[test]
    fn test_ddm_v4_protocol() {
        #[derive(JsonSchema)]
        #[allow(dead_code)]
        struct Protocol {
            update: Update,
            pull_response: PullResponse,
        }

        let schema = schemars::schema_for!(Protocol);
        expectorate::assert_contents(
            "tests/output/ddm_v4_protocol.json",
            &serde_json::to_string_pretty(&schema).unwrap(),
        );
    }

    fn mcast_origin(overlay: &str, underlay: &str) -> MulticastOrigin {
        MulticastOrigin {
            overlay_group: overlay.parse().unwrap(),
            underlay_group: underlay.parse().unwrap(),
            vni: 77,
            metric: 0,
            source: None,
        }
    }

    fn multicast_update() -> MulticastUpdate {
        let pv = MulticastPathVector {
            origin: mcast_origin("233.252.0.1", "ff04::1"),
            path: vec![MulticastPathHop::new(
                "router-1".into(),
                Ipv6Addr::LOCALHOST,
            )],
        };
        MulticastUpdate::announce([pv].into_iter().collect())
    }

    #[test]
    fn v4_update_round_trips() {
        let update = Update {
            underlay: None,
            tunnel: None,
            multicast: Some(multicast_update()),
        };
        let json = serde_json::to_string(&update).unwrap();
        let back: Update = serde_json::from_str(&json).unwrap();
        assert!(back.multicast.is_some());
        assert_eq!(back.multicast.unwrap().announce.len(), 1);
    }

    #[test]
    fn v4_update_deserializes_as_v3_drops_multicast() {
        let update = Update {
            underlay: None,
            tunnel: None,
            multicast: Some(multicast_update()),
        };
        let json = serde_json::to_string(&update).unwrap();
        // A v3 peer deserializes this as a v3 update, silently dropping the
        // unknown multicast field.
        let v3: v3::Update = serde_json::from_str(&json).unwrap();
        assert!(v3.underlay.is_none());
        assert!(v3.tunnel.is_none());
    }

    // A v4 node reading a populated v3 update keeps the underlay and tunnel
    // halves and defaults the absent multicast half to None.
    #[test]
    fn populated_v3_update_deserializes_as_v4() {
        let v3 = v3::Update {
            underlay: Some(underlay_update()),
            tunnel: Some(tunnel_update()),
        };
        let json = serde_json::to_string(&v3).unwrap();
        let update: Update = serde_json::from_str(&json).unwrap();
        assert!(update.underlay.is_some());
        assert!(update.tunnel.is_some());
        assert!(update.multicast.is_none());
    }

    #[test]
    fn v4_pull_response_round_trips() {
        let pv = MulticastPathVector {
            origin: mcast_origin("ff0e::1", "ff04::2"),
            path: vec![],
        };
        let resp = PullResponse {
            underlay: None,
            tunnel: None,
            multicast: Some([pv].into_iter().collect()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: PullResponse = serde_json::from_str(&json).unwrap();
        assert!(back.multicast.is_some());
    }

    #[test]
    fn v4_pull_response_deserializes_as_v3() {
        let pv = MulticastPathVector {
            origin: mcast_origin("233.252.0.1", "ff04::1"),
            path: vec![],
        };
        let resp = PullResponse {
            underlay: None,
            tunnel: None,
            multicast: Some([pv].into_iter().collect()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        // A v3 peer drops the multicast field.
        let v3: v3::PullResponse = serde_json::from_str(&json).unwrap();
        assert!(v3.underlay.is_none());
        assert!(v3.tunnel.is_none());
    }

    #[test]
    fn from_conversions_strip_multicast() {
        let update = Update {
            underlay: None,
            tunnel: None,
            multicast: Some(multicast_update()),
        };
        // Downconvert to v3 for an older peer, then back. Multicast has no v3
        // representation, so the round trip drops it.
        let v3 = v3::Update::from(update);
        let back = Update::from(v3);
        assert!(back.multicast.is_none());
    }

    fn underlay_update() -> v3::UnderlayUpdate {
        let pv = v3::PathVector {
            destination: "fd00::/64".parse().unwrap(),
            path: vec!["router-1".into()],
        };
        v3::UnderlayUpdate::announce([pv].into_iter().collect())
    }

    fn tunnel_update() -> v3::TunnelUpdate {
        let origin = v3::TunnelOrigin {
            overlay_prefix: "10.0.0.0/24".parse().unwrap(),
            boundary_addr: Ipv6Addr::LOCALHOST,
            vni: 77,
            metric: 0,
        };
        v3::TunnelUpdate::announce([origin].into_iter().collect())
    }

    // A v4 update carrying all three halves must keep its underlay and tunnel
    // halves intact when downconverted for older peers, while the multicast
    // half (which has no v3 or v2 wire form) is dropped.
    #[test]
    fn mixed_update_down_conversion_preserves_underlay_and_tunnel() {
        let update = Update {
            underlay: Some(underlay_update()),
            tunnel: Some(tunnel_update()),
            multicast: Some(multicast_update()),
        };

        let v3 = v3::Update::from(update.clone());
        assert!(v3.underlay.is_some());
        assert!(v3.tunnel.is_some());
        assert_eq!(v3.underlay.as_ref().unwrap().announce.len(), 1);
        assert_eq!(v3.tunnel.as_ref().unwrap().announce.len(), 1);

        let v2 = crate::v2::Update::from(v3);
        assert!(v2.underlay.is_some());
        assert!(v2.tunnel.is_some());
        assert_eq!(v2.underlay.unwrap().announce.len(), 1);
        assert_eq!(v2.tunnel.unwrap().announce.len(), 1);
    }

    // Metric is excluded from the wire identity so a metric-only change updates
    // an existing entry rather than duplicating it inside a HashSet.
    #[test]
    fn multicast_origin_identity_excludes_metric() {
        let mut a = mcast_origin("233.252.0.1", "ff04::1");
        let mut b = a.clone();
        a.metric = 0;
        b.metric = 100;
        assert_eq!(a, b);
    }
}
