// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ALL TYPES IN THIS FILE ARE FOR DDM PROTOCOL VERSION 4. THEY SHALL NEVER
//! CHANGE. THESE TYPES CAN BE REMOVED WHEN DDMV4 CLIENTS AND SERVERS NO LONGER
//! EXIST BUT THEIR DEFINITIONS SHALL NEVER CHANGE.
//!
//! This version extends version 3 with multicast group subscription
//! propagation (as described in [RFD 488]). The underlay and tunnel fields
//! remain unchanged and are re-imported directly. The multicast on-the-wire
//! types carry dendrite's validated types (`dpd-types-versions`), enforcing
//! their rules at the deserialization boundary. These rules are part of this
//! version's contract and changing them requires a new protocol version.
//!
//! [RFD 488]: https://rfd.shared.oxide.computer/rfd/488

use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};

use dpd_types_versions::v8::mcast::UnderlayMulticastIpv6;
use dpd_types_versions::v14::mcast::{
    ExternalMulticastIp as OverlayMulticast, MulticastSourceError,
    UnicastAddrV4, UnicastAddrV6, is_ssm_address,
};
use dpd_types_versions::v14::network::Vni;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{RouterId, v3};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct Update {
    pub underlay: Option<v3::UnderlayUpdate>,
    pub tunnel: Option<v3::TunnelUpdate>,
    pub multicast: Option<MulticastUpdate>,
}

impl Update {
    /// Build an [`Update`] whose fields carry the announcements from
    /// the [`PullResponse`] `pr`.
    ///
    /// The resulting [`Update`] contains no withdrawals. These come from
    /// diffing what's been imported from the peer against the full snapshot.
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

/// The route snapshot a peer advertises, sent in full in one response.
///
/// A multicast-only pull disregards the underlay and tunnel fields.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct PullResponse {
    pub underlay: Option<HashSet<v3::PathVector>>,
    pub tunnel: Option<HashSet<v3::TunnelOrigin>>,
    pub multicast: Option<HashSet<MulticastPathVector>>,
}

/// Multicast group subscription updates.
///
/// Each entry is a [`MulticastPathVector`], containing the group origin
/// and the path used for loop detection.
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

/// The multicast group origin as exchanged between DDM peers.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(try_from = "MulticastOriginShadow", into = "MulticastOriginShadow")]
pub struct MulticastOrigin {
    /// The overlay multicast group address (IPv4 or IPv6).
    overlay_group: OverlayMulticast,

    /// The underlay multicast group address that the overlay group maps to
    /// (1:1).
    underlay_group: UnderlayMulticastIpv6,

    /// VNI identifying the VPC/network context for this group.
    vni: Vni,

    /// The metric for path selection. Among paths of equal length, a lower
    /// value is preferred.
    ///
    /// Ignored for equality and hashing.
    metric: u64,

    /// Optional source address for Source-Specific Multicast `(S,G)` routes.
    /// `None` for Any-Source Multicast `(*,G)` routes.
    source: Option<IpAddr>,
}

/// Errors raised while validating a [`MulticastOrigin`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MulticastOriginError {
    /// The source address failed unicast source validation, returning a
    /// [`MulticastSourceError`].
    #[error(transparent)]
    Source(#[from] MulticastSourceError),

    /// A source address uses a different IP address family than the group
    /// address.
    #[error(
        "Source IP {source_ip} does not match multicast group address family \
         ({group})"
    )]
    SourceFamilyMismatch {
        /// The rejected source address.
        source_ip: IpAddr,
        /// The group address whose IP address family it must match.
        group: IpAddr,
    },

    /// An SSM group requires a source address ([RFC 4607] §2).
    ///
    /// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
    #[error(
        "Group IP {group} is a Source-Specific Multicast address and requires \
         a source to be defined"
    )]
    SsmRequiresSource {
        /// The SSM group address.
        group: IpAddr,
    },
}

impl MulticastOrigin {
    /// Create a validated multicast origin with a zero metric.
    ///
    /// # Errors
    ///
    /// Returns
    ///
    /// - [`MulticastOriginError::Source`] if `source` fails unicast
    ///   source validation;
    /// - [`MulticastOriginError::SourceFamilyMismatch`] if
    ///   `source` and `overlay_group` use different IP address families;
    /// - [`MulticastOriginError::SsmRequiresSource`] if `overlay_group` is an
    ///   SSM address and `source` is `None`.
    pub fn new(
        overlay_group: OverlayMulticast,
        underlay_group: UnderlayMulticastIpv6,
        vni: Vni,
        source: Option<IpAddr>,
    ) -> Result<Self, MulticastOriginError> {
        let group = overlay_group.ip();
        match source {
            None if is_ssm_address(group) => {
                return Err(MulticastOriginError::SsmRequiresSource { group });
            }
            None => {}
            Some(source_ip) => {
                match source_ip {
                    IpAddr::V4(v4) => {
                        UnicastAddrV4::new(v4)?;
                    }
                    IpAddr::V6(v6) => {
                        UnicastAddrV6::new(v6)?;
                    }
                }
                if source_ip.is_ipv4() != group.is_ipv4() {
                    return Err(MulticastOriginError::SourceFamilyMismatch {
                        source_ip,
                        group,
                    });
                }
            }
        }
        Ok(Self {
            overlay_group,
            underlay_group,
            vni,
            metric: 0,
            source,
        })
    }

    /// Return this origin with `metric` replaced.
    pub fn with_metric(mut self, metric: u64) -> Self {
        self.metric = metric;
        self
    }

    /// Return the overlay multicast group address.
    pub const fn overlay_group(&self) -> OverlayMulticast {
        self.overlay_group
    }

    /// Return the underlay multicast group address.
    pub const fn underlay_group(&self) -> UnderlayMulticastIpv6 {
        self.underlay_group
    }

    /// Return the VNI.
    pub const fn vni(&self) -> Vni {
        self.vni
    }

    /// Return the path-selection metric.
    pub const fn metric(&self) -> u64 {
        self.metric
    }

    /// Return the source address, or `None` for an `(*,G)` origin.
    pub const fn source(&self) -> Option<IpAddr> {
        self.source
    }
}

/// The multicast group origin as exchanged between DDM peers.
#[derive(Deserialize, Serialize, JsonSchema)]
#[schemars(rename = "MulticastOrigin")]
struct MulticastOriginShadow {
    /// The overlay multicast group address (IPv4 or IPv6).
    overlay_group: OverlayMulticast,

    /// The underlay multicast group address that the overlay group maps to
    /// (1:1).
    underlay_group: UnderlayMulticastIpv6,

    /// VNI identifying the VPC/network context for this group.
    #[schemars(with = "u32", range(max = 0xFF_FFFF))]
    vni: Vni,

    /// The metric for path selection. Among paths of equal length, a lower
    /// value is preferred.
    #[serde(default)]
    metric: u64,

    /// Optional source address for Source-Specific Multicast `(S,G)` routes.
    /// `None` for Any-Source Multicast `(*,G)` routes.
    #[serde(default)]
    source: Option<IpAddr>,
}

impl TryFrom<MulticastOriginShadow> for MulticastOrigin {
    type Error = MulticastOriginError;

    fn try_from(o: MulticastOriginShadow) -> Result<Self, Self::Error> {
        Ok(
            Self::new(o.overlay_group, o.underlay_group, o.vni, o.source)?
                .with_metric(o.metric),
        )
    }
}

impl From<MulticastOrigin> for MulticastOriginShadow {
    fn from(o: MulticastOrigin) -> Self {
        Self {
            overlay_group: o.overlay_group,
            underlay_group: o.underlay_group,
            vni: o.vni,
            metric: o.metric,
            source: o.source,
        }
    }
}

impl JsonSchema for MulticastOrigin {
    fn schema_name() -> String {
        MulticastOriginShadow::schema_name()
    }

    fn json_schema(
        generator: &mut schemars::r#gen::SchemaGenerator,
    ) -> schemars::schema::Schema {
        MulticastOriginShadow::json_schema(generator)
    }
}

/// Identity of a [`MulticastOrigin`], including its group, its underlay
/// mapping, VNI, and source.
#[derive(PartialEq, Eq, Hash)]
struct Identity {
    overlay_group: OverlayMulticast,
    underlay_group: UnderlayMulticastIpv6,
    vni: Vni,
    source: Option<IpAddr>,
}

impl MulticastOrigin {
    /// Return the identity used for equality and hashing.
    ///
    /// Excludes `metric`, which is a mutable path-selection attribute. Routing
    /// `PartialEq` and `Hash` through this accessor keeps the field set
    /// defined once, avoiding drift.
    fn identity(&self) -> Identity {
        Identity {
            overlay_group: self.overlay_group,
            underlay_group: self.underlay_group,
            vni: self.vni,
            source: self.source,
        }
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

/// A single hop in the multicast path.
///
/// `router_id` identifies the hop for loop detection, and `underlay_addr`
/// is the address replication toward this router targets.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct MulticastPathHop {
    /// Router identifier (i.e., the ddmd router ID, which defaults to the
    /// hostname).
    pub router_id: RouterId,

    /// The underlay address of this router (for replication targeting).
    pub underlay_addr: Ipv6Addr,
}

impl MulticastPathHop {
    /// Create a hop with the given router identity.
    pub fn new(router_id: RouterId, underlay_addr: Ipv6Addr) -> Self {
        Self {
            router_id,
            underlay_addr,
        }
    }
}

/// A multicast group subscription announcement that propagates through DDM.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct MulticastPathVector {
    /// The multicast group origin information.
    pub origin: MulticastOrigin,

    /// The path to the current router, ordered outward from the subscriber's
    /// router (which is first in the list).
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
mod tests {
    use super::*;

    fn vni() -> Vni {
        Vni::new(77).expect("valid multicast test VNI")
    }

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
        MulticastOrigin::new(
            overlay.parse().unwrap(),
            underlay.parse().unwrap(),
            vni(),
            None,
        )
        .unwrap()
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
    fn v4_update_json_deserializes_as_v3() {
        let update = Update {
            underlay: Some(underlay_update()),
            tunnel: Some(tunnel_update()),
            multicast: Some(multicast_update()),
        };
        let json = serde_json::to_string(&update).unwrap();
        let v3: v3::Update = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v3.underlay.unwrap().announce,
            update.underlay.unwrap().announce,
        );
        assert_eq!(
            v3.tunnel.unwrap().announce,
            update.tunnel.unwrap().announce,
        );
    }

    // A v4 peer reading a v3 update keeps the underlay and tunnel fields and
    // defaults the missing multicast field to None.
    #[test]
    fn v3_update_json_deserializes_as_v4() {
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

    // A v4 update containing all three fields must keep its underlay and
    // tunnel fields intact when being downconverted for older peers, while the
    // multicast field (which has no v3 or v2 wire form) is dropped.
    #[test]
    fn v4_update_downconverts_to_v3_and_v2() {
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

    fn v3_pull_response() -> v3::PullResponse {
        v3::PullResponse {
            underlay: Some(underlay_update().announce),
            tunnel: Some(tunnel_update().announce),
        }
    }

    #[test]
    fn v3_pull_response_upconverts_as_complete_snapshot() {
        let v3 = v3_pull_response();
        let v4 = PullResponse::from(v3.clone());
        assert_eq!(v4.underlay, v3.underlay);
        assert_eq!(v4.tunnel, v3.tunnel);
        assert!(v4.multicast.is_none());
    }

    #[test]
    fn v3_pull_response_json_deserializes_as_v4() {
        let v3 = v3_pull_response();
        let json = serde_json::to_string(&v3).unwrap();
        let v4: PullResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(v4.underlay, v3.underlay);
        assert_eq!(v4.tunnel, v3.tunnel);
        assert!(v4.multicast.is_none());
    }

    #[test]
    fn v4_pull_response_downconverts_to_v3() {
        let pv = MulticastPathVector {
            origin: mcast_origin("233.252.0.1", "ff04::1"),
            path: vec![],
        };
        let v3 = v3_pull_response();
        let v4 = PullResponse {
            underlay: v3.underlay.clone(),
            tunnel: v3.tunnel.clone(),
            multicast: Some([pv].into_iter().collect()),
        };
        let down = v3::PullResponse::from(v4);
        assert_eq!(down.underlay, v3.underlay);
        assert_eq!(down.tunnel, v3.tunnel);
    }

    #[test]
    fn v4_pull_response_json_deserializes_as_v3() {
        let pv = MulticastPathVector {
            origin: mcast_origin("233.252.0.1", "ff04::1"),
            path: vec![],
        };
        let v3 = v3_pull_response();
        let v4 = PullResponse {
            underlay: v3.underlay.clone(),
            tunnel: v3.tunnel.clone(),
            multicast: Some([pv].into_iter().collect()),
        };
        let json = serde_json::to_string(&v4).unwrap();
        let down: v3::PullResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(down.underlay, v3.underlay);
        assert_eq!(down.tunnel, v3.tunnel);
    }

    #[test]
    fn v2_update_upconverts_through_v3_to_v4() {
        let v3 = v3::Update {
            underlay: Some(underlay_update()),
            tunnel: Some(tunnel_update()),
        };
        let v2 = crate::v2::Update::from(v3.clone());
        let v4 = Update::from(v3::Update::from(v2));
        assert_eq!(
            v4.underlay.unwrap().announce,
            v3.underlay.unwrap().announce,
        );
        assert_eq!(v4.tunnel.unwrap().announce, v3.tunnel.unwrap().announce);
        assert!(v4.multicast.is_none());
    }

    // Metric is excluded from the identity, so origins differing only in metric
    // collide within a HashSet.
    #[test]
    fn multicast_origin_identity_excludes_metric() {
        use std::hash::{BuildHasher, RandomState};

        let a = mcast_origin("233.252.0.1", "ff04::1");
        let b = a.clone().with_metric(100);
        assert_eq!(a, b);
        let hasher = RandomState::new();
        assert_eq!(hasher.hash_one(&a), hasher.hash_one(&b));
    }

    #[test]
    fn multicast_origin_encoding() {
        let asm = mcast_origin("233.252.0.1", "ff04::1");
        assert_eq!(
            serde_json::to_value(&asm).unwrap(),
            serde_json::json!({
                "overlay_group": "233.252.0.1",
                "underlay_group": "ff04::1",
                "vni": 77,
                "metric": 0,
                "source": null,
            }),
        );

        let ssm = MulticastOrigin::new(
            "ff3e::8000:1".parse().unwrap(),
            "ff04::2".parse().unwrap(),
            Vni::new(16_777_215).unwrap(),
            Some("fd00::1".parse().unwrap()),
        )
        .unwrap()
        .with_metric(10);
        assert_eq!(
            serde_json::to_value(&ssm).unwrap(),
            serde_json::json!({
                "overlay_group": "ff3e::8000:1",
                "underlay_group": "ff04::2",
                "vni": 16777215,
                "metric": 10,
                "source": "fd00::1",
            }),
        );
    }

    #[test]
    fn multicast_origin_decoding() {
        let origins = [
            mcast_origin("233.252.0.1", "ff04::1"),
            MulticastOrigin::new(
                "ff3e::8000:1".parse().unwrap(),
                "ff04::2".parse().unwrap(),
                Vni::new(16_777_215).unwrap(),
                Some("fd00::1".parse().unwrap()),
            )
            .unwrap()
            .with_metric(10),
            MulticastOrigin::new(
                "232.1.1.1".parse().unwrap(),
                "ff04::3".parse().unwrap(),
                vni(),
                Some("10.0.0.1".parse().unwrap()),
            )
            .unwrap()
            .with_metric(5),
            MulticastOrigin::new(
                "233.252.0.1".parse().unwrap(),
                "ff04::4".parse().unwrap(),
                vni(),
                Some("192.168.1.1".parse().unwrap()),
            )
            .unwrap()
            .with_metric(1),
        ];

        for origin in origins {
            let json = serde_json::to_value(&origin).unwrap();
            let back: MulticastOrigin = serde_json::from_value(json).unwrap();
            assert_eq!(back, origin);
            assert_eq!(back.metric(), origin.metric());
            assert_eq!(back.source(), origin.source());
        }
    }

    fn origin_json(
        overlay: &str,
        underlay: &str,
        vni: u32,
        source: Option<&str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "overlay_group": overlay,
            "underlay_group": underlay,
            "vni": vni,
            "source": source,
        })
    }

    #[test]
    fn multicast_origin_acceptance_contract() {
        let accept = [
            // IPv4 ASM group w/o a source.
            origin_json("233.252.0.1", "ff04::1", 77, None),
            // 224.0.0.0/24 (local network control) is allowed. RFC 5771 §4
            // mentions that routers don't forward it off link, not that it's
            // invalid.
            origin_json("224.0.0.1", "ff04::1", 77, None),
            // IPv4 SSM group w/ a source.
            origin_json("232.1.1.1", "ff04::1", 77, Some("10.0.0.1")),
            // IPv6 global-scope ASM group w/o a source.
            origin_json("ff0e::1", "ff04::1", 77, None),
            // IPv6 SSM group w/ a source.
            origin_json("ff3e::8000:1", "ff04::1", 77, Some("fd00::1")),
            // Underlay: low end of ff04::/64.
            origin_json("233.252.0.1", "ff04::", 77, None),
            // Underlay: high end of ff04::/64.
            origin_json("233.252.0.1", "ff04::ffff:ffff:ffff:ffff", 77, None),
            // VNI lower bound.
            origin_json("233.252.0.1", "ff04::1", 0, None),
            // VNI upper bound (24 bits).
            origin_json("233.252.0.1", "ff04::1", 16_777_215, None),
            // ASM may carry a source. RFC 1918 sources are allowed.
            origin_json("233.252.0.1", "ff04::1", 77, Some("192.168.1.1")),
            // Shared address space (RFC 6598) source.
            origin_json("233.252.0.1", "ff04::1", 77, Some("100.64.0.1")),
            // Last unicast IPv4 address below 224/4.
            origin_json("233.252.0.1", "ff04::1", 77, Some("223.255.255.255")),
            // IPv6 ULA source on an ASM group.
            origin_json("ff0e::1", "ff04::1", 77, Some("fd00::1")),
            // IPv6 documentation-prefix source.
            origin_json("ff0e::1", "ff04::1", 77, Some("2001:db8::1")),
            // Just below 232/8: ASM and no source needed.
            origin_json("231.255.255.255", "ff04::1", 77, None),
            // Just above 232/8: ASM and no source needed.
            origin_json("233.0.0.1", "ff04::1", 77, None),
            // Top of 232/8 is SSM w/ a source.
            origin_json("232.255.255.255", "ff04::1", 77, Some("10.0.0.1")),
            // ffbx::/32 (X flag set) is SSM w/ a source.
            origin_json("ffbe::8000:1", "ff04::1", 77, Some("fd00::1")),
            // The rsvd/RIID nibble is ignored for SSM, w/ a source.
            origin_json("ff3e:100::8000:1", "ff04::1", 77, Some("fd00::1")),
            // metric and source are optional on the wire.
            serde_json::json!({
                "overlay_group": "233.252.0.1",
                "underlay_group": "ff04::1",
                "vni": 77,
            }),
        ];

        for json in accept {
            assert!(
                serde_json::from_value::<MulticastOrigin>(json.clone()).is_ok(),
                "v4 must accept {json}",
            );
        }

        let reject = [
            // Overlay group is IPv4 unicast.
            origin_json("10.0.0.1", "ff04::1", 77, None),
            // Overlay group is IPv6 unicast.
            origin_json("fd00::1", "ff04::1", 77, None),
            // 224.0.0.0 is the reserved base address (RFC 1112 §4).
            origin_json("224.0.0.0", "ff04::1", 77, None),
            // 232.0.0.0 is the SSM null address (even w/ a source).
            origin_json("232.0.0.0", "ff04::1", 77, Some("10.0.0.1")),
            // Interface-local scope is never forwarded.
            origin_json("ff01::1", "ff04::1", 77, None),
            // Link-local scope is never forwarded.
            origin_json("ff02::1", "ff04::1", 77, None),
            // ff0x:: is a reserved base address (RFC 4291 §2.7.1).
            origin_json("ff0e::", "ff04::1", 77, None),
            // ff04::/64 is the underlay subnet and can't be an overlay group.
            origin_json("ff04::1", "ff04::1", 77, None),
            // Underlay outside ff04::/64 (global scope).
            origin_json("233.252.0.1", "ff0e::1", 77, None),
            // Underlay just past the end of ff04::/64.
            origin_json("233.252.0.1", "ff04:0:0:1::1", 77, None),
            // Underlay is unicast.
            origin_json("233.252.0.1", "fd00::1", 77, None),
            // VNI past 24 bits.
            origin_json("233.252.0.1", "ff04::1", 16_777_216, None),
            // IPv4 SSM group w/o a source.
            origin_json("232.1.1.1", "ff04::1", 77, None),
            // IPv6 SSM group w/o a source.
            origin_json("ff3e::8000:1", "ff04::1", 77, None),
            // Top of 232/8 w/o a source.
            origin_json("232.255.255.255", "ff04::1", 77, None),
            // ffbx::/32 SSM w/o a source.
            origin_json("ffbe::8000:1", "ff04::1", 77, None),
            // SSM w/ the rsvd/RIID nibble set, w/o a source.
            origin_json("ff3e:100::8000:1", "ff04::1", 77, None),
            // IPv6 multicast source.
            origin_json("233.252.0.1", "ff04::1", 77, Some("ff0e::1")),
            // IPv4 multicast source.
            origin_json("233.252.0.1", "ff04::1", 77, Some("224.0.0.1")),
            // IPv6 multicast source on an IPv6 group.
            origin_json("ff0e::1", "ff04::1", 77, Some("ff0e::2")),
            // IPv6 source on an IPv4 group.
            origin_json("233.252.0.1", "ff04::1", 77, Some("fd00::1")),
            // IPv4 source on an IPv6 group.
            origin_json("ff0e::1", "ff04::1", 77, Some("10.0.0.1")),
            // Unspecified IPv4 source.
            origin_json("233.252.0.1", "ff04::1", 77, Some("0.0.0.0")),
            // Loopback IPv4 source.
            origin_json("233.252.0.1", "ff04::1", 77, Some("127.0.0.1")),
            // Limited broadcast source.
            origin_json("233.252.0.1", "ff04::1", 77, Some("255.255.255.255")),
            // Link-local IPv4 source.
            origin_json("233.252.0.1", "ff04::1", 77, Some("169.254.1.1")),
            // 0.0.0.0/8 source, which RPF can't resolve.
            origin_json("233.252.0.1", "ff04::1", 77, Some("0.1.2.3")),
            // Class E (240.0.0.0/4) source.
            origin_json("233.252.0.1", "ff04::1", 77, Some("240.0.0.1")),
            // Unspecified IPv6 source.
            origin_json("ff0e::1", "ff04::1", 77, Some("::")),
            // Loopback IPv6 source.
            origin_json("ff0e::1", "ff04::1", 77, Some("::1")),
            // Link-local IPv6 source.
            origin_json("ff0e::1", "ff04::1", 77, Some("fe80::1")),
            // IPv4-mapped IPv6 source.
            origin_json("ff0e::1", "ff04::1", 77, Some("::ffff:10.0.0.1")),
            // IPv4-compatible IPv6 source.
            origin_json("ff0e::1", "ff04::1", 77, Some("::10.0.0.1")),
            // vni is required.
            serde_json::json!({
                "overlay_group": "233.252.0.1",
                "underlay_group": "ff04::1",
            }),
        ];

        for json in reject {
            assert!(
                serde_json::from_value::<MulticastOrigin>(json.clone())
                    .is_err(),
                "v4 must reject {json}",
            );
        }
    }

    #[test]
    fn multicast_origin_group_contract() {
        let decodes = |group: &str, source: Option<&str>| {
            serde_json::from_value::<MulticastOrigin>(origin_json(
                group, "ff04::1", 77, source,
            ))
            .is_ok()
        };

        for group in [
            // Realm-local scope.
            "ff03::1",
            // Site-local scope.
            "ff05::1",
            // Unassigned scope 6.
            "ff06::1",
            // Unassigned scope 7.
            "ff07::1",
            // Organization-local scope.
            "ff08::1",
            // Unassigned scope 9.
            "ff09::1",
            // Unassigned scope d.
            "ff0d::1",
            // Global scope.
            "ff0e::1",
            // Reserved scope f is not rejected.
            "ff0f::1",
            // Admin-local scope just past the ff04::/64 underlay subnet.
            "ff04:0:0:1::1",
            // Admin-local scope outside ff04::/64 in the second segment.
            "ff04:1::1",
            // Admin-local scope outside ff04::/64 in the fourth segment.
            "ff04::1:0:0:0:1",
            // Transient admin-local. The underlay subnet only covers flags=0.
            "ff14::1",
            // A transient base address isn't the reserved ff0x::.
            "ff1e::",
            // Embedded RP w/ a /64 prefix.
            "ff7e:140:2001:db8::1",
            // Embedded RP w/ a /32 prefix.
            "ff7e:120:2001:db8::1",
            // Embedded RP w/ the rsvd nibble set, which is ignored.
            "ff7e:f140:2001:db8:beef:feed:0:1234",
            // Embedded RP w/ every prefix segment nonzero.
            "ff7e:140:2001:db8:beef:feed:0:1234",
        ] {
            assert!(decodes(group, None), "v4 must accept ASM {group}");
        }

        for group in [
            // Lowest nonzero SSM group ID.
            "ff3e::1",
            // Low SSM group ID.
            "ff3e::1234",
            // Last group ID below the null group ID.
            "ff3e::3fff:ffff",
            // Just above the null group ID ff3x::4000:0.
            "ff3e::4000:1",
            // Last group ID below the host-allocated block.
            "ff3e::7fff:ffff",
            // Start of the host-allocated block.
            "ff3e::8000:0",
            // Highest SSM group ID.
            "ff3e::ffff:ffff",
            // Site-local SSM scope.
            "ff35::4000:1",
            // SSM w/ a nonzero fourth segment.
            "ff3e:0:0:1::8000:1",
            // SSM w/ a nonzero third segment.
            "ff3e:0:1234::f000:1",
            // SSM w/ the ff2/rsvd nibbles set, which are ignored.
            "ff3e:f000:1234::1",
            // Null group ID, but a nonzero prefix makes it a different group.
            "ff3e:0:1234::4000:0",
        ] {
            assert!(
                decodes(group, Some("fd00::1")),
                "v4 must accept SSM {group}",
            );
        }

        for (group, source) in [
            // Reserved scope 0.
            ("ff00::1", None),
            // Interface-local scope.
            ("ff01::1", None),
            // Link-local scope.
            ("ff02::1", None),
            // Interface-local scope w/ the T flag. Scope is checked
            // separately.
            ("ff11::1", None),
            // Link-local SSM, even w/ a source.
            ("ff32::4000:1", Some("fd00::1")),
            // Reserved base address, realm-local.
            ("ff03::", None),
            // Reserved base address, site-local.
            ("ff05::", None),
            // Reserved base address, global.
            ("ff0e::", None),
            // Reserved base address, scope f.
            ("ff0f::", None),
            // Underlay subnet, low end.
            ("ff04::", None),
            // Underlay subnet.
            ("ff04::1", None),
            // Underlay subnet, high end.
            ("ff04::ffff:ffff:ffff:ffff", None),
            // P flag w/o T (RFC 7371 §4.1.1).
            ("ff2e::1", None),
            // P flag w/o T, w/ a prefix.
            ("ff2e:20:2001:db8::1", None),
            // SSM null group ID ff3x::4000:0, even w/ a source.
            ("ff3e::4000:0", Some("fd00::1")),
            // SSM null group ID w/ the ff2/rsvd nibbles set.
            ("ff3e:f000::4000:0", Some("fd00::1")),
            // Embedded RP (R flag) w/o P.
            ("ff5e:140:2001:db8::1", None),
            // Embedded RP w/o T.
            ("ff6e:140:2001:db8::1", None),
            // Embedded RP w/ a zero prefix length.
            ("ff7e:100:2001:db8::1", None),
            // Embedded RP w/ a prefix length over 64.
            ("ff7e:180:2001:db8::1", None),
            // Embedded RP w/ a zero RP interface ID.
            ("ff7e:40:2001:db8::1", None),
            // Embedded RP whose derived address is in ::/16.
            ("ff7e:140::1", None),
            // Embedded RP whose derived address is link-local.
            ("ff7e:140:fe80::1", None),
            // Embedded RP whose derived address is multicast.
            ("ff7e:140:ff00::1", None),
        ] {
            assert!(!decodes(group, source), "v4 must reject {group}");
        }
    }
}
