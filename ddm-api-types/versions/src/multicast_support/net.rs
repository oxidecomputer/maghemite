// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multicast origin and validated underlay address types added in
//! API version 3 (MULTICAST_SUPPORT).

pub use client_common::multicast::{
    OverlayMulticast, OverlayMulticastError, UnderlayMulticastError,
    UnderlayMulticastIpv6,
};
pub use client_common::vni::{Vni, VniError};
use ddm_protocol::v4;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Error promoting a wire [`v4::MulticastOrigin`] to the validated
/// [`MulticastOrigin`].
#[derive(Debug, thiserror::Error)]
pub enum MulticastOriginError {
    /// The overlay group is not a multicast address.
    #[error(transparent)]
    OverlayGroup(#[from] OverlayMulticastError),

    /// The underlay group is not within ff04::/64.
    #[error(transparent)]
    UnderlayGroup(#[from] UnderlayMulticastError),

    /// The VNI exceeds the 24-bit Geneve maximum.
    #[error(transparent)]
    Vni(#[from] VniError),
}

fn default_multicast_vni() -> Vni {
    Vni::DEFAULT_MULTICAST
}

/// Origin information for a multicast group announcement.
///
/// Analogous to `TunnelOrigin` but for multicast groups. Represents a
/// subscription to a multicast group that should be advertised via DDM.
/// `overlay_group` is the application-visible multicast address (e.g.,
/// 233.252.0.1 or ff0e::1), while `underlay_group` is the mapped
/// admin-local scoped IPv6 address (ff04::X) used in the underlay network.
#[derive(Debug, Clone, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MulticastOrigin {
    /// The overlay multicast group address (IPv4 or IPv6).
    /// This is the group address visible to applications.
    /// Validated at construction to be a multicast address.
    pub overlay_group: OverlayMulticast,

    /// The underlay multicast group address (ff04::X).
    /// Validated at construction to be within ff04::/64.
    pub underlay_group: UnderlayMulticastIpv6,

    /// VNI for this multicast group (identifies the VPC/network context).
    #[serde(default = "default_multicast_vni")]
    pub vni: Vni,

    /// Metric for path selection (lower is better).
    ///
    /// Used for multi-rack replication optimization.
    /// Excluded from identity (Hash/Eq) so that metric changes update an
    /// existing entry rather than creating a duplicate.
    #[serde(default)]
    pub metric: u64,

    /// Optional source address for Source-Specific Multicast (S,G) routes.
    /// `None` for Any-Source Multicast (*,G) routes.
    #[serde(default)]
    pub source: Option<IpAddr>,
}

impl MulticastOrigin {
    /// Identity used for equality and hashing: the group, its underlay
    /// mapping, VNI, and source. Excludes `metric`, a mutable path-selection
    /// attribute, so a metric change updates an existing entry rather than
    /// creating a duplicate. Routing both `PartialEq` and `Hash` through this
    /// accessor keeps the field set defined once so the two cannot drift.
    ///
    /// This type is not used in ordered collections (BTreeSet). See #649 for
    /// why adding `Ord` here would require more care.
    fn identity(
        &self,
    ) -> (
        &OverlayMulticast,
        &UnderlayMulticastIpv6,
        &Vni,
        &Option<IpAddr>,
    ) {
        (
            &self.overlay_group,
            &self.underlay_group,
            &self.vni,
            &self.source,
        )
    }

    /// Return a stable string key for this origin's identity.
    ///
    /// Serializes only the identity fields, matching `PartialEq`/`Hash`, so a
    /// keyed store overwrites the entry for an origin whose `metric` changed
    /// rather than leaving a stale entry under the prior metric. Deriving the
    /// key from [`MulticastOrigin::identity`] keeps it from drifting from
    /// equality.
    ///
    /// # Errors
    ///
    /// Returns an error if the identity fields fail to serialize.
    pub fn identity_key(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.identity())
    }
}

impl PartialEq for MulticastOrigin {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl std::hash::Hash for MulticastOrigin {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity().hash(state);
    }
}

// Locally-originated groups are operator-supplied and validated at the admin
// boundary. Before propagation on the wire the validated form is lowered to the
// plain `v4::MulticastOrigin`. The reverse promotion is deliberately absent:
// peer-supplied routes are stored in their plain form,
// trusted like tunnel and underlay routes. The one exception is the underlay
// group, which reaches DPD directly, so the exchange handler enforces its
// ff04::/64 invariant at import.
impl From<&MulticastOrigin> for v4::MulticastOrigin {
    fn from(o: &MulticastOrigin) -> Self {
        Self {
            overlay_group: o.overlay_group.ip(),
            underlay_group: o.underlay_group.ip(),
            vni: o.vni.as_u32(),
            metric: o.metric,
            source: o.source,
        }
    }
}

impl From<MulticastOrigin> for v4::MulticastOrigin {
    fn from(o: MulticastOrigin) -> Self {
        Self::from(&o)
    }
}

// Promote a peer-supplied wire origin to the validated form. Peer routes
// arrive as the plain `v4::MulticastOrigin`. Promotion enforces the invariants
// the rich type guarantees, the overlay group being multicast, the underlay
// group within ff04::/64, and the VNI within the 24-bit range, so an invalid
// origin is rejected at the exchange boundary before it can be stored or reach
// DPD.
impl TryFrom<&v4::MulticastOrigin> for MulticastOrigin {
    type Error = MulticastOriginError;

    fn try_from(o: &v4::MulticastOrigin) -> Result<Self, Self::Error> {
        Ok(Self {
            overlay_group: OverlayMulticast::new(o.overlay_group)?,
            underlay_group: UnderlayMulticastIpv6::new(o.underlay_group)?,
            vni: Vni::new(o.vni)?,
            metric: o.metric,
            source: o.source,
        })
    }
}

impl TryFrom<v4::MulticastOrigin> for MulticastOrigin {
    type Error = MulticastOriginError;

    fn try_from(o: v4::MulticastOrigin) -> Result<Self, Self::Error> {
        Self::try_from(&o)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn multicast_origin_rejects_bad_underlay() {
        let json = serde_json::json!({
            "overlay_group": "233.252.0.1",
            "underlay_group": "ff0e::1",
            "vni": 77
        });
        let result: Result<MulticastOrigin, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn multicast_origin_accepts_valid() {
        let json = serde_json::json!({
            "overlay_group": "233.252.0.1",
            "underlay_group": "ff04::1",
            "vni": 77
        });
        let origin: MulticastOrigin = serde_json::from_value(json).unwrap();
        assert_eq!(
            origin.underlay_group.ip(),
            Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1),
        );
    }

    // Metric is excluded from the identity so a metric-only change updates an
    // existing entry rather than duplicating it, mirroring the wire-type
    // contract in `v4::MulticastOrigin`.
    #[test]
    fn multicast_origin_identity_excludes_metric() {
        let base: MulticastOrigin = serde_json::from_value(serde_json::json!({
            "overlay_group": "233.252.0.1",
            "underlay_group": "ff04::1",
            "vni": 77,
            "metric": 0
        }))
        .unwrap();
        let mut other = base.clone();
        other.metric = 100;
        assert_eq!(base, other);
    }
}
