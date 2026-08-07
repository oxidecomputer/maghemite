// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `UNIFY_BGP_NEIGHBORS` BGP config types.
//!
//! Collapses the numbered (`Neighbor`) and unnumbered (`UnnumberedNeighbor`)
//! peer types into a single bare config type `NeighborConfig` identified by a
//! `PeerId`, with an explicit `port`. The separate `BgpPeerParameters` struct
//! is eliminated and its fields are inlined (no `#[serde(flatten)]`).
//!
//! `NeighborConfig` is the shared peer config payload used by `Neighbor` and
//! `ApplyRequest`. Single-neighbor create/update endpoints keep the existing
//! `/bgp/config/neighbor` route and carry `asn` in the `Neighbor` envelope.
//! `ApplyRequest` stores peers in an identity-derived map that rejects duplicate
//! `PeerId`s. The read/stored `Neighbor` type composes `NeighborConfig` together
//! with its `asn` (nested, no `#[serde(flatten)]`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::num::NonZeroU16;

use iddqd::{IdOrdItem, IdOrdMap, id_upcast};
use oxnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;
use crate::v1::bgp::peer::PeerId;
use crate::v4::bgp::config::JitterRange;
use crate::v11::bgp::config::{Ipv4UnicastConfig, Ipv6UnicastConfig};

/// Default TCP port used for BGP connections.
const BGP_PORT: u16 = 179;

/// BGP neighbor configuration: everything about a peer except the `asn` router
/// it belongs to.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct NeighborConfig {
    /// Peer identity: `Ip` for numbered peers, `Interface` for unnumbered.
    pub peer: PeerId,
    /// TCP port of the peer. `None` means the well-known BGP port.
    pub port: Option<NonZeroU16>,
    pub name: String,
    pub group: String,
    /// Advertised IPv6 router lifetime (RA). Only meaningful for unnumbered
    /// peers; ignored for numbered peers.
    pub act_as_a_default_ipv6_router: u16,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub passive: bool,
    pub remote_asn: Option<u32>,
    pub min_ttl: Option<u8>,
    pub md5_auth_key: Option<String>,
    pub multi_exit_discriminator: Option<u32>,
    pub communities: Vec<u32>,
    pub local_pref: Option<u32>,
    pub enforce_first_as: bool,
    pub vlan_id: Option<u16>,
    pub ipv4_unicast: Option<Ipv4UnicastConfig>,
    pub ipv6_unicast: Option<Ipv6UnicastConfig>,
    pub deterministic_collision_resolution: bool,
    pub idle_hold_jitter: Option<JitterRange>,
    pub connect_retry_jitter: Option<JitterRange>,
    pub src_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
}

impl IdOrdItem for NeighborConfig {
    type Key<'a> = &'a PeerId;

    fn key(&self) -> Self::Key<'_> {
        &self.peer
    }

    id_upcast!();
}

/// A BGP neighbor as read from / stored in the database: the bare
/// `NeighborConfig` composed with the `asn` router it belongs to.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct Neighbor {
    pub asn: u32,
    pub config: NeighborConfig,
}

/// Reset request for a BGP neighbor, identified by a peer string (IP address or
/// interface name).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NeighborResetRequest {
    pub asn: u32,
    /// Peer identifier as a string (IP address or interface name).
    pub peer: String,
    pub op: crate::v4::bgp::config::NeighborResetOp,
}

/// Apply configuration changes to an ASN.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ApplyRequest {
    /// Make this configuration the complete desired state for the router.
    Apply {
        asn: u32,
        originate: Vec<IpNet>,
        checker: Option<v1::bgp::config::CheckerSource>,
        shaper: Option<v1::bgp::config::ShaperSource>,
        /// Peers keyed by the `PeerId` embedded in each configuration. Each
        /// `peer` must be unique; duplicate peer identities are rejected.
        peers: IdOrdMap<NeighborConfig>,
    },
    /// Delete the router and all state owned by it.
    Delete { asn: u32 },
}

// ===== upgrade conversions (v11 split -> v13 unified), total =====

impl From<crate::v11::bgp::config::Neighbor> for Neighbor {
    fn from(old: crate::v11::bgp::config::Neighbor) -> Self {
        let crate::v11::bgp::config::Neighbor {
            asn,
            name,
            group,
            host,
            parameters,
        } = old;
        Self {
            asn,
            config: neighbor_config_from_v11(
                PeerId::Ip(host.ip()),
                NonZeroU16::new(host.port()),
                name,
                group,
                0,
                parameters,
            ),
        }
    }
}

impl From<crate::v11::bgp::config::UnnumberedNeighbor> for Neighbor {
    fn from(old: crate::v11::bgp::config::UnnumberedNeighbor) -> Self {
        let crate::v11::bgp::config::UnnumberedNeighbor {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters,
        } = old;
        Self {
            asn,
            config: neighbor_config_from_v11(
                PeerId::Interface(interface),
                None,
                name,
                group,
                act_as_a_default_ipv6_router,
                parameters,
            ),
        }
    }
}

/// Error returned when downgrading a unified `Neighbor`/`NeighborConfig` to an
/// older split type whose peer kind does not match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKindMismatch;

impl std::fmt::Display for PeerKindMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer kind does not match the requested neighbor type")
    }
}

impl std::error::Error for PeerKindMismatch {}

// ===== downgrade conversions (v13 unified -> v11 split), partial =====

impl TryFrom<Neighbor> for crate::v11::bgp::config::Neighbor {
    type Error = PeerKindMismatch;
    fn try_from(n: Neighbor) -> Result<Self, Self::Error> {
        let Neighbor { asn, config } = n;
        let PeerId::Ip(ip) = config.peer else {
            return Err(PeerKindMismatch);
        };
        let port = config.port.map(NonZeroU16::get).unwrap_or(BGP_PORT);
        Ok(Self {
            asn,
            name: config.name.clone(),
            group: config.group.clone(),
            host: SocketAddr::new(ip, port).into(),
            parameters: params_v11_from_config(&config),
        })
    }
}

impl TryFrom<Neighbor> for crate::v11::bgp::config::UnnumberedNeighbor {
    type Error = PeerKindMismatch;
    fn try_from(n: Neighbor) -> Result<Self, Self::Error> {
        let Neighbor { asn, config } = n;
        let PeerId::Interface(ref interface) = config.peer else {
            return Err(PeerKindMismatch);
        };
        Ok(Self {
            asn,
            name: config.name.clone(),
            group: config.group.clone(),
            interface: interface.clone(),
            act_as_a_default_ipv6_router: config.act_as_a_default_ipv6_router,
            parameters: params_v11_from_config(&config),
        })
    }
}

// ===== NeighborResetRequest conversions (upgrade only; request bodies) =====

impl From<crate::v4::bgp::config::NeighborResetRequest>
    for NeighborResetRequest
{
    fn from(old: crate::v4::bgp::config::NeighborResetRequest) -> Self {
        let crate::v4::bgp::config::NeighborResetRequest { asn, addr, op } =
            old;
        Self {
            asn,
            peer: addr.to_string(),
            op,
        }
    }
}

impl From<crate::v5::bgp::config::UnnumberedNeighborResetRequest>
    for NeighborResetRequest
{
    fn from(
        old: crate::v5::bgp::config::UnnumberedNeighborResetRequest,
    ) -> Self {
        let crate::v5::bgp::config::UnnumberedNeighborResetRequest {
            asn,
            interface,
            op,
        } = old;
        Self {
            asn,
            peer: interface,
            op,
        }
    }
}

// ===== NeighborConfig conversions (v13 -> v11 split types) =====

impl TryFrom<NeighborConfig> for crate::v11::bgp::config::BgpPeerConfig {
    type Error = PeerKindMismatch;
    fn try_from(c: NeighborConfig) -> Result<Self, Self::Error> {
        let PeerId::Ip(ip) = c.peer else {
            return Err(PeerKindMismatch);
        };
        let port = c.port.map(NonZeroU16::get).unwrap_or(BGP_PORT);
        Ok(Self {
            host: SocketAddr::new(ip, port).into(),
            name: c.name.clone(),
            parameters: params_v11_from_config(&c),
        })
    }
}

impl TryFrom<NeighborConfig>
    for crate::v11::bgp::config::UnnumberedBgpPeerConfig
{
    type Error = PeerKindMismatch;
    fn try_from(c: NeighborConfig) -> Result<Self, Self::Error> {
        let PeerId::Interface(ref interface) = c.peer else {
            return Err(PeerKindMismatch);
        };
        Ok(Self {
            interface: interface.clone(),
            name: c.name.clone(),
            router_lifetime: c.act_as_a_default_ipv6_router,
            parameters: params_v11_from_config(&c),
        })
    }
}

// ===== ApplyRequest conversions =====

/// Error returned when converting apply requests between API versions.
#[derive(Debug, thiserror::Error)]
pub enum ApplyRequestConversionError {
    #[error("peer {0} appears in more than one BGP peer group")]
    DuplicatePeer(PeerId),
    #[error("the older BGP apply API cannot represent router deletion")]
    DeleteUnsupported,
}

impl TryFrom<crate::v11::bgp::config::ApplyRequest> for ApplyRequest {
    type Error = ApplyRequestConversionError;

    fn try_from(
        old: crate::v11::bgp::config::ApplyRequest,
    ) -> Result<Self, Self::Error> {
        let crate::v11::bgp::config::ApplyRequest {
            asn,
            originate,
            checker,
            shaper,
            peers,
            unnumbered_peers,
        } = old;
        let mut merged = IdOrdMap::new();
        for (group, list) in peers {
            for old in list {
                let crate::v11::bgp::config::BgpPeerConfig {
                    host,
                    name,
                    parameters,
                } = old;
                let config = neighbor_config_from_v11(
                    PeerId::Ip(host.ip()),
                    NonZeroU16::new(host.port()),
                    name,
                    group.clone(),
                    0,
                    parameters,
                );
                let peer = config.peer.clone();
                merged.insert_unique(config).map_err(|_| {
                    ApplyRequestConversionError::DuplicatePeer(peer)
                })?;
            }
        }
        for (group, list) in unnumbered_peers {
            for old in list {
                let crate::v11::bgp::config::UnnumberedBgpPeerConfig {
                    interface,
                    name,
                    router_lifetime,
                    parameters,
                } = old;
                let config = neighbor_config_from_v11(
                    PeerId::Interface(interface),
                    None,
                    name,
                    group.clone(),
                    router_lifetime,
                    parameters,
                );
                let peer = config.peer.clone();
                merged.insert_unique(config).map_err(|_| {
                    ApplyRequestConversionError::DuplicatePeer(peer)
                })?;
            }
        }
        Ok(Self::Apply {
            asn,
            originate,
            checker,
            shaper,
            peers: merged,
        })
    }
}

impl TryFrom<ApplyRequest> for crate::v11::bgp::config::ApplyRequest {
    type Error = ApplyRequestConversionError;

    fn try_from(new: ApplyRequest) -> Result<Self, Self::Error> {
        let ApplyRequest::Apply {
            asn,
            originate,
            checker,
            shaper,
            peers,
        } = new
        else {
            return Err(ApplyRequestConversionError::DeleteUnsupported);
        };
        let mut numbered: HashMap<
            String,
            Vec<crate::v11::bgp::config::BgpPeerConfig>,
        > = HashMap::new();
        let mut unnumbered: HashMap<
            String,
            Vec<crate::v11::bgp::config::UnnumberedBgpPeerConfig>,
        > = HashMap::new();
        for cfg in peers {
            let parameters = params_v11_from_config(&cfg);
            match cfg.peer {
                PeerId::Ip(ip) => {
                    let port =
                        cfg.port.map(NonZeroU16::get).unwrap_or(BGP_PORT);
                    numbered.entry(cfg.group).or_default().push(
                        crate::v11::bgp::config::BgpPeerConfig {
                            host: SocketAddr::new(ip, port).into(),
                            name: cfg.name,
                            parameters,
                        },
                    );
                }
                PeerId::Interface(interface) => {
                    unnumbered.entry(cfg.group).or_default().push(
                        crate::v11::bgp::config::UnnumberedBgpPeerConfig {
                            interface,
                            name: cfg.name,
                            router_lifetime: cfg.act_as_a_default_ipv6_router,
                            parameters,
                        },
                    );
                }
            }
        }
        Ok(Self {
            asn,
            originate,
            checker,
            shaper,
            peers: numbered,
            unnumbered_peers: unnumbered,
        })
    }
}

// Build a v13 `NeighborConfig` from a v11 `BgpPeerParameters` plus the bits
// that live outside `parameters` in v11.
fn neighbor_config_from_v11(
    peer: PeerId,
    port: Option<NonZeroU16>,
    name: String,
    group: String,
    act_as_a_default_ipv6_router: u16,
    p: crate::v11::bgp::config::BgpPeerParameters,
) -> NeighborConfig {
    NeighborConfig {
        peer,
        port,
        name,
        group,
        act_as_a_default_ipv6_router,
        hold_time: p.hold_time,
        idle_hold_time: p.idle_hold_time,
        delay_open: p.delay_open,
        connect_retry: p.connect_retry,
        keepalive: p.keepalive,
        resolution: p.resolution,
        passive: p.passive,
        remote_asn: p.remote_asn,
        min_ttl: p.min_ttl,
        md5_auth_key: p.md5_auth_key,
        multi_exit_discriminator: p.multi_exit_discriminator,
        communities: p.communities,
        local_pref: p.local_pref,
        enforce_first_as: p.enforce_first_as,
        vlan_id: p.vlan_id,
        ipv4_unicast: p.ipv4_unicast,
        ipv6_unicast: p.ipv6_unicast,
        deterministic_collision_resolution: p
            .deterministic_collision_resolution,
        idle_hold_jitter: p.idle_hold_jitter,
        connect_retry_jitter: p.connect_retry_jitter,
        src_addr: p.src_addr,
        src_port: p.src_port,
    }
}

// Rebuild a v11 `BgpPeerParameters` from a v13 `NeighborConfig`.
fn params_v11_from_config(
    c: &NeighborConfig,
) -> crate::v11::bgp::config::BgpPeerParameters {
    crate::v11::bgp::config::BgpPeerParameters {
        hold_time: c.hold_time,
        idle_hold_time: c.idle_hold_time,
        delay_open: c.delay_open,
        connect_retry: c.connect_retry,
        keepalive: c.keepalive,
        resolution: c.resolution,
        passive: c.passive,
        remote_asn: c.remote_asn,
        min_ttl: c.min_ttl,
        md5_auth_key: c.md5_auth_key.clone(),
        multi_exit_discriminator: c.multi_exit_discriminator,
        communities: c.communities.clone(),
        local_pref: c.local_pref,
        enforce_first_as: c.enforce_first_as,
        vlan_id: c.vlan_id,
        ipv4_unicast: c.ipv4_unicast.clone(),
        ipv6_unicast: c.ipv6_unicast.clone(),
        deterministic_collision_resolution: c
            .deterministic_collision_resolution,
        idle_hold_jitter: c.idle_hold_jitter,
        connect_retry_jitter: c.connect_retry_jitter,
        src_addr: c.src_addr,
        src_port: c.src_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn neighbor(peer: PeerId, group: &str) -> NeighborConfig {
        NeighborConfig {
            peer,
            port: None,
            name: "test-peer".into(),
            group: group.into(),
            act_as_a_default_ipv6_router: 0,
            hold_time: 6,
            idle_hold_time: 0,
            delay_open: 0,
            connect_retry: 5,
            keepalive: 2,
            resolution: 100,
            passive: false,
            remote_asn: None,
            min_ttl: None,
            md5_auth_key: None,
            multi_exit_discriminator: None,
            communities: Vec::new(),
            local_pref: None,
            enforce_first_as: false,
            vlan_id: None,
            ipv4_unicast: None,
            ipv6_unicast: None,
            deterministic_collision_resolution: false,
            idle_hold_jitter: None,
            connect_retry_jitter: None,
            src_addr: None,
            src_port: None,
        }
    }

    #[test]
    fn apply_request_serde_uses_peer_array() {
        let peer = PeerId::Ip("192.0.2.1".parse().unwrap());
        let mut peers = IdOrdMap::new();
        peers.insert_unique(neighbor(peer, "rack-a")).unwrap();
        let request = ApplyRequest::Apply {
            asn: 47,
            originate: Vec::new(),
            checker: None,
            shaper: None,
            peers,
        };

        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["action"], "apply");
        assert!(value["peers"].is_array());
        serde_json::from_value::<ApplyRequest>(value.clone()).unwrap();
    }

    #[test]
    fn id_ord_map_deserialization_rejects_duplicate_peer_ids() {
        let peer = PeerId::Ip("192.0.2.1".parse().unwrap());
        let peers = serde_json::json!([
            neighbor(peer.clone(), "rack-a"),
            neighbor(peer, "rack-b"),
        ]);

        assert!(
            serde_json::from_value::<IdOrdMap<NeighborConfig>>(peers).is_err()
        );
    }

    #[test]
    fn delete_request_serde_is_explicit() {
        let request = ApplyRequest::Delete { asn: 47 };

        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value, serde_json::json!({ "asn": 47, "action": "delete" }));
        let decoded: ApplyRequest = serde_json::from_value(value).unwrap();
        assert!(matches!(decoded, ApplyRequest::Delete { asn: 47 }));
    }

    #[test]
    fn v11_apply_upgrade_rejects_peer_in_multiple_groups() {
        let peer = PeerId::Ip("192.0.2.1".parse().unwrap());
        let old_peer = crate::v11::bgp::config::BgpPeerConfig::try_from(
            neighbor(peer.clone(), "ignored"),
        )
        .unwrap();
        let request = crate::v11::bgp::config::ApplyRequest {
            asn: 47,
            originate: Vec::new(),
            checker: None,
            shaper: None,
            peers: HashMap::from([
                ("rack-a".into(), vec![old_peer.clone()]),
                ("rack-b".into(), vec![old_peer]),
            ]),
            unnumbered_peers: HashMap::new(),
        };

        let error = ApplyRequest::try_from(request).unwrap_err();
        assert!(matches!(
            error,
            ApplyRequestConversionError::DuplicatePeer(actual) if actual == peer
        ));
    }

    #[test]
    fn apply_downgrade_preserves_both_peer_kinds() {
        let mut peers = IdOrdMap::new();
        peers
            .insert_unique(neighbor(
                PeerId::Ip("192.0.2.1".parse().unwrap()),
                "numbered",
            ))
            .unwrap();
        peers
            .insert_unique(neighbor(
                PeerId::Interface("tfportqsfp0_0".into()),
                "unnumbered",
            ))
            .unwrap();
        let request = ApplyRequest::Apply {
            asn: 47,
            originate: Vec::new(),
            checker: None,
            shaper: None,
            peers,
        };

        let old =
            crate::v11::bgp::config::ApplyRequest::try_from(request).unwrap();
        assert_eq!(old.peers["numbered"].len(), 1);
        assert_eq!(old.unnumbered_peers["unnumbered"].len(), 1);
    }
}
