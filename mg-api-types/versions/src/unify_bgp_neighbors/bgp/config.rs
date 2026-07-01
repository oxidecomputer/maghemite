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
//! `/bgp/config/neighbor` route and carry `asn`/`group` in the `Neighbor`
//! envelope; `ApplyRequest` carries `asn` in its envelope and `group` as the
//! `peers` map key. The read/stored `Neighbor` type composes `NeighborConfig`
//! together with its `asn`/`group` (nested, no `#[serde(flatten)]`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::num::NonZeroU16;

use oxnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;
use crate::v1::bgp::peer::PeerId;
use crate::v4::bgp::config::JitterRange;
use crate::v11::bgp::config::{Ipv4UnicastConfig, Ipv6UnicastConfig};

/// Default TCP port used for BGP connections.
const BGP_PORT: u16 = 179;

/// Bare BGP neighbor configuration: everything about a peer except the `asn`
/// router it belongs to and the peer `group` it is a member of.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct NeighborConfig {
    /// Peer identity: `Ip` for numbered peers, `Interface` for unnumbered.
    pub peer: PeerId,
    /// TCP port of the peer. `None` means the well-known BGP port.
    pub port: Option<NonZeroU16>,
    pub name: String,
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

/// A BGP neighbor as read from / stored in the database: the bare
/// `NeighborConfig` composed with the `asn` router it belongs to and the peer
/// `group` it is a member of.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct Neighbor {
    pub asn: u32,
    pub group: String,
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
pub struct ApplyRequest {
    pub asn: u32,
    pub originate: Vec<IpNet>,
    pub checker: Option<v1::bgp::config::CheckerSource>,
    pub shaper: Option<v1::bgp::config::ShaperSource>,
    /// Lists of peers indexed by peer group.
    pub peers: HashMap<String, Vec<NeighborConfig>>,
}

// ===== upgrade conversions (v11 split -> v12 unified), total =====

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
            group,
            config: neighbor_config_from_v11(
                PeerId::Ip(host.ip()),
                NonZeroU16::new(host.port()),
                name,
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
            group,
            config: neighbor_config_from_v11(
                PeerId::Interface(interface),
                None,
                name,
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

// ===== downgrade conversions (v12 unified -> v11 split), partial =====

impl TryFrom<Neighbor> for crate::v11::bgp::config::Neighbor {
    type Error = PeerKindMismatch;
    fn try_from(n: Neighbor) -> Result<Self, Self::Error> {
        let Neighbor { asn, group, config } = n;
        let PeerId::Ip(ip) = config.peer else {
            return Err(PeerKindMismatch);
        };
        let port = config.port.map(NonZeroU16::get).unwrap_or(BGP_PORT);
        Ok(Self {
            asn,
            name: config.name.clone(),
            group,
            host: SocketAddr::new(ip, port).into(),
            parameters: params_v11_from_config(&config),
        })
    }
}

impl TryFrom<Neighbor> for crate::v11::bgp::config::UnnumberedNeighbor {
    type Error = PeerKindMismatch;
    fn try_from(n: Neighbor) -> Result<Self, Self::Error> {
        let Neighbor { asn, group, config } = n;
        let PeerId::Interface(ref interface) = config.peer else {
            return Err(PeerKindMismatch);
        };
        Ok(Self {
            asn,
            name: config.name.clone(),
            group,
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

// ===== NeighborConfig conversions (v11 BgpPeerConfig <-> v12) =====

impl From<crate::v11::bgp::config::BgpPeerConfig> for NeighborConfig {
    fn from(old: crate::v11::bgp::config::BgpPeerConfig) -> Self {
        let crate::v11::bgp::config::BgpPeerConfig {
            host,
            name,
            parameters,
        } = old;
        neighbor_config_from_v11(
            PeerId::Ip(host.ip()),
            NonZeroU16::new(host.port()),
            name,
            0,
            parameters,
        )
    }
}

impl From<crate::v11::bgp::config::UnnumberedBgpPeerConfig> for NeighborConfig {
    fn from(old: crate::v11::bgp::config::UnnumberedBgpPeerConfig) -> Self {
        let crate::v11::bgp::config::UnnumberedBgpPeerConfig {
            interface,
            name,
            router_lifetime,
            parameters,
        } = old;
        neighbor_config_from_v11(
            PeerId::Interface(interface),
            None,
            name,
            router_lifetime,
            parameters,
        )
    }
}

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

impl From<crate::v11::bgp::config::ApplyRequest> for ApplyRequest {
    fn from(old: crate::v11::bgp::config::ApplyRequest) -> Self {
        let crate::v11::bgp::config::ApplyRequest {
            asn,
            originate,
            checker,
            shaper,
            peers,
            unnumbered_peers,
        } = old;
        let mut merged: HashMap<String, Vec<NeighborConfig>> = HashMap::new();
        for (group, list) in peers {
            merged
                .entry(group)
                .or_default()
                .extend(list.into_iter().map(NeighborConfig::from));
        }
        for (group, list) in unnumbered_peers {
            merged
                .entry(group)
                .or_default()
                .extend(list.into_iter().map(NeighborConfig::from));
        }
        Self {
            asn,
            originate,
            checker,
            shaper,
            peers: merged,
        }
    }
}

impl From<ApplyRequest> for crate::v11::bgp::config::ApplyRequest {
    fn from(new: ApplyRequest) -> Self {
        let ApplyRequest {
            asn,
            originate,
            checker,
            shaper,
            peers,
        } = new;
        let mut numbered: HashMap<
            String,
            Vec<crate::v11::bgp::config::BgpPeerConfig>,
        > = HashMap::new();
        let mut unnumbered: HashMap<
            String,
            Vec<crate::v11::bgp::config::UnnumberedBgpPeerConfig>,
        > = HashMap::new();
        for (group, list) in peers {
            for cfg in list {
                match crate::v11::bgp::config::BgpPeerConfig::try_from(
                    cfg.clone(),
                ) {
                    Ok(c) => numbered.entry(group.clone()).or_default().push(c),
                    Err(_) => {
                        if let Ok(u) = crate::v11::bgp::config::UnnumberedBgpPeerConfig::try_from(cfg) {
                            unnumbered.entry(group.clone()).or_default().push(u);
                        }
                    }
                }
            }
        }
        Self {
            asn,
            originate,
            checker,
            shaper,
            peers: numbered,
            unnumbered_peers: unnumbered,
        }
    }
}

// Build a v12 `NeighborConfig` from a v11 `BgpPeerParameters` plus the bits
// that live outside `parameters` in v11.
fn neighbor_config_from_v11(
    peer: PeerId,
    port: Option<NonZeroU16>,
    name: String,
    act_as_a_default_ipv6_router: u16,
    p: crate::v11::bgp::config::BgpPeerParameters,
) -> NeighborConfig {
    NeighborConfig {
        peer,
        port,
        name,
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

// Rebuild a v11 `BgpPeerParameters` from a v12 `NeighborConfig`.
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
