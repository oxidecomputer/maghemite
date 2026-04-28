// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

use rdb_types_versions::v1::prefix::Prefix;
use rdb_types_versions::v4::policy::ImportExportPolicy4;

use crate::v4::bgp::JitterRange;
use crate::{latest, v1, v4, v5};

impl std::fmt::Display for latest::bgp::NeighborResetRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "neighbor {} asn {} op {:?}",
            self.addr, self.asn, self.op
        )
    }
}

impl latest::bgp::NeighborSelector {
    /// Convert peer string to PeerId using FromStr implementation.
    /// Tries to parse as IP first, otherwise treats as interface name.
    pub fn to_peer_id(&self) -> rdb_types_versions::v1::peer::PeerId {
        self.peer.parse().expect("PeerId::from_str never fails")
    }
}

impl latest::bgp::Neighbor {
    /// Validate that at least one address family is enabled, and that
    /// `src_addr` (if set) is the same IP version as `host`.
    pub fn validate_address_families(&self) -> Result<(), String> {
        if self.parameters.ipv4_unicast.is_none()
            && self.parameters.ipv6_unicast.is_none()
        {
            return Err("at least one address family must be enabled".into());
        }
        if let Some(src) = self.parameters.src_addr {
            let host_is_v4 = self.host.ip().is_ipv4();
            let src_is_v4 = src.is_ipv4();
            if host_is_v4 != src_is_v4 {
                return Err(format!(
                    "src_addr ({src}) IP version does not match host ({}) IP version",
                    self.host.ip()
                ));
            }
        }
        Ok(())
    }
}

impl latest::bgp::UnnumberedNeighbor {
    /// Validate that at least one address family is enabled, and that
    /// `src_addr` (if set) is IPv6 — unnumbered BGP uses link-local IPv6
    /// addressing, so an IPv4 source address is never valid.
    pub fn validate_address_families(&self) -> Result<(), String> {
        if self.parameters.ipv4_unicast.is_none()
            && self.parameters.ipv6_unicast.is_none()
        {
            return Err("at least one address family must be enabled".into());
        }
        if let Some(src) = self.parameters.src_addr
            && src.is_ipv4()
        {
            return Err(format!(
                "src_addr ({src}) must be IPv6 for unnumbered neighbors"
            ));
        }
        Ok(())
    }
}

// ----- v2 (ipv6_basic) <-> v1 (initial) downgrades for PeerInfo / FsmStateKind -----

impl From<bgp_types_versions::v2::session::FsmStateKind>
    for v1::bgp::FsmStateKind
{
    fn from(kind: bgp_types_versions::v2::session::FsmStateKind) -> Self {
        use bgp_types_versions::v2::session::FsmStateKind as V2;
        match kind {
            V2::Idle => Self::Idle,
            V2::Connect => Self::Connect,
            V2::Active => Self::Active,
            V2::OpenSent => Self::OpenSent,
            V2::OpenConfirm => Self::OpenConfirm,
            // We convert ConnectionCollision to OpenSent, because one
            // connection is always in OpenSent for the duration of
            // the colliison (unless we've already transitioned out of
            // ConnectionCollision), so this is technically correct, even if
            // it's only correct from the perspective of just one connection.
            V2::ConnectionCollision => Self::OpenSent,
            V2::SessionSetup => Self::SessionSetup,
            V2::Established => Self::Established,
        }
    }
}

impl From<crate::v2::bgp::PeerInfo> for v1::bgp::PeerInfo {
    fn from(info: crate::v2::bgp::PeerInfo) -> Self {
        Self {
            state: v1::bgp::FsmStateKind::from(info.state),
            asn: info.asn,
            duration_millis: info.duration_millis,
            timers: info.timers,
        }
    }
}

// ----- v1 (initial) <-> v8 (bgp_src_addr) conversions -----

impl From<v1::bgp::BgpPeerConfig> for latest::bgp::BgpPeerConfig {
    fn from(cfg: v1::bgp::BgpPeerConfig) -> Self {
        // Legacy v1 BgpPeerConfig is IPv4-only.
        Self {
            host: cfg.host,
            name: cfg.name,
            parameters: latest::bgp::BgpPeerParameters {
                hold_time: cfg.parameters.hold_time,
                idle_hold_time: cfg.parameters.idle_hold_time,
                delay_open: cfg.parameters.delay_open,
                connect_retry: cfg.parameters.connect_retry,
                keepalive: cfg.parameters.keepalive,
                resolution: cfg.parameters.resolution,
                passive: cfg.parameters.passive,
                remote_asn: cfg.parameters.remote_asn,
                min_ttl: cfg.parameters.min_ttl,
                md5_auth_key: cfg.parameters.md5_auth_key,
                multi_exit_discriminator: cfg
                    .parameters
                    .multi_exit_discriminator,
                communities: cfg.parameters.communities,
                local_pref: cfg.parameters.local_pref,
                enforce_first_as: cfg.parameters.enforce_first_as,
                ipv4_unicast: Some(v4::bgp::Ipv4UnicastConfig {
                    nexthop: None,
                    import_policy: ImportExportPolicy4::from(
                        cfg.parameters.allow_import,
                    ),
                    export_policy: ImportExportPolicy4::from(
                        cfg.parameters.allow_export,
                    ),
                }),
                ipv6_unicast: None,
                vlan_id: cfg.parameters.vlan_id,
                connect_retry_jitter: Some(JitterRange {
                    min: 0.75,
                    max: 1.0,
                }),
                idle_hold_jitter: None,
                deterministic_collision_resolution: false,
                src_addr: None,
                src_port: None,
            },
        }
    }
}

impl From<v1::bgp::ApplyRequest> for latest::bgp::ApplyRequest {
    fn from(req: v1::bgp::ApplyRequest) -> Self {
        Self {
            asn: req.asn,
            originate: req.originate.iter().map(|p| Prefix::V4(*p)).collect(),
            checker: req.checker,
            shaper: req.shaper,
            peers: req
                .peers
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        v.into_iter()
                            .map(latest::bgp::BgpPeerConfig::from)
                            .collect(),
                    )
                })
                .collect(),
            unnumbered_peers: HashMap::default(),
        }
    }
}

// ----- v4 (mp_bgp) <-> v8 (bgp_src_addr) conversions -----

impl From<latest::bgp::BgpPeerParameters> for v4::bgp::BgpPeerParameters {
    fn from(p: latest::bgp::BgpPeerParameters) -> Self {
        Self {
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
        }
    }
}

impl From<v4::bgp::BgpPeerParameters> for latest::bgp::BgpPeerParameters {
    fn from(p: v4::bgp::BgpPeerParameters) -> Self {
        Self {
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
            src_addr: None,
            src_port: None,
        }
    }
}

impl From<latest::bgp::BgpPeerConfig> for v4::bgp::BgpPeerConfig {
    fn from(cfg: latest::bgp::BgpPeerConfig) -> Self {
        Self {
            host: cfg.host,
            name: cfg.name,
            parameters: v4::bgp::BgpPeerParameters::from(cfg.parameters),
        }
    }
}

impl From<v4::bgp::BgpPeerConfig> for latest::bgp::BgpPeerConfig {
    fn from(cfg: v4::bgp::BgpPeerConfig) -> Self {
        Self {
            host: cfg.host,
            name: cfg.name,
            parameters: latest::bgp::BgpPeerParameters::from(cfg.parameters),
        }
    }
}

impl From<latest::bgp::UnnumberedBgpPeerConfig>
    for v4::bgp::UnnumberedBgpPeerConfig
{
    fn from(cfg: latest::bgp::UnnumberedBgpPeerConfig) -> Self {
        Self {
            interface: cfg.interface,
            name: cfg.name,
            router_lifetime: cfg.router_lifetime,
            parameters: v4::bgp::BgpPeerParameters::from(cfg.parameters),
        }
    }
}

impl From<v4::bgp::UnnumberedBgpPeerConfig>
    for latest::bgp::UnnumberedBgpPeerConfig
{
    fn from(cfg: v4::bgp::UnnumberedBgpPeerConfig) -> Self {
        Self {
            interface: cfg.interface,
            name: cfg.name,
            router_lifetime: cfg.router_lifetime,
            parameters: latest::bgp::BgpPeerParameters::from(cfg.parameters),
        }
    }
}

impl From<latest::bgp::Neighbor> for v4::bgp::Neighbor {
    fn from(n: latest::bgp::Neighbor) -> Self {
        Self {
            asn: n.asn,
            name: n.name,
            group: n.group,
            host: n.host,
            parameters: v4::bgp::BgpPeerParameters::from(n.parameters),
        }
    }
}

impl From<v4::bgp::Neighbor> for latest::bgp::Neighbor {
    fn from(n: v4::bgp::Neighbor) -> Self {
        Self {
            asn: n.asn,
            name: n.name,
            group: n.group,
            host: n.host,
            parameters: latest::bgp::BgpPeerParameters::from(n.parameters),
        }
    }
}

impl From<v4::bgp::ApplyRequest> for latest::bgp::ApplyRequest {
    fn from(req: v4::bgp::ApplyRequest) -> Self {
        Self {
            asn: req.asn,
            originate: req.originate,
            checker: req.checker,
            shaper: req.shaper,
            peers: req
                .peers
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        v.into_iter()
                            .map(latest::bgp::BgpPeerConfig::from)
                            .collect(),
                    )
                })
                .collect(),
            unnumbered_peers: req
                .unnumbered_peers
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        v.into_iter()
                            .map(latest::bgp::UnnumberedBgpPeerConfig::from)
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

// ----- v5 (unnumbered) <-> v8 (bgp_src_addr) conversions -----

impl From<latest::bgp::UnnumberedNeighbor> for v5::bgp::UnnumberedNeighbor {
    fn from(n: latest::bgp::UnnumberedNeighbor) -> Self {
        Self {
            asn: n.asn,
            name: n.name,
            group: n.group,
            interface: n.interface,
            act_as_a_default_ipv6_router: n.act_as_a_default_ipv6_router,
            parameters: v4::bgp::BgpPeerParameters::from(n.parameters),
        }
    }
}

impl From<v5::bgp::UnnumberedNeighbor> for latest::bgp::UnnumberedNeighbor {
    fn from(n: v5::bgp::UnnumberedNeighbor) -> Self {
        Self {
            asn: n.asn,
            name: n.name,
            group: n.group,
            interface: n.interface,
            act_as_a_default_ipv6_router: n.act_as_a_default_ipv6_router,
            parameters: latest::bgp::BgpPeerParameters::from(n.parameters),
        }
    }
}
