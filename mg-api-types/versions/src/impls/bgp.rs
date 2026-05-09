// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

use crate::v1::rdb::policy::ImportExportPolicy as ImportExportPolicyV1;
use crate::v1::rdb::prefix::Prefix;
use crate::v4::rdb::neighbor::{
    BgpNeighborInfo, BgpNeighborParameters, BgpUnnumberedNeighborInfo,
};
use crate::v4::rdb::policy::{ImportExportPolicy4, ImportExportPolicy6};

use crate::v4::bgp::config::{
    Ipv4UnicastConfig, Ipv6UnicastConfig, JitterRange,
};
use crate::{latest, v1, v4, v5};
use std::net::IpAddr;

// Each conversion below uses full-struct destructuring at the source
// boundary as a compile barrier: adding a field to a published or
// runtime type fails to bind here, forcing a deliberate decision about
// how (or whether) the new field threads through to the target type.
// Bindings prefixed with `_:` are intentionally dropped — that decision
// is documented at the destructure site.

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
    pub fn to_peer_id(&self) -> crate::v1::rdb::peer::PeerId {
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

    /// Construct a latest `Neighbor` from an rdb `BgpNeighborInfo`.
    pub fn from_rdb_neighbor_info(asn: u32, rq: &BgpNeighborInfo) -> Self {
        let BgpNeighborInfo {
            asn: _,
            name,
            group,
            host,
            parameters,
        } = rq.clone();
        Self {
            asn,
            name,
            host,
            group,
            parameters: latest_params_from_rdb(parameters),
        }
    }

    /// Construct a latest `Neighbor` from a latest `BgpPeerConfig`.
    pub fn from_bgp_peer_config(
        asn: u32,
        group: String,
        rq: latest::bgp::BgpPeerConfig,
    ) -> Self {
        let latest::bgp::BgpPeerConfig {
            host,
            name,
            parameters,
        } = rq;
        Self {
            asn,
            name,
            host,
            group,
            parameters,
        }
    }
}

impl v1::bgp::config::Neighbor {
    /// Construct a v1 `Neighbor` from an rdb `BgpNeighborInfo`.
    pub fn from_rdb_neighbor_info(asn: u32, rq: &BgpNeighborInfo) -> Self {
        let BgpNeighborInfo {
            asn: _,
            name,
            group,
            host,
            parameters,
        } = rq.clone();
        Self {
            asn,
            group,
            name,
            host,
            parameters: v1_params_from_rdb(parameters),
        }
    }

    /// Construct a v1 `Neighbor` from a v1 `BgpPeerConfig`.
    pub fn from_bgp_peer_config(
        asn: u32,
        group: String,
        rq: v1::bgp::config::BgpPeerConfig,
    ) -> Self {
        let v1::bgp::config::BgpPeerConfig {
            host,
            name,
            parameters,
        } = rq;
        Self {
            asn,
            group,
            host,
            name,
            parameters,
        }
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

    /// Construct an `UnnumberedNeighbor` from a latest `UnnumberedBgpPeerConfig`.
    pub fn from_bgp_peer_config(
        asn: u32,
        group: String,
        rq: latest::bgp::UnnumberedBgpPeerConfig,
    ) -> Self {
        let latest::bgp::UnnumberedBgpPeerConfig {
            interface,
            name,
            router_lifetime,
            parameters,
        } = rq;
        Self {
            asn,
            group,
            interface,
            name,
            act_as_a_default_ipv6_router: router_lifetime,
            parameters,
        }
    }

    /// Construct an `UnnumberedNeighbor` from an rdb `BgpUnnumberedNeighborInfo`.
    pub fn from_rdb_neighbor_info(
        asn: u32,
        rq: &BgpUnnumberedNeighborInfo,
    ) -> Self {
        let BgpUnnumberedNeighborInfo {
            asn: _,
            name,
            group,
            interface,
            router_lifetime,
            parameters,
        } = rq.clone();
        Self {
            asn,
            group,
            name,
            interface,
            act_as_a_default_ipv6_router: router_lifetime,
            parameters: latest_params_from_rdb(parameters),
        }
    }
}

/// Build a latest `BgpPeerParameters` from runtime `BgpNeighborParameters`.
fn latest_params_from_rdb(
    params: BgpNeighborParameters,
) -> latest::bgp::BgpPeerParameters {
    let BgpNeighborParameters {
        hold_time,
        idle_hold_time,
        delay_open,
        connect_retry,
        keepalive,
        resolution,
        passive,
        remote_asn,
        min_ttl,
        md5_auth_key,
        multi_exit_discriminator,
        communities,
        local_pref,
        enforce_first_as,
        ipv4_enabled,
        ipv6_enabled,
        allow_import4,
        allow_export4,
        allow_import6,
        allow_export6,
        nexthop4,
        nexthop6,
        vlan_id,
        src_addr,
        src_port,
    } = params;

    latest::bgp::BgpPeerParameters {
        remote_asn,
        min_ttl,
        hold_time,
        idle_hold_time,
        delay_open,
        connect_retry,
        keepalive,
        resolution,
        passive,
        md5_auth_key,
        multi_exit_discriminator,
        communities,
        local_pref,
        enforce_first_as,
        ipv4_unicast: ipv4_unicast_config_new(
            ipv4_enabled,
            nexthop4,
            allow_import4,
            allow_export4,
        ),
        ipv6_unicast: ipv6_unicast_config_new(
            ipv6_enabled,
            nexthop6,
            allow_import6,
            allow_export6,
        ),
        vlan_id,
        connect_retry_jitter: Some(JitterRange {
            min: 0.75,
            max: 1.0,
        }),
        idle_hold_jitter: None,
        deterministic_collision_resolution: false,
        src_addr,
        src_port,
    }
}

/// Build a v1 `BgpPeerParameters` from runtime `BgpNeighborParameters`.
fn v1_params_from_rdb(
    params: BgpNeighborParameters,
) -> v1::bgp::config::BgpPeerParameters {
    let BgpNeighborParameters {
        hold_time,
        idle_hold_time,
        delay_open,
        connect_retry,
        keepalive,
        resolution,
        passive,
        remote_asn,
        min_ttl,
        md5_auth_key,
        multi_exit_discriminator,
        communities,
        local_pref,
        enforce_first_as,
        // v1 has no per-AF enablement; it folds the v4+ split policies
        // back into single allow_import / allow_export fields below.
        ipv4_enabled: _,
        ipv6_enabled: _,
        allow_import4,
        allow_export4,
        allow_import6,
        allow_export6,
        // v1 has no per-AF nexthop, no source-address binding.
        nexthop4: _,
        nexthop6: _,
        src_addr: _,
        src_port: _,
        vlan_id,
    } = params;

    v1::bgp::config::BgpPeerParameters {
        remote_asn,
        min_ttl,
        hold_time,
        idle_hold_time,
        delay_open,
        connect_retry,
        keepalive,
        resolution,
        passive,
        md5_auth_key,
        multi_exit_discriminator,
        communities,
        local_pref,
        enforce_first_as,
        allow_import: ImportExportPolicyV1::from_per_af_policies(
            &allow_import4,
            &allow_import6,
        ),
        allow_export: ImportExportPolicyV1::from_per_af_policies(
            &allow_export4,
            &allow_export6,
        ),
        vlan_id,
    }
}

fn ipv4_unicast_config_new(
    enabled: bool,
    nexthop: Option<IpAddr>,
    import_policy: ImportExportPolicy4,
    export_policy: ImportExportPolicy4,
) -> Option<Ipv4UnicastConfig> {
    if enabled {
        Some(Ipv4UnicastConfig {
            nexthop,
            import_policy,
            export_policy,
        })
    } else {
        None
    }
}

fn ipv6_unicast_config_new(
    enabled: bool,
    nexthop: Option<IpAddr>,
    import_policy: ImportExportPolicy6,
    export_policy: ImportExportPolicy6,
) -> Option<Ipv6UnicastConfig> {
    if enabled {
        Some(Ipv6UnicastConfig {
            nexthop,
            import_policy,
            export_policy,
        })
    } else {
        None
    }
}

// ----- v2 (ipv6_basic) <-> v1 (initial) downgrades for PeerInfo / FsmStateKind -----

impl From<crate::v2::bgp::session::FsmStateKind>
    for v1::bgp::config::FsmStateKind
{
    fn from(kind: crate::v2::bgp::session::FsmStateKind) -> Self {
        // The match exhausts all v2 variants; adding a v2 variant fails
        // to compile here, forcing an explicit v1 mapping.
        use crate::v2::bgp::session::FsmStateKind as V2;
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

impl From<crate::v2::bgp::history::PeerInfo> for v1::bgp::config::PeerInfo {
    fn from(info: crate::v2::bgp::history::PeerInfo) -> Self {
        let crate::v2::bgp::history::PeerInfo {
            state,
            asn,
            duration_millis,
            timers,
        } = info;
        Self {
            state: v1::bgp::config::FsmStateKind::from(state),
            asn,
            duration_millis,
            timers,
        }
    }
}

// ----- v1 (initial, frozen) -> latest upgrades -----

impl From<v1::bgp::config::BgpPeerConfig> for latest::bgp::BgpPeerConfig {
    fn from(cfg: v1::bgp::config::BgpPeerConfig) -> Self {
        // v1 is frozen; if this destructure stops compiling the v1
        // contract has been violated upstream — fix that, don't teach
        // this conversion to handle a new field.
        let v1::bgp::config::BgpPeerConfig {
            host,
            name,
            parameters,
        } = cfg;
        let v1::bgp::config::BgpPeerParameters {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive,
            remote_asn,
            min_ttl,
            md5_auth_key,
            multi_exit_discriminator,
            communities,
            local_pref,
            enforce_first_as,
            allow_import,
            allow_export,
            vlan_id,
        } = parameters;
        Self {
            host,
            name,
            parameters: latest::bgp::BgpPeerParameters {
                hold_time,
                idle_hold_time,
                delay_open,
                connect_retry,
                keepalive,
                resolution,
                passive,
                remote_asn,
                min_ttl,
                md5_auth_key,
                multi_exit_discriminator,
                communities,
                local_pref,
                enforce_first_as,
                ipv4_unicast: Some(v4::bgp::config::Ipv4UnicastConfig {
                    nexthop: None,
                    import_policy: ImportExportPolicy4::from(allow_import),
                    export_policy: ImportExportPolicy4::from(allow_export),
                }),
                ipv6_unicast: None,
                vlan_id,
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

impl From<v1::bgp::config::ApplyRequest> for latest::bgp::ApplyRequest {
    fn from(req: v1::bgp::config::ApplyRequest) -> Self {
        // v1 is frozen by design and must never gain a field. If this
        // destructure stops compiling, the v1 contract has been
        // violated upstream — fix that, don't teach this conversion to
        // handle a new field.
        let v1::bgp::config::ApplyRequest {
            asn,
            originate,
            checker,
            shaper,
            peers,
        } = req;
        Self {
            asn,
            originate: originate.iter().map(|p| Prefix::V4(*p)).collect(),
            checker,
            shaper,
            peers: peers
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

// ----- v4 (mp_bgp, frozen) <-> latest (v8) BgpPeerParameters -----

impl From<latest::bgp::BgpPeerParameters>
    for v4::bgp::config::BgpPeerParameters
{
    fn from(p: latest::bgp::BgpPeerParameters) -> Self {
        let latest::bgp::BgpPeerParameters {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive,
            remote_asn,
            min_ttl,
            md5_auth_key,
            multi_exit_discriminator,
            communities,
            local_pref,
            enforce_first_as,
            vlan_id,
            ipv4_unicast,
            ipv6_unicast,
            deterministic_collision_resolution,
            idle_hold_jitter,
            connect_retry_jitter,
            // v4 has no source-address binding; the v8 fields are
            // dropped on the way down.
            src_addr: _,
            src_port: _,
        } = p;
        Self {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive,
            remote_asn,
            min_ttl,
            md5_auth_key,
            multi_exit_discriminator,
            communities,
            local_pref,
            enforce_first_as,
            vlan_id,
            ipv4_unicast,
            ipv6_unicast,
            deterministic_collision_resolution,
            idle_hold_jitter,
            connect_retry_jitter,
        }
    }
}

impl From<v4::bgp::config::BgpPeerParameters>
    for latest::bgp::BgpPeerParameters
{
    fn from(p: v4::bgp::config::BgpPeerParameters) -> Self {
        // v4 is frozen; if this destructure stops compiling the v4
        // contract has been violated upstream — fix that, don't teach
        // this conversion to handle a new field.
        let v4::bgp::config::BgpPeerParameters {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive,
            remote_asn,
            min_ttl,
            md5_auth_key,
            multi_exit_discriminator,
            communities,
            local_pref,
            enforce_first_as,
            vlan_id,
            ipv4_unicast,
            ipv6_unicast,
            deterministic_collision_resolution,
            idle_hold_jitter,
            connect_retry_jitter,
        } = p;
        Self {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive,
            remote_asn,
            min_ttl,
            md5_auth_key,
            multi_exit_discriminator,
            communities,
            local_pref,
            enforce_first_as,
            vlan_id,
            ipv4_unicast,
            ipv6_unicast,
            deterministic_collision_resolution,
            idle_hold_jitter,
            connect_retry_jitter,
            src_addr: None,
            src_port: None,
        }
    }
}

impl From<latest::bgp::BgpPeerConfig> for v4::bgp::config::BgpPeerConfig {
    fn from(cfg: latest::bgp::BgpPeerConfig) -> Self {
        let latest::bgp::BgpPeerConfig {
            host,
            name,
            parameters,
        } = cfg;
        Self {
            host,
            name,
            parameters: v4::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v4::bgp::config::BgpPeerConfig> for latest::bgp::BgpPeerConfig {
    fn from(cfg: v4::bgp::config::BgpPeerConfig) -> Self {
        // v4 is frozen by design and must never gain a field. If this
        // destructure stops compiling, the v4 contract has been
        // violated upstream — fix that, don't teach this conversion to
        // handle a new field.
        let v4::bgp::config::BgpPeerConfig {
            host,
            name,
            parameters,
        } = cfg;
        Self {
            host,
            name,
            parameters: latest::bgp::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<latest::bgp::UnnumberedBgpPeerConfig>
    for v4::bgp::config::UnnumberedBgpPeerConfig
{
    fn from(cfg: latest::bgp::UnnumberedBgpPeerConfig) -> Self {
        let latest::bgp::UnnumberedBgpPeerConfig {
            interface,
            name,
            router_lifetime,
            parameters,
        } = cfg;
        Self {
            interface,
            name,
            router_lifetime,
            parameters: v4::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v4::bgp::config::UnnumberedBgpPeerConfig>
    for latest::bgp::UnnumberedBgpPeerConfig
{
    fn from(cfg: v4::bgp::config::UnnumberedBgpPeerConfig) -> Self {
        // v4 is frozen by design and must never gain a field. If this
        // destructure stops compiling, the v4 contract has been
        // violated upstream — fix that, don't teach this conversion to
        // handle a new field.
        let v4::bgp::config::UnnumberedBgpPeerConfig {
            interface,
            name,
            router_lifetime,
            parameters,
        } = cfg;
        Self {
            interface,
            name,
            router_lifetime,
            parameters: latest::bgp::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<latest::bgp::Neighbor> for v4::bgp::config::Neighbor {
    fn from(n: latest::bgp::Neighbor) -> Self {
        let latest::bgp::Neighbor {
            asn,
            name,
            group,
            host,
            parameters,
        } = n;
        Self {
            asn,
            name,
            group,
            host,
            parameters: v4::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v4::bgp::config::Neighbor> for latest::bgp::Neighbor {
    fn from(n: v4::bgp::config::Neighbor) -> Self {
        // v4 is frozen by design and must never gain a field. If this
        // destructure stops compiling, the v4 contract has been
        // violated upstream — fix that, don't teach this conversion to
        // handle a new field.
        let v4::bgp::config::Neighbor {
            asn,
            name,
            group,
            host,
            parameters,
        } = n;
        Self {
            asn,
            name,
            group,
            host,
            parameters: latest::bgp::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v4::bgp::config::ApplyRequest> for latest::bgp::ApplyRequest {
    fn from(req: v4::bgp::config::ApplyRequest) -> Self {
        // v4 is frozen by design and must never gain a field. If this
        // destructure stops compiling, the v4 contract has been
        // violated upstream — fix that, don't teach this conversion to
        // handle a new field.
        let v4::bgp::config::ApplyRequest {
            asn,
            originate,
            checker,
            shaper,
            peers,
            unnumbered_peers,
        } = req;
        Self {
            asn,
            originate,
            checker,
            shaper,
            peers: peers
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
            unnumbered_peers: unnumbered_peers
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

// ----- v5 (unnumbered, frozen) <-> latest (v8) UnnumberedNeighbor -----

impl From<latest::bgp::UnnumberedNeighbor> for v5::bgp::UnnumberedNeighbor {
    fn from(n: latest::bgp::UnnumberedNeighbor) -> Self {
        let latest::bgp::UnnumberedNeighbor {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters,
        } = n;
        Self {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters: v4::bgp::config::BgpPeerParameters::from(parameters),
        }
    }
}

impl From<v5::bgp::UnnumberedNeighbor> for latest::bgp::UnnumberedNeighbor {
    fn from(n: v5::bgp::UnnumberedNeighbor) -> Self {
        // v5 is frozen by design and must never gain a field. If this
        // destructure stops compiling, the v5 contract has been
        // violated upstream — fix that, don't teach this conversion to
        // handle a new field.
        let v5::bgp::UnnumberedNeighbor {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters,
        } = n;
        Self {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters: latest::bgp::BgpPeerParameters::from(parameters),
        }
    }
}

// ----- AfiSafi / BgpCapability conversions (reabsorbed from bgp/src/params.rs) -----

impl From<&crate::v1::bgp::messages::AddPathElement> for latest::bgp::AfiSafi {
    fn from(value: &crate::v1::bgp::messages::AddPathElement) -> Self {
        let crate::v1::bgp::messages::AddPathElement {
            afi,
            safi,
            // send_receive is wire-protocol metadata that does not
            // belong on the schema-published AfiSafi shape.
            send_receive: _,
        } = value.clone();
        Self { afi, safi }
    }
}

impl From<&crate::v1::bgp::messages::Capability>
    for latest::bgp::BgpCapability
{
    fn from(value: &crate::v1::bgp::messages::Capability) -> Self {
        // BgpCapability has structured variants only for capabilities
        // we actively implement (MultiprotocolExtensions, RouteRefresh,
        // FourOctetAsn, AddPath). The remaining v1 Capability variants
        // are deliberately collapsed into BgpCapability::Unknown(code)
        // because there is no meaningful structured representation for
        // them today — most are RFC-listed but not yet implemented in
        // bgp.
        //
        // The match below names every v1 Capability variant explicitly
        // rather than using a wildcard arm, so that adding a new v1
        // variant fails to compile here. That forces a deliberate
        // decision: add a structured BgpCapability variant for it, or
        // route it to Unknown like the others.
        use crate::v1::bgp::messages::{Capability, CapabilityCode};
        match value {
            Capability::MultiprotocolExtensions { afi, safi } => {
                Self::MultiprotocolExtensions(latest::bgp::AfiSafi {
                    afi: *afi,
                    safi: *safi,
                })
            }
            Capability::RouteRefresh {} => Self::RouteRefresh,
            Capability::FourOctetAs { asn } => Self::FourOctetAsn(*asn),
            Capability::AddPath { elements } => Self::AddPath {
                elements: elements
                    .iter()
                    .map(|e| latest::bgp::AfiSafi {
                        afi: e.afi,
                        safi: e.safi,
                    })
                    .collect(),
            },
            // Capabilities without a structured BgpCapability shape.
            c @ (Capability::OutboundRouteFiltering {}
            | Capability::MultipleRoutesToDestination {}
            | Capability::ExtendedNextHopEncoding { .. }
            | Capability::BGPExtendedMessage {}
            | Capability::BgpSec {}
            | Capability::MultipleLabels {}
            | Capability::BgpRole {}
            | Capability::GracefulRestart {}
            | Capability::DynamicCapability {}
            | Capability::MultisessionBgp {}
            | Capability::EnhancedRouteRefresh {}
            | Capability::LongLivedGracefulRestart {}
            | Capability::RoutingPolicyDistribution {}
            | Capability::Fqdn {}
            | Capability::PrestandardRouteRefresh {}
            | Capability::PrestandardOrfAndPd {}
            | Capability::PrestandardOutboundRouteFiltering {}
            | Capability::PrestandardMultisession {}
            | Capability::PrestandardFqdn {}
            | Capability::PrestandardOperationalMessage {}
            | Capability::Experimental { .. }
            | Capability::Unassigned { .. }
            | Capability::Reserved { .. }) => {
                Self::Unknown(CapabilityCode::from(c.clone()) as u8)
            }
        }
    }
}
