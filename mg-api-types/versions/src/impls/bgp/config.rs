// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Display and helper impls for the latest BGP neighbor / reset / peer-config
//! types.

use crate::latest;
use crate::latest::bgp::config::Ipv4UnicastConfig;
use crate::latest::bgp::config::Ipv6UnicastConfig;
use crate::latest::bgp::config::JitterRange;
use crate::latest::bgp::policy::ImportExportPolicy4;
use crate::latest::bgp::policy::ImportExportPolicy6;
use crate::latest::rdb::neighbor::BgpNeighborInfo;
use crate::latest::rdb::neighbor::BgpNeighborParameters;
use crate::latest::rdb::neighbor::BgpUnnumberedNeighborInfo;
use std::net::IpAddr;

// Each conversion below uses full-struct destructuring at the source
// boundary as a compile barrier: adding a field to a published or
// runtime type fails to bind here, forcing a deliberate decision about
// how (or whether) the new field threads through to the target type.
// Bindings prefixed with `_:` are intentionally dropped — that decision
// is documented at the destructure site.

impl std::fmt::Display for latest::bgp::config::NeighborResetRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "neighbor {} asn {} op {:?}",
            self.addr, self.asn, self.op
        )
    }
}

impl latest::bgp::config::NeighborSelector {
    /// Convert peer string to PeerId using FromStr implementation.
    /// Tries to parse as IP first, otherwise treats as interface name.
    pub fn to_peer_id(&self) -> latest::bgp::peer::PeerId {
        self.peer.parse().expect("PeerId::from_str never fails")
    }
}

impl latest::bgp::config::Neighbor {
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
            host: host.into(),
            group,
            parameters: latest_params_from_rdb(parameters),
        }
    }

    /// Construct a latest `Neighbor` from a latest `BgpPeerConfig`.
    pub fn from_bgp_peer_config(
        asn: u32,
        group: String,
        rq: latest::bgp::config::BgpPeerConfig,
    ) -> Self {
        let latest::bgp::config::BgpPeerConfig {
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

impl latest::bgp::config::UnnumberedNeighbor {
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
        rq: latest::bgp::config::UnnumberedBgpPeerConfig,
    ) -> Self {
        let latest::bgp::config::UnnumberedBgpPeerConfig {
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
) -> latest::bgp::config::BgpPeerParameters {
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

    latest::bgp::config::BgpPeerParameters {
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
            allow_import4.into(),
            allow_export4.into(),
        ),
        ipv6_unicast: ipv6_unicast_config_new(
            ipv6_enabled,
            nexthop6,
            allow_import6.into(),
            allow_export6.into(),
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
