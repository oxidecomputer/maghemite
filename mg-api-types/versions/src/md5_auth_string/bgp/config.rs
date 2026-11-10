// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{v1, v4, v14};
use oxnet::{IpNet, Md5AuthString, Md5AuthStringError, SocketAddrJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct BgpPeerParameters {
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub passive: bool,
    pub remote_asn: Option<u32>,
    pub min_ttl: Option<u8>,
    pub md5_auth_key: Option<Md5AuthString>,
    pub multi_exit_discriminator: Option<u32>,
    pub communities: Vec<u32>,
    pub local_pref: Option<u32>,
    pub enforce_first_as: bool,
    pub vlan_id: Option<u16>,
    /// IPv4 Unicast address family configuration (None = disabled)
    pub ipv4_unicast: Option<v14::bgp::config::Ipv4UnicastConfig>,
    /// IPv6 Unicast address family configuration (None = disabled)
    pub ipv6_unicast: Option<v14::bgp::config::Ipv6UnicastConfig>,
    /// Enable deterministic collision resolution in Established state.
    /// When true, uses BGP-ID comparison per RFC 4271 §6.8 for collision
    /// resolution even when one connection is already in Established state.
    /// When false, Established connection always wins (timing-based resolution).
    pub deterministic_collision_resolution: bool,
    /// Jitter range for idle hold timer. When used, the idle hold timer is
    /// multiplied by a random value within the (min, max) range supplied.
    /// Useful to help break repeated synchronization of connection collisions.
    pub idle_hold_jitter: Option<v4::bgp::config::JitterRange>,
    /// Jitter range for connect_retry timer. When used, the connect_retry timer
    /// is multiplied by a random value within the (min, max) range supplied.
    /// Useful to help break repeated synchronization of connection collisions.
    pub connect_retry_jitter: Option<v4::bgp::config::JitterRange>,
    /// Source IP address to bind when establishing outbound TCP connections.
    /// None means the system selects the source address.
    pub src_addr: Option<IpAddr>,
    /// Source TCP port to bind when establishing outbound TCP connections.
    /// None means the system selects the source port.
    pub src_port: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct BgpPeerConfig {
    pub host: SocketAddrJson,
    pub name: String,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct UnnumberedBgpPeerConfig {
    pub interface: String,
    pub name: String,
    pub router_lifetime: u16,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

/// Neighbor configuration with explicit per-address-family enablement (v3 API)
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct Neighbor {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub host: SocketAddrJson,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct UnnumberedNeighbor {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub interface: String,
    pub act_as_a_default_ipv6_router: u16,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

/// Apply changes to an ASN (current version with per-AF policies).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct ApplyRequest {
    /// ASN to apply changes to.
    pub asn: u32,
    /// Complete set of prefixes to originate.
    pub originate: Vec<IpNet>,
    /// Checker rhai code to apply to ingress open and update messages.
    pub checker: Option<v1::bgp::config::CheckerSource>,
    /// Checker rhai code to apply to egress open and update messages.
    pub shaper: Option<v1::bgp::config::ShaperSource>,
    /// Lists of peers indexed by peer group.
    pub peers: HashMap<String, Vec<BgpPeerConfig>>,
    /// Lists of unnumbered peers indexed by peer group.
    #[serde(default)]
    pub unnumbered_peers: HashMap<String, Vec<UnnumberedBgpPeerConfig>>,
}

fn md5_auth_key_from_v14(
    key: Option<String>,
) -> Result<Option<Md5AuthString>, Md5AuthStringError> {
    key.map(Md5AuthString::new).transpose()
}

fn md5_auth_key_to_v14(key: Option<Md5AuthString>) -> Option<String> {
    key.map(String::from)
}

impl TryFrom<v14::bgp::config::BgpPeerParameters> for BgpPeerParameters {
    type Error = Md5AuthStringError;

    fn try_from(
        old: v14::bgp::config::BgpPeerParameters,
    ) -> Result<Self, Self::Error> {
        let v14::bgp::config::BgpPeerParameters {
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
            src_addr,
            src_port,
        } = old;

        Ok(Self {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive,
            remote_asn,
            min_ttl,
            md5_auth_key: md5_auth_key_from_v14(md5_auth_key)?,
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
            src_addr,
            src_port,
        })
    }
}

impl From<BgpPeerParameters> for v14::bgp::config::BgpPeerParameters {
    fn from(new: BgpPeerParameters) -> Self {
        let BgpPeerParameters {
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
            src_addr,
            src_port,
        } = new;

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
            md5_auth_key: md5_auth_key_to_v14(md5_auth_key),
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
            src_addr,
            src_port,
        }
    }
}

impl TryFrom<v14::bgp::config::BgpPeerConfig> for BgpPeerConfig {
    type Error = Md5AuthStringError;

    fn try_from(
        old: v14::bgp::config::BgpPeerConfig,
    ) -> Result<Self, Self::Error> {
        let v14::bgp::config::BgpPeerConfig {
            host,
            name,
            parameters,
        } = old;
        Ok(Self {
            host,
            name,
            parameters: parameters.try_into()?,
        })
    }
}

impl From<BgpPeerConfig> for v14::bgp::config::BgpPeerConfig {
    fn from(new: BgpPeerConfig) -> Self {
        let BgpPeerConfig {
            host,
            name,
            parameters,
        } = new;
        Self {
            host,
            name,
            parameters: parameters.into(),
        }
    }
}

impl TryFrom<v14::bgp::config::UnnumberedBgpPeerConfig>
    for UnnumberedBgpPeerConfig
{
    type Error = Md5AuthStringError;

    fn try_from(
        old: v14::bgp::config::UnnumberedBgpPeerConfig,
    ) -> Result<Self, Self::Error> {
        let v14::bgp::config::UnnumberedBgpPeerConfig {
            interface,
            name,
            router_lifetime,
            parameters,
        } = old;
        Ok(Self {
            interface,
            name,
            router_lifetime,
            parameters: parameters.try_into()?,
        })
    }
}

impl From<UnnumberedBgpPeerConfig>
    for v14::bgp::config::UnnumberedBgpPeerConfig
{
    fn from(new: UnnumberedBgpPeerConfig) -> Self {
        let UnnumberedBgpPeerConfig {
            interface,
            name,
            router_lifetime,
            parameters,
        } = new;
        Self {
            interface,
            name,
            router_lifetime,
            parameters: parameters.into(),
        }
    }
}

impl TryFrom<v14::bgp::config::Neighbor> for Neighbor {
    type Error = Md5AuthStringError;

    fn try_from(old: v14::bgp::config::Neighbor) -> Result<Self, Self::Error> {
        let v14::bgp::config::Neighbor {
            asn,
            name,
            group,
            host,
            parameters,
        } = old;
        Ok(Self {
            asn,
            name,
            group,
            host,
            parameters: parameters.try_into()?,
        })
    }
}

impl From<Neighbor> for v14::bgp::config::Neighbor {
    fn from(new: Neighbor) -> Self {
        let Neighbor {
            asn,
            name,
            group,
            host,
            parameters,
        } = new;
        Self {
            asn,
            name,
            group,
            host,
            parameters: parameters.into(),
        }
    }
}

impl TryFrom<v14::bgp::config::UnnumberedNeighbor> for UnnumberedNeighbor {
    type Error = Md5AuthStringError;

    fn try_from(
        old: v14::bgp::config::UnnumberedNeighbor,
    ) -> Result<Self, Self::Error> {
        let v14::bgp::config::UnnumberedNeighbor {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters,
        } = old;
        Ok(Self {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters: parameters.try_into()?,
        })
    }
}

impl From<UnnumberedNeighbor> for v14::bgp::config::UnnumberedNeighbor {
    fn from(new: UnnumberedNeighbor) -> Self {
        let UnnumberedNeighbor {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters,
        } = new;
        Self {
            asn,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router,
            parameters: parameters.into(),
        }
    }
}

impl TryFrom<v14::bgp::config::ApplyRequest> for ApplyRequest {
    type Error = Md5AuthStringError;

    fn try_from(
        old: v14::bgp::config::ApplyRequest,
    ) -> Result<Self, Self::Error> {
        let v14::bgp::config::ApplyRequest {
            asn,
            originate,
            checker,
            shaper,
            peers,
            unnumbered_peers,
        } = old;
        Ok(Self {
            asn,
            originate,
            checker,
            shaper,
            peers: peers
                .into_iter()
                .map(|(group, peers)| {
                    Ok((
                        group,
                        peers
                            .into_iter()
                            .map(BgpPeerConfig::try_from)
                            .collect::<Result<Vec<_>, _>>()?,
                    ))
                })
                .collect::<Result<HashMap<_, _>, Md5AuthStringError>>()?,
            unnumbered_peers: unnumbered_peers
                .into_iter()
                .map(|(group, peers)| {
                    Ok((
                        group,
                        peers
                            .into_iter()
                            .map(UnnumberedBgpPeerConfig::try_from)
                            .collect::<Result<Vec<_>, _>>()?,
                    ))
                })
                .collect::<Result<HashMap<_, _>, Md5AuthStringError>>()?,
        })
    }
}

impl From<ApplyRequest> for v14::bgp::config::ApplyRequest {
    fn from(new: ApplyRequest) -> Self {
        let ApplyRequest {
            asn,
            originate,
            checker,
            shaper,
            peers,
            unnumbered_peers,
        } = new;
        Self {
            asn,
            originate,
            checker,
            shaper,
            peers: peers
                .into_iter()
                .map(|(group, peers)| {
                    (group, peers.into_iter().map(Into::into).collect())
                })
                .collect(),
            unnumbered_peers: unnumbered_peers
                .into_iter()
                .map(|(group, peers)| {
                    (group, peers.into_iter().map(Into::into).collect())
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v14_parameters(
        md5_auth_key: impl Into<String>,
    ) -> v14::bgp::config::BgpPeerParameters {
        let mut parameters: v14::bgp::config::BgpPeerParameters =
            BgpPeerParameters::default().into();
        parameters.md5_auth_key = Some(md5_auth_key.into());
        parameters
    }

    #[test]
    fn v14_neighbor_conversions_round_trip() {
        let numbered = v14::bgp::config::Neighbor {
            asn: 64512,
            name: "numbered".into(),
            group: "test".into(),
            host: "192.0.2.1:179"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
            parameters: v14_parameters("numbered secret"),
        };
        let unnumbered = v14::bgp::config::UnnumberedNeighbor {
            asn: 64512,
            name: "unnumbered".into(),
            group: "test".into(),
            interface: "tfportqsfp0_0".into(),
            act_as_a_default_ipv6_router: 1800,
            parameters: v14_parameters("unnumbered secret"),
        };

        let numbered_round_trip = v14::bgp::config::Neighbor::from(
            Neighbor::try_from(numbered.clone()).unwrap(),
        );
        let unnumbered_round_trip = v14::bgp::config::UnnumberedNeighbor::from(
            UnnumberedNeighbor::try_from(unnumbered.clone()).unwrap(),
        );

        assert_eq!(numbered_round_trip, numbered);
        assert_eq!(unnumbered_round_trip, unnumbered);
    }

    #[test]
    fn v14_apply_request_conversion_preserves_peer_maps() {
        let request = v14::bgp::config::ApplyRequest {
            asn: 64512,
            originate: vec!["192.0.2.0/24".parse().unwrap()],
            checker: None,
            shaper: None,
            peers: HashMap::from([(
                "numbered".into(),
                vec![v14::bgp::config::BgpPeerConfig {
                    host: "192.0.2.1:179"
                        .parse::<std::net::SocketAddr>()
                        .unwrap()
                        .into(),
                    name: "numbered".into(),
                    parameters: v14_parameters("numbered secret"),
                }],
            )]),
            unnumbered_peers: HashMap::from([(
                "unnumbered".into(),
                vec![v14::bgp::config::UnnumberedBgpPeerConfig {
                    interface: "tfportqsfp0_0".into(),
                    name: "unnumbered".into(),
                    router_lifetime: 1800,
                    parameters: v14_parameters("unnumbered secret"),
                }],
            )]),
        };
        let expected = serde_json::to_value(&request).unwrap();

        let round_trip = v14::bgp::config::ApplyRequest::from(
            ApplyRequest::try_from(request).unwrap(),
        );

        assert_eq!(serde_json::to_value(round_trip).unwrap(), expected);
    }

    #[test]
    fn v14_conversion_rejects_invalid_md5_auth_key() {
        assert_eq!(
            BgpPeerParameters::try_from(v14_parameters("")),
            Err(Md5AuthStringError::Empty),
        );
    }
}
