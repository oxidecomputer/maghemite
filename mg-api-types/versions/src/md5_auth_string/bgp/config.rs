// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{v1, v4, v8, v11};
use oxnet::{IpNet, SocketAddrJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Clone, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct Md5AuthString(String);

impl Md5AuthString {
    // max length in bytes
    const MAX_LEN: usize = 80;

    pub fn new(source: String) -> Result<Self, Md5AuthStringError> {
        if source.is_empty() {
            return Err(Md5AuthStringError::Empty);
        }

        if source.len() > Self::MAX_LEN {
            return Err(Md5AuthStringError::TooLong { len: source.len() });
        }

        if !source.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            return Err(Md5AuthStringError::NotPrintableAscii);
        }

        Ok(Self(source))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<String> for Md5AuthString {
    type Error = Md5AuthStringError;

    fn try_from(source: String) -> Result<Self, Self::Error> {
        Self::new(source)
    }
}

impl From<Md5AuthString> for String {
    fn from(source: Md5AuthString) -> Self {
        source.into_inner()
    }
}

impl std::fmt::Debug for Md5AuthString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Md5AuthString(<redacted>)")
    }
}

impl std::error::Error for Md5AuthStringError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Md5AuthStringError {
    Empty,
    TooLong { len: usize },
    NotPrintableAscii,
}

impl std::fmt::Display for Md5AuthStringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Md5AuthStringError::Empty => {
                write!(f, "MD5 auth string must not be empty")
            }
            Md5AuthStringError::TooLong { len } => {
                write!(
                    f,
                    "MD5 auth string length must be <= {}, found {len}",
                    Md5AuthString::MAX_LEN
                )
            }
            Md5AuthStringError::NotPrintableAscii => write!(
                f,
                "MD5 auth string must be fully comprised of printable ASCII characters"
            ),
        }
    }
}

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
    pub ipv4_unicast: Option<v11::bgp::config::Ipv4UnicastConfig>,
    /// IPv6 Unicast address family configuration (None = disabled)
    pub ipv6_unicast: Option<v11::bgp::config::Ipv6UnicastConfig>,
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

fn md5_auth_key_from_v11(
    key: Option<String>,
) -> Result<Option<Md5AuthString>, Md5AuthStringError> {
    key.map(Md5AuthString::new).transpose()
}

fn md5_auth_key_to_v11(key: Option<Md5AuthString>) -> Option<String> {
    key.map(String::from)
}

impl TryFrom<v11::bgp::config::BgpPeerParameters> for BgpPeerParameters {
    type Error = Md5AuthStringError;

    fn try_from(
        old: v11::bgp::config::BgpPeerParameters,
    ) -> Result<Self, Self::Error> {
        let v11::bgp::config::BgpPeerParameters {
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
            md5_auth_key: md5_auth_key_from_v11(md5_auth_key)?,
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

impl From<BgpPeerParameters> for v11::bgp::config::BgpPeerParameters {
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
            md5_auth_key: md5_auth_key_to_v11(md5_auth_key),
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

impl TryFrom<v11::bgp::config::BgpPeerConfig> for BgpPeerConfig {
    type Error = Md5AuthStringError;

    fn try_from(
        old: v11::bgp::config::BgpPeerConfig,
    ) -> Result<Self, Self::Error> {
        let v11::bgp::config::BgpPeerConfig {
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

impl From<BgpPeerConfig> for v11::bgp::config::BgpPeerConfig {
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

impl TryFrom<v11::bgp::config::UnnumberedBgpPeerConfig>
    for UnnumberedBgpPeerConfig
{
    type Error = Md5AuthStringError;

    fn try_from(
        old: v11::bgp::config::UnnumberedBgpPeerConfig,
    ) -> Result<Self, Self::Error> {
        let v11::bgp::config::UnnumberedBgpPeerConfig {
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
    for v11::bgp::config::UnnumberedBgpPeerConfig
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

impl TryFrom<v11::bgp::config::Neighbor> for Neighbor {
    type Error = Md5AuthStringError;

    fn try_from(old: v11::bgp::config::Neighbor) -> Result<Self, Self::Error> {
        let v11::bgp::config::Neighbor {
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

impl From<Neighbor> for v11::bgp::config::Neighbor {
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

impl TryFrom<v11::bgp::config::UnnumberedNeighbor> for UnnumberedNeighbor {
    type Error = Md5AuthStringError;

    fn try_from(
        old: v11::bgp::config::UnnumberedNeighbor,
    ) -> Result<Self, Self::Error> {
        let v11::bgp::config::UnnumberedNeighbor {
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

impl From<UnnumberedNeighbor> for v11::bgp::config::UnnumberedNeighbor {
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

impl TryFrom<v11::bgp::config::ApplyRequest> for ApplyRequest {
    type Error = Md5AuthStringError;

    fn try_from(
        old: v11::bgp::config::ApplyRequest,
    ) -> Result<Self, Self::Error> {
        let v11::bgp::config::ApplyRequest {
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

impl TryFrom<v8::bgp::config::ApplyRequest> for ApplyRequest {
    type Error = Md5AuthStringError;

    fn try_from(
        old: v8::bgp::config::ApplyRequest,
    ) -> Result<Self, Self::Error> {
        Self::try_from(v11::bgp::config::ApplyRequest::from(old))
    }
}

impl From<ApplyRequest> for v11::bgp::config::ApplyRequest {
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
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn is_valid_md5_auth_string(source: &str) -> bool {
        !source.is_empty()
            && source.len() <= Md5AuthString::MAX_LEN
            && source.chars().all(|c| c.is_ascii_graphic() || c == ' ')
    }

    fn printable_ascii_string(
        len: impl Into<proptest::collection::SizeRange>,
    ) -> impl Strategy<Value = String> {
        proptest::collection::vec(0x20_u8..=0x7e, len)
            .prop_map(|bytes| String::from_utf8(bytes).unwrap())
    }

    fn invalid_md5_auth_string() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(String::new()),
            printable_ascii_string(Md5AuthString::MAX_LEN + 1..=128),
            any::<String>()
                .prop_filter("must violate Md5AuthString invariants", |s| {
                    !is_valid_md5_auth_string(s)
                }),
        ]
    }

    proptest! {
        #[test]
        fn constructor_accepts_exactly_nonempty_printable_ascii_up_to_80_bytes(
            source in printable_ascii_string(1..=Md5AuthString::MAX_LEN),
        ) {
            let key = Md5AuthString::new(source.clone())?;

            prop_assert_eq!(key.as_str(), source.as_str());
            prop_assert_eq!(key.as_bytes(), source.as_bytes());
            prop_assert_eq!(String::from(key), source);
        }

        #[test]
        fn constructor_rejects_all_other_strings(
            source in invalid_md5_auth_string(),
        ) {
            prop_assert!(Md5AuthString::new(source).is_err());
        }

        #[test]
        fn serde_round_trip_matches_constructor_invariants(
            source in any::<String>(),
        ) {
            let json = serde_json::to_string(&source).unwrap();
            let deserialized = serde_json::from_str::<Md5AuthString>(&json);

            if is_valid_md5_auth_string(&source) {
                let key = deserialized?;
                prop_assert_eq!(key.as_str(), source.as_str());

                let serialized = serde_json::to_string(&key).unwrap();
                prop_assert_eq!(serialized, json);
            } else {
                prop_assert!(deserialized.is_err());
            }
        }

        #[test]
        fn valid_md5_auth_string_json_round_trips(
            source in printable_ascii_string(1..=Md5AuthString::MAX_LEN),
        ) {
            let json = serde_json::to_string(&source).unwrap();
            let key: Md5AuthString = serde_json::from_str(&json)?;
            let serialized = serde_json::to_string(&key).unwrap();

            prop_assert_eq!(key.as_str(), source.as_str());
            prop_assert_eq!(serialized, json);
        }
    }

    #[test]
    fn debug_redacts_inner_string() {
        let key = Md5AuthString::new("super secret".to_string()).unwrap();

        assert_eq!(format!("{key:?}"), "Md5AuthString(<redacted>)");
    }
}
