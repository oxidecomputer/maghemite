// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::BGP_PORT;
use mg_api_types::bgp::config::{
    BgpPeerParameters, Neighbor, UnnumberedNeighbor,
};
use mg_api_types::bgp::peer::PeerId;
use mg_api_types_versions::v1;
use rdb::Asn;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct PeerConfig {
    pub name: String,
    pub group: String,
    pub id: PeerId,
    pub port: NonZeroU16,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct RouterConfig {
    pub asn: Asn,
    pub id: u32,
}

// ----- PeerConfig boundary conversions -----
//
// `PeerConfig` is bgp-internal (non-published) and tracks only the
// fields needed to drive the connection state machine — most
// BgpPeerParameters fields are session-level and don't belong here.
// Each conversion destructures both the outer Neighbor-shaped type
// and the embedded BgpPeerParameters so a field addition on either
// fails to bind here, forcing a deliberate decision about whether
// the new field belongs on PeerConfig. Bindings prefixed `_:` are
// intentionally dropped.

impl From<Neighbor> for PeerConfig {
    fn from(rq: Neighbor) -> Self {
        let Neighbor {
            asn: _,
            name,
            group,
            host,
            parameters,
        } = rq;
        let BgpPeerParameters {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive: _,
            remote_asn: _,
            min_ttl: _,
            md5_auth_key: _,
            multi_exit_discriminator: _,
            communities: _,
            local_pref: _,
            enforce_first_as: _,
            vlan_id: _,
            ipv4_unicast: _,
            ipv6_unicast: _,
            deterministic_collision_resolution: _,
            idle_hold_jitter: _,
            connect_retry_jitter: _,
            src_addr: _,
            src_port: _,
        } = parameters;
        Self {
            name,
            group,
            id: PeerId::Ip(host.ip()),
            port: NonZeroU16::new(host.port()).unwrap_or(BGP_PORT),
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
        }
    }
}

impl From<v1::bgp::config::Neighbor> for PeerConfig {
    fn from(rq: v1::bgp::config::Neighbor) -> Self {
        let v1::bgp::config::Neighbor {
            asn: _,
            name,
            group,
            host,
            parameters,
        } = rq;
        let v1::bgp::config::BgpPeerParameters {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive: _,
            remote_asn: _,
            min_ttl: _,
            md5_auth_key: _,
            multi_exit_discriminator: _,
            communities: _,
            local_pref: _,
            enforce_first_as: _,
            allow_import: _,
            allow_export: _,
            vlan_id: _,
        } = parameters;
        Self {
            name,
            group,
            id: PeerId::Ip(host.ip()),
            port: NonZeroU16::new(host.port()).unwrap_or(BGP_PORT),
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
        }
    }
}

impl PeerConfig {
    /// Construct a `PeerConfig` from an `UnnumberedNeighbor`. The peer is
    /// identified by its interface; the connection target is resolved via NDP
    /// at connect time, and the port is always the well-known BGP port.
    pub fn from_unnumbered_neighbor(n: &UnnumberedNeighbor) -> Self {
        let UnnumberedNeighbor {
            asn: _,
            name,
            group,
            interface,
            act_as_a_default_ipv6_router: _,
            parameters,
        } = n.clone();
        let BgpPeerParameters {
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
            passive: _,
            remote_asn: _,
            min_ttl: _,
            md5_auth_key: _,
            multi_exit_discriminator: _,
            communities: _,
            local_pref: _,
            enforce_first_as: _,
            vlan_id: _,
            ipv4_unicast: _,
            ipv6_unicast: _,
            deterministic_collision_resolution: _,
            idle_hold_jitter: _,
            connect_retry_jitter: _,
            src_addr: _,
            src_port: _,
        } = parameters;
        Self {
            name,
            group,
            id: PeerId::Interface(interface),
            port: BGP_PORT,
            hold_time,
            idle_hold_time,
            delay_open,
            connect_retry,
            keepalive,
            resolution,
        }
    }
}
