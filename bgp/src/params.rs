// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::config::PeerConfig;
use crate::session::FsmStateKindV2;
use rdb::{ImportExportPolicy, PolicyAction, Prefix4, Prefix6};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Router {
    /// Autonomous system number for this router
    pub asn: u32,

    /// Id for this router
    pub id: u32,

    /// Listening address <addr>:<port>
    pub listen: String,

    /// Gracefully shut this router down.
    pub graceful_shutdown: bool,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub enum NeighborResetOp {
    Hard,
    SoftInbound,
    SoftOutbound,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
pub struct Neighbor {
    pub asn: u32,
    pub name: String,
    pub host: SocketAddr,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub group: String,
    pub passive: bool,
    pub remote_asn: Option<u32>,
    pub min_ttl: Option<u8>,
    pub md5_auth_key: Option<String>,
    pub multi_exit_discriminator: Option<u32>,
    pub communities: Vec<u32>,
    pub local_pref: Option<u32>,
    pub enforce_first_as: bool,
    pub allow_import: ImportExportPolicy,
    pub allow_export: ImportExportPolicy,
    pub vlan_id: Option<u16>,
}

impl From<Neighbor> for PeerConfig {
    fn from(rq: Neighbor) -> Self {
        Self {
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
        }
    }
}

impl Neighbor {
    pub fn from_bgp_peer_config(
        asn: u32,
        group: String,
        rq: BgpPeerConfig,
    ) -> Self {
        Self {
            asn,
            remote_asn: rq.remote_asn,
            min_ttl: rq.min_ttl,
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
            passive: rq.passive,
            group: group.clone(),
            md5_auth_key: rq.md5_auth_key,
            multi_exit_discriminator: rq.multi_exit_discriminator,
            communities: rq.communities,
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            allow_import: rq.allow_import,
            allow_export: rq.allow_export,
            vlan_id: rq.vlan_id,
        }
    }

    pub fn from_rdb_neighbor_info(asn: u32, rq: &rdb::BgpNeighborInfo) -> Self {
        Self {
            asn,
            remote_asn: rq.remote_asn,
            min_ttl: rq.min_ttl,
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
            passive: rq.passive,
            group: rq.group.clone(),
            md5_auth_key: rq.md5_auth_key.clone(),
            multi_exit_discriminator: rq.multi_exit_discriminator,
            communities: rq.communities.clone(),
            local_pref: rq.local_pref,
            enforce_first_as: rq.enforce_first_as,
            allow_import: rq.allow_import.clone(),
            allow_export: rq.allow_export.clone(),
            vlan_id: rq.vlan_id,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddExportPolicyRequest {
    /// ASN of the router to apply the export policy to.
    pub asn: u32,

    /// Address of the peer to apply this policy to.
    pub addr: IpAddr,

    /// Prefix this policy applies to.
    pub prefix: Prefix4,

    /// Priority of the policy, higher value is higher priority.
    pub priority: u16,

    /// The policy action to apply.
    pub action: PolicyAction,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Origin4 {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Origin6 {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix6>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Withdraw4Request {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GracefulShutdownRequest {
    /// ASN of the router to gracefully shut down.
    pub asn: u32,
    /// Set whether or not graceful shutdown is initiated from this router.
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetOriginated4Request {
    /// ASN of the router to get originated prefixes from.
    pub asn: u32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetRoutersRequest {}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetRouersResponse {
    pub router: Vec<RouterInfo>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RouterInfo {
    pub asn: u32,
    pub peers: BTreeMap<IpAddr, PeerInfoV1>,
    pub graceful_shutdown: bool,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DynamicTimerInfo {
    pub configured: Duration,
    pub negotiated: Duration,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PeerTimers {
    pub hold: DynamicTimerInfo,
    pub keepalive: DynamicTimerInfo,
}

/// Simplified representation of a BGP state without having to carry a
/// connection. This does not include the ConnectionCollision state for
/// backwards comptability with the initial release of the versioned dropshot
/// API.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema,
)]
pub enum FsmStateKindV1 {
    /// Initial state. Refuse all incomming BGP connections. No resources
    /// allocated to peer.
    Idle,

    /// Waiting for the TCP connection to be completed.
    Connect,

    /// Trying to acquire peer by listening for and accepting a TCP connection.
    Active,

    /// Waiting for open message from peer.
    OpenSent,

    /// Waiting for keepaliave or notification from peer.
    OpenConfirm,

    /// Sync up with peers.
    SessionSetup,

    /// Able to exchange update, notification and keepliave messages with peers.
    Established,
}

impl From<FsmStateKindV2> for FsmStateKindV1 {
    fn from(kind: FsmStateKindV2) -> Self {
        match kind {
            FsmStateKindV2::Idle => FsmStateKindV1::Idle,
            FsmStateKindV2::Connect => FsmStateKindV1::Connect,
            FsmStateKindV2::Active => FsmStateKindV1::Active,
            FsmStateKindV2::OpenSent => FsmStateKindV1::OpenSent,
            FsmStateKindV2::OpenConfirm => FsmStateKindV1::OpenConfirm,
            // We convert ConnectionCollision to OpenSent, because one
            // connection is always in OpenSent for the duration of
            // the colliison (unless we've already transitioned out of
            // ConnectionCollision), so this is technically correct, even if
            // it's only correct from the perspective of just one connection.
            FsmStateKindV2::ConnectionCollision => FsmStateKindV1::OpenSent,
            FsmStateKindV2::SessionSetup => FsmStateKindV1::SessionSetup,
            FsmStateKindV2::Established => FsmStateKindV1::Established,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PeerInfoV1 {
    pub state: FsmStateKindV1,
    pub asn: Option<u32>,
    pub duration_millis: u64,
    pub timers: PeerTimers,
}

impl From<PeerInfoV2> for PeerInfoV1 {
    fn from(info: PeerInfoV2) -> Self {
        Self {
            state: FsmStateKindV1::from(info.state),
            asn: info.asn,
            duration_millis: info.duration_millis,
            timers: info.timers,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PeerInfoV2 {
    pub state: FsmStateKindV2,
    pub asn: Option<u32>,
    pub duration_millis: u64,
    pub timers: PeerTimers,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct CheckerSource {
    pub asn: u32,
    pub code: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct ShaperSource {
    pub asn: u32,
    pub code: String,
}

/// Apply changes to an ASN.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct ApplyRequest {
    /// ASN to apply changes to.
    pub asn: u32,
    /// Complete set of prefixes to originate. Any active prefixes not in this
    /// list will be removed. All prefixes in this list are ensured to be in
    /// the originating set.
    pub originate: Vec<Prefix4>,

    /// Checker rhai code to apply to ingress open and update messages.
    pub checker: Option<CheckerSource>,

    /// Checker rhai code to apply to egress open and update messages.
    pub shaper: Option<ShaperSource>,

    /// Lists of peers indexed by peer group. Set's within a peer group key are
    /// a total set. For example, the value
    ///
    /// ```text
    /// {"foo": [a, b, d]}
    /// ```
    /// Means that the peer group "foo" only contains the peers `a`, `b` and
    /// `d`. If there is a peer `c` currently in the peer group "foo", it will
    /// be removed.
    pub peers: HashMap<String, Vec<BgpPeerConfig>>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct BgpPeerConfig {
    pub host: SocketAddr,
    pub name: String,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64, //Create then read only
    pub passive: bool,
    pub remote_asn: Option<u32>,
    pub min_ttl: Option<u8>,
    pub md5_auth_key: Option<String>,
    pub multi_exit_discriminator: Option<u32>,
    pub communities: Vec<u32>,
    pub local_pref: Option<u32>,
    pub enforce_first_as: bool,
    pub allow_import: ImportExportPolicy,
    pub allow_export: ImportExportPolicy,
    pub vlan_id: Option<u16>,
}

pub enum PolicySource {
    Checker(String),
    Shaper(String),
}

pub enum PolicyKind {
    Checker,
    Shaper,
}
