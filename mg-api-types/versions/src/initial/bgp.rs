// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bgp_types_versions::v1::session::MessageHistory as MessageHistoryV1;
use rdb_types_versions::v1::policy::ImportExportPolicy;
use rdb_types_versions::v1::prefix::Prefix4;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AsnSelector {
    /// ASN of the router to get imported prefixes from.
    pub asn: u32,
}

/// V1 API NeighborSelector (numbered peers only).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NeighborSelector {
    pub asn: u32,
    pub addr: IpAddr,
}

/// V1 API neighbor reset operations (backwards compatibility)
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[schemars(rename = "NeighborResetOp")]
pub enum NeighborResetOp {
    Hard,
    SoftInbound,
    SoftOutbound,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NeighborResetRequest {
    pub asn: u32,
    pub addr: IpAddr,
    pub op: NeighborResetOp,
}

#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct MessageHistoryRequest {
    /// ASN of the BGP router
    pub asn: u32,
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponse {
    pub by_peer: HashMap<IpAddr, MessageHistoryV1>,
}

/// Legacy neighbor configuration (v1/v2 API compatibility)
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[schemars(rename = "Neighbor")]
pub struct Neighbor {
    pub asn: u32,
    pub name: String,
    pub group: String,
    pub host: SocketAddr,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

/// Apply changes to an ASN (v1/v2 API - legacy format).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[schemars(rename = "ApplyRequest")]
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

/// BGP peer configuration for v1/v2 API (legacy format with combined import/export).
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[schemars(rename = "BgpPeerConfig")]
pub struct BgpPeerConfig {
    pub host: SocketAddr,
    pub name: String,
    #[serde(flatten)]
    pub parameters: BgpPeerParameters,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[schemars(rename = "BgpPeerParameters")]
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
    pub md5_auth_key: Option<String>,
    pub multi_exit_discriminator: Option<u32>,
    pub communities: Vec<u32>,
    pub local_pref: Option<u32>,
    pub enforce_first_as: bool,
    pub allow_import: ImportExportPolicy,
    pub allow_export: ImportExportPolicy,
    pub vlan_id: Option<u16>,
}

// CheckerSource / ShaperSource appear in v1+ as fields of ApplyRequest. They
// are forced into v1 by the ApplyRequest field walk; full unversioned-but-
// published treatment lands with sub-chunk 6c.
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

// ============================================================================
// API Compatibility Types (VERSION_INITIAL / v1.0.0)
// ============================================================================
// These types maintain backward compatibility with the INITIAL API version.
// FsmStateKind here lacks the ConnectionCollision state added in
// VERSION_IPV6_BASIC. Used exclusively for API responses via
// /bgp/status/neighbors endpoint (v1). Never used internally - always convert
// from current types at API boundary.
//
// Delete these types when VERSION_INITIAL is retired.

/// Simplified representation of a BGP state without having to carry a
/// connection. This does not include the ConnectionCollision state for
/// backwards comptability with the initial release of the versioned dropshot
/// API.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, JsonSchema,
)]
#[schemars(rename = "FsmStateKind")]
pub enum FsmStateKind {
    /// Initial state. Refuse all incomming BGP connections. No resources
    /// allocated to peer.
    Idle,

    /// Waiting for the TCP connection to be completed.
    Connect,

    /// Trying to acquire peer by listening for and accepting a TCP connection.
    Active,

    /// Waiting for open message from peer.
    OpenSent,

    /// Waiting for keepalive or notification from peer.
    OpenConfirm,

    /// Sync up with peers.
    SessionSetup,

    /// Able to exchange update, notification and keepliave messages with peers.
    Established,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[schemars(rename = "DynamicTimerInfo")]
pub struct DynamicTimerInfo {
    pub configured: Duration,
    pub negotiated: Duration,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[schemars(rename = "PeerTimers")]
pub struct PeerTimers {
    pub hold: DynamicTimerInfo,
    pub keepalive: DynamicTimerInfo,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[schemars(rename = "PeerInfo")]
pub struct PeerInfo {
    pub state: FsmStateKind,
    pub asn: Option<u32>,
    pub duration_millis: u64,
    pub timers: PeerTimers,
}

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

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Origin4 {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}
