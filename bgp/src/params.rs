// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    config::PeerConfig,
    session::{SessionCounters, SessionInfo},
};
use rdb::{PolicyAction, Prefix4};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddrV6},
    sync::atomic::Ordering,
    time::Duration,
};

// ----- Versioned BGP-config families re-exported from mg-types-versions -----
//
// Migrated to mg-types-versions in RFD 619 Phase 2d sub-chunk 6a. These
// re-exports preserve the existing `bgp::params::*` public surface so
// internal Bgp callers don't have to change.
pub use mg_types_versions::v1::bgp::{
    ApplyRequest as ApplyRequestV1, BgpPeerConfig as BgpPeerConfigV1,
    BgpPeerParameters as BgpPeerParametersV1, CheckerSource,
    DynamicTimerInfo as DynamicTimerInfoV1, FsmStateKind as FsmStateKindV1,
    Neighbor as NeighborV1, NeighborResetOp as NeighborResetOpV1, Origin4,
    PeerInfo as PeerInfoV1, PeerTimers as PeerTimersV1, Router, ShaperSource,
};
pub use mg_types_versions::v2::bgp::{Origin6, PeerInfo as PeerInfoV2};
pub use mg_types_versions::v4::bgp::{
    AfiSafi, ApplyRequest as ApplyRequestV6, BgpCapability,
    BgpPeerConfig as BgpPeerConfigV6, BgpPeerParameters as BgpPeerParametersV6,
    DynamicTimerInfo, Ipv4UnicastConfig, Ipv6UnicastConfig, JitterRange,
    Neighbor as NeighborV6, NeighborResetOp, PeerCounters, StaticTimerInfo,
    UnnumberedBgpPeerConfig as UnnumberedBgpPeerConfigV6,
};
pub use mg_types_versions::v5::bgp::{
    PeerInfo, PeerTimers, UnnumberedNeighbor as UnnumberedNeighborV6,
};
pub use mg_types_versions::v8::bgp::{
    ApplyRequest, BgpPeerConfig, BgpPeerParameters, Neighbor,
    UnnumberedBgpPeerConfig, UnnumberedNeighbor,
};

/// Timer configuration extracted from SessionInfo.
/// This is a lightweight value type that can be cloned and passed without locks.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TimerConfig {
    pub connect_retry_time: Duration,
    pub keepalive_time: Duration,
    pub hold_time: Duration,
    pub idle_hold_time: Duration,
    pub delay_open_time: Duration,
    pub resolution: Duration,
    pub connect_retry_jitter: Option<JitterRange>,
    pub idle_hold_jitter: Option<JitterRange>,
}

impl TimerConfig {
    /// Extract timer config from SessionInfo without holding lock
    pub fn from_session_info(session: &SessionInfo) -> Self {
        Self {
            connect_retry_time: session.connect_retry_time,
            keepalive_time: session.keepalive_time,
            hold_time: session.hold_time,
            idle_hold_time: session.idle_hold_time,
            delay_open_time: session.delay_open_time,
            resolution: session.resolution,
            connect_retry_jitter: session.connect_retry_jitter,
            idle_hold_jitter: session.idle_hold_jitter,
        }
    }
}

// ----- PeerConfig boundary conversions -----
//
// `PeerConfig` is bgp-internal (non-published). Boundary conversions live
// here as inherent `From` impls since `PeerConfig` is local to bgp.

impl From<Neighbor> for PeerConfig {
    fn from(rq: Neighbor) -> Self {
        Self {
            name: rq.name.clone(),
            group: rq.group.clone(),
            host: rq.host,
            hold_time: rq.parameters.hold_time,
            idle_hold_time: rq.parameters.idle_hold_time,
            delay_open: rq.parameters.delay_open,
            connect_retry: rq.parameters.connect_retry,
            keepalive: rq.parameters.keepalive,
            resolution: rq.parameters.resolution,
        }
    }
}

impl From<NeighborV1> for PeerConfig {
    fn from(rq: NeighborV1) -> Self {
        Self {
            name: rq.name.clone(),
            group: rq.group.clone(),
            host: rq.host,
            hold_time: rq.parameters.hold_time,
            idle_hold_time: rq.parameters.idle_hold_time,
            delay_open: rq.parameters.delay_open,
            connect_retry: rq.parameters.connect_retry,
            keepalive: rq.parameters.keepalive,
            resolution: rq.parameters.resolution,
        }
    }
}

impl PeerConfig {
    /// Construct a `PeerConfig` from an `UnnumberedNeighbor` (uses the supplied
    /// IPv6 link-local socket address as the connection target).
    pub fn from_unnumbered_neighbor(
        n: &UnnumberedNeighbor,
        addr: SocketAddrV6,
    ) -> Self {
        Self {
            name: n.name.clone(),
            host: addr.into(),
            group: n.group.clone(),
            hold_time: n.parameters.hold_time,
            idle_hold_time: n.parameters.idle_hold_time,
            delay_open: n.parameters.delay_open,
            connect_retry: n.parameters.connect_retry,
            keepalive: n.parameters.keepalive,
            resolution: n.parameters.resolution,
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
    pub peers: BTreeMap<IpAddr, PeerInfoV2>,
    pub graceful_shutdown: bool,
}

impl From<&SessionCounters> for PeerCounters {
    fn from(value: &SessionCounters) -> Self {
        Self {
            connection_retries: value
                .connection_retries
                .load(Ordering::Relaxed),
            active_connections_accepted: value
                .active_connections_accepted
                .load(Ordering::Relaxed),
            active_connections_declined: value
                .active_connections_declined
                .load(Ordering::Relaxed),
            passive_connections_accepted: value
                .passive_connections_accepted
                .load(Ordering::Relaxed),
            passive_connections_declined: value
                .passive_connections_declined
                .load(Ordering::Relaxed),
            transitions_to_idle: value
                .transitions_to_idle
                .load(Ordering::Relaxed),
            transitions_to_connect: value
                .transitions_to_connect
                .load(Ordering::Relaxed),
            transitions_to_active: value
                .transitions_to_active
                .load(Ordering::Relaxed),
            transitions_to_open_sent: value
                .transitions_to_open_sent
                .load(Ordering::Relaxed),
            transitions_to_open_confirm: value
                .transitions_to_open_confirm
                .load(Ordering::Relaxed),
            transitions_to_connection_collision: value
                .transitions_to_connection_collision
                .load(Ordering::Relaxed),
            transitions_to_session_setup: value
                .transitions_to_session_setup
                .load(Ordering::Relaxed),
            transitions_to_established: value
                .transitions_to_established
                .load(Ordering::Relaxed),
            hold_timer_expirations: value
                .hold_timer_expirations
                .load(Ordering::Relaxed),
            idle_hold_timer_expirations: value
                .idle_hold_timer_expirations
                .load(Ordering::Relaxed),
            prefixes_advertised: value
                .prefixes_advertised
                .load(Ordering::Relaxed),
            prefixes_imported: value.prefixes_imported.load(Ordering::Relaxed),
            keepalives_sent: value.keepalives_sent.load(Ordering::Relaxed),
            keepalives_received: value
                .keepalives_received
                .load(Ordering::Relaxed),
            route_refresh_sent: value
                .route_refresh_sent
                .load(Ordering::Relaxed),
            route_refresh_received: value
                .route_refresh_received
                .load(Ordering::Relaxed),
            opens_sent: value.opens_sent.load(Ordering::Relaxed),
            opens_received: value.opens_received.load(Ordering::Relaxed),
            notifications_sent: value
                .notifications_sent
                .load(Ordering::Relaxed),
            notifications_received: value
                .notifications_received
                .load(Ordering::Relaxed),
            updates_sent: value.updates_sent.load(Ordering::Relaxed),
            updates_received: value.updates_received.load(Ordering::Relaxed),
            unexpected_update_message: value
                .unexpected_update_message
                .load(Ordering::Relaxed),
            unexpected_keepalive_message: value
                .unexpected_keepalive_message
                .load(Ordering::Relaxed),
            unexpected_open_message: value
                .unexpected_open_message
                .load(Ordering::Relaxed),
            unexpected_route_refresh_message: value
                .unexpected_route_refresh_message
                .load(Ordering::Relaxed),
            unexpected_notification_message: value
                .unexpected_notification_message
                .load(Ordering::Relaxed),
            update_nexhop_missing: value
                .update_nexhop_missing
                .load(Ordering::Relaxed),
            open_handle_failures: value
                .open_handle_failures
                .load(Ordering::Relaxed),
            unnegotiated_address_family: value
                .unnegotiated_address_family
                .load(Ordering::Relaxed),
            notification_send_failure: value
                .notification_send_failure
                .load(Ordering::Relaxed),
            open_send_failure: value.open_send_failure.load(Ordering::Relaxed),
            keepalive_send_failure: value
                .keepalive_send_failure
                .load(Ordering::Relaxed),
            route_refresh_send_failure: value
                .route_refresh_send_failure
                .load(Ordering::Relaxed),
            update_send_failure: value
                .update_send_failure
                .load(Ordering::Relaxed),
            tcp_connection_failure: value
                .tcp_connection_failure
                .load(Ordering::Relaxed),
            md5_auth_failures: value.md5_auth_failures.load(Ordering::Relaxed),
            connector_panics: value.connector_panics.load(Ordering::Relaxed),
        }
    }
}

pub enum PolicySource {
    Checker(String),
    Shaper(String),
}

pub enum PolicyKind {
    Checker,
    Shaper,
}
