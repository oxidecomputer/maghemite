// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! MRIB (Multicast Routing Information Base) API types.

use std::net::IpAddr;

use mg_common::net::UnderlayMulticastIpv6;
use rdb::types::{AddressFamily, MulticastRouteKey, Vni};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Input for adding static multicast routes.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct StaticMulticastRouteInput {
    /// The multicast route key (S,G) or (*,G).
    pub key: MulticastRouteKey,
    /// Underlay multicast group address (ff04::/64).
    pub underlay_group: UnderlayMulticastIpv6,
}

/// Request body for adding static multicast routes to the MRIB.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MribAddStaticRequest {
    /// List of static multicast routes to add.
    pub routes: Vec<StaticMulticastRouteInput>,
}

/// Request body for deleting static multicast routes from the MRIB.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MribDeleteStaticRequest {
    /// List of route keys to delete.
    pub keys: Vec<MulticastRouteKey>,
}

/// Response containing the current RPF rebuild interval.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MribRpfRebuildIntervalResponse {
    /// Minimum interval between RPF cache rebuilds in milliseconds.
    /// A value of 0 means rate-limiting is disabled.
    pub interval_ms: u64,
}

/// Request body for setting the RPF rebuild interval.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MribRpfRebuildIntervalRequest {
    /// Minimum interval between RPF cache rebuilds in milliseconds.
    /// A value of 0 disables rate-limiting.
    /// Every unicast RIB change triggers an immediate poptrie rebuild.
    pub interval_ms: u64,
}

/// Filter for multicast route origin.
#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
pub enum RouteOriginFilter {
    /// Static routes only (operator configured).
    Static,
    /// Dynamic routes only (learned via IGMP, MLD, etc.).
    Dynamic,
}

/// Query parameters for MRIB routes.
///
/// When `group` is provided, looks up a specific route.
/// When `group` is omitted, lists all routes (with optional filters).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MribQuery {
    /// Multicast group address. If provided, returns a specific route.
    /// If omitted, returns all routes matching the filters.
    #[serde(default)]
    pub group: Option<IpAddr>,
    /// Source address (`None` for (*,G) routes). Only used when `group`
    /// is set.
    #[serde(default)]
    pub source: Option<IpAddr>,
    /// VNI (defaults to 77 for fleet-scoped multicast). Only used when
    /// `group` is set.
    #[serde(default = "default_multicast_vni")]
    pub vni: Vni,
    /// Filter by address family. Only used when listing all routes.
    #[serde(default)]
    pub address_family: Option<AddressFamily>,
    /// Filter by route origin ("static" or "dynamic").
    /// Only used when listing all routes.
    #[serde(default)]
    pub route_origin: Option<RouteOriginFilter>,
}

fn default_multicast_vni() -> Vni {
    Vni::DEFAULT_MULTICAST_VNI
}
