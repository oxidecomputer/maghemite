// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{v11, v14};
use oxnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::num::NonZeroU8;

/// The id of a router.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(transparent)]
pub struct RouterId(pub uuid::Uuid);

/// Name, id and tunnel endpoint (TEP) address of a router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RouterInfo {
    pub id: RouterId,
    pub name: String,
    /// Tunnel endpoint address of the router.
    pub tep: Ipv6Addr,
}

/// BGP configuration of a router.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BgpSpec {
    /// Autonomous system number for this router.
    pub asn: u32,
    /// Complete set of prefixes to originate.
    pub originate: Vec<IpNet>,
    /// Checker rhai code to apply to ingress open and update messages.
    pub checker: Option<String>,
    /// Shaper rhai code to apply to egress open and update messages.
    pub shaper: Option<String>,
    /// Lists of peers indexed by peer group.
    #[serde(default)]
    pub peers: HashMap<String, Vec<v14::bgp::config::BgpPeerConfig>>,
    /// Lists of unnumbered peers indexed by peer group.
    #[serde(default)]
    pub unnumbered_peers:
        HashMap<String, Vec<v14::bgp::config::UnnumberedBgpPeerConfig>>,
    /// Maximum number of equal-cost paths per destination. Defaults to 1.
    #[serde(default)]
    pub max_paths: Option<NonZeroU8>,
}

/// The complete configuration of a router.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RouterSpec {
    pub name: String,
    pub id: RouterId,
    /// BGP configuration. The router runs no BGP when absent.
    pub bgp: Option<BgpSpec>,
    /// Complete set of IPv4 static routes.
    #[serde(default)]
    pub static4: Vec<v11::static_routes::StaticRoute4>,
    /// Complete set of IPv6 static routes.
    #[serde(default)]
    pub static6: Vec<v11::static_routes::StaticRoute6>,
    /// Complete set of BFD peers.
    #[serde(default)]
    pub bfd_peers: Vec<v14::bfd::BfdPeerConfig>,
}

/// The complete list of routers. A router that is not in the list is removed.
/// The default router is never removed. When it is not in the list, its
/// configuration is emptied.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApplyRoutersRequest {
    pub routers: Vec<RouterSpec>,
}

/// The routers that were not applied. Every other router in the request was.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ApplyRoutersResponse {
    pub not_applied: Vec<RouterNotApplied>,
}

/// A router that was not applied, and why.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct RouterNotApplied {
    pub id: RouterId,
    pub name: String,
    pub reason: String,
}

/// Selects a router in path parameters.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RouterSelector {
    /// Id of the router, or its name if the value does not parse as an id.
    pub router: String,
}
