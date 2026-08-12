// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Named router instances and the multi-router reconciler request.

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::net::Ipv6Addr;

use oxnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;
use crate::v11;
use crate::v12;

/// Identifier for a named router instance. Scopes all of the router's
/// persistent state and is handed down to the platform layer
/// (OPTE/dendrite) together with the router's TEP address.
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

impl RouterId {
    pub fn new_random() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Display for RouterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A named router instance (VRF-like). BGP configuration, static routes and
/// BFD peers all attach to a router, and each router has its own RIB and its
/// own tunnel endpoint (TEP) address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RouterInfo {
    pub id: RouterId,
    pub name: String,
    /// Tunnel endpoint address for this router's RIB. Advertised to ddmd as
    /// the boundary address for prefixes selected into this router's loc-RIB.
    pub tep: Ipv6Addr,
}

/// BGP configuration for one router in a [`RouterSpec`]. Combines the
/// router-level settings (ASN, BGP id, listen address) with the declarative
/// peer/origination set from `ApplyRequest`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BgpSpec {
    /// Autonomous system number for this router.
    pub asn: u32,
    /// BGP id for this router.
    pub id: u32,
    /// Listening address `<addr>:<port>`.
    pub listen: String,
    /// Complete set of prefixes to originate.
    pub originate: Vec<IpNet>,
    /// Checker rhai code to apply to ingress open and update messages.
    pub checker: Option<v1::bgp::config::CheckerSource>,
    /// Shaper rhai code to apply to egress open and update messages.
    pub shaper: Option<v1::bgp::config::ShaperSource>,
    /// Lists of peers indexed by peer group.
    #[serde(default)]
    pub peers: HashMap<String, Vec<v11::bgp::config::BgpPeerConfig>>,
    /// Lists of unnumbered peers indexed by peer group.
    #[serde(default)]
    pub unnumbered_peers:
        HashMap<String, Vec<v11::bgp::config::UnnumberedBgpPeerConfig>>,
}

/// Full desired state for one named router.
///
/// The router's TEP address is not part of the spec: the daemon generates a
/// random ULA when the router is created and persists it (observable via
/// [`RouterInfo`]). Consumers key on the router id, which rides with the
/// TEP in ddm tunnel advertisements.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RouterSpec {
    pub name: String,
    pub id: RouterId,
    /// BGP configuration (None = no BGP for this router).
    pub bgp: Option<BgpSpec>,
    /// Complete set of IPv4 static routes.
    #[serde(default)]
    pub static4: Vec<v11::static_routes::StaticRoute4>,
    /// Complete set of IPv6 static routes.
    #[serde(default)]
    pub static6: Vec<v11::static_routes::StaticRoute6>,
    /// Complete set of BFD peers.
    #[serde(default)]
    pub bfd_peers: Vec<v12::bfd::BfdPeerConfig>,
}

/// The multi-router reconciler request: the complete desired router list.
/// Routers absent from the list are torn down; present ones are created or
/// updated in place.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MultiRouterApplyRequest {
    pub routers: Vec<RouterSpec>,
}

/// Selects a named router in path parameters.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RouterSelector {
    /// Name of the router.
    pub router: String,
}
