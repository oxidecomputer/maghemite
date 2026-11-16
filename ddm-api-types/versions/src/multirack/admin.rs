// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use oxnet::Ipv6Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::net::Ipv6Addr;

/// The prefix used to summarize the underlay space of a rack.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
pub struct RackPrefix {
    pub prefix: Ipv6Net,
}

/// The underlay address of this router, used as the source address of the
/// underlay routes it installs.
///
/// Must be a routable unicast address: not unspecified, loopback, multicast,
/// or link-local.
// Construct with `UnderlayAddress::new`, which deserializing also uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
pub struct UnderlayAddress {
    pub(crate) address: Ipv6Addr,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PrefixKind {
    Underlay,
    Bootstrap,
}

/// A prefix originated by this DDM router.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct OriginatedPrefix {
    pub kind: PrefixKind,
    pub prefix: Ipv6Net,
}

/// A prefix learned from a DDM peer.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct LearnedPrefix {
    pub kind: PrefixKind,
    pub prefix: Ipv6Net,

    /// The Path that this prefix took through the network.
    /// Each element is a DDM Router ID.
    pub path: Vec<String>,
}

/// A map of prefixes, keyed by addrobj_name.
pub type PrefixMap = BTreeMap<String, HashSet<LearnedPrefix>>;
