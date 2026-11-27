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

/// Why an `Ipv6Addr` cannot be an [`UnderlayAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UnderlayAddressError {
    #[error("underlay address must not be unspecified")]
    UnspecifiedAddress,
    #[error("underlay address must not be loopback")]
    LoopbackAddress,
    #[error("underlay address must be unicast, not multicast {0}")]
    MulticastAddress(Ipv6Addr),
    #[error("underlay address must not be link-local {0}")]
    LinkLocalAddress(Ipv6Addr),
}

/// The underlay address of this router, used as the source address of the
/// underlay routes it installs.
///
/// Must be a routable unicast address: not unspecified, loopback, multicast,
/// or link-local.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(try_from = "Ipv6Addr", into = "Ipv6Addr")]
pub struct UnderlayAddress(Ipv6Addr);

impl UnderlayAddress {
    /// Returns an error unless `address` is a routable unicast address: not
    /// unspecified, loopback, multicast, or link-local.
    pub fn new(address: Ipv6Addr) -> Result<Self, UnderlayAddressError> {
        if address.is_unspecified() {
            return Err(UnderlayAddressError::UnspecifiedAddress);
        }
        if address.is_loopback() {
            return Err(UnderlayAddressError::LoopbackAddress);
        }
        if address.is_multicast() {
            return Err(UnderlayAddressError::MulticastAddress(address));
        }
        if address.is_unicast_link_local() {
            return Err(UnderlayAddressError::LinkLocalAddress(address));
        }
        Ok(Self(address))
    }

    pub fn address(&self) -> Ipv6Addr {
        self.0
    }
}

impl TryFrom<Ipv6Addr> for UnderlayAddress {
    type Error = UnderlayAddressError;
    fn try_from(address: Ipv6Addr) -> Result<Self, Self::Error> {
        Self::new(address)
    }
}

impl From<UnderlayAddress> for Ipv6Addr {
    fn from(address: UnderlayAddress) -> Self {
        address.0
    }
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
