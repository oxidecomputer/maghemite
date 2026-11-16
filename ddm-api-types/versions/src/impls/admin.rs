// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::latest::admin::{PrefixKind, UnderlayAddress};
use serde::{Deserialize, Deserializer};
use std::net::Ipv6Addr;

impl std::fmt::Display for PrefixKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Underlay => write!(f, "underlay"),
            Self::Bootstrap => write!(f, "bootstrap"),
        }
    }
}

impl std::str::FromStr for PrefixKind {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "underlay" => Ok(Self::Underlay),
            "bootstrap" => Ok(Self::Bootstrap),
            _ => Err(r#"Prefix kind must be "underlay" or "bootstrap""#),
        }
    }
}

impl UnderlayAddress {
    /// Returns an error unless `address` is a routable unicast address: not
    /// unspecified, loopback, multicast, or link-local.
    pub fn new(address: Ipv6Addr) -> Result<Self, &'static str> {
        if address.is_unspecified() {
            return Err("underlay address must not be unspecified");
        }
        if address.is_loopback() {
            return Err("underlay address must not be loopback");
        }
        if address.is_multicast() {
            return Err("underlay address must be unicast");
        }
        if address.is_unicast_link_local() {
            return Err("underlay address must not be link-local");
        }
        Ok(Self { address })
    }

    pub fn address(&self) -> Ipv6Addr {
        self.address
    }
}

impl<'de> Deserialize<'de> for UnderlayAddress {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Same wire shape as the derived JsonSchema, validated by `new`.
        #[derive(Deserialize)]
        struct Unchecked {
            address: Ipv6Addr,
        }
        let Unchecked { address } = Unchecked::deserialize(d)?;
        Self::new(address).map_err(serde::de::Error::custom)
    }
}
