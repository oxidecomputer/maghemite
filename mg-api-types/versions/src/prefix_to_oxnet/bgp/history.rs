// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v2;
use oxnet::Ipv6Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Origin6 {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Ipv6Net>,
}

impl From<v2::bgp::history::Origin6> for Origin6 {
    fn from(old: v2::bgp::history::Origin6) -> Self {
        // v2 is frozen; compile barrier protects against upstream field additions.
        let v2::bgp::history::Origin6 { asn, prefixes } = old;
        Self {
            asn,
            prefixes: prefixes.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<Origin6> for v2::bgp::history::Origin6 {
    fn from(new: Origin6) -> Self {
        // v2 is frozen; compile barrier protects against upstream field additions.
        let Origin6 { asn, prefixes } = new;
        Self {
            asn,
            prefixes: prefixes.into_iter().map(Into::into).collect(),
        }
    }
}
