// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v2;
use oxnet::Ipv6Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// IPv6 prefixes to originate from an ASN.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Origin6 {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Ipv6Net>,
}

// ---------------------------------------------------------------------------
// Upgrade conversion: v2 → v10
// ---------------------------------------------------------------------------

impl From<v2::bgp::history::Origin6> for Origin6 {
    fn from(old: v2::bgp::history::Origin6) -> Self {
        // v2 is frozen; compile barrier protects against upstream field additions.
        let v2::bgp::history::Origin6 { asn, prefixes } = old;
        Self {
            asn,
            prefixes: prefixes
                .into_iter()
                .map(|p| Ipv6Net::new_unchecked(p.value, p.length))
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Downgrade conversion: v10 → v2
// ---------------------------------------------------------------------------

impl From<Origin6> for v2::bgp::history::Origin6 {
    fn from(new: Origin6) -> Self {
        // v2 is frozen; compile barrier protects against upstream field additions.
        let Origin6 { asn, prefixes } = new;
        Self {
            asn,
            prefixes: prefixes
                .into_iter()
                .map(|n| crate::v1::rdb::prefix::Prefix6 {
                    value: n.addr(),
                    length: n.width(),
                })
                .collect(),
        }
    }
}
