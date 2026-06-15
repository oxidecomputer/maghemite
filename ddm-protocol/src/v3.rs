// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ALL TYPES IN THIS FILE ARE FOR DDM PROTOCOL VERSION 3. THEY SHALL NEVER
//! CHANGE. THESE TYPES CAN BE REMOVED WHEN DDMV3 CLIENTS AND SERVERS NO LONGER
//! EXIST BUT THEIR DEFINITIONS SHALL NEVER CHANGE.

use std::{collections::HashSet, net::Ipv6Addr};

use oxnet::{IpNet, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct Update {
    pub underlay: Option<UnderlayUpdate>,
    pub tunnel: Option<TunnelUpdate>,
}

impl Update {
    /// Build an `Update` whose underlay/tunnel halves carry the announcements
    /// from the [`PullResponse`] `pr`. Used by [`pull`] to project a pull
    /// response back into the update event stream.
    pub fn announce(pr: PullResponse) -> Self {
        Self {
            underlay: pr.underlay.map(UnderlayUpdate::announce),
            tunnel: pr.tunnel.map(TunnelUpdate::announce),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct PullResponse {
    pub underlay: Option<HashSet<PathVector>>,
    pub tunnel: Option<HashSet<TunnelOrigin>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct UnderlayUpdate {
    pub announce: HashSet<PathVector>,
    pub withdraw: HashSet<PathVector>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct TunnelUpdate {
    pub announce: HashSet<TunnelOrigin>,
    pub withdraw: HashSet<TunnelOrigin>,
}

impl TunnelUpdate {
    pub fn announce(prefixes: HashSet<TunnelOrigin>) -> Self {
        Self {
            announce: prefixes,
            ..Default::default()
        }
    }
    pub fn withdraw(prefixes: HashSet<TunnelOrigin>) -> Self {
        Self {
            withdraw: prefixes,
            ..Default::default()
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct PathVector {
    pub destination: Ipv6Net,
    pub path: Vec<String>,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelOrigin {
    pub overlay_prefix: IpNet,
    pub boundary_addr: Ipv6Addr,
    pub vni: u32,
    #[serde(default)]
    pub metric: u64,
}

impl UnderlayUpdate {
    pub fn announce(prefixes: HashSet<PathVector>) -> Self {
        Self {
            announce: prefixes,
            ..Default::default()
        }
    }
    pub fn withdraw(prefixes: HashSet<PathVector>) -> Self {
        Self {
            withdraw: prefixes,
            ..Default::default()
        }
    }
    pub fn with_path_element(&self, element: String) -> Self {
        Self {
            announce: self
                .announce
                .iter()
                .map(|x| {
                    let mut pv = x.clone();
                    pv.path.push(element.clone());
                    pv
                })
                .collect(),
            withdraw: self
                .withdraw
                .iter()
                .map(|x| {
                    let mut pv = x.clone();
                    pv.path.push(element.clone());
                    pv
                })
                .collect(),
        }
    }
}

impl From<UnderlayUpdate> for Update {
    fn from(u: UnderlayUpdate) -> Self {
        Update {
            underlay: Some(u),
            tunnel: None,
        }
    }
}

impl From<TunnelUpdate> for Update {
    fn from(t: TunnelUpdate) -> Self {
        Update {
            underlay: None,
            tunnel: Some(t),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Write out the JSON schema for the DDMv3 protocol to a file for
    // validation. This should not change.
    #[test]
    fn test_ddm_v3_protocol() {
        #[derive(JsonSchema)]
        #[allow(dead_code)]
        struct Protocol {
            update: Update,
            pull_response: PullResponse,
        }

        let schema = schemars::schema_for!(Protocol);
        expectorate::assert_contents(
            "tests/output/ddm_v3_protocol.json",
            &serde_json::to_string_pretty(&schema).unwrap(),
        );
    }
}
