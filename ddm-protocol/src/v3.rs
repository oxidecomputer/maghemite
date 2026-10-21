// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ALL TYPES IN THIS FILE ARE FOR DDM PROTOCOL VERSION 3. THEY SHALL NEVER
//! CHANGE. THESE TYPES CAN BE REMOVED WHEN DDMV3 CLIENTS AND SERVERS NO LONGER
//! EXIST BUT THEIR DEFINITIONS SHALL NEVER CHANGE.

use std::{collections::HashSet, net::Ipv6Addr};

use oxnet::{IpNet, Ipv6Net, SocketAddrV6Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct Update {
    pub underlay: Option<UnderlayUpdate>,
    pub tunnel: Option<TunnelUpdate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rack: Option<RackUpdate>,
}

impl Update {
    /// Build an `Update` whose underlay/tunnel/rack parts carry the
    /// announcements from `pr`. Used by [`pull`] to project a pull response
    /// back into the update event stream.
    pub fn announce(pr: PullResponse) -> Self {
        Self {
            underlay: pr.underlay.map(UnderlayUpdate::announce),
            tunnel: pr.tunnel.map(TunnelUpdate::announce),
            rack: pr.rack.map(RackUpdate::announce),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct PullResponse {
    pub underlay: Option<HashSet<PathVector>>,
    pub tunnel: Option<HashSet<TunnelOrigin>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rack: Option<HashSet<RackPrefix>>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct RackPrefix {
    pub path_vector: PathVector,
    pub multi_rack_join_addr: Option<SocketAddrV6Json>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct RackUpdate {
    pub announce: HashSet<RackPrefix>,
    pub withdraw: HashSet<RackPrefix>,
}

impl RackUpdate {
    pub fn announce(prefixes: HashSet<RackPrefix>) -> Self {
        Self {
            announce: prefixes,
            ..Default::default()
        }
    }
    pub fn withdraw(prefixes: HashSet<RackPrefix>) -> Self {
        Self {
            withdraw: prefixes,
            ..Default::default()
        }
    }
    /// See [`UnderlayUpdate::with_path_element`].
    pub fn with_path_element(&self, element: String) -> Self {
        let push = |x: &RackPrefix| {
            let mut rp = x.clone();
            rp.path_vector.path.push(element.clone());
            rp
        };
        Self {
            announce: self.announce.iter().map(push).collect(),
            withdraw: self.withdraw.iter().map(push).collect(),
        }
    }
    /// See [`UnderlayUpdate::break_loops`].
    pub fn break_loops(&self, hostname: &String) -> Self {
        Self {
            announce: self
                .announce
                .iter()
                .filter(|x| !x.path_vector.path.contains(hostname))
                .cloned()
                .collect(),
            withdraw: self.withdraw.clone(),
        }
    }
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
    pub fn break_loops(&self, hostname: &String) -> Self {
        Self {
            announce: self
                .announce
                .iter()
                .filter(|x| !x.path.contains(hostname))
                .cloned()
                .collect(),
            withdraw: self.withdraw.clone(),
        }
    }
}

impl From<UnderlayUpdate> for Update {
    fn from(u: UnderlayUpdate) -> Self {
        Update {
            underlay: Some(u),
            ..Default::default()
        }
    }
}

impl From<TunnelUpdate> for Update {
    fn from(t: TunnelUpdate) -> Self {
        Update {
            tunnel: Some(t),
            ..Default::default()
        }
    }
}

impl From<RackUpdate> for Update {
    fn from(r: RackUpdate) -> Self {
        Update {
            rack: Some(r),
            ..Default::default()
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
