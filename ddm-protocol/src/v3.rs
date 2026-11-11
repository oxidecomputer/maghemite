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
    /// This update without the announcements that have `router_id` in their
    /// path, because they have already gone through that router.
    pub fn break_loops(&self, router_id: &str) -> Self {
        // compilation barrier. a new route class must be checked here.
        let Self { underlay, tunnel } = self;
        Self {
            underlay: underlay.as_ref().map(|u| u.break_loops(router_id)),
            // Tunnel routes carry no path.
            tunnel: tunnel.clone(),
        }
    }

    /// The update that turns the routes we hold from a peer into the routes in
    /// its pull response `pr`: announce what is new and withdraw what is
    /// missing. A pull response is the peer's complete advertisement, not an
    /// incremental one.
    pub fn from_pull_response(
        pr: PullResponse,
        held_underlay: &HashSet<PathVector>,
        held_tunnel: &HashSet<TunnelOrigin>,
    ) -> Self {
        // An absent half means the peer advertises nothing of that kind, which
        // withdraws everything we hold from it.
        let pulled_underlay = pr.underlay.unwrap_or_default();
        let pulled_tunnel = pr.tunnel.unwrap_or_default();

        let underlay = UnderlayUpdate {
            announce: pulled_underlay
                .difference(held_underlay)
                .cloned()
                .collect(),
            withdraw: held_underlay
                .difference(&pulled_underlay)
                .cloned()
                .collect(),
        };
        let tunnel = TunnelUpdate {
            announce: pulled_tunnel.difference(held_tunnel).copied().collect(),
            withdraw: held_tunnel.difference(&pulled_tunnel).copied().collect(),
        };

        // Leave out halves with no changes, so that handle_update doesn't run
        // their handlers with empty sets.
        let mut update = Self::default();
        if !underlay.announce.is_empty() || !underlay.withdraw.is_empty() {
            update.underlay = Some(underlay);
        }
        if !tunnel.announce.is_empty() || !tunnel.withdraw.is_empty() {
            update.tunnel = Some(tunnel);
        }
        update
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
    pub fn break_loops(&self, hostname: &str) -> Self {
        Self {
            announce: self
                .announce
                .iter()
                .filter(|x| !x.path.iter().any(|h| h == hostname))
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

    fn path_vector(destination: &str, path: &[&str]) -> PathVector {
        PathVector {
            destination: destination.parse().unwrap(),
            path: path.iter().map(|x| x.to_string()).collect(),
        }
    }

    fn tunnel_origin(metric: u64) -> TunnelOrigin {
        TunnelOrigin {
            overlay_prefix: "0.0.0.0/0".parse().unwrap(),
            boundary_addr: "fd00:a::1".parse().unwrap(),
            vni: 99,
            metric,
        }
    }

    // https://github.com/oxidecomputer/maghemite/issues/993: routes we hold
    // from a peer that its pull response no longer carries must be withdrawn,
    // not kept.
    #[test]
    fn pull_response_withdraws_routes_missing_from_reply() {
        // We hold X and Y from the peer, and it now advertises Y and Z.
        let x = path_vector("fd00:1::/64", &["peer"]);
        let y = path_vector("fd00:2::/64", &["peer"]);
        let z = path_vector("fd00:3::/64", &["peer"]);
        // We hold a tunnel origin from the peer, and it now advertises none.
        let t = tunnel_origin(0);
        let pr = PullResponse {
            underlay: Some(HashSet::from([y.clone(), z.clone()])),
            tunnel: None,
        };

        let update = Update::from_pull_response(
            pr,
            &HashSet::from([x.clone(), y]),
            &HashSet::from([t]),
        );

        let underlay = update.underlay.expect("underlay changes");
        assert_eq!(underlay.announce, HashSet::from([z]));
        assert_eq!(underlay.withdraw, HashSet::from([x]));
        let tunnel = update.tunnel.expect("tunnel changes");
        assert_eq!(tunnel.announce, HashSet::new());
        assert_eq!(tunnel.withdraw, HashSet::from([t]));
    }

    // A route whose path or metric changed is a different route: the old one
    // is withdrawn and the new one announced, even though the destination or
    // overlay prefix is the same.
    #[test]
    fn pull_response_replaces_changed_routes() {
        let old_path = path_vector("fd00:1::/64", &["peer"]);
        let new_path = path_vector("fd00:1::/64", &["far", "peer"]);
        let old_metric = tunnel_origin(0);
        let new_metric = tunnel_origin(100);
        let pr = PullResponse {
            underlay: Some(HashSet::from([new_path.clone()])),
            tunnel: Some(HashSet::from([new_metric])),
        };

        let update = Update::from_pull_response(
            pr,
            &HashSet::from([old_path.clone()]),
            &HashSet::from([old_metric]),
        );

        let underlay = update.underlay.expect("underlay changes");
        assert_eq!(underlay.announce, HashSet::from([new_path]));
        assert_eq!(underlay.withdraw, HashSet::from([old_path]));
        let tunnel = update.tunnel.expect("tunnel changes");
        assert_eq!(tunnel.announce, HashSet::from([new_metric]));
        assert_eq!(tunnel.withdraw, HashSet::from([old_metric]));
    }

    // The peer's pull response has the same routes we already hold from it,
    // so nothing changed. The returned Update must have `underlay: None` and
    // `tunnel: None`, so that handle_update skips the underlay and tunnel
    // handlers instead of running them with empty sets.
    #[test]
    fn pull_response_without_changes_returns_empty_update() {
        let pv = path_vector("fd00:1::/64", &["peer"]);
        let t = tunnel_origin(100);
        let pr = PullResponse {
            underlay: Some(HashSet::from([pv.clone()])),
            tunnel: Some(HashSet::from([t])),
        };

        let update = Update::from_pull_response(
            pr,
            &HashSet::from([pv]),
            &HashSet::from([t]),
        );

        assert!(update.underlay.is_none());
        assert!(update.tunnel.is_none());
    }
}
