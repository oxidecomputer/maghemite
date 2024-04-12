// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use crate::error::Error;

#[derive(
    Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq, JsonSchema,
)]
pub struct Path {
    pub nexthop: IpAddr,
    pub bgp_id: u32,
    pub shutdown: bool,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub as_path: Vec<u32>,
}

impl Path {
    pub fn for_static(nexthop: IpAddr) -> Self {
        Self {
            nexthop,
            bgp_id: 0,
            shutdown: false,
            med: None,
            local_pref: None,
            as_path: Vec::new(),
        }
    }
}

#[derive(
    Copy, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Debug,
)]
pub struct StaticRouteKey {
    pub prefix: Prefix,
    pub nexthop: IpAddr,
}

#[derive(
    Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize, JsonSchema,
)]
pub struct Route4Key {
    pub prefix: Prefix4,
    pub nexthop: Ipv4Addr,
}

impl ToString for Route4Key {
    fn to_string(&self) -> String {
        format!("{}/{}", self.nexthop, self.prefix)
    }
}

impl FromStr for Route4Key {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (nexthop, prefix) =
            s.split_once('/').ok_or("malformed route key".to_string())?;

        Ok(Self {
            prefix: prefix.parse()?,
            nexthop: nexthop
                .parse()
                .map_err(|_| "malformed ip addr".to_string())?,
        })
    }
}

impl Route4Key {
    pub fn db_key(&self) -> Vec<u8> {
        self.to_string().as_bytes().into()
    }
}

pub struct Route4MetricKey {
    pub route: Route4Key,
    pub metric: String,
}

impl ToString for Route4MetricKey {
    fn to_string(&self) -> String {
        format!("{}/{}", self.route.to_string(), self.metric,)
    }
}

impl Route4MetricKey {
    pub fn db_key(&self) -> Vec<u8> {
        self.to_string().as_bytes().into()
    }
}

pub struct Policy4Key {
    pub peer: String,
    pub prefix: Prefix4,
    pub tag: String,
}

impl ToString for Policy4Key {
    fn to_string(&self) -> String {
        format!("{}/{}/{}", self.peer, self.prefix, self.tag,)
    }
}

impl Policy4Key {
    pub fn db_key(&self) -> Vec<u8> {
        self.to_string().as_bytes().into()
    }
}

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Hash, Eq, PartialEq, JsonSchema,
)]
pub struct Prefix4 {
    pub value: Ipv4Addr,
    pub length: u8,
}

impl Prefix4 {
    pub fn db_key(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = self.value.octets().into();
        buf.push(self.length);
        buf
    }

    pub fn from_db_key(v: &[u8]) -> Result<Self, Error> {
        if v.len() < 5 {
            Err(Error::DbKey(format!(
                "buffer to short for prefix 4 key {} < 5",
                v.len()
            )))
        } else {
            Ok(Prefix4 {
                value: Ipv4Addr::new(v[0], v[1], v[2], v[3]),
                length: v[4],
            })
        }
    }
}

impl fmt::Display for Prefix4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.value, self.length)
    }
}

impl FromStr for Prefix4 {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (value, length) =
            s.split_once('/').ok_or("malformed route key".to_string())?;

        Ok(Self {
            value: value
                .parse()
                .map_err(|_| "malformed ip addr".to_string())?,
            length: length
                .parse()
                .map_err(|_| "malformed length".to_string())?,
        })
    }
}

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Hash, Eq, PartialEq, JsonSchema,
)]
pub struct Prefix6 {
    pub value: Ipv6Addr,
    pub length: u8,
}

impl fmt::Display for Prefix6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.value, self.length)
    }
}

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Hash, Eq, PartialEq, JsonSchema,
)]
pub enum Prefix {
    V4(Prefix4),
    V6(Prefix6),
}

impl From<Prefix4> for Prefix {
    fn from(value: Prefix4) -> Self {
        Self::V4(value)
    }
}

impl From<Prefix6> for Prefix {
    fn from(value: Prefix6) -> Self {
        Self::V6(value)
    }
}

#[derive(Serialize, Deserialize)]
pub struct BgpAttributes4 {
    pub origin: Ipv4Addr,
    pub path: Vec<Asn>,
}

#[derive(Serialize, Deserialize)]
pub struct BgpAttributes6 {
    pub origin: Ipv4Addr,
    pub path: Vec<Asn>,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Asn {
    TwoOctet(u16),
    FourOctet(u32),
}

impl std::fmt::Display for Asn {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        match self {
            Asn::TwoOctet(asn) => write!(f, "{}", asn),
            Asn::FourOctet(asn) => write!(f, "{}", asn),
        }
    }
}

impl From<u32> for Asn {
    fn from(value: u32) -> Asn {
        Asn::FourOctet(value)
    }
}

impl From<u16> for Asn {
    fn from(value: u16) -> Asn {
        Asn::TwoOctet(value)
    }
}

impl Asn {
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::TwoOctet(value) => u32::from(*value),
            Self::FourOctet(value) => *value,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum Status {
    Up,
    Down,
}

pub fn to_buf<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(&value, &mut buf)?;
    Ok(buf)
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone, JsonSchema)]
pub enum PolicyAction {
    Allow,
    Deny,
}

impl FromStr for PolicyAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" | "Allow" => Ok(Self::Allow),
            "deny" | "Deny" => Ok(Self::Allow),
            _ => Err("Unknown policy action, must be allow or deny".into()),
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct Policy {
    pub action: PolicyAction,
    pub priority: u16,
}

#[derive(Clone, Default, Debug)]
pub struct OriginChangeSet {
    pub added: HashSet<Prefix4>,
    pub removed: HashSet<Prefix4>,
}

impl OriginChangeSet {
    pub fn added<V: Into<HashSet<Prefix4>>>(v: V) -> Self {
        Self {
            added: v.into(),
            ..Default::default()
        }
    }
    pub fn removed<V: Into<HashSet<Prefix4>>>(v: V) -> Self {
        Self {
            removed: v.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct BgpRouterInfo {
    pub id: u32,
    pub listen: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct BgpNeighborInfo {
    pub asn: u32,
    pub name: String,
    pub host: SocketAddr,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub group: String,
    pub passive: bool,
    pub remote_asn: Option<u32>,
    pub min_ttl: Option<u8>,
    pub md5_auth_key: Option<Md5Key>,
    pub multi_exit_discriminator: Option<u32>,
    pub communities: Vec<u32>,
    pub local_pref: Option<u32>,
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub struct BfdPeerConfig {
    /// Address of the peer to add.
    pub peer: IpAddr,
    /// Address to listen on for control messages from the peer.
    pub listen: IpAddr,
    /// Acceptable time between control messages in microseconds.
    pub required_rx: u64,
    /// Detection threshold for connectivity as a multipler to required_rx
    pub detection_threshold: u8,
    /// Mode is single-hop (RFC 5881) or multi-hop (RFC 5883).
    pub mode: SessionMode,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub enum SessionMode {
    SingleHop,
    MultiHop,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Md5Key {
    pub value: Vec<u8>,
}

#[derive(Clone, Default, Debug)]
pub struct PrefixChangeNotification {
    pub changed: HashSet<Prefix>,
}

impl From<Prefix> for PrefixChangeNotification {
    fn from(value: Prefix) -> Self {
        Self {
            changed: HashSet::from([value]),
        }
    }
}

impl From<Prefix4> for PrefixChangeNotification {
    fn from(value: Prefix4) -> Self {
        Self {
            changed: HashSet::from([value.into()]),
        }
    }
}

impl From<Prefix6> for PrefixChangeNotification {
    fn from(value: Prefix6) -> Self {
        Self {
            changed: HashSet::from([value.into()]),
        }
    }
}
