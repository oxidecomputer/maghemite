// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::error::Error;
use anyhow::Result;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::Display;
use std::fmt::{self, Formatter};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq)]
pub struct Path {
    pub nexthop: IpAddr,
    pub shutdown: bool,
    pub rib_priority: u8,
    pub bgp: Option<BgpPathProperties>,
    pub vlan_id: Option<u16>,
}

// Define a basic ordering on paths so bestpath selection is deterministic
impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Path {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.nexthop != other.nexthop {
            return self.nexthop.cmp(&other.nexthop);
        }
        if self.shutdown != other.shutdown {
            return self.shutdown.cmp(&other.shutdown);
        }
        if self.rib_priority != other.rib_priority {
            return self.rib_priority.cmp(&other.rib_priority);
        }
        self.bgp.cmp(&other.bgp)
    }
}

impl From<StaticRouteKey> for Path {
    fn from(value: StaticRouteKey) -> Self {
        Self {
            nexthop: value.nexthop,
            vlan_id: value.vlan_id,
            rib_priority: value.rib_priority,
            shutdown: false,
            bgp: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Eq, PartialEq)]
pub struct BgpPathProperties {
    pub origin_as: u32,
    pub id: u32,
    pub peer: IpAddr,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub as_path: Vec<u32>,
    pub stale: Option<DateTime<Utc>>,
}

impl BgpPathProperties {
    pub fn as_stale(&self) -> Self {
        let mut s = self.clone();
        s.stale = Some(Utc::now());
        s
    }
}

impl PartialOrd for BgpPathProperties {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for BgpPathProperties {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.origin_as != other.origin_as {
            return self.origin_as.cmp(&other.origin_as);
        }
        if self.id != other.id {
            return self.id.cmp(&other.id);
        }
        // MED should *not* be used as a basis for comparison. Paths with
        // distinct MED values are not distinct paths.
        if self.as_path != other.as_path {
            return self.as_path.cmp(&other.as_path);
        }
        self.stale.cmp(&other.stale)
    }
}

#[derive(
    Copy, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Debug,
)]
pub struct StaticRouteKey {
    pub prefix: Prefix,
    pub nexthop: IpAddr,
    pub vlan_id: Option<u16>,
    pub rib_priority: u8,
}

#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Route4Key {
    pub prefix: Prefix4,
    pub nexthop: Ipv4Addr,
}

impl Display for Route4Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.nexthop, self.prefix)
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

impl Display for Route4MetricKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.route, self.metric,)
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

impl Display for Policy4Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.peer, self.prefix, self.tag,)
    }
}

impl Policy4Key {
    pub fn db_key(&self) -> Vec<u8> {
        self.to_string().as_bytes().into()
    }
}

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Eq, PartialEq, JsonSchema,
)]
pub struct Prefix4 {
    pub value: Ipv4Addr,
    pub length: u8,
}

impl PartialOrd for Prefix4 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Prefix4 {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.value != other.value {
            return self.value.cmp(&other.value);
        }
        self.length.cmp(&other.length)
    }
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

impl PartialOrd for Prefix6 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Prefix6 {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.value != other.value {
            return self.value.cmp(&other.value);
        }
        self.length.cmp(&other.length)
    }
}

impl fmt::Display for Prefix6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.value, self.length)
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    JsonSchema,
    PartialOrd,
    Ord,
)]
pub enum Prefix {
    V4(Prefix4),
    V6(Prefix6),
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Prefix::V4(p) => p.fmt(f),
            Prefix::V6(p) => p.fmt(f),
        }
    }
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

#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct BgpRouterInfo {
    pub id: u32,
    pub listen: String,
    pub graceful_shutdown: bool,
}

#[derive(
    Default, Debug, Serialize, Deserialize, Clone, JsonSchema, Eq, PartialEq,
)]
pub enum ImportExportPolicy {
    #[default]
    NoFiltering,
    Allow(BTreeSet<Prefix>),
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
    pub md5_auth_key: Option<String>,
    pub multi_exit_discriminator: Option<u32>,
    pub communities: Vec<u32>,
    pub local_pref: Option<u32>,
    pub enforce_first_as: bool,
    pub allow_import: ImportExportPolicy,
    pub allow_export: ImportExportPolicy,
    pub vlan_id: Option<u16>,
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

#[derive(Clone, Default, Debug)]
pub struct PrefixChangeNotification {
    pub changed: BTreeSet<Prefix>,
}

impl From<Prefix> for PrefixChangeNotification {
    fn from(value: Prefix) -> Self {
        Self {
            changed: BTreeSet::from([value]),
        }
    }
}

impl From<Prefix4> for PrefixChangeNotification {
    fn from(value: Prefix4) -> Self {
        Self {
            changed: BTreeSet::from([value.into()]),
        }
    }
}

impl From<Prefix6> for PrefixChangeNotification {
    fn from(value: Prefix6) -> Self {
        Self {
            changed: BTreeSet::from([value.into()]),
        }
    }
}

#[derive(Clone, Copy, Eq, Debug, Ord, PartialEq, PartialOrd)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
    All,
}
