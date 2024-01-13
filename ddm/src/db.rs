// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::{JsonSchema, JsonSchema_repr};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::{HashMap, HashSet};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Default, Clone)]
pub struct Db {
    data: Arc<Mutex<DbData>>,
}

#[derive(Default, Clone)]
pub struct DbData {
    pub peers: HashMap<u32, PeerInfo>,
    pub imported: HashSet<Route>,
    pub originated: HashSet<Ipv6Prefix>,
    pub imported_tunnel: HashSet<TunnelRoute>,
    pub originated_tunnel: HashSet<TunnelOrigin>,
}

unsafe impl Sync for Db {}
unsafe impl Send for Db {}

impl Db {
    pub fn dump(&self) -> DbData {
        self.data.lock().unwrap().clone()
    }

    pub fn peers(&self) -> HashMap<u32, PeerInfo> {
        self.data.lock().unwrap().peers.clone()
    }

    pub fn imported(&self) -> HashSet<Route> {
        self.data.lock().unwrap().imported.clone()
    }

    pub fn imported_tunnel(&self) -> HashSet<TunnelRoute> {
        self.data.lock().unwrap().imported_tunnel.clone()
    }

    pub fn import(&self, r: &HashSet<Route>) {
        self.data.lock().unwrap().imported.extend(r.clone());
    }

    pub fn import_tunnel(&self, r: &HashSet<TunnelRoute>) {
        self.data.lock().unwrap().imported_tunnel.extend(r.clone());
    }

    pub fn delete_import(&self, r: &HashSet<Route>) {
        let imported = &mut self.data.lock().unwrap().imported;
        for x in r {
            imported.remove(x);
        }
    }

    pub fn delete_import_tunnel(&self, r: &HashSet<TunnelRoute>) {
        let imported = &mut self.data.lock().unwrap().imported_tunnel;
        for x in r {
            imported.remove(x);
        }
    }

    pub fn originate(&self, p: &HashSet<Ipv6Prefix>) {
        self.data.lock().unwrap().originated.extend(p);
    }

    pub fn originate_tunnel(&self, p: &HashSet<TunnelOrigin>) {
        self.data
            .lock()
            .unwrap()
            .originated_tunnel
            .extend(p.clone());
    }

    pub fn originated(&self) -> HashSet<Ipv6Prefix> {
        self.data.lock().unwrap().originated.clone()
    }

    pub fn originated_tunnel(&self) -> HashSet<TunnelOrigin> {
        self.data.lock().unwrap().originated_tunnel.clone()
    }

    pub fn withdraw(&self, p: &HashSet<Ipv6Prefix>) {
        for prefix in p {
            self.data.lock().unwrap().originated.remove(prefix);
        }
    }

    pub fn withdraw_tunnel(&self, p: &HashSet<TunnelOrigin>) {
        for prefix in p {
            self.data.lock().unwrap().originated_tunnel.remove(prefix);
        }
    }

    /// Set peer info at the given index. Returns true if peer information was
    /// changed.
    pub fn set_peer(&self, index: u32, info: PeerInfo) -> bool {
        match self.data.lock().unwrap().peers.insert(index, info.clone()) {
            Some(previous) => previous == info,
            None => true,
        }
    }

    pub fn remove_nexthop_routes(
        &self,
        nexthop: Ipv6Addr,
    ) -> (HashSet<Route>, HashSet<TunnelRoute>) {
        let mut data = self.data.lock().unwrap();
        // Routes are generally held in sets to prevent duplication and provide
        // handy set-algebra operations.
        let mut removed = HashSet::new();
        for x in &data.imported {
            if x.nexthop == nexthop {
                removed.insert(x.clone());
            }
        }
        for x in &removed {
            data.imported.remove(x);
        }

        let mut tnl_removed = HashSet::new();
        for x in &data.imported_tunnel {
            if x.nexthop == nexthop {
                tnl_removed.insert(x.clone());
            }
        }
        for x in &tnl_removed {
            data.imported_tunnel.remove(x);
        }
        (removed, tnl_removed)
    }

    pub fn remove_peer(&self, index: u32) {
        self.data.lock().unwrap().peers.remove(&index);
    }

    pub fn routes_by_vector(
        &self,
        dst: Ipv6Prefix,
        nexthop: Ipv6Addr,
    ) -> Vec<Route> {
        let data = self.data.lock().unwrap();
        let mut result = Vec::new();
        for x in &data.imported {
            if x.destination == dst && x.nexthop == nexthop {
                result.push(x.clone());
            }
        }
        result
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema,
)]
pub enum PeerStatus {
    NoContact,
    Active,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PeerInfo {
    pub status: PeerStatus,
    pub addr: Ipv6Addr,
    pub host: String,
    pub kind: RouterKind,
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Serialize_repr,
    Deserialize_repr,
    JsonSchema_repr,
)]
#[repr(u8)]
pub enum RouterKind {
    Server,
    Transit,
}

impl std::fmt::Display for RouterKind {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> Result<(), std::fmt::Error> {
        match self {
            Self::Server => write!(f, "server"),
            Self::Transit => write!(f, "transit"),
        }
    }
}

impl std::str::FromStr for RouterKind {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "server" => Ok(Self::Server),
            "transit" => Ok(Self::Transit),
            _ => Err(r#"Router kind must be "server" or "transit""#),
        }
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct Ipv6Prefix {
    pub addr: Ipv6Addr,
    pub len: u8,
}

#[derive(Debug, Error)]
pub enum Ipv6PrefixParseError {
    #[error("expected CIDR representation <addr>/<mask>")]
    Cidr,

    #[error("address parse error: {0}")]
    Addr(#[from] AddrParseError),

    #[error("mask parse error: {0}")]
    Mask(#[from] ParseIntError),
}

impl std::str::FromStr for Ipv6Prefix {
    type Err = Ipv6PrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() < 2 {
            return Err(Ipv6PrefixParseError::Cidr);
        }

        Ok(Ipv6Prefix {
            addr: Ipv6Addr::from_str(parts[0])?,
            len: u8::from_str(parts[1])?,
        })
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelRoute {
    pub origin: TunnelOrigin,

    // The nexthop is only used to associate the route with a peer allowing us
    // to remove the route if the peer expires. It does not influence what goes
    // into the underlaying underlay routing platform. Tunnel routes only
    // influence the state of the unerlying encapsulation service.
    pub nexthop: Ipv6Addr,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelOrigin {
    pub overlay_prefix: IpPrefix,
    pub boundary_addr: Ipv6Addr,
    pub vni: u32,
}

impl From<crate::db::TunnelRoute> for TunnelOrigin {
    fn from(x: crate::db::TunnelRoute) -> Self {
        Self {
            overlay_prefix: x.origin.overlay_prefix,
            boundary_addr: x.origin.boundary_addr,
            vni: x.origin.vni,
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct Route {
    pub destination: Ipv6Prefix,
    pub nexthop: Ipv6Addr,
    pub ifname: String,
    pub path: Vec<String>,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct Ipv4Prefix {
    pub addr: Ipv4Addr,
    pub len: u8,
}

#[derive(Debug, Error)]
pub enum Ipv4PrefixParseError {
    #[error("expected CIDR representation <addr>/<mask>")]
    Cidr,

    #[error("address parse error: {0}")]
    Addr(#[from] AddrParseError),

    #[error("mask parse error: {0}")]
    Mask(#[from] ParseIntError),
}

impl std::str::FromStr for Ipv4Prefix {
    type Err = Ipv4PrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() < 2 {
            return Err(Ipv4PrefixParseError::Cidr);
        }

        Ok(Ipv4Prefix {
            addr: Ipv4Addr::from_str(parts[0])?,
            len: u8::from_str(parts[1])?,
        })
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum IpPrefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}

impl IpPrefix {
    pub fn addr(&self) -> IpAddr {
        match self {
            Self::V4(s) => s.addr.into(),
            Self::V6(s) => s.addr.into(),
        }
    }

    pub fn length(&self) -> u8 {
        match self {
            Self::V4(s) => s.len,
            Self::V6(s) => s.len,
        }
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(s) => write!(f, "{}/{}", s.addr, s.len),
            Self::V6(s) => write!(f, "{}/{}", s.addr, s.len),
        }
    }
}

#[derive(Debug, Error)]
pub enum IpPrefixParseError {
    #[error("v4 address parse error: {0}")]
    V4(#[from] Ipv4PrefixParseError),

    #[error("v4 address parse error: {0}")]
    V6(#[from] Ipv6PrefixParseError),
}

impl std::str::FromStr for IpPrefix {
    type Err = IpPrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(result) = Ipv4Prefix::from_str(s) {
            return Ok(IpPrefix::V4(result));
        }
        Ok(IpPrefix::V6(Ipv6Prefix::from_str(s)?))
    }
}
