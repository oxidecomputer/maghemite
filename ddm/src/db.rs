// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::{JsonSchema, JsonSchema_repr};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use slog::{error, Logger};
use std::collections::{HashMap, HashSet};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// The handle used to open a persistent key-value tree for originated
/// prefixes.
const ORIGINATE: &str = "originate";

/// The handle used to open a persistent key-value tree for originated
/// tunnel endpoints.
const TUNNEL_ORIGINATE: &str = "tunnel_originate";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("datastore error {0}")]
    DataStore(#[from] sled::Error),

    #[error("db key error {0}")]
    DbKey(String),

    #[error("db value error {0}")]
    DbValue(String),

    #[error("serialization error {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct Db {
    data: Arc<Mutex<DbData>>,
    persistent_data: sled::Db,
    log: Logger,
}

#[derive(Default, Clone)]
pub struct DbData {
    pub peers: HashMap<u32, PeerInfo>,
    pub imported: HashSet<Route>,
    pub imported_tunnel: HashSet<TunnelRoute>,
}

unsafe impl Sync for Db {}
unsafe impl Send for Db {}

impl Db {
    pub fn new(db_path: &str, log: Logger) -> Result<Self, sled::Error> {
        Ok(Self {
            data: Arc::new(Mutex::new(DbData::default())),
            persistent_data: sled::open(db_path)?,
            log,
        })
    }
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

    pub fn originate(
        &self,
        prefixes: &HashSet<Ipv6Prefix>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(ORIGINATE)?;
        for p in prefixes {
            tree.insert(p.db_key(), "")?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn originate_tunnel(
        &self,
        origins: &HashSet<TunnelOrigin>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(TUNNEL_ORIGINATE)?;
        for o in origins {
            let entry = serde_json::to_string(o)?;
            tree.insert(entry.as_str(), "")?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn originated(&self) -> Result<HashSet<Ipv6Prefix>, Error> {
        let tree = self.persistent_data.open_tree(ORIGINATE)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, _value) = match item {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error ddm originated prefix: {e}"
                        );
                        return None;
                    }
                };
                Some(match Ipv6Prefix::from_db_key(&key) {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error parsing ddm origin entry value: {e}"
                        );
                        return None;
                    }
                })
            })
            .collect();
        Ok(result)
    }

    pub fn originated_tunnel(&self) -> Result<HashSet<TunnelOrigin>, Error> {
        let tree = self.persistent_data.open_tree(TUNNEL_ORIGINATE)?;
        let result = tree
            .scan_prefix(vec![])
            .filter_map(|item| {
                let (key, _value) = match item {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error fetching ddm tunnel origin entry: {e}"
                        );
                        return None;
                    }
                };
                let value = String::from_utf8_lossy(&key);
                let value: TunnelOrigin = match serde_json::from_str(&value) {
                    Ok(item) => item,
                    Err(e) => {
                        error!(
                            self.log,
                            "db: error parsing ddm tunnel origin: {e}"
                        );
                        return None;
                    }
                };
                Some(value)
            })
            .collect();
        Ok(result)
    }

    pub fn withdraw(
        &self,
        prefixes: &HashSet<Ipv6Prefix>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(ORIGINATE)?;
        for p in prefixes {
            tree.remove(p.db_key())?;
        }
        tree.flush()?;
        Ok(())
    }

    pub fn withdraw_tunnel(
        &self,
        origins: &HashSet<TunnelOrigin>,
    ) -> Result<(), Error> {
        let tree = self.persistent_data.open_tree(TUNNEL_ORIGINATE)?;
        for o in origins {
            let entry = serde_json::to_string(o)?;
            tree.remove(entry.as_str())?;
        }
        tree.flush()?;
        Ok(())
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

impl Ipv6Prefix {
    pub fn db_key(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = self.addr.octets().into();
        buf.push(self.len);
        buf
    }

    pub fn from_db_key(v: &[u8]) -> Result<Self, Error> {
        if v.len() < 17 {
            Err(Error::DbKey(format!(
                "buffer to short for prefix 6 key {} < 17",
                v.len()
            )))
        } else {
            Ok(Self {
                addr: Ipv6Addr::from(<[u8; 16]>::try_from(&v[..16]).unwrap()),
                len: v[16],
            })
        }
    }
}

impl std::fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
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
    // influence the state of the underlying encapsulation service.
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

impl std::fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
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

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(p) => p.fmt(f),
            Self::V6(p) => p.fmt(f),
        }
    }
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
