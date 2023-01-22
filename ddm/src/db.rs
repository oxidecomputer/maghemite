// Copyright 2022 Oxide Computer Company

use schemars::{JsonSchema, JsonSchema_repr};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::{HashMap, HashSet};
use std::net::{AddrParseError, Ipv6Addr};
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

    pub fn import(&self, r: &HashSet<Route>) {
        self.data.lock().unwrap().imported.extend(r.clone());
    }

    pub fn delete_import(&self, r: &HashSet<Route>) {
        let imported = &mut self.data.lock().unwrap().imported;
        for x in r {
            imported.remove(x);
        }
    }

    pub fn originate(&self, p: &HashSet<Ipv6Prefix>) {
        self.data.lock().unwrap().originated.extend(p);
    }

    pub fn withdraw(&self, p: &HashSet<Ipv6Prefix>) {
        for prefix in p {
            self.data.lock().unwrap().originated.remove(prefix);
        }
    }

    pub fn set_peer(&self, index: u32, info: PeerInfo) {
        self.data.lock().unwrap().peers.insert(index, info);
    }

    pub fn remove_nexthop_routes(&self, nexthop: Ipv6Addr) -> HashSet<Route> {
        let mut data = self.data.lock().unwrap();
        let mut removed = HashSet::new();
        for x in &data.imported {
            if x.nexthop == nexthop {
                removed.insert(x.clone());
            }
        }
        for x in &removed {
            data.imported.remove(x);
        }
        removed
    }

    pub fn remove_peer(&self, index: u32) {
        self.data.lock().unwrap().peers.remove(&index);
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

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
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
pub struct Route {
    pub destination: Ipv6Prefix,
    pub nexthop: Ipv6Addr,
    pub ifname: String,
}
