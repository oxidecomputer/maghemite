use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr},
    num::ParseIntError,
};
use thiserror::Error;

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
pub struct Ipv6Prefix {
    pub addr: Ipv6Addr,
    pub len: u8,
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
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelOrigin {
    pub overlay_prefix: IpPrefix,
    pub boundary_addr: Ipv6Addr,
    pub vni: u32,
    #[serde(default)]
    pub metric: u64,
}
