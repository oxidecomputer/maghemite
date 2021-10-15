// Copyright 2021 Oxide Computer Company
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use rift_protocol::Level;
use std::net::{Ipv6Addr, AddrParseError};
use std::num::ParseIntError;
use thiserror::Error;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
pub struct Ipv6Prefix {
    pub addr: Ipv6Addr,
    pub mask: u8,
}

#[derive(Debug, Error)]
pub enum Ipv6PrefixParseError {
    #[error("expected CIDR representation <addr>/<mask")]
    Cidr,

    #[error("address parse error: {0}")]
    Addr(#[from] AddrParseError),

    #[error("mask parse error: {0}")]
    Mask(#[from] ParseIntError),
}

impl FromStr for Ipv6Prefix {
    type Err = Ipv6PrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {

        let parts: Vec<&str> = s.split("/").collect();
        if parts.len() < 2 {
            return Err(Ipv6PrefixParseError::Cidr);
        }

        Ok(Ipv6Prefix{
            addr: Ipv6Addr::from_str(parts[0])?,
            mask: u8::from_str(parts[1])?,
        })

    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
pub struct Config {
    pub id: u64,
    pub level: Level,
    pub prefix: Option<Ipv6Prefix>,
}
